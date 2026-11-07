package org.openscale.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import org.openscale.go.openscale.Openscale
import org.openscale.go.openscale.Platform
import org.openscale.go.openscale.Tunnel
import java.net.InetAddress
import java.util.concurrent.Executors

/**
 * OpenScale VPN servisi (#173, #175, #178; ADR-0101).
 *
 * İnce kabuk: Go çekirdeğinden planı alır, VpnService.Builder ile arayüzü
 * kurar, dosya tanıtıcısını Go'ya devreder. Uygulamanın kendisi VPN dışında
 * tutulur (addDisallowedApplication), böylece WireGuard ve koordinatör
 * bağlantıları tünele dönmez; WireGuard soketleri ayrıca protect() ile
 * korunur.
 *
 * Kill switch (#175): Android'in "Her zaman açık VPN" + "VPN olmadan
 * bağlantıları engelle" ayarıdır; sistem bu servisi açılışta kendisi
 * başlatır (intent null veya android.net.VpnService). Ek olarak, çıkış
 * düğümü seçiliyken bağlantı kurulamazsa servis tüm trafiği yutan bir arayüz
 * tutar (uygulama içi kill switch): engelleme ayarı kapalı olsa da trafik
 * tünel dışına çıkmaz.
 *
 * Pil (#178): push servisi yok, uyandırma kilidi yok; Go tarafındaki pil
 * dostu profil eşleri yalnızca trafik varken canlı tutar. Ağ değişince
 * yalnızca Go'ya haber verilir.
 */
class OpenScaleVpnService : VpnService() {

    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var vault: KeyVault
    private lateinit var prefs: Prefs

    // Yalnızca worker iş parçacığında değişir.
    private var tunnel: Tunnel? = null
    private var blackhole: ParcelFileDescriptor? = null
    private var observer: NetworkObserver? = null

    /** Çalışan tünelin çıkış düğümü (politika veya elle seçim, P27). */
    @Volatile
    private var currentExit: String = ""

    /** Fiziksel ağ (#179): politika bunu kullanır. */
    @Volatile
    private var netKind: String = ""

    @Volatile
    private var netSsid: String = ""

    /** Konum izni olmadan ağ kimliği (#477, P08). */
    @Volatile
    private var netId: String = ""

    private val main = Handler(Looper.getMainLooper())
    private val policyRecheck = Runnable { worker.execute { applyPolicy() } }

    /** Kullanım sayacı (#471, P08): yalnızca worker iş parçacığında. */
    private val usage by lazy { UsageMeter(this) }
    private val usageTick = object : Runnable {
        override fun run() {
            worker.execute { usage.sample(netKind) }
            main.postDelayed(this, UsageMeter.SAMPLE_MS)
        }
    }

    private val platform = object : Platform {
        override fun protect(fd: Long): Boolean = this@OpenScaleVpnService.protect(fd.toInt())

        override fun log(level: Long, line: String) {
            val priority = when (level) {
                0L -> Log.DEBUG
                2L -> Log.WARN
                3L -> Log.ERROR
                else -> Log.INFO
            }
            Log.println(priority, TAG, line)
        }

        override fun statusChanged(status: String) {
            lastStatus = status
            val st = runCatching { JSONObject(status) }.getOrNull()
            val running = st?.optBoolean("running") == true
            notifyText(statusText(st))
            OpenScaleTileService.requestRefresh(this@OpenScaleVpnService)
            StatusWidget.refresh(this@OpenScaleVpnService)
            // Tünel durdu (ör. "bu cihaz belgede yok"): kayıp modu (#184).
            if (!running) {
                worker.execute {
                    if (tunnel != null && tunnel?.running() == false &&
                        LossMode.checkAndWipe(this@OpenScaleVpnService, vault, prefs)
                    ) {
                        wiped()
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        vault = KeyVault(this)
        prefs = Prefs(this)
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            worker.execute {
                stopWatching()
                disconnect()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            return START_NOT_STICKY
        }
        // ACTION_CONNECT, ya da her zaman açık VPN için sistemin başlatması.
        startInForeground(R.string.notif_connecting)
        worker.execute {
            // Politika değişmiş olabilir (SSID gerekip gerekmediği): gözlemci yeniden kurulur.
            stopWatching()
            connect()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Başka bir VPN seçildi veya kullanıcı izni geri aldı.
        worker.execute {
            stopWatching()
            disconnect()
            stopSelf()
        }
    }

    override fun onDestroy() {
        worker.execute {
            stopWatching()
            disconnect()
        }
        worker.shutdown()
        super.onDestroy()
    }

    private fun connect() {
        disconnect()
        val stateDir = Prefs.stateDir(this)
        if (Openscale.version() != GO_API) {
            failClosed(getString(R.string.err_api))
            return
        }
        // Kayıp modu (#184): iptal edilmiş cihaz bağlanmaz, anahtarı silinir.
        if (LossMode.checkAndWipe(this, vault, prefs)) {
            wiped()
            return
        }
        watchNetwork()
        currentExit = effectiveExit()
        val secrets = try {
            vault.load()
        } catch (e: Exception) {
            failClosed(e.message ?: "anahtar okunamadı")
            return
        }
        try {
            val options = prefs.optionsJson(currentExit)
            val plan = JSONObject(Openscale.plan(stateDir, secrets, options))
            val builder = Builder()
                .setSession(plan.getString("session"))
                .setMtu(plan.getInt("mtu"))
                .setMetered(false)
            forEachPrefix(plan.getJSONArray("addresses")) { a, len -> builder.addAddress(a, len) }
            forEachPrefix(plan.getJSONArray("routes")) { a, len -> builder.addRoute(a, len) }
            plan.optJSONArray("dns_servers")?.let { arr ->
                for (i in 0 until arr.length()) builder.addDnsServer(InetAddress.getByName(arr.getString(i)))
            }
            plan.optJSONArray("search_domains")?.let { arr ->
                for (i in 0 until arr.length()) builder.addSearchDomain(arr.getString(i))
            }
            applyApps(builder, plan)
            val pfd = builder.establish() ?: throw IllegalStateException("VPN izni yok")
            // Tanıtıcının sahibi artık Go; hata olsa da Go kapatır.
            val fd = pfd.detachFd()
            val t = Openscale.newTunnel(stateDir, platform)
            t.start(fd.toLong(), secrets, options)
            tunnel = t
            // #175: ayar sistemde; uygulama yalnızca durumu gösterir ve
            // çıkış düğümsüz engellemenin interneti keseceğini bildirir.
            alwaysOnState = getString(
                R.string.always_on_state,
                getString(if (isAlwaysOn) R.string.yes else R.string.no),
                getString(if (isLockdownEnabled) R.string.yes else R.string.no),
            )
            if (isLockdownEnabled && !plan.optBoolean("full_tunnel")) {
                Log.w(TAG, "VPN olmadan engelleme açık ama çıkış düğümü yok: ağ dışı internet trafiği engelli")
            }
        } catch (e: Exception) {
            Log.w(TAG, "bağlantı kurulamadı", e)
            failClosed(e.message ?: "bağlantı kurulamadı")
        } finally {
            secrets.fill(0)
        }
    }

    /**
     * Uygulama bazlı bölme (F-049, P27). Builder ya izinli ya hariç listesi
     * alır, ikisini birden değil. Uygulamanın kendisi her durumda VPN
     * dışındadır: hariç kipinde listeye eklenir, izinli kipinde hiç eklenmez.
     * Kurulu olmayan paket atlanır; izinli kipinde hiçbiri eklenemezse bütün
     * uygulamalar (bu uygulama dahil, döngü) VPN'e gireceğinden bağlanılmaz.
     */
    private fun applyApps(builder: Builder, plan: JSONObject) {
        val allowed = plan.optJSONArray("allowed_apps")
        if (allowed != null && allowed.length() > 0) {
            var added = 0
            for (i in 0 until allowed.length()) {
                val pkg = allowed.getString(i)
                if (pkg == packageName) continue
                try {
                    builder.addAllowedApplication(pkg)
                    added++
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "kurulu olmayan uygulama atlandı: $pkg")
                }
            }
            check(added > 0) { getString(R.string.apps_none_installed) }
            return
        }
        // Uygulamanın kendi bağlantıları (WireGuard, koordinatör) VPN dışında.
        builder.addDisallowedApplication(packageName)
        plan.optJSONArray("disallowed_apps")?.let { arr ->
            for (i in 0 until arr.length()) {
                val pkg = arr.getString(i)
                if (pkg == packageName) continue
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "kurulu olmayan uygulama atlandı: $pkg")
                }
            }
        }
    }

    /** Ağ politikası açıksa onun seçtiği, değilse elle seçilen çıkış düğümü (#179). */
    private fun effectiveExit(): String {
        if (!prefs.policyEnabled || prefs.networkPolicy.isEmpty()) return prefs.exitNode
        if (netKind.isEmpty()) {
            // Gözlemci henüz rapor vermedi: etkin ağa bakılır.
            val cm = getSystemService(ConnectivityManager::class.java)
            val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            netKind = when {
                caps == null -> ""
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkObserver.KIND_WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkObserver.KIND_CELLULAR
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkObserver.KIND_ETHERNET
                else -> "other"
            }
        }
        return try {
            if (netId.isEmpty() && (netKind == NetworkObserver.KIND_WIFI || netKind == NetworkObserver.KIND_ETHERNET)) {
                netId = NetworkObserver.currentIdentity(this)
            }
            Openscale.exitNodeForNetworkID(prefs.networkPolicy, netKind, netSsid, netId, prefs.exitNode)
        } catch (e: Exception) {
            // Bozuk politika: elle seçime düşülür (o da yoksa çıkış düğümü yok).
            Log.w(TAG, "ağ politikası okunamadı", e)
            prefs.exitNode
        }
    }

    /** Ağ değişti: politika başka bir çıkış düğümü seçiyorsa yeniden bağlanır. */
    private fun applyPolicy() {
        if (tunnel == null && blackhole == null) return
        val want = effectiveExit()
        if (want != currentExit) {
            Log.i(TAG, "ağ politikası çıkış düğümünü değiştiriyor")
            connect()
        }
    }

    /** Kayıp modu (#184) anahtarları sildi: bağlantı yok, kalıcı bildirim. */
    private fun wiped() {
        stopWatching()
        disconnect()
        lastStatus = JSONObject().put("running", false).put("error", getString(R.string.lost_wiped)).toString()
        stopForeground(STOP_FOREGROUND_DETACH)
        notifyText(getString(R.string.lost_wiped))
        OpenScaleTileService.requestRefresh(this)
        stopSelf()
    }

    /** Hata: çıkış düğümü seçiliyse trafik tünel dışına çıkmasın diye yutulur. */
    private fun failClosed(reason: String) {
        lastStatus = JSONObject().put("running", false).put("error", reason).toString()
        OpenScaleTileService.requestRefresh(this)
        if (currentExit.isEmpty() && prefs.exitNode.isEmpty()) {
            notifyState(R.string.notif_connecting)
            return
        }
        try {
            blackhole = Builder()
                .setSession("OpenScale (engelli)")
                .addAddress("10.111.222.1", 32)
                .addAddress("fd6f:7363::1", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDisallowedApplication(packageName)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "engelleme arayüzü kurulamadı", e)
        }
        notifyState(R.string.notif_blocked)
    }

    /** Tüneli ve engelleme arayüzünü kapatır; ağ gözlemcisi yeniden bağlanmada kalır. */
    private fun disconnect() {
        tunnel?.stop()
        tunnel = null
        blackhole?.let { runCatching { it.close() } }
        blackhole = null
    }

    /** Servis tamamen durunca ağ gözlemcisi de kapanır. */
    private fun stopWatching() {
        main.removeCallbacks(policyRecheck)
        main.removeCallbacks(usageTick)
        if (observer != null) usage.sample(netKind) // son farkı yaz (#471)
        observer?.stop()
        observer = null
    }

    /**
     * Wi-Fi ile mobil veri arasında geçişte Go yolları hemen yeniden dener
     * (#178); ağ türü veya Wi-Fi adı değişince politika (#179) 2 sn sonra
     * yeniden değerlendirilir (hızlı geçişlerde tekrar tekrar bağlanmaz).
     */
    private fun watchNetwork() {
        if (observer != null) return
        val wantSsid = prefs.policyEnabled && prefs.networkPolicy.contains("\"ssid\"")
        val o = NetworkObserver(this, wantSsid) { kind, ssid, id, switched ->
            // Önceki ağın trafiği önceki ağ türüne yazılır (#471).
            val previous = netKind
            if (kind != previous) worker.execute { usage.sample(previous) }
            netKind = kind
            netSsid = ssid
            netId = id
            if (switched) worker.execute { tunnel?.networkChanged() }
            if (prefs.policyEnabled) {
                main.removeCallbacks(policyRecheck)
                main.postDelayed(policyRecheck, POLICY_DEBOUNCE_MS)
            }
        }
        o.start()
        observer = o
        main.removeCallbacks(usageTick)
        main.postDelayed(usageTick, UsageMeter.SAMPLE_MS)
    }

    /** Bildirim metni: durum, çıkış düğümü ve eş sayısı. */
    private fun statusText(st: JSONObject?): String {
        if (st == null) return getString(R.string.notif_connecting)
        if (!st.optBoolean("running")) {
            val err = st.optString("error")
            return if (err.isNotEmpty()) getString(R.string.notif_error, err) else getString(R.string.notif_connecting)
        }
        val exit = st.optString("exit_node")
        val peers = st.optInt("peers")
        return if (exit.isNotEmpty()) {
            getString(R.string.notif_connected_exit, exit, peers)
        } else {
            getString(R.string.notif_connected_peers, peers)
        }
    }

    private fun forEachPrefix(arr: org.json.JSONArray, add: (String, Int) -> Unit) {
        for (i in 0 until arr.length()) {
            val p = arr.getString(i)
            val slash = p.lastIndexOf('/')
            require(slash > 0) { "geçersiz önek: $p" }
            add(p.substring(0, slash), p.substring(slash + 1).toInt())
        }
    }

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW).apply {
                // #475: kilit ekranında yalnızca genel sürüm (cihaz adı, çıkış
                // düğümü, hata metni yok). Kullanıcı kanalı daha da gizleyebilir.
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
        )
    }

    private fun notification(textRes: Int): Notification = notification(getString(textRes))

    /**
     * Kalıcı bildirim: durum metni ve "Bağlantıyı kes" eylemi. Biyometrik
     * kilit açıksa (#177) eylem doğrudan kesmez, ana ekranı doğrulama
     * isteğiyle açar. Bildirim kilit ekranında ayrıntı göstermez.
     */
    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = if (prefs.biometricLock) {
            PendingIntent.getActivity(
                this, 1,
                DisconnectRequest.intent(this),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        } else {
            PendingIntent.getService(
                this, 2,
                Intent(this, OpenScaleVpnService::class.java).setAction(ACTION_DISCONNECT),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
        // #475: genel sürümde yalnızca uygulama adı; eylem ve içerik yok.
        val redacted = Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .build()
        return Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(redacted)
            .addAction(Notification.Action.Builder(null, getString(R.string.disconnect), stop).build())
            .build()
    }

    private fun startInForeground(textRes: Int) {
        val n = notification(textRes)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    private fun notifyState(textRes: Int) = notifyText(getString(textRes))

    private fun notifyText(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        const val ACTION_CONNECT = "org.openscale.android.CONNECT"
        const val ACTION_DISCONNECT = "org.openscale.android.DISCONNECT"
        const val GO_API = "openscale-mobile/3"
        private const val TAG = "OpenScale"
        private const val CHANNEL = "openscale-vpn"
        private const val NOTIFICATION_ID = 1
        private const val POLICY_DEBOUNCE_MS = 2000L

        @Volatile
        var lastStatus: String = "{\"running\":false}"

        @Volatile
        var alwaysOnState: String = ""

        fun start(context: Context) {
            context.startForegroundService(Intent(context, OpenScaleVpnService::class.java).setAction(ACTION_CONNECT))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, OpenScaleVpnService::class.java).setAction(ACTION_DISCONNECT))
        }
    }
}
