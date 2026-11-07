package org.openscale.android

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import org.openscale.go.openscale.Openscale
import java.util.concurrent.Executors

/**
 * En küçük arayüz (#173): anahtar oluşturma ve kayıt isteği, ağa katılım,
 * çıkış düğümü ve pil seçimi, bağlan/kes ve her zaman açık VPN ayarlarına
 * geçiş (#175). Kütüphane kullanılmaz; görünümler koddan kurulur.
 *
 * P27: QR ile kayıt ve davet okuma (#182), kayıt isteğinin QR olarak
 * gösterilmesi, biyometrik kilit (#177), ağ politikası (#179), uygulama
 * bazlı bölme (F-049), kayıp modu bilgisi (#184) ve imza sertifikası
 * özeti (#183).
 */
class MainActivity : Activity() {

    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var vault: KeyVault
    private lateinit var prefs: Prefs

    private lateinit var status: TextView
    private lateinit var request: TextView
    private lateinit var bundleInput: EditText
    private lateinit var fpInput: EditText
    private lateinit var exitInput: EditText
    private lateinit var battery: CheckBox
    private lateinit var qrImage: ImageView
    private lateinit var lockBox: CheckBox
    private lateinit var gate: BiometricGate
    private lateinit var scan: ScanHandler
    private var requestLine: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Kayıt isteği ve katılım paketi ekran görüntüsüne ve son uygulamalar
        // önizlemesine düşmez.
        // #474: API 33+ son uygulamalar önizlemesi de kapatılır; pencereler
        // (davet onayı, NFC) SecureWindow ile ayrıca korunur.
        SecureWindow.activity(this)
        vault = KeyVault(this)
        prefs = Prefs(this)
        gate = BiometricGate(this, prefs)
        setContentView(buildLayout())
        scan = ScanHandler(this, vault, gate, status, bundleInput, fpInput)
        handleIntent(intent)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
        // Kayıp modu (#184): uygulama açılışında da denetlenir.
        worker.execute {
            if (LossMode.checkAndWipe(this, vault, prefs)) {
                OpenScaleVpnService.stop(this)
                runOnUiThread { refreshStatus() }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    override fun onDestroy() {
        scan.cancel()
        worker.shutdown()
        super.onDestroy()
    }

    /**
     * Bildirim veya kutucuktan gelen kesme isteği: biyometrik kilitten geçer (#177).
     * SECURITY FIX: CWE-926 (bulgu 10) MainActivity dışa açıktır; kesme
     * isteği yalnızca dışa kapalı DisconnectRequest takma adından gelirse
     * kabul edilir. Başka bir uygulamanın MainActivity'ye gönderdiği aynı
     * eylem yok sayılır: etkinlik yalnızca öne gelir, tünel kapanmaz.
     */
    private fun handleIntent(intent: Intent?) {
        if (intent?.action != ACTION_REQUEST_DISCONNECT) return
        val accepted = DisconnectRequest.accept(intent.action, intent.component?.className)
        intent.action = null
        if (accepted) disconnect()
    }

    private fun disconnect() {
        gate.run(getString(R.string.disconnect)) { OpenScaleVpnService.stop(this) }
    }

    private fun buildLayout(): View {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        fun text(s: String) = TextView(this).apply { text = s; textSize = 15f }
        fun button(res: Int, onClick: () -> Unit) = Button(this).apply {
            setText(res)
            setOnClickListener { onClick() }
        }

        status = text("").also { col.addView(text(getString(R.string.status_title))); col.addView(it) }

        col.addView(button(R.string.key_create) { createKey() })
        col.addView(button(R.string.key_show) { showRequest() })
        // #182: telefon kayıt isteğini QR olarak gösterir, yönetici bilgisayar okur.
        qrImage = ImageView(this).apply {
            adjustViewBounds = true
            contentDescription = getString(R.string.key_qr_desc)
            visibility = View.GONE
        }
        col.addView(qrImage)
        request = text("").apply { setTextIsSelectable(true) }
        col.addView(request)
        col.addView(button(R.string.key_copy) { copyRequest() })
        col.addView(text(getString(R.string.key_hint)))

        bundleInput = EditText(this).apply {
            setHint(R.string.join_bundle)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        fpInput = EditText(this).apply {
            setHint(R.string.join_fp)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        col.addView(button(R.string.scan) { startActivityForResult(Intent(this, QrScanActivity::class.java), REQ_SCAN) })
        // #470: kamerasız alternatif; okunan davet QR'deki gibi onaydan geçer.
        if (NfcInvite.available(this)) {
            col.addView(button(R.string.nfc_receive) { NfcInvite.receive(this) { scan.handle(it) } })
        }
        if (NfcInvite.canShare(this)) {
            col.addView(button(R.string.nfc_share) { NfcInvite.share(this) })
        }
        col.addView(bundleInput)
        col.addView(fpInput)
        col.addView(button(R.string.join) { join() })

        exitInput = EditText(this).apply {
            setHint(R.string.exit_node)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setText(prefs.exitNode)
        }
        battery = CheckBox(this).apply {
            setText(R.string.battery)
            isChecked = prefs.batterySaver
        }
        col.addView(exitInput)
        col.addView(battery)
        col.addView(button(R.string.connect) { connect() })
        col.addView(button(R.string.disconnect) { disconnect() })
        col.addView(button(R.string.policy_title) {
            gate.run(getString(R.string.policy_title)) { PolicyDialog.show(this, prefs, REQ_LOCATION) { reconnectIfRunning() } }
        })
        col.addView(button(R.string.apps_title) {
            gate.run(getString(R.string.apps_title)) { AppPicker.show(this, prefs) { reconnectIfRunning() } }
        })
        lockBox = CheckBox(this).apply {
            setText(R.string.bio_lock)
            isChecked = prefs.biometricLock
            setOnClickListener {
                // Görünür durum yalnızca doğrulamadan sonra değişir.
                val want = isChecked
                isChecked = prefs.biometricLock
                val done: (Boolean) -> Unit = { lockBox.isChecked = prefs.biometricLock }
                if (want) gate.enable(done) else gate.disable(done)
            }
        }
        col.addView(lockBox)

        col.addView(button(R.string.always_on) { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) })
        col.addView(text(getString(R.string.always_on_help)))

        // #183: kurulu APK'nın imza sertifikası; sahibin yayımladığıyla karşılaştırılır.
        val certs = runCatching { AppSignature.certificateSha256(this) }.getOrDefault(emptyList())
        col.addView(text(getString(R.string.sign_cert, certs.joinToString("\n").ifEmpty { "?" })).apply { setTextIsSelectable(true) })

        return ScrollView(this).apply { addView(col) }
    }

    private fun background(work: () -> String) {
        worker.execute {
            val msg = try {
                work()
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
            runOnUiThread { status.text = msg }
        }
    }

    private fun createKey() = background {
        if (vault.hasKey()) {
            "Cihaz anahtarı zaten var."
        } else {
            val secrets = Openscale.generateDeviceSecrets()
            try {
                vault.store(secrets)
                prefs.wipedAt = 0L // kayıp modu (#184) bildirimi artık geçerli değil
            } finally {
                secrets.fill(0)
            }
            "Cihaz anahtarı oluşturuldu ve Keystore ile şifrelendi."
        }
    }

    private fun showRequest() = background {
        val secrets = vault.load()
        val out = try {
            Openscale.enrollmentRequest(secrets, Build.MODEL ?: "android")
        } finally {
            secrets.fill(0)
        }
        val line = out.substringBefore('\n')
        val fp = out.substringAfter('\n', "")
        val sas = vault.load().let { s ->
            try {
                Openscale.deviceSAS(s)
            } finally {
                s.fill(0)
            }
        }
        val png = Openscale.encodeQRPNG(line)
        val bitmap = BitmapFactory.decodeByteArray(png, 0, png.size)
        runOnUiThread {
            requestLine = line
            qrImage.setImageBitmap(bitmap)
            qrImage.visibility = View.VISIBLE
            request.text = getString(R.string.key_request_text, line, fp, sas)
        }
        "Kayıt isteği hazır."
    }

    private fun copyRequest() {
        if (requestLine.isEmpty()) return
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("OpenScale kayıt isteği", requestLine)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        cm.setPrimaryClip(clip)
    }

    private fun join() = gate.run(getString(R.string.join)) {
        val bundle = bundleInput.text.toString()
        val fp = fpInput.text.toString()
        background {
            val summary = Openscale.join(Prefs.stateDir(this), bundle, fp)
            runOnUiThread { bundleInput.setText("") }
            "Ağa katılındı: $summary"
        }
    }

    private fun connect() {
        val exit = exitInput.text.toString().trim()
        if (exit != prefs.exitNode) {
            // Çıkış düğümünü değiştirmek veya kapatmak kilitlidir (#177).
            gate.run(getString(R.string.exit_change)) {
                prefs.exitNode = exit
                connect()
            }
            return
        }
        prefs.batterySaver = battery.isChecked
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN)
        } else {
            OpenScaleVpnService.start(this)
        }
    }

    @Deprecated("Activity sonuç API'si; AndroidX kullanılmadığı için")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            OpenScaleVpnService.start(this)
        }
        if (requestCode == REQ_SCAN && resultCode == RESULT_OK) {
            data?.getStringExtra(QrScanActivity.EXTRA_TEXT)?.let { scan.handle(it) }
        }
    }

    /** Politika veya uygulama listesi değişti: çalışan tünel yeni seçenekle kurulur. */
    private fun reconnectIfRunning() {
        val running = runCatching { JSONObject(OpenScaleVpnService.lastStatus).optBoolean("running") }.getOrDefault(false)
        if (running) OpenScaleVpnService.start(this)
    }

    private fun refreshStatus() {
        val always = OpenScaleVpnService.alwaysOnState.ifEmpty {
            getString(R.string.always_on_state, getString(R.string.unknown), getString(R.string.unknown))
        }
        val lost = if (prefs.wipedAt != 0L) getString(R.string.lost_wiped) + "\n" else ""
        status.text = lost + OpenScaleVpnService.lastStatus + "\n" + always
        // #471: bu ayın OpenScale trafiği (cihazdan çıkmaz).
        worker.execute {
            val usage = UsageMeter.summary(this)
            if (usage.isNotEmpty()) runOnUiThread { status.append("\n" + usage) }
        }
    }

    companion object {
        /** Biyometrik kilitli kesme isteği (bildirim, hızlı ayar kutucuğu). */
        const val ACTION_REQUEST_DISCONNECT = DisconnectRequest.ACTION
        private const val REQ_VPN = 1
        private const val REQ_NOTIFICATIONS = 2
        private const val REQ_SCAN = 3
        private const val REQ_LOCATION = 4
    }
}
