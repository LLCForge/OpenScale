package org.openscale.android

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import org.openscale.go.openscale.Openscale
import java.net.Inet4Address

/**
 * Fiziksel ağı izler (#178, #179): ağ değişiminde Go'ya haber verilir ve
 * mobil veri / Wi-Fi politikası ağ türüne ve Wi-Fi adına göre çıkış düğümünü
 * seçer. Uygulama kendi VPN'inin dışında olduğundan varsayılan ağ fiziksel
 * ağdır.
 *
 * Wi-Fi adı (SSID) Android 10+ üzerinde konum izni ve açık konum ister; izin
 * yalnızca sahip SSID kuralı yazdığında istenir. İzin yoksa ad "" kalır ve
 * SSID kuralları eşleşmez. Ad cihazdan çıkmaz.
 */
class NetworkObserver(
    private val context: Context,
    private val wantSsid: Boolean,
    private val listener: Listener,
) {
    fun interface Listener {
        /**
         * [switched]: farklı bir ağa geçildi veya ağ kayboldu. [netId]: konum
         * izni gerektirmeyen yerel ağ kimliği (#477), bilinmiyorsa "".
         */
        fun onNetwork(kind: String, ssid: String, netId: String, switched: Boolean)
    }

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var lastKind = ""
    private var lastSsid = ""
    private var lastNetId = ""

    fun start() {
        val includeLocation = wantSsid && hasLocation()
        val cb = if (Build.VERSION.SDK_INT >= 31 && includeLocation) {
            // API 31+: SSID yalnızca bu bayrakla NetworkCapabilities'e girer.
            object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
                override fun onAvailable(network: Network) = report(null, true)
                override fun onLost(network: Network) = report(null, true)
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = report(caps, false)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = report(null, false)
            }
        } else {
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = report(null, true)
                override fun onLost(network: Network) = report(null, true)
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = report(caps, false)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = report(null, false)
            }
        }
        cm.registerDefaultNetworkCallback(cb)
        callback = cb
    }

    fun stop() {
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        callback = null
    }

    private fun report(caps: NetworkCapabilities?, switched: Boolean) {
        val c = caps ?: cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        val kind = when {
            c == null -> ""
            c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> KIND_WIFI
            c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> KIND_CELLULAR
            c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> KIND_ETHERNET
            else -> "other"
        }
        val ssid = if (kind == KIND_WIFI && wantSsid && hasLocation()) ssidOf(c) else ""
        val netId = if (kind == KIND_WIFI || kind == KIND_ETHERNET) identity(context, cm, cm.activeNetwork) else ""
        if (!switched && kind == lastKind && ssid == lastSsid && netId == lastNetId) return
        lastKind = kind
        lastSsid = ssid
        lastNetId = netId
        listener.onNetwork(kind, ssid, netId, switched)
    }

    private fun ssidOf(caps: NetworkCapabilities?): String {
        if (Build.VERSION.SDK_INT >= 31) {
            val info = caps?.transportInfo as? WifiInfo
            return info?.ssid ?: ""
        }
        // API 29-30: WifiManager üzerinden (31'de kullanımdan kalktı).
        val wm = context.applicationContext.getSystemService(WifiManager::class.java)
        @Suppress("DEPRECATION")
        return wm?.connectionInfo?.ssid ?: ""
    }

    private fun hasLocation(): Boolean =
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    companion object {
        const val KIND_WIFI = "wifi"
        const val KIND_CELLULAR = "cellular"
        const val KIND_ETHERNET = "ethernet"

        /**
         * Konum izni olmadan ağ kimliği (#477): LinkProperties'teki IPv4
         * ağ geçidi, DHCP sunucusu, DNS sunucuları, arama alanı ve IPv4 alt
         * ağı, kuruluma özel tuzla Go'da özetlenir (NetworkID). Bilgiler
         * cihazdan çıkmaz; kimlik doğrulanmaz (SSID gibi).
         */
        fun identity(context: Context, cm: ConnectivityManager, network: Network?): String {
            val lp = network?.let { cm.getLinkProperties(it) } ?: return ""
            val gateway = lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress ?: ""
            val dhcp = if (Build.VERSION.SDK_INT >= 30) lp.dhcpServerAddress?.hostAddress ?: "" else ""
            val dns = lp.dnsServers.mapNotNull { it.hostAddress }.joinToString(",")
            val subnet = lp.linkAddresses.firstOrNull { it.address is Inet4Address }
                ?.let { "${it.address.hostAddress}/${it.prefixLength}" } ?: ""
            return try {
                Openscale.networkID(Prefs(context).netIdSalt(), gateway, dhcp, dns, lp.domains ?: "", subnet)
            } catch (e: Exception) {
                ""
            }
        }

        /** Etkin ağın türü ve kimliği (politika penceresi "bulunduğum ağ" için). */
        fun currentIdentity(context: Context): String {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val n = cm.activeNetwork ?: return ""
            val caps = cm.getNetworkCapabilities(n) ?: return ""
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
            ) {
                return ""
            }
            return identity(context, cm, n)
        }
    }
}
