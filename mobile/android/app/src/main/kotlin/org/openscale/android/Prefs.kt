package org.openscale.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Gizli olmayan tercihler; anahtarlar burada değil KeyVault'tadır. */
class Prefs(private val context: Context) {
    private val sp = context.getSharedPreferences("openscale", Context.MODE_PRIVATE)

    var exitNode: String
        get() = sp.getString(KEY_EXIT, "") ?: ""
        set(v) = sp.edit().putString(KEY_EXIT, v.trim()).apply()

    var batterySaver: Boolean
        get() = sp.getBoolean(KEY_BATTERY, true)
        set(v) = sp.edit().putBoolean(KEY_BATTERY, v).apply()

    /** Uygulama bazlı bölme (F-049, P27): "", "include" veya "exclude". */
    var appsMode: String
        get() = sp.getString(KEY_APPS_MODE, "") ?: ""
        set(v) = sp.edit().putString(KEY_APPS_MODE, v).apply()

    var apps: Set<String>
        get() = sp.getStringSet(KEY_APPS, emptySet())?.toSet() ?: emptySet()
        set(v) = sp.edit().putStringSet(KEY_APPS, v.toSet()).apply()

    /** Mobil veri ve Wi-Fi politikası (#179): Go'nun doğruladığı JSON. */
    var networkPolicy: String
        get() = sp.getString(KEY_POLICY, "") ?: ""
        set(v) = sp.edit().putString(KEY_POLICY, v).apply()

    var policyEnabled: Boolean
        get() = sp.getBoolean(KEY_POLICY_ON, false)
        set(v) = sp.edit().putBoolean(KEY_POLICY_ON, v).apply()

    /** Biyometrik kilit (#177): hassas işlemler kimlik doğrulaması ister. */
    var biometricLock: Boolean
        get() = sp.getBoolean(KEY_BIOMETRIC, false)
        set(v) = sp.edit().putBoolean(KEY_BIOMETRIC, v).apply()

    /** Kayıp modu (#184): anahtarların iptal nedeniyle silindiği an (ms), yoksa 0. */
    var wipedAt: Long
        get() = sp.getLong(KEY_WIPED, 0L)
        set(v) = sp.edit().putLong(KEY_WIPED, v).apply()

    /**
     * Ağ kimliği tuzu (#477): kuruluma özel, ilk kullanımda üretilir; kimlik
     * başka telefonlarla ilişkilendirilemez. Sır değildir ama dışarı verilmez.
     */
    fun netIdSalt(): String = synchronized(Prefs::class.java) {
        sp.getString(KEY_NETID_SALT, null)?.takeIf { it.length == 64 } ?: run {
            val salt = org.openscale.go.openscale.Openscale.newNetworkIDSalt()
            sp.edit().putString(KEY_NETID_SALT, salt).commit()
            salt
        }
    }

    /**
     * Plan ve Tunnel.start'a aynı dize verilir (ADR-0101). [exit] ağ
     * politikasının seçtiği çıkış düğümüdür; null ise elle seçilen.
     */
    fun optionsJson(exit: String? = null): String {
        val o = JSONObject()
            .put("exit_node", exit ?: exitNode)
            .put("battery_saver", batterySaver)
        val mode = appsMode
        // Uygulamanın kendisi her zaman VPN dışındadır; listeye girmez.
        val list = apps.filter { it != context.packageName }.sorted()
        if ((mode == MODE_INCLUDE || mode == MODE_EXCLUDE) && list.isNotEmpty()) {
            o.put("apps_mode", mode).put("apps", JSONArray(list))
        }
        return o.toString()
    }

    companion object {
        const val MODE_INCLUDE = "include"
        const val MODE_EXCLUDE = "exclude"
        private const val KEY_EXIT = "exit_node"
        private const val KEY_BATTERY = "battery_saver"
        private const val KEY_APPS_MODE = "apps_mode"
        private const val KEY_APPS = "apps"
        private const val KEY_POLICY = "network_policy"
        private const val KEY_POLICY_ON = "network_policy_on"
        private const val KEY_BIOMETRIC = "biometric_lock"
        private const val KEY_WIPED = "wiped_at"
        private const val KEY_NETID_SALT = "netid_salt"

        /** Ağ belgesi ve kök çapası; yedeğe girmeyen klasörde. */
        fun stateDir(context: Context): String =
            File(context.noBackupFilesDir, "openscale").absolutePath
    }
}
