package org.openscale.android

import android.content.Context
import android.net.TrafficStats
import android.os.Process
import android.util.Log
import org.json.JSONObject
import org.openscale.go.openscale.Openscale
import java.io.File
import java.time.YearMonth

/**
 * Mobil veri kullanım sayacı (#471, P08).
 *
 * Uygulamanın kendi UID'sinin trafiği (TrafficStats) örneklenir: WireGuard
 * tüneli, aktarıcı ve koordinatör bağlantıları ve arka plan trafiği; uygulama
 * kendi VPN'inin dışında olduğundan bu sayı fiziksel ağdaki gerçek
 * tüketimdir. Fark, ölçüldüğü ağ türüne (wifi, cellular, diğer) yazılır;
 * toplama ve ay tutma Go'dadır (UsageAdd). Sayaç cihazdan çıkmaz. Yeniden
 * başlatmada sistem sayacı sıfırlanırsa o örnek yalnızca yeni başlangıç olur.
 * Çağrılar tek iş parçacığından (VPN servisinin işçisi) yapılır.
 */
class UsageMeter(private val context: Context) {
    private val uid = Process.myUid()
    private var lastRx = -1L
    private var lastTx = -1L

    /** O ana kadarki farkı [kind] ağına yazar ve yeni başlangıcı alır. */
    fun sample(kind: String) {
        val rx = TrafficStats.getUidRxBytes(uid)
        val tx = TrafficStats.getUidTxBytes(uid)
        if (rx == TrafficStats.UNSUPPORTED.toLong() || tx == TrafficStats.UNSUPPORTED.toLong()) return
        if (lastRx >= 0 && rx >= lastRx && tx >= lastTx && kind.isNotEmpty()) {
            try {
                Openscale.usageAdd(path(context), YearMonth.now().toString(), kind, rx - lastRx, tx - lastTx)
            } catch (e: Exception) {
                Log.w(TAG, "kullanım sayacı yazılamadı", e)
            }
        }
        lastRx = rx
        lastTx = tx
    }

    companion object {
        private const val TAG = "OpenScaleUsage"
        const val SAMPLE_MS = 60_000L

        fun path(context: Context): String = File(context.noBackupFilesDir, "usage.json").absolutePath

        /** Bu ayın özeti: "mobil veri X MB, Wi-Fi Y MB" (okunamazsa ""). */
        fun summary(context: Context): String = try {
            val month = YearMonth.now().toString()
            val months = JSONObject(Openscale.usageSummary(path(context))).getJSONArray("months")
            var text = ""
            for (i in 0 until months.length()) {
                val m = months.getJSONObject(i)
                if (m.optString("month") != month) continue
                fun total(k: String) = m.getJSONObject(k).let { it.optLong("rx") + it.optLong("tx") }
                text = context.getString(R.string.usage_month, mb(total("cellular")), mb(total("wifi")))
            }
            text
        } catch (e: Exception) {
            ""
        }

        private fun mb(bytes: Long): String = String.format(java.util.Locale.ROOT, "%.1f", bytes / 1_000_000.0)
    }
}
