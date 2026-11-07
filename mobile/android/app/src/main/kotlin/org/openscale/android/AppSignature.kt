package org.openscale.android

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest

/**
 * Google Play'siz dağıtım (#183, P27): APK sahibin kendi anahtarıyla
 * imzalanır. Android bir güncellemeyi yalnızca aynı imza sertifikasıyla
 * kabul eder; ilk kurulumda sertifikanın SHA-256 özeti sahibin ayrı bir
 * kanaldan yayımladığı değerle karşılaştırılır (docs/android-dagitim.md).
 * Bu ekran o değeri gösterir. Ağ bağlantısı kurulmaz.
 */
object AppSignature {

    /** İmza sertifikalarının SHA-256 özetleri (AA:BB:… biçiminde). */
    fun certificateSha256(context: Context): List<String> {
        // GET_SIGNING_CERTIFICATES: API 28+ (minSdk 29).
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: return emptyList()
        val certs = signing.apkContentsSigners
        return certs.orEmpty().map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
                .joinToString(":") { "%02X".format(it) }
        }
    }
}
