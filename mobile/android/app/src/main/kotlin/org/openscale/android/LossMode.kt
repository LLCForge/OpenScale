package org.openscale.android

import android.content.Context
import android.util.Log
import org.json.JSONObject
import org.openscale.go.openscale.Openscale
import java.io.File

/**
 * Kayıp modu (#184, P27).
 *
 * Telefon kaybolunca sahip onu panelden iptal eder (her cihaz gibi). İptal
 * kök anahtarla imzalı ağ belgesindedir; koordinatör onu sahteleyemez. Bu
 * sınıf uygulama açılışında, her bağlanmadan önce ve tünel "üye değil"
 * hatasıyla durunca Go'ya sorar: belge bu cihazın anahtarlarını iptal
 * edilmiş listeliyorsa Keystore anahtarı, şifreli cihaz anahtarı ve ağ
 * belgesi silinir, yerel bayrak yazılır. Kontrol kanalından gelen bir "sil"
 * komutu yoktur ve olmayacaktır.
 *
 * Sınır: telefon hiç çevrimiçi olmazsa yeni belgeyi göremez; o durumda
 * koruma Keystore'dur (anahtar cihazdan çıkarılamaz) ve iptal, cihazın ağa
 * erişimini zaten keser.
 */
object LossMode {
    private const val TAG = "OpenScaleLost"

    /** Sonuç: true ise anahtarlar silindi (cihaz iptal edilmiş). Ağ iş parçacığında çağrılır. */
    fun checkAndWipe(context: Context, vault: KeyVault, prefs: Prefs): Boolean {
        val stateDir = Prefs.stateDir(context)
        if (!vault.hasKey() || !Openscale.isJoined(stateDir)) return false
        val secrets = try {
            vault.load()
        } catch (e: Exception) {
            Log.w(TAG, "anahtar okunamadı; kayıp denetimi atlandı", e)
            return false
        }
        val revoked = try {
            JSONObject(Openscale.revocationStatus(stateDir, secrets)).optBoolean("revoked", false)
        } catch (e: Exception) {
            Log.w(TAG, "iptal durumu okunamadı", e)
            false
        } finally {
            secrets.fill(0)
        }
        if (!revoked) return false
        wipe(context, vault, prefs)
        return true
    }

    /** Anahtarları ve ağ durumunu siler; tercihler (gizli olmayan) kalır. */
    fun wipe(context: Context, vault: KeyVault, prefs: Prefs) {
        runCatching { vault.destroy() }.onFailure { Log.e(TAG, "anahtar silinemedi", it) }
        val dir = File(Prefs.stateDir(context))
        // Yalnızca uygulamanın kendi yedeksiz klasöründeki "openscale" dizini.
        if (dir.name == "openscale" && dir.parentFile == context.noBackupFilesDir) {
            dir.deleteRecursively()
        }
        prefs.exitNode = ""
        prefs.wipedAt = System.currentTimeMillis()
        Log.w(TAG, "cihaz ağdan iptal edilmiş: anahtarlar ve ağ belgesi silindi")
    }
}
