package org.openscale.android

import android.app.Activity
import android.app.KeyguardManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.widget.Toast

/**
 * Biyometrik kilit (#177, P27).
 *
 * Açıkken bağlantıyı kesmek, çıkış düğümünü değiştirmek veya kapatmak, ağ
 * politikasını ve uygulama listesini değiştirmek, ağa katılmak ve kilidin
 * kendisini kapatmak biyometrik doğrulama (veya cihaz kilidi) ister.
 * Çerçeve API'si kullanılır (android.hardware.biometrics, API 28+); AndroidX
 * yoktur.
 *
 * Sınır: bu bir uygulama içi kilittir. Android Ayarlar > VPN ekranından
 * bağlantıyı kesmek sistemin elindedir ve engellenemez; anahtar Keystore'da
 * kullanıcı doğrulamasına bağlanmaz (her zaman açık VPN kilitli ekranda da
 * yeniden bağlanabilmelidir, ADR-0101).
 */
class BiometricGate(private val activity: Activity, private val prefs: Prefs) {

    /** Cihazda ekran kilidi (PIN, desen, parola) var mı. */
    fun deviceSecure(): Boolean =
        activity.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true

    /**
     * Kilit açıksa doğrulama ister, başarılıysa [action] ana iş parçacığında
     * çalışır. Kilit kapalıysa [action] hemen çalışır. Ekran kilidi yoksa
     * işlem reddedilir: doğrulanacak bir kimlik kalmamıştır.
     */
    fun run(reason: String, action: () -> Unit) {
        if (!prefs.biometricLock) {
            action()
            return
        }
        authenticate(reason, action)
    }

    /** Kilidi açar: önce ekran kilidi ve bir doğrulama ister. */
    fun enable(onDone: (Boolean) -> Unit) {
        if (!deviceSecure()) {
            toast(R.string.bio_need_lock)
            onDone(false)
            return
        }
        authenticate(activity.getString(R.string.bio_enable)) {
            prefs.biometricLock = true
            onDone(true)
        }
    }

    /** Kilidi kapatmak da doğrulama ister. */
    fun disable(onDone: (Boolean) -> Unit) {
        run(activity.getString(R.string.bio_disable)) {
            prefs.biometricLock = false
            onDone(true)
        }
    }

    private fun authenticate(reason: String, action: () -> Unit) {
        if (!deviceSecure()) {
            toast(R.string.bio_need_lock)
            return
        }
        val builder = BiometricPrompt.Builder(activity)
            .setTitle(activity.getString(R.string.app_name))
            .setSubtitle(reason)
        if (Build.VERSION.SDK_INT >= 30) {
            // API 30+: güçlü biyometri veya cihaz kilidi.
            builder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
        } else {
            // API 29: aynı davranışın eski adı.
            @Suppress("DEPRECATION")
            builder.setDeviceCredentialAllowed(true)
        }
        val prompt = builder.build()
        prompt.authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    action()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    Toast.makeText(activity, errString ?: activity.getString(R.string.bio_failed), Toast.LENGTH_SHORT).show()
                }
            },
        )
    }

    private fun toast(res: Int) = Toast.makeText(activity, res, Toast.LENGTH_LONG).show()
}
