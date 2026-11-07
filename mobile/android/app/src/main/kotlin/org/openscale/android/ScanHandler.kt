package org.openscale.android

import android.app.Activity
import android.app.AlertDialog
import android.os.Build
import android.util.Log
import android.widget.EditText
import android.widget.TextView
import org.json.JSONObject
import org.openscale.go.openscale.InviteJoin
import org.openscale.go.openscale.InviteObserver
import org.openscale.go.openscale.Openscale

/**
 * Okunan QR metnini işler (#182, P27). Hiçbir şey kendiliğinden uygulanmaz:
 *  - davet kodu: ağ kimliği, kök parmak izi ve kök doğrulama kodu (ADR-0062)
 *    gösterilir; sahip bunları kendi ekranıyla karşılaştırıp "Katıl" der,
 *    ardından cihaz koordinatöre kayıt isteği gönderir ve sahip panelde dört
 *    haneli kodu karşılaştırarak onaylar (ADR-0014);
 *  - katılım paketi ve kök parmak izi: ilgili alana yazılır, katılım yine
 *    "Ağa katıl" düğmesiyle ve parmak izi karşılaştırmasıyla yapılır;
 *  - kayıt isteği ve kök anahtar kâğıt yedeği: telefonda kullanılmaz.
 */
class ScanHandler(
    private val activity: Activity,
    private val vault: KeyVault,
    private val gate: BiometricGate,
    private val status: TextView,
    private val bundleInput: EditText,
    private val fpInput: EditText,
) {
    @Volatile
    private var join: InviteJoin? = null

    fun handle(text: String) {
        val r = try {
            JSONObject(Openscale.classifyScan(text))
        } catch (e: Exception) {
            status.setText(R.string.scan_unknown)
            return
        }
        when (r.optString("kind")) {
            "invite" -> confirmInvite(text, r)
            "join_bundle" -> {
                bundleInput.setText(text)
                status.setText(R.string.scan_bundle)
            }
            "root_fingerprint" -> {
                fpInput.setText(r.optString("root_fingerprint"))
                status.setText(R.string.scan_fp)
            }
            else -> status.text = r.optString("message").ifEmpty { activity.getString(R.string.scan_unknown) }
        }
    }

    private fun confirmInvite(code: String, r: JSONObject) {
        val msg = activity.getString(
            R.string.invite_confirm,
            r.optString("network_id"),
            r.optString("root_fingerprint"),
            r.optString("root_sas"),
            r.optString("coordinator"),
        )
        // #474: parmak izi ve doğrulama kodu ekran görüntüsüne düşmez.
        SecureWindow.show(
            AlertDialog.Builder(activity)
                .setTitle(R.string.invite_title)
                .setMessage(msg)
                .setPositiveButton(R.string.join) { _, _ ->
                    gate.run(activity.getString(R.string.join)) { startJoin(code) }
                }
                .setNegativeButton(android.R.string.cancel, null),
        )
    }

    private fun startJoin(code: String) {
        if (!vault.hasKey()) {
            status.setText(R.string.invite_need_key)
            return
        }
        val observer = object : InviteObserver {
            override fun waiting(shortCode: String, sas: String) {
                activity.runOnUiThread {
                    status.text = activity.getString(R.string.invite_waiting, shortCode, sas)
                }
            }

            override fun log(level: Long, line: String) {
                if (level >= 2L) Log.w(TAG, line)
            }
        }
        val j = Openscale.newInviteJoin(Prefs.stateDir(activity), observer)
        join = j
        status.setText(R.string.invite_sending)
        // Katılım dakikalarca bekleyebilir: kendi iş parçacığında.
        Thread({
            val secrets = try {
                vault.load()
            } catch (e: Exception) {
                activity.runOnUiThread { status.text = e.message ?: "anahtar okunamadı" }
                return@Thread
            }
            val msg = try {
                val summary = j.run(secrets, code, Build.MODEL ?: "android")
                activity.getString(R.string.invite_joined, summary)
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            } finally {
                secrets.fill(0)
                join = null
            }
            activity.runOnUiThread { status.text = msg }
        }, "openscale-invite").start()
    }

    /** Ekran kapanırken bekleyen katılım iptal edilir. */
    fun cancel() {
        join?.cancel()
    }

    private companion object {
        const val TAG = "OpenScaleInvite"
    }
}
