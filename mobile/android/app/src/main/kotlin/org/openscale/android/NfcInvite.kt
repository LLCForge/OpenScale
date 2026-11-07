package org.openscale.android

import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.tech.Ndef
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import org.openscale.go.openscale.Openscale

/**
 * NFC ile davet aktarımı (#470, P08; QR'ye kamerasız alternatif).
 *
 * Veren: sahip (veya sahibin davet kodunu ilettiği telefon) kodu yapıştırır,
 * "Dokundurarak paylaş" der; telefon 60 sn boyunca tek okumalık bir NFC
 * etiketi olur (InviteHceService). Alan: "NFC ile davet al" okuyucu kipini
 * açar, okunan metin QR'den gelmiş gibi ScanHandler'a gider: ağ kimliği,
 * kök parmak izi ve kök doğrulama kodu sahibin ekranıyla karşılaştırılmadan
 * katılım yapılmaz. NFC yeni bir güven yolu eklemez.
 */
object NfcInvite {

    private const val POLL_MS = 500L

    fun available(activity: Activity): Boolean = NfcAdapter.getDefaultAdapter(activity) != null

    fun canShare(activity: Activity): Boolean =
        available(activity) && activity.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)

    /** Davet kodunu yapıştırma ve paylaşma penceresi. */
    fun share(activity: Activity) {
        if (!canShare(activity)) {
            Toast.makeText(activity, R.string.nfc_unavailable, Toast.LENGTH_LONG).show()
            return
        }
        val pad = (16 * activity.resources.displayMetrics.density).toInt()
        val input = EditText(activity).apply {
            setHint(R.string.nfc_share_hint)
            // Parola gibi: klavye öğrenmez, ekranda gizli.
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val col = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(input)
            addView(TextView(activity).apply { setText(R.string.nfc_share_help) })
        }
        SecureWindow.show(
            AlertDialog.Builder(activity)
                .setTitle(R.string.nfc_share)
                .setView(col)
                .setPositiveButton(R.string.nfc_share_start) { _, _ ->
                    val code = input.text.toString()
                    input.setText("")
                    startSharing(activity, code)
                }
                .setNegativeButton(android.R.string.cancel, null),
        )
    }

    private fun startSharing(activity: Activity, code: String) {
        val tag = try {
            InviteHceService.arm(activity, code)
        } catch (e: Exception) {
            Toast.makeText(activity, e.message ?: activity.getString(R.string.scan_unknown), Toast.LENGTH_LONG).show()
            return
        }
        val handler = Handler(Looper.getMainLooper())
        var dialog: AlertDialog? = null
        val poll = object : Runnable {
            override fun run() {
                when {
                    tag.delivered() -> {
                        InviteHceService.disarm(activity)
                        dialog?.dismiss()
                        Toast.makeText(activity, R.string.nfc_share_done, Toast.LENGTH_LONG).show()
                    }
                    InviteHceService.expired() -> {
                        InviteHceService.disarm(activity)
                        dialog?.dismiss()
                        Toast.makeText(activity, R.string.nfc_share_expired, Toast.LENGTH_LONG).show()
                    }
                    else -> handler.postDelayed(this, POLL_MS)
                }
            }
        }
        dialog = SecureWindow.show(
            AlertDialog.Builder(activity)
                .setTitle(R.string.nfc_share)
                .setMessage(R.string.nfc_share_waiting)
                .setNegativeButton(android.R.string.cancel, null)
                .setOnDismissListener {
                    handler.removeCallbacks(poll)
                    InviteHceService.disarm(activity)
                },
        )
        handler.postDelayed(poll, POLL_MS)
    }

    /**
     * Okuyucu kipi: tek bir OpenScale davet kaydı okunur ve [onText]'e
     * (ana iş parçacığında) verilir. Yalnızca keşifte önbelleğe alınan NDEF
     * iletisi kullanılır; veren etiket tek okumalık olduğundan yeniden
     * okunmaz.
     */
    fun receive(activity: Activity, onText: (String) -> Unit) {
        val adapter = NfcAdapter.getDefaultAdapter(activity)
        if (adapter == null || !adapter.isEnabled) {
            Toast.makeText(activity, R.string.nfc_unavailable, Toast.LENGTH_LONG).show()
            return
        }
        var dialog: AlertDialog? = null
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
        adapter.enableReaderMode(activity, { tag ->
            val msg = Ndef.get(tag)?.cachedNdefMessage ?: return@enableReaderMode
            val text = try {
                Openscale.nfcInviteFromNDEF(msg.toByteArray())
            } catch (e: Exception) {
                activity.runOnUiThread {
                    Toast.makeText(activity, e.message ?: activity.getString(R.string.scan_unknown), Toast.LENGTH_LONG).show()
                }
                return@enableReaderMode
            }
            activity.runOnUiThread {
                dialog?.dismiss()
                onText(text)
            }
        }, flags, null)
        dialog = SecureWindow.show(
            AlertDialog.Builder(activity)
                .setTitle(R.string.nfc_receive)
                .setMessage(R.string.nfc_receive_waiting)
                .setNegativeButton(android.R.string.cancel, null)
                .setOnDismissListener { runCatching { adapter.disableReaderMode(activity) } },
        )
    }
}
