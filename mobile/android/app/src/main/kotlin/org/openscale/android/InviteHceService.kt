package org.openscale.android

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.SystemClock
import org.openscale.go.openscale.NfcTag

/**
 * NFC ile davet aktarımı, veren taraf (#470, P08).
 *
 * Telefon salt okunur bir NFC Forum Type 4 etiketi gibi davranır (HCE);
 * APDU durum makinesi Go'dadır (NfcTag). Bileşen bildirimde kapalıdır
 * (android:enabled="false"): yalnızca paylaşım penceresi açıkken, en fazla
 * [ARM_MS] boyunca ve tek bir tam okuma için açılır; okunduktan, süre
 * dolduktan veya pencere kapandıktan sonra kod bellekten silinir ve bileşen
 * yeniden kapatılır. Ekran kilidi açık olmadan sistem bu servise APDU
 * iletmez (apduservice.xml: requireDeviceUnlock).
 */
class InviteHceService : HostApduService() {

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        val tag = current()
        if (tag == null || commandApdu == null) return NOT_FOUND
        return try {
            tag.process(commandApdu)
        } catch (e: Exception) {
            NOT_FOUND
        }
    }

    override fun onDeactivated(reason: Int) {
        if (armed?.delivered() == true) disarm(this)
    }

    companion object {
        private val NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())
        const val ARM_MS = 60_000L

        @Volatile
        private var armed: NfcTag? = null

        @Volatile
        private var armedUntil = 0L

        private fun current(): NfcTag? {
            val t = armed ?: return null
            return if (SystemClock.elapsedRealtime() < armedUntil) t else null
        }

        /** Daveti etiket olarak yükler ve servisi açar. */
        fun arm(context: Context, inviteCode: String): NfcTag {
            disarm(context)
            val tag = org.openscale.go.openscale.Openscale.newNfcTag(inviteCode)
            armed = tag
            armedUntil = SystemClock.elapsedRealtime() + ARM_MS
            setEnabled(context, true)
            return tag
        }

        fun expired(): Boolean = SystemClock.elapsedRealtime() >= armedUntil

        /** Kodu bellekten siler ve servisi kapatır. */
        fun disarm(context: Context) {
            armed?.wipe()
            armed = null
            armedUntil = 0L
            setEnabled(context, false)
        }

        private fun setEnabled(context: Context, on: Boolean) {
            val state = if (on) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            }
            runCatching {
                context.packageManager.setComponentEnabledSetting(
                    ComponentName(context, InviteHceService::class.java),
                    state,
                    PackageManager.DONT_KILL_APP,
                )
            }
        }
    }
}
