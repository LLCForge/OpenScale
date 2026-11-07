package org.openscale.android

import android.app.Activity
import android.app.Dialog
import android.os.Build
import android.view.WindowManager

/**
 * Ekran görüntüsü engeli (#474, P08).
 *
 * FLAG_SECURE yalnızca konduğu pencereyi korur: AlertDialog ayrı bir
 * penceredir ve etkinliğin bayrağını devralmaz. Davet kodu, kök parmak izi,
 * doğrulama kodları ve kayıt isteği gösteren her pencere bu yardımcıdan
 * geçer. API 33+ son uygulamalar önizlemesi ayrıca kapatılır.
 */
object SecureWindow {

    fun activity(activity: Activity) {
        activity.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) {
            activity.setRecentsScreenshotEnabled(false)
        }
    }

    /** Pencere oluşmadan önce çağrılmalı (show() öncesi create() sonrası da olur). */
    fun dialog(dialog: Dialog): Dialog {
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        return dialog
    }

    /** AlertDialog.Builder.show() yerine: güvenli bayrağı gösterilmeden önce koyar. */
    fun show(builder: android.app.AlertDialog.Builder): android.app.AlertDialog {
        val d = builder.create()
        dialog(d)
        d.show()
        return d
    }
}
