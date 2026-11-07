package org.openscale.android

import android.content.ComponentName
import android.content.Context
import android.content.Intent

/**
 * Biyometrik kilitli kesme isteği (#177) ve gönderenin doğrulanması (F5,
 * güvenlik denetimi bulgu 10).
 *
 * MainActivity başlatıcı olduğu için dışa açıktır; cihazdaki herhangi bir
 * uygulama onu istediği eylemle başlatabilir. Bu yüzden kesme isteği eylem
 * dizesine bakılarak kabul edilmez. Uygulamanın kendi bildirimi, kutucuğu
 * ve ana ekran bileşeni isteği yalnızca dışa kapalı (android:exported=false)
 * `.DisconnectRequest` takma adı üzerinden gönderir. Sistem başka bir
 * uygulamanın bu takma adı başlatmasına izin vermez (SecurityException);
 * MainActivity'nin kendi bileşen adıyla gelen kesme isteği yok sayılır.
 */
object DisconnectRequest {
    /** Kesme isteğinin eylemi. */
    const val ACTION = "org.openscale.android.REQUEST_DISCONNECT"

    /**
     * Takma adın tam sınıf adı. Manifestteki ".DisconnectRequest" gradle
     * namespace'ine göre çözülür, applicationId'ye göre değil.
     */
    const val ALIAS_CLASS = "org.openscale.android.DisconnectRequest"

    /** Uygulama içi kesme isteği: yalnızca dışa kapalı takma adı hedefler. */
    fun intent(context: Context): Intent =
        Intent(ACTION).setComponent(ComponentName(context, ALIAS_CLASS))

    /**
     * Gelen niyet kesme isteği olarak kabul edilir mi. Yalnızca eylem
     * [ACTION] ve niyetin çözüldüğü bileşen dışa kapalı takma ad ise evet.
     * Saf işlev: Android sınıfı kullanmaz, JVM'siz denetlenebilir.
     */
    fun accept(action: String?, componentClass: String?): Boolean =
        action == ACTION && componentClass == ALIAS_CLASS
}
