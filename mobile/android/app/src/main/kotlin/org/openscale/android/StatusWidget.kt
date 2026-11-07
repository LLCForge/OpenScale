package org.openscale.android

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import org.json.JSONObject

/**
 * Ana ekran bileşeni (#472, P08): bağlantı durumu, çıkış düğümü ve tek
 * dokunuşla bağlan/kes.
 *
 * Düğmenin hedefi her yenilemede durumdan seçilir (hızlı ayar kutucuğuyla
 * aynı kurallar): bağlıyken ve biyometrik kilit açıkken (#177) ana ekran
 * doğrulama isteğiyle açılır; VPN izni yoksa ana ekran açılır (izin
 * penceresi bir Activity ister); aksi hâlde servis doğrudan başlatılır veya
 * durdurulur. Bileşen eş sayısı, IP veya hata metni göstermez (#475 ile aynı
 * ilke: ana ekran başkalarınca görülebilir). Yenileme yalnızca servis durumu
 * değişince yapılır; periyodik uyandırma yoktur (#178).
 */
class StatusWidget : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        update(context, manager, ids)
    }

    companion object {
        fun refresh(context: Context) {
            runCatching {
                val manager = AppWidgetManager.getInstance(context) ?: return
                val ids = manager.getAppWidgetIds(ComponentName(context, StatusWidget::class.java))
                if (ids.isNotEmpty()) update(context, manager, ids)
            }
        }

        private fun update(context: Context, manager: AppWidgetManager, ids: IntArray) {
            val status = runCatching { JSONObject(OpenScaleVpnService.lastStatus) }.getOrNull()
            val on = status?.optBoolean("running") == true
            val exit = status?.optString("exit_node").orEmpty()
            val text = when {
                !on -> context.getString(R.string.tile_off)
                exit.isNotEmpty() -> context.getString(R.string.tile_exit, exit)
                else -> context.getString(R.string.tile_on)
            }
            val prefs = Prefs(context)
            val action = when {
                on && prefs.biometricLock -> PendingIntent.getActivity(
                    context, 10,
                    DisconnectRequest.intent(context),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
                on -> PendingIntent.getService(
                    context, 11,
                    Intent(context, OpenScaleVpnService::class.java).setAction(OpenScaleVpnService.ACTION_DISCONNECT),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
                VpnService.prepare(context) != null -> PendingIntent.getActivity(
                    context, 12, Intent(context, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
                else -> PendingIntent.getForegroundService(
                    context, 13,
                    Intent(context, OpenScaleVpnService::class.java).setAction(OpenScaleVpnService.ACTION_CONNECT),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
            }
            val open = PendingIntent.getActivity(
                context, 14, Intent(context, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            for (id in ids) {
                val views = RemoteViews(context.packageName, R.layout.widget_status).apply {
                    setTextViewText(R.id.widget_status, text)
                    setTextViewText(R.id.widget_toggle, context.getString(if (on) R.string.disconnect else R.string.connect))
                    setOnClickPendingIntent(R.id.widget_toggle, action)
                    setOnClickPendingIntent(R.id.widget_status, open)
                }
                manager.updateAppWidget(id, views)
            }
        }
    }
}
