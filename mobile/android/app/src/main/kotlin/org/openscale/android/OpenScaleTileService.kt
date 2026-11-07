package org.openscale.android

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.json.JSONObject

/**
 * Hızlı ayar kutucuğu (P27). Bağlıysa keser, değilse bağlar.
 *
 * Kesmek biyometrik kilit açıkken (#177) doğrudan yapılmaz: ana ekran
 * doğrulama isteğiyle açılır. VPN izni henüz verilmemişse de ana ekran açılır
 * (izin penceresi bir Activity ister). Kilitli ekranda önce kilit açılır.
 */
class OpenScaleTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun { toggle() }
        } else {
            toggle()
        }
    }

    private fun toggle() {
        val prefs = Prefs(this)
        if (running()) {
            if (prefs.biometricLock) {
                openMain(DisconnectRequest.intent(this))
            } else {
                OpenScaleVpnService.stop(this)
            }
        } else if (VpnService.prepare(this) != null) {
            openMain(null)
        } else {
            OpenScaleVpnService.start(this)
        }
        refresh()
    }

    private fun openMain(target: Intent?) {
        val intent = (target ?: Intent(this, MainActivity::class.java))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            // API 34+: Intent ile başlatma kaldırıldı, PendingIntent gerekir.
            val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun running(): Boolean =
        runCatching { JSONObject(OpenScaleVpnService.lastStatus).optBoolean("running") }.getOrDefault(false)

    private fun refresh() {
        val tile = qsTile ?: return
        val status = runCatching { JSONObject(OpenScaleVpnService.lastStatus) }.getOrNull()
        val on = status?.optBoolean("running") == true
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        // Tile.subtitle: API 29+ (minSdk 29).
        val exit = status?.optString("exit_node").orEmpty()
        // #475: kutucuk kilit ekranında da görünür; çıkış düğümü adı orada gösterilmez.
        tile.subtitle = when {
            !on -> getString(R.string.tile_off)
            exit.isNotEmpty() && !isLocked -> getString(R.string.tile_exit, exit)
            else -> getString(R.string.tile_on)
        }
        tile.updateTile()
    }

    companion object {
        /** Servis durumu değişince kutucuğu yeniler (dinlemiyorsa sistem sonra çağırır). */
        fun requestRefresh(context: Context) {
            runCatching {
                requestListeningState(context, ComponentName(context, OpenScaleTileService::class.java))
            }
        }
    }
}
