package org.openscale.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast

/**
 * Uygulama bazlı bölünmüş tünel seçimi (F-049, P27).
 *
 * Paket görünürlüğü için QUERY_ALL_PACKAGES istenmez; manifestteki
 * <queries> yalnızca başlatıcıda görünen uygulamaları açar. Liste cihazdan
 * çıkmaz.
 */
object AppPicker {

    private data class App(val pkg: String, val label: String)

    fun show(activity: Activity, prefs: Prefs, onSaved: () -> Unit) {
        val pm = activity.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = pm.queryIntentActivities(launcher, 0)
            .map { App(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
            .filter { it.pkg != activity.packageName }
            .distinctBy { it.pkg }
            .sortedBy { it.label.lowercase() }
        val selected = prefs.apps.toMutableSet()
        val checked = BooleanArray(apps.size) { apps[it].pkg in selected }

        val pad = (16 * activity.resources.displayMetrics.density).toInt()
        val header = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
        }
        val group = RadioGroup(activity)
        val all = RadioButton(activity).apply { id = 1; setText(R.string.apps_all) }
        val include = RadioButton(activity).apply { id = 2; setText(R.string.apps_include) }
        val exclude = RadioButton(activity).apply { id = 3; setText(R.string.apps_exclude) }
        group.addView(all)
        group.addView(include)
        group.addView(exclude)
        group.check(
            when (prefs.appsMode) {
                Prefs.MODE_INCLUDE -> 2
                Prefs.MODE_EXCLUDE -> 3
                else -> 1
            },
        )
        header.addView(TextView(activity).apply { setText(R.string.apps_title); textSize = 20f })
        header.addView(group)
        header.addView(TextView(activity).apply { setText(R.string.apps_help) })

        AlertDialog.Builder(activity)
            .setCustomTitle(header)
            .setMultiChoiceItems(apps.map { it.label }.toTypedArray(), checked) { _, which, isChecked ->
                if (isChecked) selected.add(apps[which].pkg) else selected.remove(apps[which].pkg)
            }
            .setPositiveButton(R.string.save) { _, _ ->
                val mode = when (group.checkedRadioButtonId) {
                    2 -> Prefs.MODE_INCLUDE
                    3 -> Prefs.MODE_EXCLUDE
                    else -> ""
                }
                if (mode.isNotEmpty() && selected.isEmpty()) {
                    // Seçimsiz "yalnızca seçilenler" bütün uygulamaları VPN'e sokar.
                    Toast.makeText(activity, R.string.apps_need_one, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                prefs.appsMode = mode
                prefs.apps = if (mode.isEmpty()) emptySet() else selected
                onSaved()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
