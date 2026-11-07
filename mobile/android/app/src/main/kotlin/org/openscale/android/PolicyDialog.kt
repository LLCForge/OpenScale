package org.openscale.android

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.text.InputType
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import org.openscale.go.openscale.Openscale

/**
 * Mobil veri ve Wi-Fi politikası (#179, P27).
 *
 * Basit form kuralları üretir; doğrulama ve değerlendirme Go'dadır
 * (CheckNetworkPolicy, ExitNodeForNetwork). Sıra:
 *   1. güvenilen Wi-Fi adları → bu ağlarda çıkış düğümü yok,
 *   2. diğer Wi-Fi → [Wi-Fi çıkış düğümü],
 *   3. mobil veri → [mobil çıkış düğümü].
 * Eşleşme yoksa elle seçilen çıkış düğümü kalır. Wi-Fi adı doğrulanmaz
 * (sahte ağ aynı adı taşıyabilir); Go bunu uyarı olarak döndürür. Ad okumak
 * için konum izni yalnızca güvenilen ad girildiğinde istenir.
 */
object PolicyDialog {

    fun show(activity: Activity, prefs: Prefs, requestCode: Int, onSaved: () -> Unit) {
        val current = parse(prefs.networkPolicy)
        val pad = (16 * activity.resources.displayMetrics.density).toInt()
        val col = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val enabled = CheckBox(activity).apply {
            setText(R.string.policy_enabled)
            isChecked = prefs.policyEnabled
        }
        fun field(hint: Int, value: String) = EditText(activity).apply {
            setHint(hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setText(value)
        }
        val trusted = field(R.string.policy_trusted, current.trusted.joinToString(", "))
        // #477: konum izni gerektirmeyen ağ kimlikleri ("n1-…").
        val trustedIds = field(R.string.policy_trusted_ids, current.trustedIds.joinToString(", "))
        val addHere = android.widget.Button(activity).apply {
            setText(R.string.policy_add_here)
            setOnClickListener {
                val id = NetworkObserver.currentIdentity(activity)
                if (id.isEmpty()) {
                    Toast.makeText(activity, R.string.policy_no_identity, Toast.LENGTH_LONG).show()
                } else {
                    val ids = trustedIds.text.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                    if (id !in ids) trustedIds.setText((ids + id).joinToString(", "))
                }
            }
        }
        val wifiExit = field(R.string.policy_wifi_exit, current.wifiExit)
        val cellExit = field(R.string.policy_cell_exit, current.cellExit)
        col.addView(enabled)
        col.addView(trustedIds)
        col.addView(addHere)
        col.addView(trusted)
        col.addView(wifiExit)
        col.addView(cellExit)
        col.addView(TextView(activity).apply { setText(R.string.policy_help) })

        AlertDialog.Builder(activity)
            .setTitle(R.string.policy_title)
            .setView(col)
            .setPositiveButton(R.string.save) { _, _ ->
                val names = trusted.text.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
                val ids = trustedIds.text.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
                val json = build(ids, names, wifiExit.text.toString().trim(), cellExit.text.toString().trim())
                val warnings = try {
                    JSONArray(Openscale.checkNetworkPolicy(Prefs.stateDir(activity), json))
                } catch (e: Exception) {
                    Toast.makeText(activity, e.message ?: activity.getString(R.string.policy_invalid), Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                prefs.networkPolicy = json
                prefs.policyEnabled = enabled.isChecked
                if (enabled.isChecked && names.isNotEmpty() &&
                    activity.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED
                ) {
                    // Android 10+ Wi-Fi adını yalnızca konum izniyle verir.
                    activity.requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION), requestCode)
                }
                if (warnings.length() > 0) {
                    val text = (0 until warnings.length()).joinToString("\n") { warnings.getString(it) }
                    AlertDialog.Builder(activity)
                        .setTitle(R.string.policy_warnings)
                        .setMessage(text)
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                }
                onSaved()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private data class Simple(val trustedIds: List<String>, val trusted: List<String>, val wifiExit: String, val cellExit: String)

    private fun build(trustedIds: List<String>, trusted: List<String>, wifiExit: String, cellExit: String): String {
        val rules = JSONArray()
        // Kimlik ağ türünden bağımsızdır: Wi-Fi ve kablolu için ayrı kural.
        for (id in trustedIds) {
            rules.put(JSONObject().put("network", "wifi").put("net_id", id).put("exit_node", ""))
            rules.put(JSONObject().put("network", "ethernet").put("net_id", id).put("exit_node", ""))
        }
        for (ssid in trusted) {
            rules.put(JSONObject().put("network", "wifi").put("ssid", ssid).put("exit_node", ""))
        }
        if (wifiExit.isNotEmpty()) rules.put(JSONObject().put("network", "wifi").put("exit_node", wifiExit))
        if (cellExit.isNotEmpty()) rules.put(JSONObject().put("network", "cellular").put("exit_node", cellExit))
        return JSONObject().put("rules", rules).toString()
    }

    /** Formun ürettiği kuralları geri okur; başka biçimde ise boş form. */
    private fun parse(json: String): Simple {
        if (json.isEmpty()) return Simple(emptyList(), emptyList(), "", "")
        return try {
            val rules = JSONObject(json).getJSONArray("rules")
            val ids = mutableListOf<String>()
            val trusted = mutableListOf<String>()
            var wifi = ""
            var cell = ""
            for (i in 0 until rules.length()) {
                val r = rules.getJSONObject(i)
                val ssid = r.optString("ssid")
                val id = r.optString("net_id")
                when {
                    id.isNotEmpty() -> if (id !in ids) ids.add(id)
                    r.optString("network") == "wifi" && ssid.isNotEmpty() -> trusted.add(ssid)
                    r.optString("network") == "wifi" -> wifi = r.optString("exit_node")
                    r.optString("network") == "cellular" -> cell = r.optString("exit_node")
                }
            }
            Simple(ids, trusted, wifi, cell)
        } catch (e: Exception) {
            Simple(emptyList(), emptyList(), "", "")
        }
    }
}
