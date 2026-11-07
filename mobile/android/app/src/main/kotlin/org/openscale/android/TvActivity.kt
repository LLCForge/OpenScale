package org.openscale.android

import android.app.Activity
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import org.openscale.go.openscale.Openscale
import java.util.concurrent.Executors

/**
 * Android TV arayüzü (#476, P08; ADR'deki kapsam).
 *
 * Uzaktan kumandayla (D-pad) kullanılır: büyük, odaklanabilir düğmeler, tek
 * sütun. Kapsam: kayıt (cihaz anahtarı ve kayıt isteğinin büyük QR kodu;
 * sahip bilgisayarda `openscale device add --request-image` ile telefondan
 * çektiği fotoğrafı okur), katılım paketi ve kök parmak izi girişi (TV
 * klavyesi veya telefondaki uzaktan kumanda uygulaması), bağlan/kes ve
 * çıkış düğümü seçimi (ağ belgesindeki çıkış düğümleri düğme olarak). TV'de
 * kamera ve NFC çoğunlukla yoktur; QR okuma, NFC, politika ve uygulama
 * seçimi telefon arayüzündedir. Aynı servis, anahtar kasası ve tercihler
 * kullanılır.
 */
class TvActivity : Activity() {

    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var vault: KeyVault
    private lateinit var prefs: Prefs
    private lateinit var gate: BiometricGate
    private lateinit var status: TextView
    private lateinit var qr: ImageView
    private lateinit var exits: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // #474: kayıt isteği ve parmak izi ekran görüntüsüne düşmez.
        SecureWindow.activity(this)
        vault = KeyVault(this)
        prefs = Prefs(this)
        gate = BiometricGate(this, prefs)
        setContentView(buildLayout())
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun buildLayout(): View {
        val d = resources.displayMetrics.density
        val pad = (48 * d).toInt() // TV güvenli alanı (overscan)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, (27 * d).toInt(), pad, (27 * d).toInt())
        }
        fun button(res: Int, onClick: () -> Unit) = Button(this).apply {
            setText(res)
            textSize = 20f
            isFocusable = true
            setOnClickListener { onClick() }
        }
        col.addView(TextView(this).apply { setText(R.string.app_name); textSize = 28f })
        status = TextView(this).apply { textSize = 20f }
        col.addView(status)

        val connect = button(R.string.connect) { connect() }
        col.addView(connect)
        col.addView(button(R.string.disconnect) {
            gate.run(getString(R.string.disconnect)) { OpenScaleVpnService.stop(this) }
        })

        col.addView(TextView(this).apply { setText(R.string.tv_exit_title); textSize = 22f })
        exits = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(exits)

        col.addView(TextView(this).apply { setText(R.string.tv_register_title); textSize = 22f })
        col.addView(button(R.string.tv_register) { register() })
        qr = ImageView(this).apply {
            adjustViewBounds = true
            maxHeight = (360 * d).toInt()
            contentDescription = getString(R.string.key_qr_desc)
            visibility = View.GONE
        }
        col.addView(qr)
        val bundle = EditText(this).apply {
            setHint(R.string.join_bundle)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val fp = EditText(this).apply {
            setHint(R.string.join_fp)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        col.addView(bundle)
        col.addView(fp)
        col.addView(button(R.string.join) {
            val b = bundle.text.toString()
            val f = fp.text.toString()
            gate.run(getString(R.string.join)) {
                background {
                    val summary = Openscale.join(Prefs.stateDir(this), b, f)
                    runOnUiThread { bundle.setText(""); refresh() }
                    getString(R.string.invite_joined, summary)
                }
            }
        })
        connect.requestFocus()
        return ScrollView(this).apply { addView(col) }
    }

    private fun background(work: () -> String) {
        worker.execute {
            val msg = try {
                work()
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
            runOnUiThread { status.text = msg }
        }
    }

    private fun refresh() {
        val st = runCatching { JSONObject(OpenScaleVpnService.lastStatus) }.getOrNull()
        val on = st?.optBoolean("running") == true
        val exit = st?.optString("exit_node").orEmpty()
        status.text = when {
            !on -> st?.optString("error")?.takeIf { it.isNotEmpty() }?.let { getString(R.string.notif_error, it) }
                ?: getString(R.string.tile_off)
            exit.isNotEmpty() -> getString(R.string.tile_exit, exit)
            else -> getString(R.string.tile_on)
        }
        worker.execute {
            val names = runCatching { JSONArray(Openscale.exitNodes(Prefs.stateDir(this))) }.getOrNull()
            runOnUiThread { showExits(names) }
        }
    }

    private fun showExits(names: JSONArray?) {
        exits.removeAllViews()
        if (names == null) {
            exits.addView(TextView(this).apply { setText(R.string.tv_not_joined); textSize = 18f })
            return
        }
        val current = prefs.exitNode
        fun choice(label: String, value: String) = Button(this).apply {
            text = if (value == current) getString(R.string.tv_selected, label) else label
            textSize = 18f
            setOnClickListener { chooseExit(value) }
        }
        exits.addView(choice(getString(R.string.tv_no_exit), ""))
        for (i in 0 until names.length()) {
            val n = names.optString(i)
            if (n.isNotEmpty()) exits.addView(choice(n, n))
        }
    }

    /** Çıkış düğümünü değiştirmek telefondaki gibi kilitlidir (#177). */
    private fun chooseExit(name: String) {
        if (name == prefs.exitNode) return
        gate.run(getString(R.string.exit_change)) {
            prefs.exitNode = name
            refresh()
            val running = runCatching { JSONObject(OpenScaleVpnService.lastStatus).optBoolean("running") }.getOrDefault(false)
            if (running) OpenScaleVpnService.start(this)
        }
    }

    private fun connect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQ_VPN)
        } else {
            OpenScaleVpnService.start(this)
        }
    }

    @Deprecated("Activity sonuç API'si; AndroidX kullanılmadığı için")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) OpenScaleVpnService.start(this)
    }

    /** Anahtar yoksa oluşturur ve kayıt isteğini büyük QR olarak gösterir (F-111). */
    private fun register() = background {
        if (!vault.hasKey()) {
            val secrets = Openscale.generateDeviceSecrets()
            try {
                vault.store(secrets)
                prefs.wipedAt = 0L
            } finally {
                secrets.fill(0)
            }
        }
        val secrets = vault.load()
        val (out, sas) = try {
            Openscale.enrollmentRequest(secrets, Build.MODEL ?: "android-tv") to Openscale.deviceSAS(secrets)
        } finally {
            secrets.fill(0)
        }
        val line = out.substringBefore('\n')
        val fpText = out.substringAfter('\n', "")
        val png = Openscale.encodeQRPNG(line)
        val bitmap = BitmapFactory.decodeByteArray(png, 0, png.size)
        runOnUiThread {
            qr.setImageBitmap(bitmap)
            qr.visibility = View.VISIBLE
        }
        getString(R.string.tv_request_text, fpText, sas)
    }

    private companion object {
        const val REQ_VPN = 1
    }
}
