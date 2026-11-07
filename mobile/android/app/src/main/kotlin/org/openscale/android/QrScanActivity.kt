package org.openscale.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import android.util.Size
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.widget.FrameLayout
import android.widget.TextView
import org.openscale.go.openscale.Openscale
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs

/**
 * QR okuyucu (#182, P27).
 *
 * Yalnızca çerçeve Camera2 API'si (API 21+; uygulama minSdk 29) ve Go'daki
 * saf QR çözücü kullanılır: ML Kit, Play Services, CameraX ve başka bir
 * kütüphane yoktur (ADR-0002, ADR-0101). Arka kameradan YUV_420_888 kareler
 * alınır; yalnızca parlaklık (Y) düzlemi kopyalanıp Go'ya verilir. Kareler
 * diske yazılmaz, ağa gitmez; okunan metin sonuç olarak döner ve hiçbir şey
 * kullanıcı onayı olmadan uygulanmaz.
 */
class QrScanActivity : Activity() {

    private lateinit var preview: TextureView
    private lateinit var hint: TextView
    private var cameraThread: HandlerThread? = null
    private var cameraHandler: Handler? = null
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var previewSize = Size(1280, 720)
    private val decoder = Executors.newSingleThreadExecutor()
    private val busy = AtomicBoolean(false)
    private val done = AtomicBoolean(false)
    private var lastFrame = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.activity(this) // #474: kamera karesi ve okunan kod önizlemeye düşmez
        preview = TextureView(this)
        hint = TextView(this).apply {
            setText(R.string.scan_hint)
            textSize = 16f
            setPadding(32, 32, 32, 32)
            setBackgroundColor(0xCC000000.toInt())
            setTextColor(0xFFFFFFFF.toInt())
        }
        val root = FrameLayout(this)
        root.addView(preview, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        root.addView(hint, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
            return
        }
        startCamera()
    }

    override fun onPause() {
        stopCamera()
        super.onPause()
    }

    override fun onDestroy() {
        decoder.shutdown()
        super.onDestroy()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_CAMERA) return
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            hint.setText(R.string.scan_no_permission)
        }
    }

    private fun startCamera() {
        val thread = HandlerThread("openscale-camera").also { it.start() }
        cameraThread = thread
        val handler = Handler(thread.looper)
        cameraHandler = handler
        if (preview.isAvailable) {
            openCamera(handler)
        } else {
            preview.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) = openCamera(handler)
                override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) = fitPreview()
                override fun onSurfaceTextureDestroyed(st: SurfaceTexture) = true
                override fun onSurfaceTextureUpdated(st: SurfaceTexture) = Unit
            }
        }
    }

    private fun openCamera(handler: Handler) {
        val cm = getSystemService(CameraManager::class.java)
        val id = cm.cameraIdList.firstOrNull { cid ->
            cm.getCameraCharacteristics(cid).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
        } ?: cm.cameraIdList.firstOrNull()
        if (id == null) {
            hint.setText(R.string.scan_no_camera)
            return
        }
        val map = cm.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        val sizes = map?.getOutputSizes(ImageFormat.YUV_420_888) ?: emptyArray()
        // ~1280x720: QR için yeterli, çözme süresi kısa.
        previewSize = sizes.minByOrNull { abs(it.width * it.height - 1280 * 720) } ?: Size(1280, 720)
        fitPreview()
        val r = ImageReader.newInstance(previewSize.width, previewSize.height, ImageFormat.YUV_420_888, 2)
        r.setOnImageAvailableListener({ onFrame(it) }, handler)
        reader = r
        try {
            cm.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    startSession(device, r, handler)
                }

                override fun onDisconnected(device: CameraDevice) {
                    device.close()
                    camera = null
                }

                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    camera = null
                    runOnUiThread { hint.setText(R.string.scan_no_camera) }
                }
            }, handler)
        } catch (e: SecurityException) {
            hint.setText(R.string.scan_no_permission)
        } catch (e: Exception) {
            Log.w(TAG, "kamera açılamadı", e)
            hint.setText(R.string.scan_no_camera)
        }
    }

    private fun startSession(device: CameraDevice, r: ImageReader, handler: Handler) {
        val st = preview.surfaceTexture ?: return
        st.setDefaultBufferSize(previewSize.width, previewSize.height)
        val previewSurface = Surface(st)
        val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
            addTarget(previewSurface)
            addTarget(r.surface)
            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
        }
        val config = SessionConfiguration(
            SessionConfiguration.SESSION_REGULAR,
            listOf(OutputConfiguration(previewSurface), OutputConfiguration(r.surface)),
            mainExecutor,
            object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    session = s
                    runCatching { s.setRepeatingRequest(request.build(), null, handler) }
                }

                override fun onConfigureFailed(s: CameraCaptureSession) {
                    runOnUiThread { hint.setText(R.string.scan_no_camera) }
                }
            },
        )
        // SessionConfiguration: API 28+.
        device.createCaptureSession(config)
    }

    /** Kare: Y düzlemini kopyalar ve en fazla saniyede beş kez çözer. */
    private fun onFrame(r: ImageReader) {
        val image = r.acquireLatestImage() ?: return
        try {
            val now = SystemClock.elapsedRealtime()
            if (done.get() || now - lastFrame < MIN_FRAME_MS || !busy.compareAndSet(false, true)) return
            lastFrame = now
            val plane = image.planes[0] // Y; pixelStride her zaman 1
            val w = image.width
            val h = image.height
            val stride = plane.rowStride
            val buf = plane.buffer
            val needed = (h - 1) * stride + w
            if (buf.remaining() < needed) {
                busy.set(false)
                return
            }
            val luma = ByteArray(needed)
            buf.get(luma, 0, needed)
            decoder.execute {
                try {
                    val text = Openscale.decodeQR(luma, w.toLong(), h.toLong(), stride.toLong())
                    if (done.compareAndSet(false, true)) {
                        runOnUiThread {
                            setResult(RESULT_OK, Intent().putExtra(EXTRA_TEXT, text))
                            finish()
                        }
                    }
                } catch (e: Exception) {
                    // Bu karede okunabilir kod yok; sonraki kare denenir.
                } finally {
                    luma.fill(0)
                    busy.set(false)
                }
            }
        } finally {
            image.close()
        }
    }

    /** Önizlemeyi kırparak en-boy oranını korur (dikey ekran, 90° sensör). */
    private fun fitPreview() {
        val vw = preview.width.toFloat()
        val vh = preview.height.toFloat()
        if (vw <= 0f || vh <= 0f) return
        // Dikeyde görüntü genişliği sensörün yüksekliğidir.
        val contentRatio = previewSize.height.toFloat() / previewSize.width.toFloat()
        val viewRatio = vw / vh
        val m = Matrix()
        if (viewRatio > contentRatio) {
            m.setScale(1f, viewRatio / contentRatio, vw / 2, vh / 2)
        } else {
            m.setScale(contentRatio / viewRatio, 1f, vw / 2, vh / 2)
        }
        runOnUiThread { preview.setTransform(m) }
    }

    private fun stopCamera() {
        runCatching { session?.close() }
        session = null
        runCatching { camera?.close() }
        camera = null
        runCatching { reader?.close() }
        reader = null
        cameraThread?.quitSafely()
        cameraThread = null
        cameraHandler = null
    }

    companion object {
        const val EXTRA_TEXT = "org.openscale.android.SCANNED_TEXT"
        private const val REQ_CAMERA = 10
        private const val MIN_FRAME_MS = 200L
        private const val TAG = "OpenScaleScan"
    }
}
