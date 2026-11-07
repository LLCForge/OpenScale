package org.openscale.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Mobil anahtar deposu (#176, ADR-0101).
 *
 * WireGuard ve Ed25519 için ham özel anahtar gerekir; Android Keystore bu
 * anahtarları dışarı vermeden kullanamaz. Bu yüzden cihaz anahtar dosyası
 * (Go'nun GenerateDeviceSecrets çıktısı) Keystore'da üretilen ve hiçbir
 * zaman dışarı çıkmayan bir AES-256-GCM anahtarıyla şifrelenip yedeğe
 * girmeyen klasörde saklanır. StrongBox varsa anahtar oradadır. Şifre çözme
 * yalnızca tünel başlarken yapılır; çözülen bayt dizisi Go'ya verildikten
 * sonra sıfırlanır.
 *
 * Kullanıcı doğrulaması (setUserAuthenticationRequired) bilerek istenmez:
 * her zaman açık VPN ekran kilitliyken de yeniden bağlanabilmelidir.
 * Biyometrik kilit (#177) ayrı bir işlemdir (P27).
 */
class KeyVault(private val context: Context) {

    private val file: AtomicFile
        get() = AtomicFile(File(context.noBackupFilesDir, FILE))

    fun hasKey(): Boolean = File(context.noBackupFilesDir, FILE).exists()

    /** Şifreler ve atomik olarak yazar. [secret] çağıranda kalır; çağıran sıfırlar. */
    fun store(secret: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(AAD)
        val sealed = cipher.doFinal(secret)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { w ->
            w.writeByte(FORMAT)
            w.writeByte(cipher.iv.size)
            w.write(cipher.iv)
            w.writeInt(sealed.size)
            w.write(sealed)
        }
        val f = file
        val stream = f.startWrite()
        try {
            stream.write(out.toByteArray())
            f.finishWrite(stream)
        } catch (e: Exception) {
            f.failWrite(stream)
            throw e
        }
    }

    /** Çözülmüş cihaz anahtar dosyasını döndürür; çağıran kullandıktan sonra sıfırlar. */
    fun load(): ByteArray {
        val data = try {
            file.readFully()
        } catch (e: FileNotFoundException) {
            throw IllegalStateException("Cihaz anahtarı yok; önce anahtar oluşturun", e)
        }
        DataInputStream(data.inputStream()).use { r ->
            require(r.readUnsignedByte() == FORMAT) { "Anahtar dosyası biçimi tanınmıyor" }
            val ivLen = r.readUnsignedByte()
            require(ivLen in 12..16) { "Anahtar dosyası bozuk" }
            val iv = ByteArray(ivLen).also { r.readFully(it) }
            val n = r.readInt()
            require(n in 1..MAX_SEALED) { "Anahtar dosyası bozuk" }
            val sealed = ByteArray(n).also { r.readFully(it) }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, existingKey(), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(AAD)
            return cipher.doFinal(sealed)
        }
    }

    /** Kayıp modu ve sıfırlama için: şifreli dosya ve Keystore anahtarı silinir. */
    fun destroy() {
        file.delete()
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

    private fun existingKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
            ?: throw IllegalStateException("Keystore anahtarı yok (uygulama verisi silinmiş olabilir)")
        return entry.secretKey
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        return try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(spec)
        return gen.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "openscale-device-key-wrap-v1"
        const val FILE = "device.key.sealed"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
        const val FORMAT = 1
        const val MAX_SEALED = 8192
        val AAD = "openscale-device-key-v1".toByteArray(Charsets.UTF_8)
    }
}
