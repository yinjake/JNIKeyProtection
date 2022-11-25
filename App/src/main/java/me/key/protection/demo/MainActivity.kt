package me.key.protection.demo

import android.content.pm.PackageManager
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.TextView
import androidx.annotation.RequiresApi
import me.key.protection.JNIKey
import me.key.protection.JNISignature
import me.key.protection.demo.databinding.ActivityMainBinding
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {
    lateinit var encryptedPairData: Pair<ByteArray, ByteArray>
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        getKeyGenerator()

        binding.encryptBtn.setOnClickListener {
            binding.decryptedText.text = encryptWithKeyStore(binding.inputText.text.toString())
        }

        binding.decryptBtn.setOnClickListener {
            val iv = encryptedPairData.first
            val encryptedData = encryptedPairData.second
            binding.decryptedText.text = decryptData(iv, encryptedData)
        }


        val value = findViewById<TextView>(R.id.value)
        Log.e("MainActivity", "  ---  " + "onCreate")
        try {
            val context = createPackageContext(
                "me.key.protection.demo",
                CONTEXT_INCLUDE_CODE or CONTEXT_IGNORE_SECURITY
            )
            Log.e("MainActivity 0 ", "  ---  $context")
            Log.e("MainActivity1", "  ---  " + JNISignature.getSignature(applicationContext))
            val flag = JNIKey.init()
            Log.e("MainActivity2", "  ---  $flag")
            val key = JNIKey.getKey()
            Log.e("MainActivity3", "  ---  $key")
            value.text = String.format("%s%s", flag, key)
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }

    }


    private fun encryptWithKeyStore(plainText: String): String {
        encryptedPairData = getEncryptedDataPair(plainText)
        return encryptedPairData.second.toString(Charsets.UTF_8)

    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getKeyGenerator() {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGeneratorSpec = KeyGenParameterSpec.Builder(
            "myKey",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(false)
            .build()
        keyGenerator.init(keyGeneratorSpec)
        keyGenerator.generateKey()
    }

    private fun getKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secreteKeyEntry: KeyStore.SecretKeyEntry =
            keyStore.getEntry("myKey", null) as KeyStore.SecretKeyEntry
        return secreteKeyEntry.secretKey
    }

    private fun getEncryptedDataPair(data: String): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getKey())

        val _iv: ByteArray = cipher.iv
        val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return Pair(_iv, encryptedData)
    }

    private fun decryptData(iv: ByteArray, encData: ByteArray): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        val keySpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, getKey(), keySpec)
        return cipher.doFinal(encData).toString(Charsets.UTF_8)

    }
}