package me.key.protection.demo

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import java.nio.charset.StandardCharsets


object AESUtil {

    private const val IV_BLOCK_SIZE = 16
    private const val KEY_ALIAS = "myKey";

    //生成KeyGenerator之后，就可以生成出加解密需要的Key了：
    val key: SecretKey = getKeyGenerator("1111").generateKey()

    //对需要保护的数据进行加密然后存储
    private const val srcData = "hello world"

    private val encryptData = AESUtil.encryptAES(srcData.toByteArray(), key)

    private val decryptKey = AESUtil.getKeyFromKeyStore("1111")


    fun encryptAES(encryptBytes: ByteArray, encryptKey: SecretKey): ByteArray? {
        try {
            //创建密码器
            val cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING")
            //用密钥初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, encryptKey)
            val final = cipher.doFinal(encryptBytes)
            // iv占前16位,加密后的数据占后面
            return cipher.iv + final
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
        } catch (e: BadPaddingException) {
            e.printStackTrace()
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
        }
        return null
    }

    fun decryptAES(decryptBytes: ByteArray, decryptKey: SecretKey): ByteArray? {
        try {
            // 先取出IV
            val iv = decryptBytes.copyOfRange(0, IV_BLOCK_SIZE)
            // 取出加密后的数据
            val decryptData = decryptBytes.copyOfRange(IV_BLOCK_SIZE, decryptBytes.size)
            val cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING")
            cipher.init(Cipher.DECRYPT_MODE, decryptKey, IvParameterSpec(iv))
            return cipher.doFinal(decryptData)
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
        } catch (e: BadPaddingException) {
            e.printStackTrace()
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
        }
        return null
    }

    //为加密生成一个Key，通过KeyGenerator来实现，先生成一个KeyGenerator
    private fun getKeyGenerator(alias: String): KeyGenerator {
        // 第一个参数指定加密算法,第二个参数指定Provider
        val keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
        val parameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT  //用于加密和解密
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)  // AEC_CBC
                .setUserAuthenticationRequired(false)   // 是否需要用户认证
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)  //AES算法的PADDING, 和前面的AESUtil里保持统一
                .build()
        } else {
            TODO("VERSION.SDK_INT < M")
        }
        keyGenerator.init(parameterSpec)
        return keyGenerator
    }

    //从KeyStore中获取Key解密
    fun getKeyFromKeyStore(alias: String): SecretKey? {
        // 参数为Provider
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        // 一定要先初始化
        keyStore.load(null)
        // 获取KeyStore中的所有Key的别名
        val aliases = keyStore.aliases()
        // KeyStore里没有key
        if (!aliases.hasMoreElements()) {
            return null
        }
        // Key的保护参数,这里为不需要密码
        val protParam: KeyStore.ProtectionParameter =
            KeyStore.PasswordProtection(null)
        // 通过别名获取Key
        val entry = keyStore.getEntry(alias, protParam) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }


    public fun main(){
        decryptKey?.let {
            // 解密数据
            val decryptAES = AESUtil.decryptAES(encryptData!!, decryptKey)

            val tmpData = String(decryptAES!!, StandardCharsets.UTF_8)
            Log.e("AESUtil 44", "  -  $tmpData")
        }
    }



}
