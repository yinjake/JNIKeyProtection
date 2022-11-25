package me.key.protection.demo;

import android.app.Activity;
import android.content.Context;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public class SecurityKeyCore implements ISecurityKeyCore {

    private Activity mContext;
    private ConfigManager mConfigManager;
    private int sdkVersion;
    private OnAuthenticationResult mOnAuthCoreResult;


    private SecStoreUtil secStoreUtil;


    private final String SIGN_ALGORITHMS = "SHA256WithRSA";
    private final String CIPHER_ALGORITHMS = "RSA/ECB/PKCS1Padding";
    private final String KEY_ALGORITHM_RSA = "RSA";
    private final int KEY_SIZE = 1024;

    private final String AKEY_KEYNAME = "SECX_ENCKEYNAME";//加密的keyName
    private final String AKEY_SEED_PWD = "SECX_SEEDPWD";//密码种子
    private final String AKEY_SEED_NPWD = "SECX_SEEDNPWD";//密码种子
    private final String AKEY_SEED_KS = "SECX_SEEDKS";//ks密码种子
    private final String AKEY_SEED_NEW_KS = "SECX_SEEDENEWKS";//新ks密码种子
    private final String AKEY_SEED_KSFILE= "SECX_SEEDKSFILE";//文件密码种子
    private final String AKEY_SEED_NEW_KSFILE= "SECX_SEEDNEWKSFILE";//新文件密码种子

    private final String AKEY_PWD = "SECX_ENCPWD";//加密密码
    private final String AKEY_NPWD = "SECX_ENCNPWD";//新密码

    private final String AKEY_KSFILE = "SECX_KSFILE";
    private final String AKEY_PUBKEY = "SECX_PUBKEY";
//    private final String AKEY_P10 = "P10REQ"; //暂时生不了P10,暂不使用

    private final String AKEY_SEED_SERVER_KEY1 = "SECX_SEED_SERVERKEY1";//远程访问的种子
    private final String AKEY_SEED_SERVER_KEY2 = "SECX_SEED_SERVERKEY2";//本地
    private final String AKEY_SERVER_KEY2 = "SECX_FILE_SERVERKEY2";


    public SecurityKeyCore(Context context) {
        mContext = (Activity) context;
        mConfigManager = ConfigManager.getInstance(context);
        sdkVersion = mConfigManager.getSDKVersion();

        secStoreUtil = SecStoreUtil.getSecStoreUtils(context);

    }

    //    接口方法,生密钥,建议接口调用时keyName为keyName+userId区分不同用户
    public void generateSecretKey(String keyName,String keyPwd,boolean useFinger){

        String encKeyName,encKeyPwd,encKSPwd,encFilePwd;
        try {
            encKeyName = setEncKeyName(keyName,keyName);
            encKeyPwd = setEncodedPwd(keyPwd,encKeyName);
            encKSPwd = setKSPwd(keyPwd,encKeyName);
            encFilePwd = setSymmetricPwd(keyPwd,encKeyName);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
            return;
        }

//        TODO 在不在安全硬件里暂时都通过AndroidKeyStore生成
//        if (sdkVersion == ConfigManager.SDK_VERSION_H && mFingerHelper.checkKeyIsInsideSecureHardware()) {
        if (sdkVersion == ConfigManager.SDK_VERSION_H) {

            generateKeyAbove6(encKeyName,encKeyPwd,useFinger);

        } else if (canCreateInTEE()) {

            //TODO 生秘钥

            //TODO 存储公钥
//                secStoreUtil.putString(AKEY_PUB + keyName, securityCipher.encryptString(Base64.encodeToString(pubKey.getEncoded(), Base64.NO_WRAP)));

            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.SUCCESS,null);
//            return SecurityKeyEngine.SUCCESS;

        } else if (sdkVersion == ConfigManager.SDK_VERSION_M || sdkVersion == ConfigManager.SDK_VERSION_L) {


            generateKeyBelow6(encKeyName,encKeyPwd,encKSPwd,encFilePwd,useFinger);

        } else {

            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_API_VERSION_NOT_SUPPORT,null);
//            return SecurityKeyEngine.ERROR_API_VERSION_NOT_SUPPORT;
        }

    }

    //    接口方法，获取公钥
    public byte[] getPublicKey(String keyName) {

//        keyName暂不使用，公钥从安全插件中取，也可以从keystore中取（复杂）

        try {
            String publicKey = secStoreUtil.decryptString(secStoreUtil.getString(AKEY_PUBKEY + getEncKeyName(keyName)));
            if (publicKey != null) {
                return Base64.decode(publicKey, Base64.NO_WRAP);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    //    接口方法，获取公钥
    public boolean containsKey(String keyName) {

//        keyName暂不使用，公钥从安全插件中取，也可以从keystore中取（复杂）
        try {
            String publicKey = secStoreUtil.decryptString(secStoreUtil.getString(AKEY_PUBKEY + getEncKeyName(keyName)));
            if (publicKey != null) {
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return false;

    }

    //    接口方法，存储数据
    public int putEncKey(String keyId, String data) {

        try {
            String random =  UUIDUtil.getUUID();
            secStoreUtil.putString(AKEY_SEED_SERVER_KEY2 + keyId,secStoreUtil.encryptString(random));

            String filePwd = SecxUtil.getMD5Code(random + mConfigManager.getCheckSecretParams() + "trustdo");
            if(filePwd!=null){
                byte[] encData = SecxUtil.get3DESEncryptCBC(data.getBytes(), filePwd.getBytes());
                if(encData!=null){
                    secStoreUtil.putString(AKEY_SERVER_KEY2 + keyId,secStoreUtil.encryptString(ByteStreamUtils.bytesToHexString(encData)));
                    return SecurityKeyEngine.SUCCESS;
                }else {
                    return SecurityKeyEngine.ERROR_CIPHER_ENCKEY_NULL;
                }
            }else{
                return SecurityKeyEngine.ERROR_CIPHER_ENCKEY_NULL;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION;
        }
    }
    //获取数据
    public String getEncKey(String keyId){
        try {
            String encDataStr = secStoreUtil.getString(AKEY_SERVER_KEY2 + keyId);
            String decDataStr = secStoreUtil.decryptString(encDataStr);
            String encRandom =  secStoreUtil.getString(AKEY_SEED_SERVER_KEY2 + keyId);
            String decRandom =  secStoreUtil.decryptString(encRandom);
            String filePwd = SecxUtil.getMD5Code(decRandom + mConfigManager.getCheckSecretParams() + "trustdo");

            byte[] decData = SecxUtil.get3DESDecryptCBC(ByteStreamUtils.hexStringToBinary(decDataStr), filePwd.getBytes());
            return new String(decData);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    //    接口方法，签名
    public void signature(String keyName,String keyPwd,byte[] dataToSign) {

//        TODO 在不在安全硬件里暂时都通过AndroidKeyStore生成
//        if (sdkVersion == ConfigManager.SDK_VERSION_H && mFingerHelper.checkKeyIsInsideSecureHardware()) {
        if (sdkVersion == ConfigManager.SDK_VERSION_H) {

            try {
                String encKeyName = getEncKeyName(keyName);

                //检验数据
                if ("".equals(dataToSign) || null == dataToSign) {
                    mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_GET_SIGN_DATA,null);
                    return;
                }
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }

                signatureAbove6(encKeyName,getEncodedPwd(encKeyName),dataToSign);

            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);

            }

        }else if(canCreateInTEE()){

            try {
                String encKeyName = getEncKeyName(keyName);

                //检验数据
                if ("".equals(dataToSign) || null == dataToSign) {
                    mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_GET_SIGN_DATA,null);
                    return;
                }
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                //TODO 签名操作


            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);

            }



        }else if( sdkVersion == ConfigManager.SDK_VERSION_M || sdkVersion == ConfigManager.SDK_VERSION_L){

            try {
                String encKeyName = getEncKeyName(keyName);

                //检验数据
                if ("".equals(dataToSign) || null == dataToSign) {
                    mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_GET_SIGN_DATA,null);
                    return;
                }
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }

                signatureBelow6(encKeyName,getEncodedPwd(encKeyName),getKSPwd(keyPwd,encKeyName),getSymmetricPwd(keyPwd,encKeyName),dataToSign);

            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);

            }


        }else{
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_API_VERSION_NOT_SUPPORT, null);

        }

    }

    //    接口方法，删除密钥
    public void deleteSecretKey(String keyName,String keyPwd) {

//        TODO 在不在安全硬件里暂时都通过AndroidKeyStore生成
//        if (sdkVersion == ConfigManager.SDK_VERSION_H && mFingerHelper.checkKeyIsInsideSecureHardware()) {
        if (sdkVersion == ConfigManager.SDK_VERSION_H) {

            try {
                String encKeyName = getEncKeyName(keyName);

                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }

                deleteAbove6(keyName,encKeyName,getEncodedPwd(encKeyName));

            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
            }

        }else if(canCreateInTEE()){

            try {
                String encKeyName = getEncKeyName(keyName);

                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                //TODO 删除操作


            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
            }

        }else if( sdkVersion == ConfigManager.SDK_VERSION_M || sdkVersion == ConfigManager.SDK_VERSION_L){

            try {
                String encKeyName = getEncKeyName(keyName);
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }

                deleteBelow6(keyName,encKeyName,getEncodedPwd(encKeyName),getKSPwd(keyPwd,encKeyName),getSymmetricPwd(keyPwd,encKeyName));

            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
            }

        }else{
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_API_VERSION_NOT_SUPPORT, null);

        }

    }



    //    接口方法，修改密码
    @Override
    public void modifyPassword(String keyName,String oldPwd,String newPwd) {

//        TODO 在不在安全硬件里暂时都通过AndroidKeyStore生成
//        if (sdkVersion == ConfigManager.SDK_VERSION_H && mFingerHelper.checkKeyIsInsideSecureHardware()) {
        if (sdkVersion == ConfigManager.SDK_VERSION_H) {

            try {
                String encKeyName = getEncKeyName(keyName);
                //检验密码
                if(!verifyPwd(oldPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                //newPwd为原文
                setEncodedNewPwd(newPwd,encKeyName);
                modifyAbove6(encKeyName,newPwd);


            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
            }

        }else if(canCreateInTEE()){

            try {
                String encKeyName = getEncKeyName(keyName);
                //检验密码
                if(!verifyPwd(oldPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }

                //TODO 修改操作


            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
            }

        }else if( sdkVersion == ConfigManager.SDK_VERSION_M || sdkVersion == ConfigManager.SDK_VERSION_L){

            try {
                String encKeyName = getEncKeyName(keyName);
                //检验密码
                if(!verifyPwd(oldPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                //缓存新密码
                String encNewPwd = setEncodedNewPwd(newPwd,encKeyName);
                String encNewKSPwd = setNewKSPwd(newPwd,encKeyName);
                String encNewFilePwd = setNewSymmetricPwd(newPwd,encKeyName);
                modifyBelow6(encKeyName,getEncodedPwd(encKeyName),getKSPwd(oldPwd,encKeyName),getSymmetricPwd(oldPwd,encKeyName),encNewPwd,encNewKSPwd,encNewFilePwd);
            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
            }

        }else{
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_API_VERSION_NOT_SUPPORT, null);

        }


    }

    //    注册回调函数
    @Override
    public void setOnAuthCoreResult(OnAuthenticationResult result){
        mOnAuthCoreResult = result;
    }

    @RequiresApi(api = Build.VERSION_CODES.P)
    public BiometricPrompt.CryptoObject getCryptoObjectAboveP(String keyName, int type){

        try {

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);
            KeyStore.PrivateKeyEntry privateKey = (KeyStore.PrivateKeyEntry) keyStore.getEntry(getEncKeyName(keyName), null);

            if (!(privateKey instanceof KeyStore.PrivateKeyEntry)) {
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                return null;
            }
            if(type == 0){
                // 获取签名
                Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
                signature.initSign(privateKey.getPrivateKey());
                BiometricPrompt.CryptoObject object = new BiometricPrompt.CryptoObject(signature);
                return object;
            }else if(type == 1) {
                Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHMS);
                cipher.init(Cipher.DECRYPT_MODE,privateKey.getPrivateKey());
                BiometricPrompt.CryptoObject object = new BiometricPrompt.CryptoObject(cipher);
                return object;
            }

        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_IO_EXCEPTION,null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_ALG_EXCEPTION,null);
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_EXCEPTION,null);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required key is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_INKEY_EXCEPTION,null);
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
//                    Log.e(TAG, "a KeyStore.Entry cannot be recovered from a KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_CANNOT_RECOVERY,null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_EXCEPTION,null);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
        }
//        catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//        }
        return null;
    }
    //    对外提供方法类 0签名，1解密
    public FingerprintManager.CryptoObject getCryptoObject(String keyName,int type){

        try {

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);
            KeyStore.PrivateKeyEntry privateKey = (KeyStore.PrivateKeyEntry) keyStore.getEntry(getEncKeyName(keyName), null);

            if (!(privateKey instanceof KeyStore.PrivateKeyEntry)) {
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                return null;
            }
            if(type == 0){
                // 获取签名
                Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
                signature.initSign(privateKey.getPrivateKey());
                FingerprintManager.CryptoObject object = new FingerprintManager.CryptoObject(signature);
                return object;
            }else if(type == 1) {
                Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHMS);
                cipher.init(Cipher.DECRYPT_MODE,privateKey.getPrivateKey());
                FingerprintManager.CryptoObject object = new FingerprintManager.CryptoObject(cipher);
                return object;
            }

        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_IO_EXCEPTION,null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_ALG_EXCEPTION,null);
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_EXCEPTION,null);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required key is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_INKEY_EXCEPTION,null);
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
//                    Log.e(TAG, "a KeyStore.Entry cannot be recovered from a KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_CANNOT_RECOVERY,null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_EXCEPTION,null);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
        }
//        catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//        }
        return null;
    }

    //    对外提供方法类验证密码
    public boolean modifyVerifyPwd(String pwd,String keyName){

        try {
            String encKeyName = getEncKeyName(keyName);
//            if(!verifyPwd(pwd,encKeyName)){//失败的时候执行回调记录错误次数
//                mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
//            }
            return verifyPwd(pwd,encKeyName);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    //  是否可以使用TEE
    private boolean canCreateInTEE(){
        return false;
    }



    public byte[] encrypt(String keyName, byte[] data){
        byte[] pubKey = getPublicKey(keyName);
        if (pubKey == null) {
            return null;
        }
        try {

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
            RSAPublicKey rasPubKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            Cipher cipher = null;
            // 使用默认RSA
            cipher = Cipher.getInstance(CIPHER_ALGORITHMS);
            // cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, rasPubKey);
            byte[] output = cipher.doFinal(data);
            return output;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e)
        {
            e.printStackTrace();
        }

        return null;

    }

    @Override
    public void decrypt(String keyName, String keyPwd, byte[] data){
//      TODO 在不在安全硬件里暂时都通过AndroidKeyStore生成
//      if (sdkVersion == ConfigManager.SDK_VERSION_H && mFingerHelper.checkKeyIsInsideSecureHardware()) {
        if (sdkVersion == ConfigManager.SDK_VERSION_H) {
            try {
                String encKeyName = getEncKeyName(keyName);
                //检验数据
                if ("".equals(data) || null == data) {
                    mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_GET_PLANTTEXT_DATA,null);
                    return;
                }
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                decryptAbove6(encKeyName,getEncodedPwd(encKeyName),data);

            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
                return;
            }

        }else if(canCreateInTEE()){
            try {
                String encKeyName = getEncKeyName(keyName);
                //检验数据
                if ("".equals(data) || null == data) {
                    mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_GET_PLANTTEXT_DATA,null);
                    return;
                }
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                //TODO 签名操作

            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
                return;
            }

        }else if( sdkVersion == ConfigManager.SDK_VERSION_M || sdkVersion == ConfigManager.SDK_VERSION_L){

            try {
                String encKeyName = getEncKeyName(keyName);

                //检验数据
                if ("".equals(data) || null == data) {
                    mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_GET_PLANTTEXT_DATA,null);
                    return;
                }
                //检验密码
                if(!verifyPwd(keyPwd,encKeyName)){
                    mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                    return;
                }
                decryptBelow6(encKeyName,getEncodedPwd(encKeyName),getKSPwd(keyPwd,encKeyName),getSymmetricPwd(keyPwd,encKeyName),data);
            } catch (Exception e) {
                e.printStackTrace();
                mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
                return;
            }

        }else{
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_API_VERSION_NOT_SUPPORT, null);
            return;
        }

    }

    private void decryptAbove6(String encKeyName,String encKeyPwd, byte[] data){

        try {

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);
            KeyStore.PrivateKeyEntry privateKey = (KeyStore.PrivateKeyEntry) keyStore.getEntry(encKeyName, null);
            if (!(privateKey instanceof KeyStore.PrivateKeyEntry)) {
                mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_GET_CIPHER_CRYPTO, null);
                return;
            }

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHMS);
            cipher.init(Cipher.DECRYPT_MODE, privateKey.getPrivateKey());
            byte[] output = cipher.doFinal(data);
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.SUCCESS, output);
            return;


        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_IO_EXCEPTION,null);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_ALG_EXCEPTION,null);

        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_CERT_EXCEPTION,null);

        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
//                    Log.e(TAG, "a KeyStore.Entry cannot be recovered from a KeyStore");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_KEY_CANNOT_RECOVERY,null);

        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_KEY_EXCEPTION,null);
        } catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        } catch (InvalidKeyException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        } catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        } catch (BadPaddingException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        }
        return;

    }

    private void decryptBelow6(String encKeyName,String encKeyPwd,String encKsPwd,String encFilePwd,byte[] data){

        try{

            //加载秘钥文件，校验密码
            byte[] ksByte = Base64.decode(secStoreUtil.decryptString(secStoreUtil.getString(AKEY_KSFILE + encKeyName)),Base64.NO_WRAP);
            byte[] decKS = SecxUtil.get3DESDecryptCBC(ksByte,encFilePwd.getBytes());
            if(decKS == null){
                mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                return;
            }

            InputStream in = ByteStreamUtils.bytesToInputStream(decKS);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in,encKsPwd.toCharArray());

            KeyStore.ProtectionParameter proParam = new KeyStore.PasswordProtection(encKeyPwd.toCharArray());
            KeyStore.Entry keyEntry = keyStore.getEntry(encKeyName, proParam);

            if (!(keyEntry instanceof KeyStore.PrivateKeyEntry)) {
                mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_GET_CIPHER_CRYPTO, null);
                return;
            }

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHMS);
            cipher.init(Cipher.DECRYPT_MODE,((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey());
            byte[] output = cipher.doFinal(data);
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.SUCCESS, output);
            return;


        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_IO_EXCEPTION,null);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_ALG_EXCEPTION,null);

        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_CERT_EXCEPTION,null);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required key is not available");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
//                    Log.e(TAG, "a KeyStore.Entry cannot be recovered from a KeyStore");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_KEY_CANNOT_RECOVERY,null);

        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_KEY_EXCEPTION,null);

        }  catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        } catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        } catch (BadPaddingException e)
        {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);

        }catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);

        }
        mOnAuthCoreResult.onAuthDecryptResult(SecurityKeyEngine.ERROR_CIPHER_DO_CIPHER,null);
        return;

    }

    //    6.0以上设备通过AndroidKeyStore生成密钥
    private void generateKeyAbove6(String encKeyName, String encKeyPwd, boolean useFinger){

        try {
            //加载keyStore
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);

            //生密钥对
            //用keyName+keyPwd 作为秘钥别名，因为6.0的设备，无法设置密码，通过此方法，调用的时候可以验证密码是否正确
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(encKeyName, KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(KEY_SIZE)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setUserAuthenticationRequired(useFinger)
                    .build();
            kpg.initialize(spec);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey priKey = keyPair.getPrivate();// null

            //TODO 生成P10请求
            //生成P10请求
//                try {
//                    String p10Str = null;
//                    p10Str = SecxUtil.getP10RequestByBuilder(SIGN_ALGORITHMS,certDN,keyPair,KEY_ALGORITHM_RSA);
//                    secStoreUtil.putString(AKEY_P10 + userId,p10Str);
//                } catch (OperatorCreationException e) {
//                    e.printStackTrace();
//                }
            //TODO 生成P10请求

//                java.lang.UnsupportedOperationException: Can not serialize AndroidKeyStore to OutputStream
//                OutputStream out  = new ByteArrayOutputStream();
//                keyStore.store(out,password.toCharArray());

//            //存储公钥,密码
            secStoreUtil.putString(AKEY_PUBKEY + encKeyName, secStoreUtil.encryptString(Base64.encodeToString(pubKey.getEncoded(), Base64.NO_WRAP)));

            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.SUCCESS,null);
//            return SecurityKeyEngine.SUCCESS;

        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_IO_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_IO_EXCEPTION;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_ALG_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_ALG_EXCEPTION;
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_CERT_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_CERT_EXCEPTION;
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_KEY_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_KEY_EXCEPTION;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this required provider is not initialized");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_CERT_PRO_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_CERT_PRO_EXCEPTION;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
//                    Log.e(TAG, "indicates the occurrence of invalid algorithm parameters");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_ALG_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_ALG_EXCEPTION;
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION;

        }
    }

    //    6.0以下设备通过KeyStore生成密钥
    private void generateKeyBelow6(String encKeyName,String encKeyPwd,String encKsPwd,String encFilePwd,boolean useFinger){

        try {
            //加载keyStore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);

            //生密钥对
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA);
            kpg.initialize(KEY_SIZE);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey priKey = keyPair.getPrivate();

            //TODO 生成P10请求
//                String p10Str = SecxUtil.getP10RequestByBuilder(SIGN_ALGORITHMS,certDN,keyPair,KEY_ALGORITHM_RSA);
//                secStoreUtil.putString(AKEY_P10 + userId, p10Str);
            //TODO 生成P10请求

            //存储密钥对
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = SecxUtil.generateCertificateByBuilder(mContext,SIGN_ALGORITHMS,keyPair);
            keyStore.setKeyEntry(encKeyName, priKey, encKeyPwd.toCharArray(), chain);

            //导出KS
            OutputStream out = new ByteArrayOutputStream();
            keyStore.store(out, encKsPwd.toCharArray());
            byte[] encData = SecxUtil.get3DESEncryptCBC(ByteStreamUtils.outputStreamToBytes(out), encFilePwd.getBytes());

            //存储公钥，ks文件
            secStoreUtil.putString(AKEY_KSFILE + encKeyName, secStoreUtil.encryptString(Base64.encodeToString(encData, Base64.NO_WRAP)));
            secStoreUtil.putString(AKEY_PUBKEY + encKeyName, secStoreUtil.encryptString(Base64.encodeToString(pubKey.getEncoded(), Base64.NO_WRAP)));

            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.SUCCESS,null);
//            return SecurityKeyEngine.SUCCESS;
        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_IO_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_IO_EXCEPTION;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_ALG_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_ALG_EXCEPTION;
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_CERT_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_CERT_EXCEPTION;
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_STORE_KEY_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_STORE_KEY_EXCEPTION;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required key is not available");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_CERT_INKEY_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_CERT_INKEY_EXCEPTION;
        } catch (SignatureException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while Signature");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_CERT_SIGN_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_CERT_SIGN_EXCEPTION;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this required provider is not initialized");
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_CERT_PRO_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_CERT_PRO_EXCEPTION;
        } catch (OperatorCreationException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_GEN_PKCS10_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_GEN_PKCS10_EXCEPTION;
        }catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthGenerateResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
//            return SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION;
        }

    }

    private void signatureAbove6(String encKeyName,String encKeyPwd, byte[] dataToSign){

        try {

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);
            KeyStore.PrivateKeyEntry privateKey = (KeyStore.PrivateKeyEntry) keyStore.getEntry(encKeyName, null);
            if (!(privateKey instanceof KeyStore.PrivateKeyEntry)) {
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_GET_SIGNATURE_CRYPTO, null);
                return;
            }

            // 获取签名
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(privateKey.getPrivateKey());
            signature.update(dataToSign);
            byte[] signed = signature.sign();
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.SUCCESS, signed);

        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_IO_EXCEPTION,null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_ALG_EXCEPTION,null);
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_EXCEPTION,null);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required key is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_INKEY_EXCEPTION,null);
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
//                    Log.e(TAG, "a KeyStore.Entry cannot be recovered from a KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_CANNOT_RECOVERY,null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_EXCEPTION,null);
        } catch (SignatureException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_DO_SIGNATURE,null);
        }

    }

    private void signatureBelow6(String encKeyName,String encKeyPwd,String encKsPwd,String encFilePwd,byte[] dataToSign){

        try{

            //加载秘钥文件，校验密码
            byte[] ksByte = Base64.decode(secStoreUtil.decryptString(secStoreUtil.getString(AKEY_KSFILE + encKeyName)),Base64.NO_WRAP);
            byte[] decKS = SecxUtil.get3DESDecryptCBC(ksByte,encFilePwd.getBytes());
            if(decKS == null){
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                return;
            }

            InputStream in = ByteStreamUtils.bytesToInputStream(decKS);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in,encKsPwd.toCharArray());

            KeyStore.ProtectionParameter proParam = new KeyStore.PasswordProtection(encKeyPwd.toCharArray());
            KeyStore.Entry keyEntry = keyStore.getEntry(encKeyName, proParam);

            if (!(keyEntry instanceof KeyStore.PrivateKeyEntry)) {
                mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_GET_SIGNATURE_CRYPTO, null);
                return;
            }
//                 获取签名
            Signature sign = Signature.getInstance(SIGN_ALGORITHMS);
            sign.initSign(((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey());
            sign.update(dataToSign);
            byte[] signed = sign.sign();
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.SUCCESS, signed);

        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_IO_EXCEPTION,null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_ALG_EXCEPTION,null);
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_EXCEPTION,null);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required key is not available");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_CERT_INKEY_EXCEPTION,null);
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
//                    Log.e(TAG, "a KeyStore.Entry cannot be recovered from a KeyStore");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_CANNOT_RECOVERY,null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_KEY_EXCEPTION,null);
        } catch (SignatureException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while Signature");
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SIGN_DO_SIGNATURE,null);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthSignResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
        }
    }

    private void deleteAbove6(String keyName,String encKeyName,String encKeyPwd){

        try {

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);
            keyStore.deleteEntry(encKeyName);

            //成功后删除数据
            secStoreUtil.removeString(AKEY_KEYNAME + keyName);
            secStoreUtil.removeString(AKEY_SEED_PWD + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_NPWD + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_KS + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_KSFILE + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_NEW_KS + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_NEW_KSFILE + encKeyName);
            secStoreUtil.removeString(AKEY_PWD + encKeyName);
            secStoreUtil.removeString(AKEY_NPWD + encKeyName);
            secStoreUtil.removeString(AKEY_KSFILE + encKeyName);
            secStoreUtil.removeString(AKEY_PUBKEY + encKeyName);
//                secStoreUtil.removeString(AKEY_P10 +userId);

            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.SUCCESS, null);
        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_IO_EXCEPTION, null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_ALG_EXCEPTION, null);
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_CERT_EXCEPTION, null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_KEY_EXCEPTION, null);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);

        }

    }

    private void deleteBelow6(String keyName,String encKeyName,String encKeyPwd,String encKsPwd,String encFilePwd){

        try {

            //校验密码，加载秘钥文件
            byte[] ksByte = Base64.decode(secStoreUtil.decryptString(secStoreUtil.getString(AKEY_KSFILE + encKeyName)),Base64.NO_WRAP);
            byte[] decKS = SecxUtil.get3DESDecryptCBC(ksByte,encFilePwd.getBytes());
            if(decKS == null){
                mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                return;
            }

            InputStream in = ByteStreamUtils.bytesToInputStream(decKS);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in,encKsPwd.toCharArray());

            keyStore.deleteEntry(encKeyName);

            //成功后删除数据
            secStoreUtil.removeString(AKEY_KEYNAME + keyName);
            secStoreUtil.removeString(AKEY_SEED_PWD + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_NPWD + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_KS + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_KSFILE + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_NEW_KS + encKeyName);
            secStoreUtil.removeString(AKEY_SEED_NEW_KSFILE + encKeyName);
            secStoreUtil.removeString(AKEY_PWD + encKeyName);
            secStoreUtil.removeString(AKEY_NPWD + encKeyName);
            secStoreUtil.removeString(AKEY_KSFILE + encKeyName);
            secStoreUtil.removeString(AKEY_PUBKEY + encKeyName);
//                secStoreUtil.removeString(AKEY_P10 +userId);

            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.SUCCESS, null);


        } catch (IOException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key a problem occurred while writing to the stream");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_IO_EXCEPTION,null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key the required algorithm is not available");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_ALG_EXCEPTION,null);
        } catch (CertificateException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key an exception occurred while loading the certificates of this KeyStore");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_CERT_EXCEPTION,null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
//                    Log.e(TAG, "generate key this KeyStore is not initialized");
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_DELETE_KEY_EXCEPTION,null);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthDeleteResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION,null);
        }

    }

    private void modifyAbove6(String encKeyName,String newPwd){
        try {
            //newPwd为原文
            modifyEncodedPwd(encKeyName);
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.SUCCESS,null);

        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_DO_MODIFY,null);

        }

    }

    private void modifyBelow6(String encKeyName,String encOldKeyPwd,String encOldKsPwd,String encOldFilePwd,String encNewKeyPwd,String encNewKsPwd,String encNewFilePwd){

        try {
            //校验密码，加载秘钥文件
            byte[] ksByte = Base64.decode(secStoreUtil.decryptString(secStoreUtil.getString(AKEY_KSFILE + encKeyName)), Base64.NO_WRAP);
            byte[] decKS = SecxUtil.get3DESDecryptCBC(ksByte, encOldFilePwd.getBytes());
            if (decKS == null) {
                mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_PASSWORD_INCORRECT, null);
                return;
            }

            InputStream in = ByteStreamUtils.bytesToInputStream(decKS);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in, encOldKsPwd.toCharArray());

            PrivateKey priKey = (PrivateKey) keyStore.getKey(encKeyName,encOldKeyPwd.toCharArray());
            if (!(priKey instanceof PrivateKey)) {
                mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_GET_SIGNATURE_CRYPTO, null);
                return;
            }

            //存储密钥对
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = (X509Certificate) keyStore.getCertificate(encKeyName);
            keyStore.setKeyEntry(encKeyName,priKey, encNewKeyPwd.toCharArray() ,chain);
            //导出KS
            OutputStream out  = new ByteArrayOutputStream();
            keyStore.store(out,encNewKsPwd.toCharArray());
            byte[] encData = SecxUtil.get3DESEncryptCBC(ByteStreamUtils.outputStreamToBytes(out),encNewFilePwd.getBytes());

            //存储
            secStoreUtil.putString(AKEY_KSFILE + encKeyName,secStoreUtil.encryptString(Base64.encodeToString(encData, Base64.NO_WRAP)));

            //更新密码
            modifyEncodedPwd(encKeyName);
            modifyEncodedKSPwd(encKeyName);
            modifyEncodedFilePwd(encKeyName);

            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.SUCCESS, null);

        } catch (CertificateException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_CERT_EXCEPTION, null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_ALG_EXCEPTION, null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_KEY_EXCEPTION, null);
        } catch (IOException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_IO_EXCEPTION, null);
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_MODIFY_KEY_CANNOT_RECOVERY, null);
        } catch (Exception e) {
            e.printStackTrace();
            mOnAuthCoreResult.onAuthModifyResult(SecurityKeyEngine.ERROR_SECSTORGE_EXCEPTION, null);
        }

    }



    //    setKeyName
    private String setEncKeyName(String keyName,String userId) throws Exception {
        String encKeyName = SecxUtil.getSHA1Code(keyName+userId);
        secStoreUtil.putString(AKEY_KEYNAME + userId,secStoreUtil.encryptString(encKeyName));
        return encKeyName;
    }
    //    getKeyName
    private String getEncKeyName(String userId) throws Exception {
        return secStoreUtil.decryptString(secStoreUtil.getString(AKEY_KEYNAME + userId));
    }



    //   设置密码
    private String setEncodedPwd(String keyPwd,String encUserId) throws Exception {
        String random =  UUIDUtil.getUUID();
        secStoreUtil.putString(AKEY_SEED_PWD + encUserId,secStoreUtil.encryptString(random));
        String res = SecxUtil.getSHA1Code(mConfigManager.getCheckSecretParams() + keyPwd + random);
        secStoreUtil.putString(AKEY_PWD + encUserId,secStoreUtil.encryptString(res));
        return res;
    }
    //    验证密码
    private boolean verifyPwd(String pwd,String encUserId) throws Exception {
        String seed = secStoreUtil.decryptString(secStoreUtil.getString(AKEY_SEED_PWD + encUserId));
        String encPwd = secStoreUtil.decryptString(secStoreUtil.getString(AKEY_PWD + encUserId));
        String res = SecxUtil.getSHA1Code(mConfigManager.getCheckSecretParams() + pwd + seed);
        if(res.equals(encPwd)){
            return true;
        }
        return false;
    }
    //    获取密码
    private String getEncodedPwd(String encUserId) throws Exception {
        return secStoreUtil.decryptString(secStoreUtil.getString(AKEY_PWD + encUserId));
    }



    //    设置ks密码
    private String setKSPwd(String keyPwd,String encUserId) throws Exception {
        String random =  UUIDUtil.getUUID();
        secStoreUtil.putString(AKEY_SEED_KS + encUserId,secStoreUtil.encryptString(random));
        return SecxUtil.getSHA1Code(mConfigManager.getCheckSecretParams() + keyPwd + random);
    }
    //    获取ks密码
    private String getKSPwd(String keyPwd,String encUserId) throws Exception {
        String seed = secStoreUtil.decryptString(secStoreUtil.getString(AKEY_SEED_KS + encUserId));
        return SecxUtil.getSHA1Code(mConfigManager.getCheckSecretParams() + keyPwd + seed);
    }
    //    设置ks新密码
    private String setNewKSPwd(String keyPwd,String encUserId) throws Exception {
        String random =  UUIDUtil.getUUID();
        secStoreUtil.putString(AKEY_SEED_NEW_KS + encUserId,secStoreUtil.encryptString(random));
        return SecxUtil.getSHA1Code(mConfigManager.getCheckSecretParams() + keyPwd + random);
    }


    //  设置文件密码
    private String setSymmetricPwd(String keyPwd,String encUserId) throws Exception {
        String random =  UUIDUtil.getUUID();
        secStoreUtil.putString(AKEY_SEED_KSFILE + encUserId,secStoreUtil.encryptString(random));
        return SecxUtil.getMD5Code(mConfigManager.getCheckSecretParams() + keyPwd + random);
    }
    //  获取文件密码
    private String getSymmetricPwd(String keyPwd,String encUserId) throws Exception {
        String seed = secStoreUtil.decryptString(secStoreUtil.getString(AKEY_SEED_KSFILE + encUserId));
        return SecxUtil.getMD5Code(mConfigManager.getCheckSecretParams() + keyPwd + seed);
    }
    //    设置文件新密码
    private String setNewSymmetricPwd(String keyPwd,String encUserId) throws Exception {
        String random =  UUIDUtil.getUUID();
        secStoreUtil.putString(AKEY_SEED_NEW_KSFILE + encUserId,secStoreUtil.encryptString(random));
        return SecxUtil.getMD5Code(mConfigManager.getCheckSecretParams() + keyPwd + random);
    }



    //    setNewPwd
    private String setEncodedNewPwd(String keyPwd,String encUserId) throws Exception {
        String random =  UUIDUtil.getUUID();
        secStoreUtil.putString(AKEY_SEED_NPWD + encUserId,secStoreUtil.encryptString(random));
        String res = SecxUtil.getSHA1Code(mConfigManager.getCheckSecretParams() + keyPwd + random);
        secStoreUtil.putString(AKEY_NPWD + encUserId,secStoreUtil.encryptString(res));
        return res;
    }


    //    modifyPwd
    private void modifyEncodedPwd(String encUserId) throws Exception {
        secStoreUtil.putString(AKEY_SEED_PWD + encUserId,secStoreUtil.getString(AKEY_SEED_NPWD + encUserId));
        secStoreUtil.putString(AKEY_PWD + encUserId,secStoreUtil.getString(AKEY_NPWD + encUserId));
    }
    //    modifyKSPwd
    private void modifyEncodedKSPwd(String encUserId) throws Exception {
        secStoreUtil.putString(AKEY_SEED_KS + encUserId,secStoreUtil.getString(AKEY_SEED_NEW_KS + encUserId));
    }
    //    modifyFilePwd
    private void modifyEncodedFilePwd(String encUserId) throws Exception {
        secStoreUtil.putString(AKEY_SEED_KSFILE + encUserId,secStoreUtil.getString(AKEY_SEED_NEW_KSFILE + encUserId));
    }

}
