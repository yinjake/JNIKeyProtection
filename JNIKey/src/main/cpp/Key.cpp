#include <jni.h>
#include <string.h>
#include <assert.h>
#include <cstdlib>
#include "log.h"

// 需要被验证应用的包名
const char *APP_PACKAGE_NAME = "me.key.protection.demo";
// 应用签名，通过 JNIDecryptKey.getSignature(getApplicationContext()) 获取，注意开发版和发布版的区别，发布版需要使用正式签名打包后获取
const char *SIGNATURE_KEY = "308202e4308201cc020101300d06092a864886f70d010105050030373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b30090603550406130255533020170d3232313033313036343035345a180f32303532313032333036343035345a30373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a028201010090c7b5dd46fe47b63431fc6ea08b5270d4af5a1c135a388613a0e21fed1da3268b04e685d2872700d9fa335a3afce3dd5d84924c92bc024807d047aa69d60dede9d422649048009b6e9d2f70824ed718a1272ec0ef15219682db8e5d9cf5066550a99d57b07131a9a47650c42d39882f8e39052ed8048575a818eec541366f60e33ff3d607a86d4900ba17934255734c54f637aebf336a22845442ff0a031454a8857e3b51fe6a5d6ff5cc19052c276609adac456d6731a2a3214cd0bb2b0a5557dc2693925f6c5bda646e4a800b0c5aad81afab235cffecbad887ff49a7a326a4783094c8dfd7abe74b3d26499cbc53ebe593307bb6ce630b4768c09acdef630203010001300d06092a864886f70d0101050500038201010061f2190e84ac0b7639cd1fb55efa4c3125e1c136c7f0de3826667d08e0a063d0da0ef437b0ecb8706237012f263f454aa20fc1d21259618f0afab3a806795608149fd848877da5944a97d22e16b04f9324b8a687bdd372317de0049306966a683d999fc6d04842938024a58870c7dc5bf9f490fd8daa8de2ad415c8f6184ec449fc4d040a885b7a49bd89f89d6def68caa1db3342873b93a0a6125c5f80502246842fd97a46ce86b2d695a600158ca4a056e0f1e22a8a67870a40b6e47a33954483b29ddb6cafb247397386285a15ec47741eef783e15834a8dc3da08ecdcc186550bde7b8c78c34bfc55a996ef142448e8ea6e42cd10518553359bb5f68800c";
// 需要被保护的密钥，请修改成你自己的密钥
const char *DECRYPT_KEY = "successful return key!";

// native 方法所在类的路径
const char *NATIVE_CLASS_PATH = "me/key/protection/JNIKey";

// 验证是否通过
static jboolean auth = JNI_FALSE;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 获取全局 Application
 */
jobject getApplicationContext(JNIEnv *env) {
    jclass activityThread = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
    return env->CallObjectMethod(at, getApplication);
}

/*
 * 初始化并判断当前 APP 是否为合法应用，只需调用一次
 */
JNICALL jboolean init(JNIEnv *env, jclass) {

    jclass binderClass = env->FindClass("android/os/Binder");
    jclass contextClass = env->FindClass("android/content/Context");
    jclass signatureClass = env->FindClass("android/content/pm/Signature");
    jclass packageNameClass = env->FindClass("android/content/pm/PackageManager");
    jclass packageInfoClass = env->FindClass("android/content/pm/PackageInfo");

    jmethodID packageManager = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID packageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jmethodID toCharsString = env->GetMethodID(signatureClass, "toCharsString", "()Ljava/lang/String;");
    jmethodID packageInfo = env->GetMethodID(packageNameClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jmethodID nameForUid = env->GetMethodID(packageNameClass, "getNameForUid", "(I)Ljava/lang/String;");
    jmethodID callingUid = env->GetStaticMethodID(binderClass, "getCallingUid", "()I");

    jint uid = env->CallStaticIntMethod(binderClass, callingUid);

    // 获取全局 Application
    jobject context = getApplicationContext(env);

    jobject packageManagerObject = env->CallObjectMethod(context, packageManager);
    jstring packNameString = (jstring) env->CallObjectMethod(context, packageName);
    jobject packageInfoObject = env->CallObjectMethod(packageManagerObject, packageInfo, packNameString, 64);
    jfieldID signaturefieldID = env->GetFieldID(packageInfoClass, "signatures", "[Landroid/content/pm/Signature;");
    jobjectArray signatureArray = (jobjectArray) env->GetObjectField(packageInfoObject, signaturefieldID);
    jobject signatureObject = env->GetObjectArrayElement(signatureArray, 0);
    jstring runningPackageName = (jstring) env->CallObjectMethod(packageManagerObject, nameForUid, uid);

    if (runningPackageName) {// 正在运行应用的包名
        const char *charPackageName = env->GetStringUTFChars(runningPackageName, 0);
        if (strcmp(charPackageName, APP_PACKAGE_NAME) != 0) {
            return JNI_FALSE;
        }
        env->ReleaseStringUTFChars(runningPackageName, charPackageName);
    } else {
        return JNI_FALSE;
    }

    jstring signatureStr = (jstring) env->CallObjectMethod(signatureObject, toCharsString);
    const char *signature = env->GetStringUTFChars((jstring) env->CallObjectMethod(signatureObject, toCharsString), NULL);

    env->DeleteLocalRef(binderClass);
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(signatureClass);
    env->DeleteLocalRef(packageNameClass);
    env->DeleteLocalRef(packageInfoClass);

    LOGE("current apk signature %s", signature);
    LOGE("reserved signature %s", SIGNATURE_KEY);
    if (strcmp(signature, SIGNATURE_KEY) == 0) {
        LOGE("verification passed");
        env->ReleaseStringUTFChars(signatureStr, signature);
        auth = JNI_TRUE;
        return JNI_TRUE;
    } else {
        LOGE("verification failed");
        auth = JNI_FALSE;
        return JNI_FALSE;
    }
}

/*
 * 获取 Key
 */
JNIEXPORT jstring JNICALL getKey(JNIEnv *env, jclass) {
    if (auth) {
        return env->NewStringUTF(DECRYPT_KEY);
    } else {// 你没有权限，验证没有通过。
        return env->NewStringUTF("You don't have permission, the verification didn't pass.");
    }
}

/*
 * 动态注册 native 方法数组，可以不受方法名称的限制，与 Java native 方法一一对应
 */
static JNINativeMethod registerMethods[] = {
        {"init",   "()Z",                  (jboolean *) init},
        {"getKey", "()Ljava/lang/String;", (jstring *) getKey},
};

/*
 * 动态注册 native 方法
 */
static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods, int numMethods) {
    jclass clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

/*
 * 默认执行的初始化方法
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGE("JNI_OnLoad");

    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    LOGE("register native methods");
    if (!registerNativeMethods(env, NATIVE_CLASS_PATH, registerMethods, sizeof(registerMethods) / sizeof(registerMethods[0]))) {
        LOGE("register native methods failed");
        return -1;
    }

    LOGE("register native methods success");
    return JNI_VERSION_1_6;
}

#ifdef __cplusplus
}
#endif