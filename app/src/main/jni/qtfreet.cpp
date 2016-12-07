#include "Android/vm/oo/Object.h"
#include "Android/libdex/DexClass.h"
#include "AntiDebug/antidebug.h"
#include "EncryptUtils/AES/aes.h"
#include <asm-generic/mman-common.h>
#include <sys/mman.h>
#include "EncryptUtils/RC4/RC4Utils.h"
#include "EncryptUtils/Base64/Base64.h"
#include "EncryptUtils/Md5/Md5Utils.h"
#include "Utils/Utils.h"
#include <iostream>
#include <map>


#define opCodeA 90
#define opCodeB 91
#define opCodeC 13
#define opCodeD 12
#define NULL 0
pthread_t id = NULL;
pthread_t id_notify = NULL;
int opCodeReverse;
int opCodeToString;
bool flag = false;
std::map<u1, u1> opcodemap;
const char final_flag[] = {
        75, 79, 43, 50, 53, 55, 102, 115, 68, 120, 57, 101, 115, 85, 85, 122,
        87, 68, 55, 85, 99, 51, 57, 116, 82, 97, 56, 52, 105, 120, 52, 87,
        0, 99, 111, 109, 47, 113, 116, 102, 114, 101, 101, 116, 47, 99, 114, 97,
};
static const unsigned char dex[] = "Zvmmq56ICjFmg0doGjPySSQxMpk+mEJr+onBi14r6O1J1wKFCRT1IZVRccvJ9Sq8BVY=";
static const unsigned char method[] = "KvWivJTkATRv";
static const unsigned char wClass[] = "Bf6ostDWGjZ4kEt3GDPhSy8/cJhv3BIE1pjYpXwn8apOyhCOVw==";

void initMap() {
    opcodemap.insert(std::make_pair(48, 97));//
    opcodemap.insert(std::make_pair(49, 54));//
    opcodemap.insert(std::make_pair(50, 102));//
    opcodemap.insert(std::make_pair(51, 99));//
    opcodemap.insert(std::make_pair(52, 57));//
    opcodemap.insert(std::make_pair(53, 48));//
    opcodemap.insert(std::make_pair(54, 49));//
    opcodemap.insert(std::make_pair(55, 101));//
    opcodemap.insert(std::make_pair(56, 50));//
    opcodemap.insert(std::make_pair(57, 51));//
    opcodemap.insert(std::make_pair(97, 52));//
    opcodemap.insert(std::make_pair(98, 53));//
    opcodemap.insert(std::make_pair(99, 55));//
    opcodemap.insert(std::make_pair(100, 100));//
    opcodemap.insert(std::make_pair(101, 56));//
    opcodemap.insert(std::make_pair(102, 98));//

    opcodemap.insert(std::make_pair(108, 116));//
    opcodemap.insert(std::make_pair(105, 108));//
    opcodemap.insert(std::make_pair(113, 105));//
    opcodemap.insert(std::make_pair(116, 113));//

}

unsigned char *AesNoPaddingDecrypt(unsigned char *out1, unsigned char *key_string) {
    AES_KEY aes;
    unsigned char out2[256];
    memset(out2, 0, 256);
    AES_set_decrypt_key(key_string, 128, &aes);
    AES_decrypt(out1, out2, &aes);
//    LOGE("out2=%s\n", out2);
    return out2;
}

unsigned char *AesNoPaddingEncrypt(unsigned char *temp, unsigned char *key_string) {
    AES_KEY aes;
    unsigned char out1[256];
    memset(out1, 0, 256);
    AES_set_encrypt_key(key_string, 128, &aes);
    AES_encrypt((const unsigned char *) temp, out1, &aes);

//    AesNoPaddingDecrypt(out1, key_string);
    return out1;
}

const char insns[] = {0x12, 0x04, 0x54, 0x53, 0xC2, 0x18, 0x6E, 0x10, 0xED, 0x3E, 0x03, 0x00, 0x0C,
                      0x03, 0x6E, 0x10, 0x34, 0x41, 0x03, 0x00, 0x0C, 0x03, 0x6E, 0x10, 0x54, 0x41,
                      0x03, 0x00, 0x0C, 0x01, 0x22, 0x02, 0x3F, 0x08, 0x70, 0x10, 0x5B, 0x41, 0x02,
                      0x00, 0x6E, 0x20, 0x65, 0x41, 0x12, 0x00, 0x6E, 0x10, 0x6A, 0x41, 0x02, 0x00,
                      0x0C, 0x03, 0x6E, 0x10, 0x6B, 0x41, 0x03, 0x00, 0x0C, 0x03, 0x6E, 0x10, 0x54,
                      0x41, 0x03, 0x00, 0x0C, 0x00, 0x6E, 0x20, 0x97, 0x40, 0x05, 0x00, 0x0A, 0x03,
                      0x38, 0x03, 0x0C, 0x00, 0x1A, 0x03, 0x12, 0x06, 0x71, 0x30, 0x87, 0x40, 0x35,
                      0x04, 0x0C, 0x03, 0x6E, 0x10, 0x89, 0x40, 0x03, 0x00, 0x0E, 0x00, 0x1A, 0x03,
                      0x8D, 0x19, 0x71, 0x30, 0x87, 0x40, 0x35, 0x04, 0x0C, 0x03, 0x6E, 0x10, 0x89,
                      0x40, 0x03, 0x00, 0x28, 0xF6};

void init() {
    char *module = (char *) RC4decrypt(dex);
    char *findMethod = (char *) RC4decrypt(method);
    char *findClass = (char *) RC4decrypt(wClass);
    u1 *pDex = (u1 *) get_module_base(-1, module);
    if (pDex != NULL) {
        //LOGD("Get Module %08x", pDex);
        pDex += sizeof(DexOptHeader);
        DexFile *pDexFile = dexFileParse(pDex, sizeof(DexHeader), kDexParseContinueOnError);
        if (pDexFile == NULL) {
            //  LOGE("Unable to parse DexFile");
            return;
        }
        const DexClassDef *pClassDef;
        for (int i = 0; i < pDexFile->pHeader->classDefsSize; ++i) {
            const DexClassDef *pDef = dexGetClassDef(pDexFile, i);
            if (!strcmp(dexStringByTypeIdx(pDexFile, pDef->classIdx),
                        findClass)) {
                pClassDef = pDef;
                break;
            }
        }
        if (pClassDef != NULL) {
            //LOGD("Class Found!!!-------");
            const u1 *pData = dexGetClassData(pDexFile, pClassDef);
            if (pData) {
                DexClassData *pClassData = dexReadAndVerifyClassData(&pData, NULL);
                for (int i = 0; i < pClassData->header.virtualMethodsSize; ++i) {
                    DexMethod *pMethod = &pClassData->virtualMethods[i];
                    const DexMethodId *pMethodId = dexGetMethodId(pDexFile, pMethod->methodIdx);
                    if (!strcmp(dexStringById(pDexFile, pMethodId->nameIdx), findMethod)) {
                        const DexCode *pCode = dexGetCode(pDexFile, pMethod);
                        struct timeval tv;
                        gettimeofday(&tv, NULL);
                        int resTime = tv.tv_sec;
                        if (mprotect(PAGE_START((int) (pCode->insns)), PAGE_SIZE,
                                     PROT_READ | PROT_WRITE) == 0) {
                            if (flag) {
                                *((u1 *) (pCode->insns) + 48) = (u1) opCodeReverse;
                                *((u1 *) (pCode->insns) + 56) = (u1) opCodeToString;
                            } else {
                                *((u1 *) (pCode->insns) + 48) = (u1) (opCodeReverse - 1);
                                *((u1 *) (pCode->insns) + 56) = (u1) (opCodeToString + 1);
                            }

                            mprotect(PAGE_START((int) (pCode->insns)), PAGE_SIZE, PROT_READ) == 0;
                            gettimeofday(&tv, NULL);
                            int destTime = tv.tv_sec;
                            CalcTime(resTime, destTime);

                        }
                        pCode->insns;
                    }
                }
                free(pClassData);
            }
        }

        dexFileFree(pDexFile);
    }
    return;
}


static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

jboolean check(JNIEnv *env, jobject obj,
               jstring str) {
    const char *flag = env->GetStringUTFChars(str, 0);
    unsigned char name[1024];
    memset(name, 0, 1024);
    getProcessName(name);
    unsigned char *key = MD5Encrypt(name);
    unsigned char aesKey[16] = {0};
    strncpy((char *) aesKey, (const char *) (key + 3), 16);
    aesKey[15] = 0;
    int size = strlen(flag);
    unsigned char content[size];
    memset(content, 0, size);
    for (int i = 0; i < size; i++) {
        int temp = (int) flag[i];
        content[i] = opcodemap.find(temp)->second;

    }
    content[size] = 0;
//    LOGE("before encrypt is %s", content);
    unsigned char *aes_res = AesNoPaddingEncrypt(content, aesKey);
    char *base64_res = Base64Encode(aes_res, strlen((const char *) aes_res));

//    char * base64_des = Base64Decode((const unsigned char *) base64_res, strlen(base64_res));
//    unsigned char * aes_des = AesNoPaddingDecrypt((unsigned char *) base64_des, aesKey);
//    LOGE("the result is sssss  ss %s" ,aes_des);
    unsigned char *result = RC4encrypt((const unsigned char *) base64_res);
//    LOGE("the result is %s", result);
//
//    unsigned char *testtt = RC4decrypt(result);
//    char *ttttttttt = Base64Decode(testtt, strlen((const char *) testtt));
//    unsigned char *aes_des = AesNoPaddingDecrypt((unsigned char *) ttttttttt, aesKey);
//    LOGE("the result is sssss  ss %s", aes_des);

    if (memcmp(final_flag, result,
               strlen((const char *) result)) == 0) {
        return true;
    }

    return false;
}

static const char *gClassName = "com/qtfreet/crackme001/MainActivity";
static JNINativeMethod gMethods[] = {
        {"check", "(Ljava/lang/String;)Z", (void *) check},
};

void *checkAnti() {
    readStatus();
    //  AntiDebug();
}


void anti_debug() {

    // LOGE("Call anti debug...");
    if (pthread_create(&id, NULL, (void *(*)(void *)) &checkAnti, NULL) != 0) {
        // LOGE("Failed to create a debug checking thread!");
        exit(-1);
    };
    pthread_detach(id);

}


void checkNotify() {
    runInotify();
}

void anti_notify() {

    // LOGE("Call anti debug...");
    if (pthread_create(&id_notify, NULL, (void *(*)(void *)) &checkNotify, NULL) != 0) {
        // LOGE("Failed to create a debug checking thread!");
        exit(-1);
    };
    pthread_detach(id_notify);
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint result = -1;
    anti_notify();
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int ran = tv.tv_sec % 2 + 10;
//    const unsigned char *test = (const unsigned char *) "111";
//    int len = strlen((const char *) test);
//    LOGE("the base64 is %s ", Base64Encode(test, len));

    switch (ran) {
        case 10:
            opCodeReverse = (opCodeA ^ ran) + 1;
            opCodeToString = (opCodeC ^ ran) - 1;
            flag = false;
            break;
        case 11:
            flag = true;
            opCodeReverse = opCodeB ^ ran;
            opCodeToString = opCodeD ^ ran;
            break;


    }
    // LOGE("the number is %d , %d ", opCodeReverse, opCodeToString);
    free(&tv);
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    initMap();
    anti_debug();
    init();
    if (registerNativeMethods(env, gClassName, gMethods,
                              sizeof(gMethods) / sizeof(gMethods[0])) == JNI_FALSE) {
        return -1;
    }

    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    return;
}