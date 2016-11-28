//
// Created by qtfreet on 2016/11/24.
//

#include <string.h>
#include "RC4Utils.h"
#include "rc4.h"
#include "../Base64/Base64.h"

const unsigned char *key = (unsigned char *) "19931012";

unsigned char *RC4decrypt(const unsigned char *dest) {
    RC4_KEY rc4_key;
    char *test = Base64Decode(dest, strlen((const char *) dest));
    int testLen = strlen(test);
    unsigned char *code;
    code = (unsigned char *) malloc(sizeof(unsigned char) * (testLen + 1));
    memset(code, 0, testLen + 1);
    RC4_set_key(&rc4_key, strlen((const char *) key), key);//这里必须再次设置密钥
    RC4(&rc4_key, testLen, (const unsigned char *) test, code);
    return code;
}

unsigned char *RC4encrypt(const unsigned char *res) {
    unsigned char *outbuffer;
    int resLen = strlen((const char *) res);
    outbuffer = (unsigned char *) malloc(sizeof(unsigned char) * (resLen + 1));
    memset(outbuffer, 0, resLen + 1);
    //用指定密钥对一段内存进行加密，结果放在outbuffer中
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, strlen((const char *) key), key);
    RC4(&rc4_key, resLen, (const unsigned char *) res, outbuffer);
    unsigned char *dest = (unsigned char *) Base64Encode(outbuffer,
                                                         strlen((const char *) outbuffer));
    return dest;
}