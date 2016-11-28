//
// Created by qtfreet on 2016/11/24.
//

#include <string.h>
#include "AesUtils.h"
#include "aes.h"


unsigned char *AesEncrypt(unsigned char *buf, unsigned char *aes_keybuf) {
    AES_KEY aes;
    unsigned char out1[256];
    memset(out1, 0, 256);
    AES_set_encrypt_key((unsigned char *) aes_keybuf, 128, &aes);
    AES_encrypt((const unsigned char *) buf, out1, &aes);
    return out1;
}

unsigned char *AesDecrypt(unsigned char *buf, unsigned char *key_string) {
    AES_KEY aes;
    unsigned char out2[256];
    memset(out2, 0, 256);
    AES_set_decrypt_key((unsigned char *) key_string, 128, &aes);
    AES_decrypt(buf, out2, &aes);
    return out2;
}