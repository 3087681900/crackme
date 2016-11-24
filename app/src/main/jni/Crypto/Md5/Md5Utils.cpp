//
// Created by qtfreet on 2016/11/24.
//

#include <string.h>
#include <stdio.h>
#include "Md5Utils.h"
#include "md5.h"

unsigned char *MD5Encrypt(unsigned char *cstr) {
    MD5_CTX context = {0};
    MD5Init(&context);
    MD5Update(&context,  cstr, strlen((const char *) cstr));
    unsigned char dest[16] = {0};
    MD5Final(dest, &context);
    int i;
    char destination[32] = {0};
    for (i = 0; i < 16; i++) {
        sprintf(destination, "%s%02x", destination, dest[i]);
    }
    return (unsigned char *) destination;
}