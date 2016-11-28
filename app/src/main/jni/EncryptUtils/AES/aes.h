//
// Created by qtfreet on 2016/11/24.
//

#ifndef CRACKME001_AES_H
#define CRACKME001_AES_H

# include <stddef.h>
#include "aes_locl.h"

# ifdef  __cplusplus
extern "C" {
# endif

# define AES_MAXNR 14

struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

const char *AES_options(void);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

# ifdef  __cplusplus
}
# endif

#endif
