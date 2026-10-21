#ifndef CORE_SHADOWSOCKS_INTERNAL_H
#define CORE_SHADOWSOCKS_INTERNAL_H
#include "shadowsocks.h"
#include <openssl/evp.h>
void core_ss_hchacha(const uint8_t [32],const uint8_t [16],uint8_t [32]);
int core_ss_crypt(EVP_CIPHER_CTX *,core_ss_method_t,const uint8_t *,const uint8_t *,int,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
#endif
