#ifndef CORE_SHADOWSOCKS_H
#define CORE_SHADOWSOCKS_H
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CORE_SS_AES128_GCM,
    CORE_SS_AES256_GCM,
    CORE_SS_CHACHA20_POLY1305,
    CORE_SS_XCHACHA20_POLY1305,
    CORE_SS_2022_AES128_GCM,
    CORE_SS_2022_AES256_GCM,
    CORE_SS_2022_CHACHA20_POLY1305
} core_ss_method_t;

int core_ss_method(const char *,core_ss_method_t *);
size_t core_ss_key_size(core_ss_method_t);
size_t core_ss_nonce_size(core_ss_method_t);
int core_ss_is_2022(core_ss_method_t);
int core_ss_master(core_ss_method_t,const uint8_t *,size_t,uint8_t [32]);
int core_ss_normalize(core_ss_method_t,const uint8_t *,size_t,uint8_t [32]);
int core_ss_subkey(core_ss_method_t,const uint8_t *,const uint8_t *,uint8_t [32]);
#endif
