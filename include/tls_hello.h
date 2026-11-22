#ifndef CORE_TLS_HELLO_H
#define CORE_TLS_HELLO_H
#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
enum { CORE_TLS_EXT_ECH=0xfe0d, CORE_TLS_ECH_DECODE_ERROR=-2 };
static inline int core_tls_ech_outer(const uint8_t *value,size_t length) {
    return value && length && value[0] == 0;
}
typedef struct {
    int retry;
    uint16_t cipher,group;
    const uint8_t *share,*cookie;
    size_t share_length,cookie_length;
} core_tls_hello_t;
int core_tls_hello_parse(const uint8_t *,size_t,const uint8_t *,size_t,core_tls_hello_t *);
int core_tls_hello_retry(const uint8_t *,size_t,const core_tls_hello_t *,uint8_t **,size_t *,EVP_PKEY **);
int core_tls_ecdh(EVP_PKEY *,uint16_t,const uint8_t *,size_t,uint8_t *,size_t *);
const uint8_t *core_tls_hello_extension(const uint8_t *,size_t,unsigned,size_t *);
int core_tls_ech_retry_configs(const uint8_t *,size_t);
#endif
