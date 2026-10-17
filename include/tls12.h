#ifndef CORE_TLS12_H
#define CORE_TLS12_H
#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
typedef enum { CORE_TLS12_RSA,CORE_TLS12_DHE,CORE_TLS12_ECDHE } core_tls12_exchange_t;
typedef enum { CORE_TLS12_GCM,CORE_TLS12_CHACHA,CORE_TLS12_CBC } core_tls12_cipher_t;
typedef struct {
    uint16_t id;
    core_tls12_exchange_t exchange;
    core_tls12_cipher_t cipher;
    unsigned key_length,mac_hash,prf_hash,ecdsa;
    const char *name;
} core_tls12_suite_t;
const core_tls12_suite_t *core_tls12_suite(unsigned);
const core_tls12_suite_t *core_tls12_suite_at(size_t);
const EVP_MD *core_tls12_digest(unsigned);
size_t core_tls12_record_bound(const core_tls12_suite_t *,int,size_t);
int core_tls12_record_seal_into(const core_tls12_suite_t *,int,EVP_CIPHER_CTX *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t *,unsigned,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int core_tls12_record_open_into(const core_tls12_suite_t *,int,EVP_CIPHER_CTX *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t *,unsigned,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int core_tls12_prf(const EVP_MD *,const uint8_t *,size_t,const char *,const uint8_t *,size_t,uint8_t *,size_t);
int core_tls12_record_seal(const core_tls12_suite_t *,int,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t *,
                          unsigned,const uint8_t *,size_t,uint8_t **,size_t *);
int core_tls12_record_open(const core_tls12_suite_t *,int,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t *,
                          unsigned,const uint8_t *,size_t,uint8_t **,size_t *);
#endif
