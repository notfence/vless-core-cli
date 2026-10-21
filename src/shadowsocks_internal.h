#ifndef CORE_SHADOWSOCKS_INTERNAL_H
#define CORE_SHADOWSOCKS_INTERNAL_H
#include "shadowsocks.h"
#include "relay_memory.h"
#include <openssl/evp.h>
enum { CORE_SS_SALT,CORE_SS_FIXED,CORE_SS_LENGTH,CORE_SS_BLOCK };
typedef struct {
    core_ss_method_t method;
    int writing,initialized,failed,started,response_ready,exhausted,bound;
    unsigned stage;
    uint8_t master[32],key[32],salt[32],request_salt[32],nonce[24],header[64];
    EVP_CIPHER_CTX *context;
    core_relay_buffer_t block;
    size_t used,needed,plain_offset,plain_length;
} core_ss_body_t;
void core_ss_hchacha(const uint8_t [32],const uint8_t [16],uint8_t [32]);
int core_ss_crypt(EVP_CIPHER_CTX *,core_ss_method_t,const uint8_t *,const uint8_t *,int,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int64_t core_ss_time(void);
int core_ss_body_init(core_ss_body_t *,core_ss_method_t,const uint8_t *,int,const uint8_t *,core_buffer_budget_t *);
void core_ss_body_clear(core_ss_body_t *);
int core_ss_request(core_ss_body_t *,const uint8_t *,size_t,const char *,uint16_t,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int core_ss_body_encode(core_ss_body_t *,const uint8_t *,size_t,size_t *,uint8_t *,size_t,size_t *);
int core_ss_body_prepare(core_ss_body_t *,uint8_t **,size_t *);
int core_ss_body_commit(core_ss_body_t *,size_t);
int core_ss_body_read(core_ss_body_t *,uint8_t *,size_t,size_t *);
int core_ss_body_eof(const core_ss_body_t *);
#endif
