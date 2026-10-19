#ifndef CORE_VMESS_INTERNAL_H
#define CORE_VMESS_INTERNAL_H
#include "vmess.h"
#include <openssl/evp.h>

typedef struct { const void *data; size_t length; } core_vmess_slice_t;
typedef struct { uint64_t lanes[25]; size_t offset; } core_vmess_shake_t;
void core_vmess_shake_init(core_vmess_shake_t *,const void *,size_t);
void core_vmess_shake_read(core_vmess_shake_t *,void *,size_t);
int core_vmess_kdf(const uint8_t *,size_t,const core_vmess_slice_t *,size_t,uint8_t [32]);
int core_vmess_cmd_key(const uint8_t [16],uint8_t [16]);
int core_vmess_digest(const EVP_MD *,const core_vmess_slice_t *,size_t,uint8_t *,unsigned);
int core_vmess_aead(EVP_CIPHER_CTX *,const EVP_CIPHER *,int,const uint8_t *,const uint8_t [12],const void *,size_t,const void *,size_t,uint8_t *,size_t *);
int64_t core_vmess_time(void);
#endif
