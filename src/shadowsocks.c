#include "shadowsocks_internal.h"
#include "blake3.h"
#include "core_random.h"
#include "uri.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <string.h>

static size_t maximum(const core_ss_body_t *body) { return core_ss_is_2022(body->method) ? 65535 : 16383; }
static unsigned read16(const uint8_t *data) { return (unsigned)data[0]<<8|data[1]; }
static void write16(uint8_t *data,size_t value) { data[0]=(uint8_t)(value>>8); data[1]=(uint8_t)value; }

static int body_error(core_ss_body_t *body,int cause) {
    body->failed=1; body->plain_length=body->plain_offset=0;
    OPENSSL_cleanse(body->master,sizeof(body->master)); OPENSSL_cleanse(body->key,sizeof(body->key));
    OPENSSL_cleanse(body->nonce,sizeof(body->nonce)); OPENSSL_cleanse(body->header,sizeof(body->header));
    OPENSSL_cleanse(body->request_salt,sizeof(body->request_salt));
    if (body->block.data) OPENSSL_cleanse(body->block.data,body->block.capacity);
    if (body->context) EVP_CIPHER_CTX_reset(body->context);
    errno=cause; return -1;
}

void core_ss_body_clear(core_ss_body_t *body) {
    if (!body) return;
    int cause=errno;
    core_relay_buffer_clear(&body->block); EVP_CIPHER_CTX_free(body->context);
    OPENSSL_cleanse(body,sizeof(*body)); errno=cause;
}

int core_ss_body_init(core_ss_body_t *body,core_ss_method_t method,const uint8_t *master,int writing,const uint8_t *request_salt,core_buffer_budget_t *memory) {
    if (!body) { errno=EINVAL; return -1; }
    memset(body,0,sizeof(*body));
    size_t size=core_ss_key_size(method);
    if (!size || !master || (!writing && core_ss_is_2022(method) && !request_salt)) { errno=EINVAL; return -1; }
    body->method=method; body->writing=!!writing; memcpy(body->master,master,size);
    if (request_salt) { memcpy(body->request_salt,request_salt,size); body->bound=1; }
    body->block=(core_relay_buffer_t){.memory=memory,.minimum=8192,.limit=maximum(body)+16,.cleanse=1};
    body->needed=size; body->context=EVP_CIPHER_CTX_new();
    if (!body->context) { core_ss_body_clear(body); errno=ENOMEM; return -1; }
    body->initialized=1; return 0;
}

static int nonce_available(core_ss_body_t *body,unsigned operations) {
    if (body->exhausted) return body_error(body,EOVERFLOW);
    uint8_t next[24]; size_t size=core_ss_nonce_size(body->method);
    memcpy(next,body->nonce,size);
    for (unsigned operation=1;operation<operations;operation++) {
        size_t i=0;
        while (i<size && ++next[i] == 0) i++;
        if (i == size) { OPENSSL_cleanse(next,sizeof(next)); return body_error(body,EOVERFLOW); }
    }
    OPENSSL_cleanse(next,sizeof(next)); return 0;
}

static int step(core_ss_body_t *body,int writing,const uint8_t *input,size_t length,uint8_t *output,size_t capacity,size_t *written) {
    if (nonce_available(body,1)) return -1;
    if (core_ss_crypt(body->context,body->method,body->key,body->nonce,writing,input,length,output,capacity,written)) return body_error(body,errno);
    size_t i=0,size=core_ss_nonce_size(body->method);
    while (i<size && ++body->nonce[i] == 0) i++;
    if (i == size) body->exhausted=1;
    return 0;
}

static int address(const char *host,uint16_t port,uint8_t output[260],size_t *length) {
    if (!host || !port || !core_server_host_valid(host)) { errno=EINVAL; return -1; }
    size_t size=strlen(host),written;
    if (inet_pton(AF_INET,host,output+1) == 1) { output[0]=1; written=5; }
    else if (inet_pton(AF_INET6,host,output+1) == 1) { output[0]=4; written=17; }
    else {
        if (!size || size > 255) { errno=EINVAL; return -1; }
        output[0]=3; output[1]=(uint8_t)size; memcpy(output+2,host,size); written=size+2;
    }
    write16(output+written,port); *length=written+2; return 0;
}

static int identity(core_ss_body_t *body,const uint8_t *key,const uint8_t *next,uint8_t output[16]) {
    static const uint8_t context[]="shadowsocks 2022 identity subkey";
    uint8_t material[64],subkey[32],hash[32],encrypted[32]; size_t size=core_ss_key_size(body->method);
    memcpy(material,key,size); memcpy(material+size,body->salt,size);
    blake3_derive_key(context,sizeof(context)-1,material,size*2,subkey); blake3_hash(next,size,hash);
    int count=0,final=0;
    int ok=EVP_CIPHER_CTX_reset(body->context) == 1 && EVP_CipherInit_ex(body->context,size == 16 ? EVP_aes_128_ecb() : EVP_aes_256_ecb(),NULL,subkey,NULL,1) == 1 &&
        EVP_CIPHER_CTX_set_padding(body->context,0) == 1 && EVP_CipherUpdate(body->context,encrypted,&count,hash,16) == 1 && count == 16 &&
        EVP_CipherFinal_ex(body->context,encrypted+count,&final) == 1 && !final;
    if (ok) memcpy(output,encrypted,16);
    OPENSSL_cleanse(material,sizeof(material)); OPENSSL_cleanse(subkey,sizeof(subkey)); OPENSSL_cleanse(hash,sizeof(hash)); OPENSSL_cleanse(encrypted,sizeof(encrypted));
    if (!ok) return body_error(body,EIO);
    return 0;
}

int core_ss_request(core_ss_body_t *body,const uint8_t *keys,size_t count,const char *target,uint16_t port,const uint8_t *first,size_t first_length,uint8_t *output,size_t capacity,size_t *written) {
    if (!written) { errno=EINVAL; return -1; }
    *written=0;
    if (!body || !body->initialized || !body->writing || body->failed || body->started || !output || !keys || !count || (!first && first_length)) { errno=EINVAL; return -1; }
    size_t size=core_ss_key_size(body->method),address_length=0,offset=0,encrypted=0;
    uint8_t destination[260],fixed[11],length[2]; uint32_t padding=0;
    if (count > 3072/size || ((!core_ss_is_2022(body->method) || body->method == CORE_SS_2022_CHACHA20_POLY1305) && count != 1) ||
        CRYPTO_memcmp(body->master,keys+(count-1)*size,size) || address(target,port,destination,&address_length)) { errno=EINVAL; goto failure; }
    if (first_length > maximum(body)-address_length-(core_ss_is_2022(body->method) ? 2 : 0) || capacity < size) { errno=EMSGSIZE; goto failure; }
    if (core_random_fill(body->salt,size) || core_ss_subkey(body->method,body->master,body->salt,body->key)) goto failure;
    memcpy(output,body->salt,size); offset=size;
    if (core_ss_is_2022(body->method)) {
        int64_t now=core_ss_time();
        if (now < 0) { errno=EIO; goto failure; }
        if (first_length < 900 && core_random_range(1,900,&padding)) goto failure;
        size_t variable=address_length+2+padding+first_length;
        size_t identities=(count-1)*16;
        if (variable > 65535 || identities > capacity-offset || capacity-offset-identities < 27+variable+16) { errno=EMSGSIZE; goto failure; }
        if (nonce_available(body,2)) goto failure;
        for (size_t i=0;i+1<count;i++) { if (identity(body,keys+i*size,keys+(i+1)*size,output+offset)) goto failure; offset+=16; }
        fixed[0]=0; for (unsigned i=0;i<8;i++) fixed[1+i]=(uint8_t)((uint64_t)now>>(56-i*8)); write16(fixed+9,variable);
        if (step(body,1,fixed,sizeof(fixed),output+offset,capacity-offset,&encrypted)) goto failure;
        offset+=encrypted;
        memcpy(output+offset,destination,address_length); write16(output+offset+address_length,padding);
        if (padding && core_random_fill(output+offset+address_length+2,padding)) goto failure;
        if (first_length) memcpy(output+offset+address_length+2+padding,first,first_length);
        if (step(body,1,output+offset,variable,output+offset,capacity-offset,&encrypted)) goto failure;
        offset+=encrypted;
    } else {
        size_t plain=address_length+first_length;
        if (capacity-offset < plain+34) { errno=ENOBUFS; goto failure; }
        if (nonce_available(body,2)) goto failure;
        write16(length,plain);
        if (step(body,1,length,2,output+offset,capacity-offset,&encrypted)) goto failure;
        offset+=encrypted;
        memcpy(output+offset,destination,address_length); if (first_length) memcpy(output+offset+address_length,first,first_length);
        if (step(body,1,output+offset,plain,output+offset,capacity-offset,&encrypted)) goto failure;
        offset+=encrypted;
    }
    body->started=1; OPENSSL_cleanse(body->master,sizeof(body->master));
    OPENSSL_cleanse(destination,sizeof(destination)); OPENSSL_cleanse(fixed,sizeof(fixed)); *written=offset; return 0;
failure: {
    int cause=errno ? errno : EIO;
    OPENSSL_cleanse(output,capacity); OPENSSL_cleanse(destination,sizeof(destination)); OPENSSL_cleanse(fixed,sizeof(fixed));
    return body_error(body,cause);
}
}

int core_ss_body_encode(core_ss_body_t *body,const uint8_t *input,size_t length,size_t *consumed,uint8_t *output,size_t capacity,size_t *written) {
    if (consumed) *consumed=0;
    if (written) *written=0;
    if (!body || !body->initialized || !body->writing || !body->started || body->failed || !consumed || !written || (!input && length) || !output) { errno=EINVAL; return -1; }
    if (!length) return 0;
    if (capacity <= 34) { errno=ENOBUFS; return -1; }
    size_t take=length; if (take > maximum(body)) take=maximum(body); if (take > capacity-34) take=capacity-34;
    uint8_t header[2]; size_t count=0;
    if (nonce_available(body,2)) return -1;
    write16(header,take);
    if (step(body,1,header,2,output,capacity,&count) || step(body,1,input,take,output+18,capacity-18,&count)) { OPENSSL_cleanse(output,capacity); return -1; }
    *consumed=take; *written=take+34; return 0;
}

int core_ss_body_prepare(core_ss_body_t *body,uint8_t **output,size_t *capacity) {
    if (output) *output=NULL;
    if (capacity) *capacity=0;
    if (!body || !body->initialized || body->writing || body->failed || !output || !capacity) { errno=EINVAL; return -1; }
    if (body->plain_length) return 0;
    if (body->stage != CORE_SS_BLOCK) { *output=body->header+body->used; *capacity=body->needed-body->used; return 0; }
    if (!body->used && body->block.capacity < body->needed) core_relay_buffer_clear(&body->block);
    int result=core_relay_buffer_reserve(&body->block,body->needed);
    if (result != 1) return result ? body_error(body,errno) : 1;
    *output=body->block.data+body->used; *capacity=body->needed-body->used; return 0;
}

int core_ss_body_commit(core_ss_body_t *body,size_t length) {
    if (!body || !body->initialized || body->writing || body->failed || body->plain_length) { errno=EINVAL; return -1; }
    if (length > body->needed-body->used || (body->stage == CORE_SS_BLOCK && (!body->block.data || body->block.capacity < body->needed))) return body_error(body,EINVAL);
    body->used+=length;
    if (body->used < body->needed) return 0;
    size_t size=core_ss_key_size(body->method),written=0;
    if (body->stage == CORE_SS_SALT) {
        memcpy(body->salt,body->header,size);
        if (body->bound && !CRYPTO_memcmp(body->salt,body->request_salt,size)) return body_error(body,EBADMSG);
        if (core_ss_subkey(body->method,body->master,body->salt,body->key)) return body_error(body,errno);
        OPENSSL_cleanse(body->master,sizeof(body->master));
        body->started=1; body->stage=core_ss_is_2022(body->method) ? CORE_SS_FIXED : CORE_SS_LENGTH;
        body->needed=core_ss_is_2022(body->method) ? size+27 : 18;
    } else if (body->stage == CORE_SS_FIXED) {
        if (nonce_available(body,2) || step(body,0,body->header,body->needed,body->header,sizeof(body->header),&written)) return -1;
        int64_t now=core_ss_time(); uint64_t epoch=0;
        if (now < 0) return body_error(body,EIO);
        for (unsigned i=0;i<8;i++) epoch=(epoch<<8)|body->header[1+i];
        if (body->header[0] != 1 || epoch > INT64_MAX ||
            (epoch > (uint64_t)now ? epoch-(uint64_t)now : (uint64_t)now-epoch) > 30 ||
            CRYPTO_memcmp(body->request_salt,body->header+9,size)) return body_error(body,EBADMSG);
        body->needed=read16(body->header+9+size)+16; body->stage=CORE_SS_BLOCK; body->response_ready=1;
        OPENSSL_cleanse(body->request_salt,sizeof(body->request_salt));
    } else if (body->stage == CORE_SS_LENGTH) {
        if (nonce_available(body,2) || step(body,0,body->header,18,body->header,sizeof(body->header),&written)) return -1;
        size_t plain=read16(body->header);
        if (plain > maximum(body)) return body_error(body,EMSGSIZE);
        body->needed=plain+16; body->stage=CORE_SS_BLOCK;
    } else if (body->stage == CORE_SS_BLOCK) {
        if (step(body,0,body->block.data,body->needed,body->block.data,body->block.capacity,&written)) return -1;
        body->plain_offset=0; body->plain_length=written;
        if (written) return 0;
        body->stage=CORE_SS_LENGTH; body->needed=18;
    } else return body_error(body,EINVAL);
    body->used=0; OPENSSL_cleanse(body->header,sizeof(body->header)); return 0;
}

int core_ss_body_read(core_ss_body_t *body,uint8_t *output,size_t capacity,size_t *written) {
    if (written) *written=0;
    if (!body || !body->initialized || body->writing || body->failed || !written || (!output && capacity)) { errno=EINVAL; return -1; }
    size_t take=body->plain_length; if (take>capacity) take=capacity;
    if (take) {
        memcpy(output,body->block.data+body->plain_offset,take); OPENSSL_cleanse(body->block.data+body->plain_offset,take);
        body->plain_offset+=take; body->plain_length-=take; *written=take;
        if (!body->plain_length) {
            body->plain_offset=body->used=0; body->stage=CORE_SS_LENGTH; body->needed=18;
            if (body->block.capacity > 8192) core_relay_buffer_clear(&body->block);
        }
    }
    return 0;
}

int core_ss_body_eof(const core_ss_body_t *body) {
    if (!body || !body->initialized || body->failed || body->writing ||
        (core_ss_is_2022(body->method) && !body->response_ready) ||
        !((body->stage == CORE_SS_LENGTH && !body->used) ||
          (body->stage == CORE_SS_SALT && !body->used) || (body->stage == CORE_SS_BLOCK && body->plain_length && body->used == body->needed))) { errno=EBADMSG; return -1; }
    return 0;
}
