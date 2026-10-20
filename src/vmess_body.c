#include "vmess_internal.h"
#include "core_random.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <string.h>

static int body_error(core_vmess_body_t *body,int cause) {
    body->failed=1;
    if (body->block.data) OPENSSL_cleanse(body->block.data,body->block.capacity);
    body->plain_length=body->plain_offset=0; errno=cause; return -1;
}

void core_vmess_body_clear(core_vmess_body_t *body) {
    if (!body) return;
    int cause=errno;
    if (body->block.data) OPENSSL_cleanse(body->block.data,body->block.capacity);
    core_relay_buffer_clear(&body->block); EVP_CIPHER_CTX_free(body->context);
    OPENSSL_cleanse(body,sizeof(*body)); errno=cause;
}

int core_vmess_body_init(core_vmess_body_t *body,const core_vmess_header_t *header,int writing,core_buffer_budget_t *memory) {
    if (!body || !header || !header->ready) { errno=EINVAL; return -1; }
    memset(body,0,sizeof(*body)); body->security=header->security; body->writing=writing != 0;
    if (body->security != CORE_VMESS_AES128_GCM && body->security != CORE_VMESS_CHACHA20_POLY1305 &&
        body->security != CORE_VMESS_NONE && body->security != CORE_VMESS_ZERO) return body_error(body,EINVAL);
    const uint8_t *key=writing ? header->request_key : header->response_key;
    memcpy(body->iv,writing ? header->request_iv : header->response_iv,16);
    memcpy(body->key,key,16);
    if (body->security == CORE_VMESS_CHACHA20_POLY1305) {
        core_vmess_slice_t part={key,16};
        if (core_vmess_digest(EVP_md5(),&part,1,body->key,16)) { core_vmess_body_clear(body); return -1; }
        part.data=body->key;
        if (core_vmess_digest(EVP_md5(),&part,1,body->key+16,16)) { core_vmess_body_clear(body); return -1; }
    }
    core_vmess_shake_init(&body->mask,body->iv,16);
    body->block=(core_relay_buffer_t){.memory=memory,.minimum=8192,.limit=16384};
    return 0;
}

static const EVP_CIPHER *body_cipher(const core_vmess_body_t *body) {
    return body->security == CORE_VMESS_AES128_GCM ? EVP_aes_128_gcm() : EVP_chacha20_poly1305();
}
static int encrypted(const core_vmess_body_t *body) { return body->security == CORE_VMESS_AES128_GCM || body->security == CORE_VMESS_CHACHA20_POLY1305; }
static unsigned mask_next(core_vmess_shake_t *mask) {
    uint8_t value[2]; core_vmess_shake_read(mask,value,sizeof(value)); return ((unsigned)value[0]<<8)|value[1];
}
static void body_nonce(const core_vmess_body_t *body,uint8_t nonce[12]) {
    memcpy(nonce,body->iv,12); nonce[0]=(uint8_t)(body->counter>>8); nonce[1]=(uint8_t)body->counter;
}
static int body_context(core_vmess_body_t *body) {
    if (!body->context) body->context=EVP_CIPHER_CTX_new();
    return body->context ? 0 : body_error(body,ENOMEM);
}

int core_vmess_body_encode(core_vmess_body_t *body,const uint8_t *input,size_t length,size_t *consumed,uint8_t *output,size_t capacity,size_t *written,int final) {
    if (consumed) *consumed=0;
    if (written) *written=0;
    if (!body || !consumed || !written || !body->writing || body->failed || body->finished || (!input && length) || (!output && capacity) || (final && length)) { errno=EINVAL; return -1; }
    if (!length && !final) return 0;
    if (body->security == CORE_VMESS_ZERO) {
        size_t take=length < capacity ? length : capacity;
        if (length && !take) { errno=ENOBUFS; return -1; }
        if (take) memcpy(output,input,take);
        *consumed=*written=take; body->finished=final != 0; return 0;
    }
    int crypto=encrypted(body);
    if (crypto && (body->counter > 65535U || (!final && body->counter == 65535U))) return body_error(body,EOVERFLOW);
    core_vmess_shake_t mask=body->mask;
    unsigned padding=crypto ? mask_next(&mask)%64 : 0;
    unsigned masked=mask_next(&mask);
    size_t take=length,limit=crypto ? 8110 : 8190;
    if (take > limit) take=limit;
    size_t need=2+take+(crypto ? 16 : 0)+padding;
    if (need > capacity || !output) { OPENSSL_cleanse(&mask,sizeof(mask)); errno=ENOBUFS; return -1; }
    int result=0;
    if (padding && core_random_fill(output+need-padding,padding)) { result=body_error(body,errno); goto cleanup; }
    size_t payload=take;
    if (crypto) {
        uint8_t nonce[12]; body_nonce(body,nonce);
        if (body_context(body) || core_vmess_aead(body->context,body_cipher(body),1,body->key,nonce,NULL,0,input,take,output+2,&payload)) result=body_error(body,errno);
        OPENSSL_cleanse(nonce,sizeof(nonce));
        if (result) goto cleanup;
        body->counter++;
    } else if (take) memcpy(output+2,input,take);
    unsigned size=(unsigned)(payload+padding)^masked;
    output[0]=(uint8_t)(size>>8); output[1]=(uint8_t)size;
    body->mask=mask; *consumed=take; *written=need; body->finished=final != 0;
cleanup:
    OPENSSL_cleanse(&mask,sizeof(mask));
    if (result) OPENSSL_cleanse(output,need);
    return result;
}

int core_vmess_body_prepare(core_vmess_body_t *body,uint8_t **output,size_t *capacity) {
    if (!body || !output || !capacity || body->writing || body->failed) { errno=EINVAL; return -1; }
    *output=NULL; *capacity=0;
    if (body->plain_length || body->finished) return 0;
    if (body->security != CORE_VMESS_ZERO && body->header_used < 2) {
        *output=body->length_bytes+body->header_used; *capacity=2-body->header_used; return 0;
    }
    size_t needed=body->security == CORE_VMESS_ZERO ? 8192 : body->block_size;
    if (!body->block_used && needed > body->block.capacity) core_relay_buffer_clear(&body->block);
    int result=core_relay_buffer_reserve(&body->block,needed);
    if (result != 1) return result < 0 ? body_error(body,errno) : -1;
    *output=body->block.data+body->block_used; *capacity=needed-body->block_used; return 0;
}

int core_vmess_body_commit(core_vmess_body_t *body,size_t length) {
    if (!body || body->writing || body->failed || body->finished || body->plain_length) { errno=EINVAL; return -1; }
    if (body->security == CORE_VMESS_ZERO) {
        if (!length || length > body->block.capacity || length > 8192) return body_error(body,EINVAL);
        body->plain_length=length; return 0;
    }
    if (body->header_used < 2) {
        if (length > 2-body->header_used) return body_error(body,EINVAL);
        body->header_used+=length;
        if (body->header_used < 2) return 0;
        body->padding=encrypted(body) ? mask_next(&body->mask)%64 : 0;
        body->block_size=(((unsigned)body->length_bytes[0]<<8)|body->length_bytes[1])^mask_next(&body->mask);
        size_t minimum=body->padding+(encrypted(body) ? 16 : 0);
        if (body->block_size < minimum || body->block_size > 16384) return body_error(body,EMSGSIZE);
        if (encrypted(body) && body->counter > 65535U) return body_error(body,EOVERFLOW);
        if (!body->block_size) body->finished=1;
        return 0;
    }
    if (length > body->block_size-body->block_used || !body->block.data || body->block.capacity < body->block_size) return body_error(body,EINVAL);
    body->block_used+=length;
    if (body->block_used != body->block_size) return 0;
    size_t payload=body->block_size-body->padding;
    if (encrypted(body)) {
        uint8_t nonce[12]; body_nonce(body,nonce);
        int result=body_context(body) || core_vmess_aead(body->context,body_cipher(body),0,body->key,nonce,NULL,0,body->block.data,payload,body->block.data,&payload);
        OPENSSL_cleanse(nonce,sizeof(nonce));
        if (result) return body_error(body,errno);
        body->counter++;
    }
    body->plain_length=payload; body->finished=payload == 0;
    OPENSSL_cleanse(body->block.data+payload,body->block.capacity-payload);
    return 0;
}

int core_vmess_body_read(core_vmess_body_t *body,uint8_t *output,size_t capacity,size_t *written) {
    if (written) *written=0;
    if (!body || !written || body->writing || body->failed || (!output && capacity)) { errno=EINVAL; return -1; }
    size_t take=body->plain_length;
    if (take > capacity) take=capacity;
    if (take) {
        memcpy(output,body->block.data+body->plain_offset,take);
        OPENSSL_cleanse(body->block.data+body->plain_offset,take);
        body->plain_offset+=take; body->plain_length-=take; *written=take;
        if (!body->plain_length) {
            body->plain_offset=body->block_used=body->block_size=body->header_used=0;
            if (body->block.capacity > 8192) core_relay_buffer_clear(&body->block);
        }
    }
    return 0;
}

int core_vmess_body_eof(const core_vmess_body_t *body) {
    if (!body || body->failed || (body->security != CORE_VMESS_ZERO && !body->finished &&
        (body->header_used == 1 || (body->header_used == 2 && body->block_used < body->block_size)))) { errno=EBADMSG; return -1; }
    return 0;
}
