#include "vmess_internal.h"
#include "core_random.h"
#include "uri.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <string.h>

static uint32_t fnv(const uint8_t *data,size_t length) {
    uint32_t hash=UINT32_C(2166136261);
    for (size_t i=0;i<length;i++) hash=(hash^data[i])*UINT32_C(16777619);
    return hash;
}
static void put32(uint8_t *output,uint32_t value) {
    for (unsigned i=0;i<4;i++) output[i]=(uint8_t)(value>>(24-8*i));
}
static uint32_t crc32(const uint8_t *data,size_t length) {
    uint32_t value=UINT32_MAX;
    for (size_t i=0;i<length;i++) {
        value^=data[i];
        for (unsigned bit=0;bit<8;bit++) value=(value>>1)^(UINT32_C(0xedb88320)&(0U-(value&1)));
    }
    return ~value;
}

static int derive(const uint8_t *input,size_t length,const char *label,const uint8_t *auth,const uint8_t *nonce,uint8_t output[32]) {
    core_vmess_slice_t paths[]={{label,strlen(label)},{auth,16},{nonce,8}};
    return core_vmess_kdf(input,length,paths,auth ? 3 : 1,output);
}

void core_vmess_header_clear(core_vmess_header_t *header) { if (header) OPENSSL_cleanse(header,sizeof(*header)); }

int core_vmess_request(core_vmess_header_t *header,const uint8_t uuid[16],const char *host,uint16_t port,core_vmess_security_t security,uint8_t *output,size_t capacity,size_t *length) {
    if (length) *length=0;
    if (!header) { errno=EINVAL; return -1; }
    core_vmess_header_clear(header);
    if (!length || !uuid || !host || !*host || !port || !output || !core_server_host_valid(host)) { errno=EINVAL; return -1; }
    if (security == CORE_VMESS_AUTO) security=core_vmess_auto_security();
    if (security != CORE_VMESS_AES128_GCM && security != CORE_VMESS_CHACHA20_POLY1305 && security != CORE_VMESS_NONE && security != CORE_VMESS_ZERO) { errno=EINVAL; return -1; }
    struct {
        uint8_t plain[CORE_VMESS_HEADER_MAX],wire[CORE_VMESS_HEADER_MAX],random[33],cmd[16],auth[16],nonce[8],key[32],iv[32],digest[32];
    } state={0};
    uint8_t address[16]; size_t address_length=strlen(host); unsigned type=2;
    if (inet_pton(AF_INET,host,address) == 1) { type=1; address_length=4; }
    else if (inet_pton(AF_INET6,host,address) == 1) { type=3; address_length=16; }
    else if (address_length > 255) { errno=EINVAL; return -1; }
    size_t offset=38+3+address_length+(type == 2); uint32_t padding=0;
    EVP_CIPHER_CTX *context=NULL; int result=-1;
    if (core_random_range(0,15,&padding)) goto cleanup;
    size_t needed=42+offset+padding+4+16;
    if (needed > capacity || needed > sizeof(state.wire)) { errno=ENOBUFS; goto cleanup; }
    int64_t timestamp=core_vmess_time();
    if (timestamp < 0) { errno=EINVAL; goto cleanup; }
    if (core_random_fill(state.random,sizeof(state.random)) || core_random_fill(state.auth+8,4) || core_random_fill(state.nonce,sizeof(state.nonce)) ||
        core_vmess_cmd_key(uuid,state.cmd)) goto cleanup;
    memcpy(header->request_key,state.random,16); memcpy(header->request_iv,state.random+16,16); header->authentication=state.random[32];
    core_vmess_slice_t part={header->request_key,16};
    if (core_vmess_digest(EVP_sha256(),&part,1,state.digest,32)) goto cleanup;
    memcpy(header->response_key,state.digest,16); part.data=header->request_iv;
    if (core_vmess_digest(EVP_sha256(),&part,1,state.digest,32)) goto cleanup;
    memcpy(header->response_iv,state.digest,16);
    state.plain[0]=1; memcpy(state.plain+1,header->request_iv,16); memcpy(state.plain+17,header->request_key,16);
    state.plain[33]=header->authentication;
    state.plain[34]=security == CORE_VMESS_ZERO ? 0 : security == CORE_VMESS_NONE ? 5 : 13;
    state.plain[35]=(uint8_t)((padding<<4)|(security == CORE_VMESS_ZERO ? CORE_VMESS_NONE : security));
    state.plain[37]=1; state.plain[38]=(uint8_t)(port>>8); state.plain[39]=(uint8_t)port; state.plain[40]=(uint8_t)type;
    size_t at=41;
    if (type == 2) state.plain[at++]=(uint8_t)address_length;
    memcpy(state.plain+at,type == 2 ? (const void *)host : (const void *)address,address_length); at+=address_length;
    if (core_random_fill(state.plain+at,padding)) goto cleanup;
    at+=padding; put32(state.plain+at,fnv(state.plain,at)); at+=4;
    for (unsigned i=0;i<8;i++) state.auth[i]=(uint8_t)((uint64_t)timestamp>>(56-8*i));
    put32(state.auth+12,crc32(state.auth,12));
    if (derive(state.cmd,16,"AES Auth ID Encryption",NULL,NULL,state.key)) goto cleanup;
    context=EVP_CIPHER_CTX_new(); int count=0,last=0;
    if (!context || EVP_EncryptInit_ex(context,EVP_aes_128_ecb(),NULL,state.key,NULL) != 1 || EVP_CIPHER_CTX_set_padding(context,0) != 1 ||
        EVP_EncryptUpdate(context,state.wire,&count,state.auth,16) != 1 || EVP_EncryptFinal_ex(context,state.wire+count,&last) != 1 || count+last != 16) { errno=EIO; goto cleanup; }
    size_t written=0; uint8_t size[2]={(uint8_t)(at>>8),(uint8_t)at};
    if (derive(state.cmd,16,"VMess Header AEAD Key_Length",state.wire,state.nonce,state.key) ||
        derive(state.cmd,16,"VMess Header AEAD Nonce_Length",state.wire,state.nonce,state.iv) ||
        core_vmess_aead(context,EVP_aes_128_gcm(),1,state.key,state.iv,state.wire,16,size,2,state.wire+16,&written)) goto cleanup;
    memcpy(state.wire+34,state.nonce,8);
    if (derive(state.cmd,16,"VMess Header AEAD Key",state.wire,state.nonce,state.key) ||
        derive(state.cmd,16,"VMess Header AEAD Nonce",state.wire,state.nonce,state.iv) ||
        core_vmess_aead(context,EVP_aes_128_gcm(),1,state.key,state.iv,state.wire,16,state.plain,at,state.wire+42,&written)) goto cleanup;
    memcpy(output,state.wire,42+written); *length=42+written;
    header->security=security; header->ready=1; header->response_needed=18; result=0;
cleanup: {
    int cause=errno; EVP_CIPHER_CTX_free(context); OPENSSL_cleanse(&state,sizeof(state));
    if (result) core_vmess_header_clear(header);
    errno=cause; return result;
}
}

int core_vmess_response(core_vmess_header_t *header,const uint8_t *input,size_t length,size_t *consumed) {
    if (consumed) *consumed=0;
    if (!header || !consumed || (!input && length) || !header->ready || header->failed) { errno=EINVAL; return -1; }
    if (header->response_ready) return 1;
    while (length) {
        size_t take=header->response_needed-header->response_used;
        if (take > length) take=length;
        memcpy(header->response+header->response_used,input,take); header->response_used+=take;
        input+=take; length-=take; *consumed+=take;
        if (header->response_used != header->response_needed) return 0;
        uint8_t key[32],iv[32],plain[259]; size_t written=0;
        int sizing=header->response_needed == 18;
        EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new();
        int bad=derive(header->response_key,16,sizing ? "AEAD Resp Header Len Key" : "AEAD Resp Header Key",NULL,NULL,key) ||
            derive(header->response_iv,16,sizing ? "AEAD Resp Header Len IV" : "AEAD Resp Header IV",NULL,NULL,iv) || !context ||
            core_vmess_aead(context,EVP_aes_128_gcm(),0,key,iv,NULL,0,header->response+(sizing ? 0 : 18),sizing ? 18 : header->response_needed-18,plain,&written);
        if (!bad && sizing) {
            unsigned size=((unsigned)plain[0]<<8)|plain[1];
            if (written != 2 || size < 4 || size > sizeof(plain)) bad=1;
            else header->response_needed=18+size+16;
        } else if (!bad) {
            bad=written < 4 || plain[0] != header->authentication || written != 4U+plain[3] || (!plain[2] && plain[3]);
            if (!bad && plain[2]) {
                uint32_t actual=plain[3] >= 4 ? ((uint32_t)plain[4]<<24)|((uint32_t)plain[5]<<16)|((uint32_t)plain[6]<<8)|plain[7] : 0;
                bad=plain[3] < 4 || actual != fnv(plain+8,plain[3]-4);
            }
            if (!bad) header->response_ready=1;
        }
        EVP_CIPHER_CTX_free(context); OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(iv,sizeof(iv)); OPENSSL_cleanse(plain,sizeof(plain));
        if (bad) { header->failed=1; OPENSSL_cleanse(header->response,sizeof(header->response)); errno=EBADMSG; return -1; }
        if (header->response_ready) { OPENSSL_cleanse(header->response,sizeof(header->response)); return 1; }
    }
    return 0;
}
