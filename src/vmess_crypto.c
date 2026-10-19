#define OPENSSL_SUPPRESS_DEPRECATED
#include "vmess_internal.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <string.h>
#include <time.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

static uint64_t rotate(uint64_t value,unsigned count) { return count ? (value<<count)|(value>>(64-count)) : value; }

static void permute(uint64_t state[25]) {
    static const uint64_t constants[24]={
        UINT64_C(0x0000000000000001),UINT64_C(0x0000000000008082),UINT64_C(0x800000000000808a),UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b),UINT64_C(0x0000000080000001),UINT64_C(0x8000000080008081),UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a),UINT64_C(0x0000000000000088),UINT64_C(0x0000000080008009),UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b),UINT64_C(0x800000000000008b),UINT64_C(0x8000000000008089),UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002),UINT64_C(0x8000000000000080),UINT64_C(0x000000000000800a),UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081),UINT64_C(0x8000000000008080),UINT64_C(0x0000000080000001),UINT64_C(0x8000000080008008)};
    static const unsigned offsets[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
    uint64_t columns[5],mixed[25];
    for (unsigned round=0;round<24;round++) {
        for (unsigned x=0;x<5;x++) columns[x]=state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20];
        for (unsigned x=0;x<5;x++) {
            uint64_t delta=columns[(x+4)%5]^rotate(columns[(x+1)%5],1);
            for (unsigned y=0;y<5;y++) state[x+5*y]^=delta;
        }
        for (unsigned x=0;x<5;x++) for (unsigned y=0;y<5;y++) mixed[y+5*((2*x+3*y)%5)]=rotate(state[x+5*y],offsets[x+5*y]);
        for (unsigned x=0;x<5;x++) for (unsigned y=0;y<5;y++) state[x+5*y]=mixed[x+5*y]^((~mixed[(x+1)%5+5*y])&mixed[(x+2)%5+5*y]);
        state[0]^=constants[round];
    }
    OPENSSL_cleanse(columns,sizeof(columns)); OPENSSL_cleanse(mixed,sizeof(mixed));
}

void core_vmess_shake_init(core_vmess_shake_t *state,const void *input,size_t length) {
    const uint8_t *data=input;
    memset(state,0,sizeof(*state));
    for (size_t i=0;i<length;i++) {
        state->lanes[state->offset/8]^=(uint64_t)data[i]<<(8*(state->offset%8));
        if (++state->offset == 168) { permute(state->lanes); state->offset=0; }
    }
    state->lanes[state->offset/8]^=UINT64_C(0x1f)<<(8*(state->offset%8));
    state->lanes[20]^=UINT64_C(0x8000000000000000);
    permute(state->lanes); state->offset=0;
}

void core_vmess_shake_read(core_vmess_shake_t *state,void *output,size_t length) {
    uint8_t *data=output;
    for (size_t i=0;i<length;i++) {
        if (state->offset == 168) { permute(state->lanes); state->offset=0; }
        data[i]=(uint8_t)(state->lanes[state->offset/8]>>(8*(state->offset%8))); state->offset++;
    }
}

int core_vmess_digest(const EVP_MD *digest,const core_vmess_slice_t *parts,size_t count,uint8_t *output,unsigned expected) {
    EVP_MD_CTX *context=EVP_MD_CTX_new(); unsigned length=0;
    int ok=context && EVP_DigestInit_ex(context,digest,NULL) == 1;
    for (size_t i=0;ok && i<count;i++) ok=EVP_DigestUpdate(context,parts[i].data,parts[i].length) == 1;
    if (ok) ok=EVP_DigestFinal_ex(context,output,&length) == 1 && length == expected;
    EVP_MD_CTX_free(context);
    if (!ok) { OPENSSL_cleanse(output,expected); errno=EIO; return -1; }
    return 0;
}

static int nested_hash(const core_vmess_slice_t *keys,size_t depth,const core_vmess_slice_t *parts,size_t count,uint8_t output[32]) {
    if (!depth) return core_vmess_digest(EVP_sha256(),parts,count,output,32);
    if (depth == 1) {
        unsigned length=0; HMAC_CTX *context=HMAC_CTX_new();
        int ok=keys[0].length <= INT_MAX && context && HMAC_Init_ex(context,keys[0].data,(int)keys[0].length,EVP_sha256(),NULL) == 1;
        for (size_t i=0;ok && i<count;i++) ok=HMAC_Update(context,parts[i].data,parts[i].length) == 1;
        if (ok) ok=HMAC_Final(context,output,&length) == 1 && length == 32;
        HMAC_CTX_free(context);
        if (!ok) { OPENSSL_cleanse(output,32); errno=EIO; return -1; }
        return 0;
    }
    uint8_t inner[32],key[64]={0},pad[64]; core_vmess_slice_t nested[10];
    int result=-1;
    if (count >= sizeof(nested)/sizeof(*nested)) { errno=EINVAL; goto cleanup; }
    if (keys[depth-1].length > sizeof(key)) {
        if (nested_hash(keys,depth-1,&keys[depth-1],1,key)) goto cleanup;
    } else if (keys[depth-1].length) memcpy(key,keys[depth-1].data,keys[depth-1].length);
    for (size_t i=0;i<sizeof(pad);i++) pad[i]=key[i]^0x36;
    nested[0]=(core_vmess_slice_t){pad,sizeof(pad)};
    memcpy(nested+1,parts,count*sizeof(*parts));
    if (nested_hash(keys,depth-1,nested,count+1,inner)) goto cleanup;
    for (size_t i=0;i<sizeof(pad);i++) pad[i]=key[i]^0x5c;
    nested[1]=(core_vmess_slice_t){inner,sizeof(inner)};
    result=nested_hash(keys,depth-1,nested,2,output);
cleanup:
    OPENSSL_cleanse(inner,sizeof(inner)); OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(pad,sizeof(pad));
    if (result) OPENSSL_cleanse(output,32);
    return result;
}

int core_vmess_kdf(const uint8_t *input,size_t length,const core_vmess_slice_t *paths,size_t count,uint8_t output[32]) {
    static const char salt[]="VMess AEAD KDF";
    core_vmess_slice_t keys[5]={{salt,sizeof(salt)-1}},part={input,length};
    if (!output || (!input && length) || count > 4 || (!paths && count)) { errno=EINVAL; return -1; }
    for (size_t i=0;i<count;i++) {
        if (!paths[i].data && paths[i].length) { errno=EINVAL; OPENSSL_cleanse(output,32); return -1; }
        keys[i+1]=paths[i];
    }
    return nested_hash(keys,count+1,&part,1,output);
}

int core_vmess_cmd_key(const uint8_t uuid[16],uint8_t key[16]) {
    static const char salt[]="c48619fe-8f02-49e0-b9e9-edf763e17e21";
    if (!uuid || !key) { errno=EINVAL; return -1; }
    core_vmess_slice_t parts[]={{uuid,16},{salt,sizeof(salt)-1}};
    return core_vmess_digest(EVP_md5(),parts,2,key,16);
}

int core_vmess_aead(EVP_CIPHER_CTX *context,const EVP_CIPHER *cipher,int writing,const uint8_t *key,const uint8_t nonce[12],const void *aad,size_t aad_length,const void *input,size_t length,uint8_t *output,size_t *written) {
    if (!written) { errno=EINVAL; return -1; }
    *written=0;
    if (!context || !cipher || !key || !nonce || (!input && length) || !output || aad_length > INT_MAX || length > INT_MAX || (!writing && length < 16)) { errno=EINVAL; return -1; }
    size_t data_length=writing ? length : length-16; int count=0,final=0;
    int ok=EVP_CIPHER_CTX_reset(context) == 1 && EVP_CipherInit_ex(context,cipher,NULL,NULL,NULL,writing) == 1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) == 1 && EVP_CipherInit_ex(context,NULL,NULL,key,nonce,writing) == 1;
    if (ok && aad_length) ok=EVP_CipherUpdate(context,NULL,&count,aad,(int)aad_length) == 1;
    if (ok && !writing) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_TAG,16,(uint8_t *)input+data_length) == 1;
    if (ok) ok=EVP_CipherUpdate(context,output,&count,input,(int)data_length) == 1;
    if (ok) ok=EVP_CipherFinal_ex(context,output+count,&final) == 1 && (size_t)(count+final) == data_length;
    if (ok && writing) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_GET_TAG,16,output+data_length) == 1;
    if (!ok) { OPENSSL_cleanse(output,data_length+(writing ? 16 : 0)); EVP_CIPHER_CTX_reset(context); errno=EBADMSG; return -1; }
    *written=data_length+(writing ? 16 : 0); return 0;
}

int64_t core_vmess_time(void) { time_t value=time(NULL); return value < 0 ? -1 : (int64_t)value; }

core_vmess_security_t core_vmess_auto_security(void) {
#if defined(__aarch64__) || defined(__arm64__)
    return CORE_VMESS_AES128_GCM;
#elif defined(__x86_64__) || defined(__i386__)
    unsigned a,b,c,d;
    if (__get_cpuid(1,&a,&b,&c,&d) && (c&bit_AES) && (c&bit_PCLMUL) && (c&bit_SSE4_1) && (c&bit_SSSE3)) return CORE_VMESS_AES128_GCM;
#endif
    return CORE_VMESS_CHACHA20_POLY1305;
}
