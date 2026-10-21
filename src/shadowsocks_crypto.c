#define OPENSSL_SUPPRESS_DEPRECATED
#include "shadowsocks_internal.h"
#include "blake3.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <string.h>
#include <strings.h>

size_t core_ss_key_size(core_ss_method_t method) {
    if (method < CORE_SS_AES128_GCM || method > CORE_SS_2022_CHACHA20_POLY1305) return 0;
    return method == CORE_SS_AES128_GCM || method == CORE_SS_2022_AES128_GCM ? 16 : 32;
}

size_t core_ss_nonce_size(core_ss_method_t method) { return core_ss_key_size(method) ? method == CORE_SS_XCHACHA20_POLY1305 ? 24 : 12 : 0; }
int core_ss_is_2022(core_ss_method_t method) { return method >= CORE_SS_2022_AES128_GCM && method <= CORE_SS_2022_CHACHA20_POLY1305; }

int core_ss_method(const char *name,core_ss_method_t *output) {
    static const struct { const char *name; core_ss_method_t method; } names[]={
        {"aes-128-gcm",CORE_SS_AES128_GCM},{"aead_aes_128_gcm",CORE_SS_AES128_GCM},
        {"aes-256-gcm",CORE_SS_AES256_GCM},{"aead_aes_256_gcm",CORE_SS_AES256_GCM},
        {"chacha20-poly1305",CORE_SS_CHACHA20_POLY1305},{"chacha20-ietf-poly1305",CORE_SS_CHACHA20_POLY1305},{"aead_chacha20_poly1305",CORE_SS_CHACHA20_POLY1305},
        {"xchacha20-poly1305",CORE_SS_XCHACHA20_POLY1305},{"xchacha20-ietf-poly1305",CORE_SS_XCHACHA20_POLY1305},{"aead_xchacha20_poly1305",CORE_SS_XCHACHA20_POLY1305},
        {"2022-blake3-aes-128-gcm",CORE_SS_2022_AES128_GCM},{"2022-blake3-aes-256-gcm",CORE_SS_2022_AES256_GCM},
        {"2022-blake3-chacha20-poly1305",CORE_SS_2022_CHACHA20_POLY1305}};
    if (name && output) for (size_t i=0;i<sizeof(names)/sizeof(*names);i++) if (!strcasecmp(name,names[i].name)) { *output=names[i].method; return 0; }
    errno=EINVAL; return -1;
}

int core_ss_master(core_ss_method_t method,const uint8_t *password,size_t length,uint8_t output[32]) {
    size_t needed=core_ss_key_size(method); uint8_t block[16]={0};
    if (!output) { errno=EINVAL; return -1; }
    OPENSSL_cleanse(output,32);
    if (!needed || core_ss_is_2022(method) || !password || !length) { errno=EINVAL; return -1; }
    EVP_MD_CTX *context=EVP_MD_CTX_new(); int ok=context != NULL;
    for (size_t offset=0;ok && offset<needed;offset+=16) {
        unsigned written=0;
        ok=EVP_DigestInit_ex(context,EVP_md5(),NULL) == 1;
        if (ok && offset) ok=EVP_DigestUpdate(context,block,sizeof(block)) == 1;
        if (ok) ok=EVP_DigestUpdate(context,password,length) == 1 && EVP_DigestFinal_ex(context,block,&written) == 1 && written == sizeof(block);
        if (ok) memcpy(output+offset,block,sizeof(block));
    }
    EVP_MD_CTX_free(context); OPENSSL_cleanse(block,sizeof(block));
    if (!ok) { OPENSSL_cleanse(output,32); errno=EIO; return -1; }
    return 0;
}

int core_ss_normalize(core_ss_method_t method,const uint8_t *input,size_t length,uint8_t output[32]) {
    size_t needed=core_ss_key_size(method); unsigned written=0; uint8_t digest[32];
    if (!output) { errno=EINVAL; return -1; }
    if (!needed || !core_ss_is_2022(method) || !input || length < needed) { OPENSSL_cleanse(output,32); errno=EINVAL; return -1; }
    int ok=1;
    if (length == needed) { memmove(output,input,needed); memset(output+needed,0,32-needed); }
    else {
        EVP_MD_CTX *context=EVP_MD_CTX_new();
        ok=context && EVP_DigestInit_ex(context,EVP_sha256(),NULL) == 1 && EVP_DigestUpdate(context,input,length) == 1 && EVP_DigestFinal_ex(context,digest,&written) == 1 && written == 32;
        EVP_MD_CTX_free(context);
        if (ok) { memcpy(output,digest,needed); memset(output+needed,0,32-needed); }
    }
    OPENSSL_cleanse(digest,sizeof(digest));
    if (!ok) { OPENSSL_cleanse(output,32); errno=EIO; return -1; }
    return 0;
}

int core_ss_subkey(core_ss_method_t method,const uint8_t *key,const uint8_t *salt,uint8_t output[32]) {
    size_t needed=core_ss_key_size(method); uint8_t material[64],prk[20],block[20]; unsigned written=0;
    int ok=0;
    if (!output) { errno=EINVAL; return -1; }
    if (!needed || !key || !salt) { OPENSSL_cleanse(output,32); errno=EINVAL; return -1; }
    if (core_ss_is_2022(method)) {
        static const uint8_t context[]="shadowsocks 2022 session subkey";
        memcpy(material,key,needed); memcpy(material+needed,salt,needed);
        blake3_derive_key(context,sizeof(context)-1,material,needed*2,output);
        memset(output+needed,0,32-needed); ok=1;
    } else {
        HMAC_CTX *context=HMAC_CTX_new();
        ok=context && HMAC(EVP_sha1(),salt,(int)needed,key,needed,prk,&written) && written == sizeof(prk);
        for (size_t offset=0;ok && offset<needed;) {
            uint8_t counter=(uint8_t)(offset/20+1);
            ok=HMAC_Init_ex(context,prk,sizeof(prk),EVP_sha1(),NULL) == 1;
            if (ok && offset) ok=HMAC_Update(context,block,sizeof(block)) == 1;
            if (ok) ok=HMAC_Update(context,(const uint8_t *)"ss-subkey",9) == 1 && HMAC_Update(context,&counter,1) == 1 && HMAC_Final(context,block,&written) == 1 && written == sizeof(block);
            size_t count=needed-offset; if (count > sizeof(block)) count=sizeof(block);
            if (ok) memcpy(output+offset,block,count);
            offset+=count;
        }
        HMAC_CTX_free(context); if (ok) memset(output+needed,0,32-needed);
    }
    OPENSSL_cleanse(material,sizeof(material)); OPENSSL_cleanse(prk,sizeof(prk)); OPENSSL_cleanse(block,sizeof(block));
    if (!ok) { OPENSSL_cleanse(output,32); errno=EIO; return -1; }
    return 0;
}

static uint32_t load32(const uint8_t *input) { return (uint32_t)input[0]|(uint32_t)input[1]<<8|(uint32_t)input[2]<<16|(uint32_t)input[3]<<24; }
static void store32(uint8_t *output,uint32_t value) { for (unsigned i=0;i<4;i++) output[i]=(uint8_t)(value>>(i*8)); }
static uint32_t rotate32(uint32_t value,unsigned shift) { return value<<shift|value>>(32-shift); }
static void quarter(uint32_t *a,uint32_t *b,uint32_t *c,uint32_t *d) {
    *a+=*b; *d=rotate32(*d^*a,16); *c+=*d; *b=rotate32(*b^*c,12);
    *a+=*b; *d=rotate32(*d^*a,8); *c+=*d; *b=rotate32(*b^*c,7);
}

void core_ss_hchacha(const uint8_t key[32],const uint8_t nonce[16],uint8_t output[32]) {
    uint32_t state[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for (unsigned i=0;i<8;i++) state[i+4]=load32(key+i*4);
    for (unsigned i=0;i<4;i++) state[i+12]=load32(nonce+i*4);
    for (unsigned i=0;i<10;i++) {
        quarter(state,state+4,state+8,state+12); quarter(state+1,state+5,state+9,state+13);
        quarter(state+2,state+6,state+10,state+14); quarter(state+3,state+7,state+11,state+15);
        quarter(state,state+5,state+10,state+15); quarter(state+1,state+6,state+11,state+12);
        quarter(state+2,state+7,state+8,state+13); quarter(state+3,state+4,state+9,state+14);
    }
    for (unsigned i=0;i<4;i++) { store32(output+i*4,state[i]); store32(output+16+i*4,state[i+12]); }
    OPENSSL_cleanse(state,sizeof(state));
}

int core_ss_crypt(EVP_CIPHER_CTX *context,core_ss_method_t method,const uint8_t *key,const uint8_t *nonce,int writing,const uint8_t *input,size_t length,uint8_t *output,size_t capacity,size_t *written) {
    if (!written) { errno=EINVAL; return -1; }
    *written=0;
    if (!context || !core_ss_key_size(method) || !key || !nonce || (!input && length) || !output || length > INT_MAX || (!writing && length < 16) || (writing && capacity < 16)) { errno=EINVAL; return -1; }
    size_t plaintext=writing ? length : length-16,total=plaintext+(writing ? 16 : 0);
    if (capacity < total) { errno=ENOBUFS; return -1; }
    uint8_t subkey[32],iv[12];
    if (method == CORE_SS_XCHACHA20_POLY1305) { core_ss_hchacha(key,nonce,subkey); memset(iv,0,4); memcpy(iv+4,nonce+16,8); key=subkey; nonce=iv; }
    const EVP_CIPHER *cipher=method == CORE_SS_AES128_GCM || method == CORE_SS_2022_AES128_GCM ? EVP_aes_128_gcm() :
        method == CORE_SS_AES256_GCM || method == CORE_SS_2022_AES256_GCM ? EVP_aes_256_gcm() : EVP_chacha20_poly1305();
    int count=0,final=0;
    int ok=EVP_CIPHER_CTX_reset(context) == 1 && EVP_CipherInit_ex(context,cipher,NULL,NULL,NULL,!!writing) == 1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) == 1 && EVP_CipherInit_ex(context,NULL,NULL,key,nonce,!!writing) == 1;
    if (ok && !writing) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_TAG,16,(uint8_t *)input+plaintext) == 1;
    if (ok) ok=EVP_CipherUpdate(context,output,&count,input,(int)plaintext) == 1;
    if (ok) ok=EVP_CipherFinal_ex(context,output+count,&final) == 1 && (size_t)(count+final) == plaintext;
    if (ok && writing) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_GET_TAG,16,output+plaintext) == 1;
    OPENSSL_cleanse(subkey,sizeof(subkey)); OPENSSL_cleanse(iv,sizeof(iv));
    if (!ok) { OPENSSL_cleanse(output,total); EVP_CIPHER_CTX_reset(context); errno=EBADMSG; return -1; }
    *written=total; return 0;
}
