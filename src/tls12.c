#define OPENSSL_SUPPRESS_DEPRECATED
#include "tls12.h"
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const core_tls12_suite_t suites[]={
    {0xcca8,CORE_TLS12_ECDHE,CORE_TLS12_CHACHA,32,0,4,0,"ECDHE-RSA-CHACHA20-POLY1305"},
    {0xcca9,CORE_TLS12_ECDHE,CORE_TLS12_CHACHA,32,0,4,1,"ECDHE-ECDSA-CHACHA20-POLY1305"},
    {0xccaa,CORE_TLS12_DHE,CORE_TLS12_CHACHA,32,0,4,0,"DHE-RSA-CHACHA20-POLY1305"},
    {0xc02f,CORE_TLS12_ECDHE,CORE_TLS12_GCM,16,0,4,0,"ECDHE-RSA-AES128-GCM-SHA256"},
    {0xc02b,CORE_TLS12_ECDHE,CORE_TLS12_GCM,16,0,4,1,"ECDHE-ECDSA-AES128-GCM-SHA256"},
    {0xc030,CORE_TLS12_ECDHE,CORE_TLS12_GCM,32,0,5,0,"ECDHE-RSA-AES256-GCM-SHA384"},
    {0xc02c,CORE_TLS12_ECDHE,CORE_TLS12_GCM,32,0,5,1,"ECDHE-ECDSA-AES256-GCM-SHA384"},
    {0x009e,CORE_TLS12_DHE,CORE_TLS12_GCM,16,0,4,0,"DHE-RSA-AES128-GCM-SHA256"},
    {0x009f,CORE_TLS12_DHE,CORE_TLS12_GCM,32,0,5,0,"DHE-RSA-AES256-GCM-SHA384"},
    {0x009c,CORE_TLS12_RSA,CORE_TLS12_GCM,16,0,4,0,"AES128-GCM-SHA256"},
    {0x009d,CORE_TLS12_RSA,CORE_TLS12_GCM,32,0,5,0,"AES256-GCM-SHA384"},
    {0xc023,CORE_TLS12_ECDHE,CORE_TLS12_CBC,16,4,4,1,"ECDHE-ECDSA-AES128-SHA256"},
    {0xc024,CORE_TLS12_ECDHE,CORE_TLS12_CBC,32,5,5,1,"ECDHE-ECDSA-AES256-SHA384"},
    {0xc027,CORE_TLS12_ECDHE,CORE_TLS12_CBC,16,4,4,0,"ECDHE-RSA-AES128-SHA256"},
    {0xc028,CORE_TLS12_ECDHE,CORE_TLS12_CBC,32,5,5,0,"ECDHE-RSA-AES256-SHA384"},
    {0x0067,CORE_TLS12_DHE,CORE_TLS12_CBC,16,4,4,0,"DHE-RSA-AES128-SHA256"},
    {0x006b,CORE_TLS12_DHE,CORE_TLS12_CBC,32,4,4,0,"DHE-RSA-AES256-SHA256"},
    {0x003c,CORE_TLS12_RSA,CORE_TLS12_CBC,16,4,4,0,"AES128-SHA256"},
    {0x003d,CORE_TLS12_RSA,CORE_TLS12_CBC,32,4,4,0,"AES256-SHA256"},
    {0xc009,CORE_TLS12_ECDHE,CORE_TLS12_CBC,16,1,4,1,"ECDHE-ECDSA-AES128-SHA"},
    {0xc00a,CORE_TLS12_ECDHE,CORE_TLS12_CBC,32,1,4,1,"ECDHE-ECDSA-AES256-SHA"},
    {0xc013,CORE_TLS12_ECDHE,CORE_TLS12_CBC,16,1,4,0,"ECDHE-RSA-AES128-SHA"},
    {0xc014,CORE_TLS12_ECDHE,CORE_TLS12_CBC,32,1,4,0,"ECDHE-RSA-AES256-SHA"},
    {0x0033,CORE_TLS12_DHE,CORE_TLS12_CBC,16,1,4,0,"DHE-RSA-AES128-SHA"},
    {0x0039,CORE_TLS12_DHE,CORE_TLS12_CBC,32,1,4,0,"DHE-RSA-AES256-SHA"},
    {0x002f,CORE_TLS12_RSA,CORE_TLS12_CBC,16,1,4,0,"AES128-SHA"},
    {0x0035,CORE_TLS12_RSA,CORE_TLS12_CBC,32,1,4,0,"AES256-SHA"},
};
const core_tls12_suite_t *core_tls12_suite_at(size_t index) { return index < sizeof(suites)/sizeof(*suites) ? &suites[index] : NULL; }
const core_tls12_suite_t *core_tls12_suite(unsigned id) {
    for (size_t i=0;i<sizeof(suites)/sizeof(*suites);i++) if (suites[i].id == id) return &suites[i];
    return NULL;
}
const EVP_MD *core_tls12_digest(unsigned hash) { return hash == 1 ? EVP_sha1() : hash == 4 ? EVP_sha256() : hash == 5 ? EVP_sha384() : NULL; }
static void clear_free(void *memory,size_t length) { if (memory) { OPENSSL_cleanse(memory,length); free(memory); } }
static int mac(const EVP_MD *digest,const uint8_t *key,size_t key_length,const uint8_t *data,size_t length,uint8_t *output) {
    unsigned size=0;
    return HMAC(digest,key,(int)key_length,data,length,output,&size) && size == (unsigned)EVP_MD_get_size(digest) ? 0 : -1;
}
int core_tls12_prf(const EVP_MD *digest,const uint8_t *secret,size_t secret_length,const char *label,
                   const uint8_t *seed,size_t seed_length,uint8_t *output,size_t length) {
    uint8_t input[256],a[64]={0},block[64]={0}; size_t label_length=strlen(label),digest_length=(size_t)EVP_MD_get_size(digest);
    if (!digest_length || digest_length > 64 || label_length > sizeof(input)-64 || seed_length > sizeof(input)-64-label_length || secret_length > INT_MAX) return -1;
    size_t suffix=label_length+seed_length; memcpy(input+digest_length,label,label_length); memcpy(input+digest_length+label_length,seed,seed_length);
    int result=mac(digest,secret,secret_length,input+digest_length,suffix,a);
    for (size_t offset=0;!result && offset<length;) {
        memcpy(input,a,digest_length);
        result=mac(digest,secret,secret_length,input,digest_length+suffix,block);
        if (result) break;
        size_t take=length-offset; if (take > digest_length) take=digest_length;
        memcpy(output+offset,block,take); offset+=take;
        result=mac(digest,secret,secret_length,a,digest_length,a);
    }
    OPENSSL_cleanse(input,sizeof(input)); OPENSSL_cleanse(a,sizeof(a)); OPENSSL_cleanse(block,sizeof(block));
    if (result) OPENSSL_cleanse(output,length);
    return result;
}
static void record_header(uint8_t header[13],uint64_t sequence,unsigned type,size_t length) {
    for (size_t i=0;i<8;i++) header[i]=(uint8_t)(sequence>>(56-8*i));
    header[8]=(uint8_t)type; header[9]=3; header[10]=3; header[11]=(uint8_t)(length>>8); header[12]=(uint8_t)length;
}
static int record_mac(const EVP_MD *digest,const uint8_t *key,uint64_t sequence,unsigned type,const uint8_t *data,size_t length,uint8_t *output) {
    uint8_t header[13]; record_header(header,sequence,type,length);
    HMAC_CTX *context=HMAC_CTX_new(); unsigned size=0;
    int ok=context && HMAC_Init_ex(context,key,EVP_MD_get_size(digest),digest,NULL) == 1 &&
        HMAC_Update(context,header,sizeof(header)) == 1 && HMAC_Update(context,data,length) == 1 && HMAC_Final(context,output,&size) == 1;
    HMAC_CTX_free(context); return ok && size == (unsigned)EVP_MD_get_size(digest) ? 0 : -1;
}
static void hash_state(unsigned hash,const void *context,uint8_t output[64]) {
    if (hash == 5) {
        const SHA512_CTX *state=context;
        for (size_t i=0;i<6;i++) for (size_t j=0;j<8;j++) output[8*i+j]=(uint8_t)(state->h[i]>>(56-8*j));
    } else {
        const SHA256_CTX *state=context; const SHA_CTX *sha1=context;
        uint32_t words[8];
        if (hash == 1) { words[0]=sha1->h0; words[1]=sha1->h1; words[2]=sha1->h2; words[3]=sha1->h3; words[4]=sha1->h4; }
        else memcpy(words,state->h,sizeof(words));
        for (size_t i=0;i<(hash == 1 ? 5U : 8U);i++) for (size_t j=0;j<4;j++) output[4*i+j]=(uint8_t)(words[i]>>(24-8*j));
        OPENSSL_cleanse(words,sizeof(words));
    }
}
static int cbc_mac(unsigned hash,const uint8_t *key,uint64_t sequence,unsigned type,const uint8_t *data,
                    size_t available,size_t length,uint8_t output[64]) {
    union { SHA_CTX sha1; SHA256_CTX sha256; SHA512_CTX sha384; } context;
    size_t block_size=hash == 5 ? 128 : 64,length_size=hash == 5 ? 16 : 8,digest_size=hash == 5 ? 48 : hash == 4 ? 32 : 20;
    uint8_t block[128]={0},inner[64]={0},candidate[64]={0},header[13];
    record_header(header,sequence,type,length);
    if (hash == 1) SHA1_Init(&context.sha1); else if (hash == 4) SHA256_Init(&context.sha256); else if (hash == 5) SHA384_Init(&context.sha384); else return -1;
    for (size_t i=0;i<block_size;i++) block[i]=(i < digest_size ? key[i] : 0)^0x36;
    if (hash == 1) SHA1_Transform(&context.sha1,block); else if (hash == 4) SHA256_Transform(&context.sha256,block); else SHA512_Transform(&context.sha384,block);
    size_t blocks=(13+available+1+length_size+block_size-1)/block_size,actual=(13+length+1+length_size+block_size-1)/block_size;
    uint64_t bits=(uint64_t)(block_size+13+length)*8;
    for (size_t index=0;index<blocks;index++) {
        for (size_t i=0;i<block_size;i++) {
            size_t position=index*block_size+i;
            uint8_t byte=position < 13 ? header[position] : position-13 < available ? data[position-13] : 0;
            byte&=(uint8_t)(0-(position < 13+length));
            byte|=0x80&(uint8_t)(0-(position == 13+length));
            if (i >= block_size-8) byte|=(uint8_t)(bits>>(8*(block_size-1-i)))&(uint8_t)(0-(index+1 == actual));
            block[i]=byte;
        }
        if (hash == 1) SHA1_Transform(&context.sha1,block); else if (hash == 4) SHA256_Transform(&context.sha256,block); else SHA512_Transform(&context.sha384,block);
        hash_state(hash,&context,candidate);
        uint8_t select=(uint8_t)(0-(index+1 == actual));
        for (size_t i=0;i<digest_size;i++) inner[i]|=candidate[i]&select;
    }
    for (size_t i=0;i<block_size;i++) block[i]=(i < digest_size ? key[i] : 0)^0x5c;
    if (hash == 1) { SHA1_Init(&context.sha1); SHA1_Update(&context.sha1,block,block_size); SHA1_Update(&context.sha1,inner,digest_size); SHA1_Final(output,&context.sha1); }
    else if (hash == 4) { SHA256_Init(&context.sha256); SHA256_Update(&context.sha256,block,block_size); SHA256_Update(&context.sha256,inner,digest_size); SHA256_Final(output,&context.sha256); }
    else { SHA384_Init(&context.sha384); SHA384_Update(&context.sha384,block,block_size); SHA384_Update(&context.sha384,inner,digest_size); SHA384_Final(output,&context.sha384); }
    OPENSSL_cleanse(&context,sizeof(context)); OPENSSL_cleanse(block,sizeof(block)); OPENSSL_cleanse(inner,sizeof(inner)); OPENSSL_cleanse(candidate,sizeof(candidate));
    return 0;
}
static unsigned cbc_padding(const uint8_t *data,size_t length,size_t mac_length,size_t *content_length) {
    unsigned padding=(unsigned)data[length-1]+1,bad=(padding > length)|(mac_length > length)|(padding+mac_length > length);
    for (size_t i=0;i<256;i++) {
        uint8_t byte=i < length ? data[length-1-i] : 0;
        bad|=(byte^(padding-1))&(unsigned)(0-(i < padding));
    }
    size_t good=(size_t)0-(bad == 0); *content_length=(length-padding-mac_length)&good; return bad == 0;
}
static void cbc_extract_mac(const uint8_t *data,size_t length,size_t offset,uint8_t *output,size_t mac_length) {
    uint8_t ring[512]={0},shifted[512]; size_t tail=length < sizeof(ring) ? length : sizeof(ring);
    memcpy(ring+sizeof(ring)-tail,data+length-tail,tail); size_t rotation=(offset-length+sizeof(ring))&(sizeof(ring)-1);
    for (size_t distance=1;distance<sizeof(ring);distance*=2) {
        uint8_t select=(uint8_t)(0-((rotation&distance) != 0));
        for (size_t i=0;i<sizeof(ring);i++) shifted[i]=(ring[(i+distance)&(sizeof(ring)-1)]&select)|(ring[i]&(uint8_t)~select);
        memcpy(ring,shifted,sizeof(ring));
    }
    memcpy(output,ring,mac_length); OPENSSL_cleanse(ring,sizeof(ring)); OPENSSL_cleanse(shifted,sizeof(shifted));
}
static const EVP_CIPHER *record_cipher(const core_tls12_suite_t *suite) {
    if (suite->cipher == CORE_TLS12_CHACHA) return EVP_chacha20_poly1305();
    if (suite->cipher == CORE_TLS12_GCM) return suite->key_length == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    return suite->key_length == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
}
int core_tls12_record_seal(const core_tls12_suite_t *suite,int etm,const uint8_t *key,const uint8_t *iv,const uint8_t *mac_key,
                           uint64_t *sequence,unsigned type,const uint8_t *plain,size_t length,uint8_t **output,size_t *output_length) {
    *output=NULL; *output_length=0;
    if (!suite || length > 16384 || *sequence >= (UINT64_C(1)<<24) || (type != 21 && type != 22 && type != 23)) { errno=EMSGSIZE; return -1; }
    const EVP_MD *digest=core_tls12_digest(suite->mac_hash); size_t mac_length=digest ? (size_t)EVP_MD_get_size(digest) : 0;
    size_t explicit_length=suite->cipher == CORE_TLS12_GCM ? 8 : suite->cipher == CORE_TLS12_CBC ? 16 : 0;
    size_t encrypted_length=length+(suite->cipher == CORE_TLS12_CBC && !etm ? mac_length : 0);
    if (suite->cipher == CORE_TLS12_CBC) encrypted_length=((encrypted_length+1+15)/16)*16;
    size_t payload_length=explicit_length+encrypted_length+(suite->cipher == CORE_TLS12_CBC ? etm ? mac_length : 0 : 16);
    uint8_t *record=malloc(5+payload_length),*padded=NULL,nonce[16]={0},header[13],authentication[64]={0}; EVP_CIPHER_CTX *context=NULL;
    int result=-1,n=0,final=0,cause=EPROTO;
    if (!record) { cause=ENOMEM; goto cleanup; }
    record[0]=(uint8_t)type; record[1]=3; record[2]=3; record[3]=(uint8_t)(payload_length>>8); record[4]=(uint8_t)payload_length;
    context=EVP_CIPHER_CTX_new(); if (!context) { cause=ENOMEM; goto cleanup; }
    if (suite->cipher == CORE_TLS12_CBC) {
        padded=malloc(encrypted_length); if (!padded) { cause=ENOMEM; goto cleanup; }
        if (RAND_bytes(nonce,16) != 1) goto cleanup;
        memcpy(record+5,nonce,16); memcpy(padded,plain,length); size_t used=length;
        if (!etm) { if (record_mac(digest,mac_key,*sequence,type,plain,length,authentication)) goto cleanup; memcpy(padded+used,authentication,mac_length); used+=mac_length; }
        memset(padded+used,(int)(encrypted_length-used-1),encrypted_length-used);
        if (EVP_EncryptInit_ex(context,record_cipher(suite),NULL,key,nonce) != 1 || EVP_CIPHER_CTX_set_padding(context,0) != 1 ||
            EVP_EncryptUpdate(context,record+21,&n,padded,(int)encrypted_length) != 1 || EVP_EncryptFinal_ex(context,record+21+n,&final) != 1 || (size_t)(n+final) != encrypted_length) goto cleanup;
        if (etm) { if (record_mac(digest,mac_key,*sequence,type,record+5,explicit_length+encrypted_length,authentication)) goto cleanup; memcpy(record+5+explicit_length+encrypted_length,authentication,mac_length); }
    } else {
        record_header(header,*sequence,type,length);
        if (suite->cipher == CORE_TLS12_GCM) { memcpy(nonce,iv,4); memcpy(nonce+4,header,8); memcpy(record+5,header,8); }
        else { memcpy(nonce,iv,12); for (size_t i=0;i<8;i++) nonce[4+i]^=header[i]; }
        uint8_t *ciphertext=record+5+explicit_length;
        if (EVP_EncryptInit_ex(context,record_cipher(suite),NULL,NULL,NULL) != 1 || EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) != 1 ||
            EVP_EncryptInit_ex(context,NULL,NULL,key,nonce) != 1 || EVP_EncryptUpdate(context,NULL,&n,header,sizeof(header)) != 1 ||
            EVP_EncryptUpdate(context,ciphertext,&n,plain,(int)length) != 1 || EVP_EncryptFinal_ex(context,ciphertext+n,&final) != 1 ||
            (size_t)(n+final) != length || EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_GET_TAG,16,ciphertext+length) != 1) goto cleanup;
    }
    (*sequence)++; *output=record; *output_length=5+payload_length; record=NULL; result=0;
cleanup:
    EVP_CIPHER_CTX_free(context); clear_free(record,5+payload_length); clear_free(padded,encrypted_length);
    OPENSSL_cleanse(nonce,sizeof(nonce)); OPENSSL_cleanse(authentication,sizeof(authentication)); if (result) errno=cause; return result;
}
int core_tls12_record_open(const core_tls12_suite_t *suite,int etm,const uint8_t *key,const uint8_t *iv,const uint8_t *mac_key,
                           uint64_t *sequence,unsigned type,const uint8_t *payload,size_t length,uint8_t **output,size_t *output_length) {
    *output=NULL; *output_length=0;
    if (!suite || length > 18432 || *sequence >= (UINT64_C(1)<<24) || (type != 21 && type != 22 && type != 23)) { errno=EMSGSIZE; return -1; }
    const EVP_MD *digest=core_tls12_digest(suite->mac_hash); size_t mac_length=digest ? (size_t)EVP_MD_get_size(digest) : 0;
    size_t explicit_length=suite->cipher == CORE_TLS12_GCM ? 8 : suite->cipher == CORE_TLS12_CBC ? 16 : 0;
    size_t tag_length=suite->cipher == CORE_TLS12_CBC ? etm ? mac_length : 0 : 16;
    if (length < explicit_length+tag_length+ (suite->cipher == CORE_TLS12_CBC ? 16U : 0U)) goto invalid;
    size_t encrypted_length=length-explicit_length-tag_length;
    if (suite->cipher == CORE_TLS12_CBC && encrypted_length%16) goto invalid;
    if (suite->cipher != CORE_TLS12_CBC && encrypted_length > 16384) goto invalid;
    uint8_t authentication[64]={0},received_mac[64]={0},nonce[16]={0},header[13],*plain=NULL; EVP_CIPHER_CTX *context=NULL;
    int result=-1,n=0,final=0,cause=EPROTO; size_t content_length=0;
    if (suite->cipher == CORE_TLS12_CBC && etm && (record_mac(digest,mac_key,*sequence,type,payload,length-mac_length,authentication) ||
        CRYPTO_memcmp(authentication,payload+length-mac_length,mac_length))) goto cleanup;
    plain=malloc(encrypted_length ? encrypted_length : 1); context=EVP_CIPHER_CTX_new();
    if (!plain || !context) { cause=ENOMEM; goto cleanup; }
    if (suite->cipher == CORE_TLS12_CBC) {
        if (EVP_DecryptInit_ex(context,record_cipher(suite),NULL,key,payload) != 1 || EVP_CIPHER_CTX_set_padding(context,0) != 1 ||
            EVP_DecryptUpdate(context,plain,&n,payload+16,(int)encrypted_length) != 1 || EVP_DecryptFinal_ex(context,plain+n,&final) != 1 || (size_t)(n+final) != encrypted_length) goto cleanup;
        unsigned valid=cbc_padding(plain,encrypted_length,etm ? 0 : mac_length,&content_length);
        if (!etm) {
            cbc_extract_mac(plain,encrypted_length,content_length,received_mac,mac_length);
            if (cbc_mac(suite->mac_hash,mac_key,*sequence,type,plain,encrypted_length,content_length,authentication)) goto cleanup;
            valid&=CRYPTO_memcmp(authentication,received_mac,mac_length) == 0;
        }
        if (!valid || content_length > 16384) goto cleanup;
    } else {
        record_header(header,*sequence,type,encrypted_length);
        if (suite->cipher == CORE_TLS12_GCM) { memcpy(nonce,iv,4); memcpy(nonce+4,payload,8); }
        else { memcpy(nonce,iv,12); for (size_t i=0;i<8;i++) nonce[4+i]^=header[i]; }
        if (EVP_DecryptInit_ex(context,record_cipher(suite),NULL,NULL,NULL) != 1 || EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) != 1 ||
            EVP_DecryptInit_ex(context,NULL,NULL,key,nonce) != 1 || EVP_DecryptUpdate(context,NULL,&n,header,sizeof(header)) != 1 ||
            EVP_DecryptUpdate(context,plain,&n,payload+explicit_length,(int)encrypted_length) != 1 ||
            EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_TAG,16,(void *)(payload+length-16)) != 1 ||
            EVP_DecryptFinal_ex(context,plain+n,&final) != 1 || (size_t)(n+final) != encrypted_length) goto cleanup;
        content_length=encrypted_length;
    }
    OPENSSL_cleanse(plain+content_length,encrypted_length-content_length);
    (*sequence)++; *output=plain; *output_length=content_length; plain=NULL; result=0;
cleanup:
    EVP_CIPHER_CTX_free(context); clear_free(plain,encrypted_length ? encrypted_length : 1);
    OPENSSL_cleanse(authentication,sizeof(authentication)); OPENSSL_cleanse(received_mac,sizeof(received_mac)); OPENSSL_cleanse(nonce,sizeof(nonce));
    if (result) errno=cause;
    return result;
invalid:
    errno=EPROTO; return -1;
}
