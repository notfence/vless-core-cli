#define OPENSSL_SUPPRESS_DEPRECATED
#include "check.h"
#include "shadowsocks.h"
#include "../src/shadowsocks_internal.h"
#include "utils.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

static unsigned crypto_calls,crypto_fail;
EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
HMAC_CTX *__real_HMAC_CTX_new(void);
int __real_EVP_DigestInit_ex(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
int __real_EVP_DigestUpdate(EVP_MD_CTX *,const void *,size_t);
int __real_EVP_DigestFinal_ex(EVP_MD_CTX *,unsigned char *,unsigned int *);
unsigned char *__real_HMAC(const EVP_MD *,const void *,int,const unsigned char *,size_t,unsigned char *,unsigned int *);
int __real_HMAC_Init_ex(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
int __real_HMAC_Update(HMAC_CTX *,const unsigned char *,size_t);
int __real_HMAC_Final(HMAC_CTX *,unsigned char *,unsigned int *);
int __real_EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *);
int __real_EVP_CipherInit_ex(EVP_CIPHER_CTX *,const EVP_CIPHER *,ENGINE *,const unsigned char *,const unsigned char *,int);
int __real_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *,int,int,void *);
int __real_EVP_CipherUpdate(EVP_CIPHER_CTX *,unsigned char *,int *,const unsigned char *,int);
int __real_EVP_CipherFinal_ex(EVP_CIPHER_CTX *,unsigned char *,int *);
static int failed(void) { return ++crypto_calls == crypto_fail; }
EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void) { return failed() ? NULL : __real_EVP_MD_CTX_new(); }
HMAC_CTX *__wrap_HMAC_CTX_new(void) { return failed() ? NULL : __real_HMAC_CTX_new(); }
int __wrap_EVP_DigestInit_ex(EVP_MD_CTX *c,const EVP_MD *m,ENGINE *e) { return failed() ? 0 : __real_EVP_DigestInit_ex(c,m,e); }
int __wrap_EVP_DigestUpdate(EVP_MD_CTX *c,const void *d,size_t n) { return failed() ? 0 : __real_EVP_DigestUpdate(c,d,n); }
int __wrap_EVP_DigestFinal_ex(EVP_MD_CTX *c,unsigned char *o,unsigned int *n) { return failed() ? 0 : __real_EVP_DigestFinal_ex(c,o,n); }
unsigned char *__wrap_HMAC(const EVP_MD *m,const void *k,int n,const unsigned char *d,size_t l,unsigned char *o,unsigned int *w) { return failed() ? NULL : __real_HMAC(m,k,n,d,l,o,w); }
int __wrap_HMAC_Init_ex(HMAC_CTX *c,const void *k,int l,const EVP_MD *m,ENGINE *e) { return failed() ? 0 : __real_HMAC_Init_ex(c,k,l,m,e); }
int __wrap_HMAC_Update(HMAC_CTX *c,const unsigned char *d,size_t n) { return failed() ? 0 : __real_HMAC_Update(c,d,n); }
int __wrap_HMAC_Final(HMAC_CTX *c,unsigned char *o,unsigned int *n) { return failed() ? 0 : __real_HMAC_Final(c,o,n); }
int __wrap_EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c) { return failed() ? 0 : __real_EVP_CIPHER_CTX_reset(c); }
int __wrap_EVP_CipherInit_ex(EVP_CIPHER_CTX *c,const EVP_CIPHER *m,ENGINE *e,const unsigned char *k,const unsigned char *n,int w) { return failed() ? 0 : __real_EVP_CipherInit_ex(c,m,e,k,n,w); }
int __wrap_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *c,int t,int n,void *p) { return failed() ? 0 : __real_EVP_CIPHER_CTX_ctrl(c,t,n,p); }
int __wrap_EVP_CipherUpdate(EVP_CIPHER_CTX *c,unsigned char *o,int *n,const unsigned char *i,int l) { return failed() ? 0 : __real_EVP_CipherUpdate(c,o,n,i,l); }
int __wrap_EVP_CipherFinal_ex(EVP_CIPHER_CTX *c,unsigned char *o,int *n) { return failed() ? 0 : __real_EVP_CipherFinal_ex(c,o,n); }

static void expect_hex(const char *name,const uint8_t *actual,size_t length,const char *expected) {
    uint8_t bytes[128]; size_t count=0;
    REQUIRE("shadowsocks/vector-hex",!hex_to_bytes(expected,bytes,sizeof(bytes),&count));
    CHECK(name,count == length && !memcmp(actual,bytes,length));
}

static void key_vectors(void) {
    const uint8_t password[]="SS+password:@%\0end";
    uint8_t key[32],salt[32],output[32];
    for (size_t i=0;i<sizeof(salt);i++) salt[i]=(uint8_t)i;
    REQUIRE("shadowsocks/master-aes128",!core_ss_master(CORE_SS_AES128_GCM,password,sizeof(password)-1,key));
    expect_hex("shadowsocks/master-aes128-vector",key,16,"3500a418a513c1d8a383f413575d49a4");
    REQUIRE("shadowsocks/subkey-aes128",!core_ss_subkey(CORE_SS_AES128_GCM,key,salt,output));
    expect_hex("shadowsocks/subkey-aes128-vector",output,16,"563499652f95ef1d96b27a95af408d02");
    REQUIRE("shadowsocks/master-chacha",!core_ss_master(CORE_SS_CHACHA20_POLY1305,password,sizeof(password)-1,key));
    expect_hex("shadowsocks/master-chacha-vector",key,32,"3500a418a513c1d8a383f413575d49a451685b59011ab1d2c789ba0e20d3e896");
    REQUIRE("shadowsocks/subkey-chacha",!core_ss_subkey(CORE_SS_CHACHA20_POLY1305,key,salt,output));
    expect_hex("shadowsocks/subkey-chacha-vector",output,32,"4aa8fdfec8baa3e6ffdfc4b0fa6bf94abb1057d09de3d7842fcab7ee490e5b1c");
    CHECK("shadowsocks/no-empty-password",core_ss_master(CORE_SS_AES128_GCM,password,0,key) < 0);
    CHECK("shadowsocks/no-2022-password-derivation",core_ss_master(CORE_SS_2022_AES128_GCM,password,sizeof(password)-1,key) < 0);
    uint8_t long_key[48]; for (size_t i=0;i<sizeof(long_key);i++) long_key[i]=(uint8_t)i;
    REQUIRE("shadowsocks/normalize-psk",!core_ss_normalize(CORE_SS_2022_AES256_GCM,long_key,sizeof(long_key),key));
    expect_hex("shadowsocks/normalize-psk-vector",key,32,"4dbdc2b2b62cb00749785bc84202236dbc3777d74660611b8e58812f0cfde6c3");
    CHECK("shadowsocks/reject-short-psk",core_ss_normalize(CORE_SS_2022_AES256_GCM,long_key,31,key) < 0);
    REQUIRE("shadowsocks/exact-psk",!core_ss_normalize(CORE_SS_2022_AES128_GCM,long_key,16,key));
    CHECK("shadowsocks/exact-psk-unchanged",!memcmp(key,long_key,16));
    for (size_t i=0;i<sizeof(key);i++) key[i]=(uint8_t)i;
    for (size_t i=0;i<sizeof(salt);i++) salt[i]=(uint8_t)(i+32);
    REQUIRE("shadowsocks/2022-subkey128",!core_ss_subkey(CORE_SS_2022_AES128_GCM,key,salt,output));
    expect_hex("shadowsocks/2022-subkey128-independent",output,16,"8180421f8f56092ca7544a64ff852536");
    REQUIRE("shadowsocks/2022-subkey256",!core_ss_subkey(CORE_SS_2022_AES256_GCM,key,salt,output));
    expect_hex("shadowsocks/2022-subkey256-independent",output,32,"374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda");
}

static void hchacha_vector(void) {
    uint8_t key[32],nonce[16]={0,0,0,9,0,0,0,0x4a,0,0,0,0,0x31,0x41,0x59,0x27},output[32];
    for (size_t i=0;i<sizeof(key);i++) key[i]=(uint8_t)i;
    core_ss_hchacha(key,nonce,output);
    expect_hex("shadowsocks/hchacha-independent-vector",output,32,"82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
}

static void crypt_vectors(void) {
    uint8_t key[32],nonce[24],wire[128],output[128]; size_t written=0,decoded=0;
    const uint8_t plain[]="\0\0Shadowsocks+wire:@%";
    const char *vectors[]={
        "936cf4a6077f982338bd02e145880761c14320a676e10b0b44b8f36317b92232c9678106f1",
        "47028573a481ad6cfe2ef4e0c2c20f04f1b3bd74d53f1daf434c6c5e29a0aed4a0cd810b32",
        "89fb5b684873ca37c4ec5c98eb36790abb1588a7749a7b6631c29f828d1320bb5bb597f0d3",
        "9ec25c17f1b6e2d9402b45a5b879df81392212e5d8c72010bae80fd46208cabff46b2bd2db"};
    for (size_t i=0;i<sizeof(key);i++) key[i]=(uint8_t)i;
    for (size_t i=0;i<sizeof(nonce);i++) nonce[i]=(uint8_t)i;
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new(); REQUIRE("shadowsocks/cipher-context",context != NULL);
    for (unsigned method=0;method<7;method++) {
        REQUIRE("shadowsocks/seal",!core_ss_crypt(context,(core_ss_method_t)method,key,nonce,1,plain,sizeof(plain)-1,wire,sizeof(wire),&written));
        unsigned vector=method >= 4 ? method-4 : method;
        expect_hex("shadowsocks/independent-aead-wire",wire,written,vectors[vector]);
        REQUIRE("shadowsocks/open",!core_ss_crypt(context,(core_ss_method_t)method,key,nonce,0,wire,written,output,sizeof(output),&decoded));
        CHECK("shadowsocks/aead-roundtrip",decoded == sizeof(plain)-1 && !memcmp(output,plain,decoded));
        for (size_t corrupt=0;corrupt<written;corrupt++) {
            wire[corrupt]^=1; memset(output,0xa5,sizeof(output));
            CHECK("shadowsocks/tag-rejection",core_ss_crypt(context,(core_ss_method_t)method,key,nonce,0,wire,written,output,sizeof(output),&decoded) < 0 && !decoded);
            uint8_t zero[sizeof(plain)-1]={0}; CHECK("shadowsocks/tag-failure-wipes-plaintext",!memcmp(output,zero,sizeof(zero)));
            wire[corrupt]^=1;
        }
        for (unsigned writing=0;writing<2;writing++) {
            crypto_calls=0;
            REQUIRE("shadowsocks/fault-baseline",!core_ss_crypt(context,(core_ss_method_t)method,key,nonce,(int)writing,writing ? plain : wire,writing ? sizeof(plain)-1 : written,output,sizeof(output),&decoded));
            unsigned calls=crypto_calls;
            for (unsigned stage=1;stage<=calls;stage++) {
                crypto_calls=0; crypto_fail=stage; memset(output,0xa5,sizeof(output));
                CHECK("shadowsocks/every-aead-operation-fails-closed",core_ss_crypt(context,(core_ss_method_t)method,key,nonce,(int)writing,writing ? plain : wire,writing ? sizeof(plain)-1 : written,output,sizeof(output),&decoded) < 0 && !decoded);
                uint8_t zero[sizeof(plain)+15]={0};
                CHECK("shadowsocks/aead-failure-cleanse",!memcmp(output,zero,sizeof(plain)-1+(writing ? 16 : 0)));
                crypto_fail=0;
                CHECK("shadowsocks/context-recovers-after-failure",!core_ss_crypt(context,(core_ss_method_t)method,key,nonce,(int)writing,writing ? plain : wire,writing ? sizeof(plain)-1 : written,output,sizeof(output),&decoded));
            }
        }
        REQUIRE("shadowsocks/empty-seal",!core_ss_crypt(context,(core_ss_method_t)method,key,nonce,1,NULL,0,wire,sizeof(wire),&written));
        CHECK("shadowsocks/empty-open",written == 16 && !core_ss_crypt(context,(core_ss_method_t)method,key,nonce,0,wire,written,output,sizeof(output),&decoded) && !decoded);
    }
    CHECK("shadowsocks/short-output",core_ss_crypt(context,CORE_SS_AES128_GCM,key,nonce,1,plain,sizeof(plain)-1,output,1,&decoded) < 0 && !decoded);
    CHECK("shadowsocks/short-tag",core_ss_crypt(context,CORE_SS_AES128_GCM,key,nonce,0,wire,15,output,sizeof(output),&decoded) < 0 && !decoded);
    EVP_CIPHER_CTX_free(context);
}

static void key_failures(void) {
    uint8_t input[48]={0},output[32],zero[32]={0};
    for (unsigned operation=0;operation<3;operation++) {
        crypto_calls=0; int result;
        if (!operation) result=core_ss_master(CORE_SS_AES256_GCM,input,sizeof(input),output);
        else if (operation == 1) result=core_ss_normalize(CORE_SS_2022_AES128_GCM,input,sizeof(input),output);
        else result=core_ss_subkey(CORE_SS_AES256_GCM,input,input,output);
        REQUIRE("shadowsocks/key-failure-baseline",!result);
        unsigned calls=crypto_calls;
        for (unsigned stage=1;stage<=calls;stage++) {
            crypto_fail=stage; crypto_calls=0; memset(output,0xa5,sizeof(output));
            if (!operation) result=core_ss_master(CORE_SS_AES256_GCM,input,sizeof(input),output);
            else if (operation == 1) result=core_ss_normalize(CORE_SS_2022_AES128_GCM,input,sizeof(input),output);
            else result=core_ss_subkey(CORE_SS_AES256_GCM,input,input,output);
            CHECK("shadowsocks/key-failure-propagates",result < 0);
            CHECK("shadowsocks/key-failure-cleanses",!memcmp(output,zero,sizeof(output)));
            crypto_fail=0;
        }
    }
}

static void methods(void) {
    const char *names[]={"aes-128-gcm","aes-256-gcm","chacha20-poly1305","xchacha20-poly1305","2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"};
    for (size_t i=0;i<sizeof(names)/sizeof(*names);i++) {
        core_ss_method_t method;
        CHECK("shadowsocks/methods",!core_ss_method(names[i],&method) && method == (core_ss_method_t)i);
        CHECK("shadowsocks/key-sizes",core_ss_key_size(method) == (i == 0 || i == 4 ? 16U : 32U));
        CHECK("shadowsocks/nonce-sizes",core_ss_nonce_size(method) == (i == 3 ? 24U : 12U));
        CHECK("shadowsocks/edition",core_ss_is_2022(method) == (i >= 4));
    }
    core_ss_method_t method;
    CHECK("shadowsocks/ietf-alias",!core_ss_method("chacha20-ietf-poly1305",&method) && method == CORE_SS_CHACHA20_POLY1305);
    CHECK("shadowsocks/xchacha-alias",!core_ss_method("aead_xchacha20_poly1305",&method) && method == CORE_SS_XCHACHA20_POLY1305);
    const char *bad[]={"none","plain","auto","aes-128-cfb","aes-192-gcm","2022-blake3-chacha8-poly1305",""};
    for (size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) CHECK("shadowsocks/unsupported-method",core_ss_method(bad[i],&method) < 0);
}

int main(void) {
    methods(); key_vectors(); hchacha_vector(); crypt_vectors(); key_failures();
    return test_result();
}
