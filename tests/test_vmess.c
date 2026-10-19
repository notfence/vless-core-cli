#define OPENSSL_SUPPRESS_DEPRECATED
#include "check.h"
#include "vmess.h"
#include "utils.h"
#include "../src/vmess_internal.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>

int __real_RAND_bytes(unsigned char *,int);
EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
HMAC_CTX *__real_HMAC_CTX_new(void);
int __real_EVP_EncryptUpdate(EVP_CIPHER_CTX *,unsigned char *,int *,const unsigned char *,int);
int __real_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *,unsigned char *,int *);
int __real_EVP_CipherUpdate(EVP_CIPHER_CTX *,unsigned char *,int *,const unsigned char *,int);
int __real_EVP_CipherFinal_ex(EVP_CIPHER_CTX *,unsigned char *,int *);
int64_t __real_core_vmess_time(void);
static unsigned random_calls,random_fail,random_position,crypto_calls,crypto_fail;
static int deterministic,bad_time;
int __wrap_RAND_bytes(unsigned char *data,int length) {
    if (++random_calls == random_fail) return 0;
    if (!deterministic) return __real_RAND_bytes(data,length);
    for (int i=0;i<length;i++) data[i]=(uint8_t)random_position++;
    return 1;
}
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void) { return ++crypto_calls == crypto_fail ? NULL : __real_EVP_CIPHER_CTX_new(); }
EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void) { return ++crypto_calls == crypto_fail ? NULL : __real_EVP_MD_CTX_new(); }
HMAC_CTX *__wrap_HMAC_CTX_new(void) { return ++crypto_calls == crypto_fail ? NULL : __real_HMAC_CTX_new(); }
int __wrap_EVP_EncryptUpdate(EVP_CIPHER_CTX *c,unsigned char *o,int *n,const unsigned char *i,int l) { return ++crypto_calls == crypto_fail ? 0 : __real_EVP_EncryptUpdate(c,o,n,i,l); }
int __wrap_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *c,unsigned char *o,int *n) { return ++crypto_calls == crypto_fail ? 0 : __real_EVP_EncryptFinal_ex(c,o,n); }
int __wrap_EVP_CipherUpdate(EVP_CIPHER_CTX *c,unsigned char *o,int *n,const unsigned char *i,int l) { return ++crypto_calls == crypto_fail ? 0 : __real_EVP_CipherUpdate(c,o,n,i,l); }
int __wrap_EVP_CipherFinal_ex(EVP_CIPHER_CTX *c,unsigned char *o,int *n) { return ++crypto_calls == crypto_fail ? 0 : __real_EVP_CipherFinal_ex(c,o,n); }
int64_t __wrap_core_vmess_time(void) { return bad_time ? -1 : INT64_C(1700000000); }

static size_t unhex(const char *text,uint8_t *output,size_t capacity) {
    size_t length=0;
    REQUIRE("vmess/vector-hex",!hex_to_bytes(text,output,capacity,&length));
    return length;
}

static void shake_vectors(void) {
    const size_t lengths[]={0,1,16,167,168,169,511};
    uint8_t data[512],expected[2048],actual[2048];
    for (size_t i=0;i<sizeof(data);i++) data[i]=(uint8_t)i;
    for (size_t i=0;i<sizeof(lengths)/sizeof(*lengths);i++) {
        EVP_MD_CTX *reference=EVP_MD_CTX_new();
        REQUIRE("vmess/shake-reference",reference && EVP_DigestInit_ex(reference,EVP_shake128(),NULL) == 1 &&
            EVP_DigestUpdate(reference,data,lengths[i]) == 1 && EVP_DigestFinalXOF(reference,expected,sizeof(expected)) == 1);
        EVP_MD_CTX_free(reference);
        core_vmess_shake_t shake;
        core_vmess_shake_init(&shake,data,lengths[i]);
        for (size_t offset=0;offset<sizeof(actual);offset++) core_vmess_shake_read(&shake,actual+offset,1);
        CHECK("vmess/shake-incremental-known-vectors",!memcmp(expected,actual,sizeof(actual)));
        core_vmess_shake_init(&shake,data,lengths[i]);
        core_vmess_shake_read(&shake,actual,sizeof(actual));
        CHECK("vmess/shake-fragment-independent",!memcmp(expected,actual,sizeof(actual)));
        OPENSSL_cleanse(&shake,sizeof(shake));
    }
}

static void header_vectors(void) {
    uint8_t uuid[16]={0},wire[CORE_VMESS_HEADER_MAX],digest[32]; size_t length;
    uuid[15]=1;
    REQUIRE("vmess/cmd-key",!core_vmess_cmd_key(uuid,digest));
    const uint8_t expected[]={0xeb,0x05,0x49,0x3e,0x6c,0xa3,0x81,0x3d,0x39,0x15,0x2d,0xdf,0x0d,0x52,0x12,0xb7};
    CHECK("vmess/cmd-key-known-vector",!memcmp(digest,expected,sizeof(expected)));
    const uint8_t binary_path[]={0,1,2,255};
    core_vmess_slice_t paths[]={{"Demo Path for Auth ID Test",26},{"second",6},{binary_path,sizeof(binary_path)}};
    uint8_t golden[CORE_VMESS_HEADER_MAX];
    REQUIRE("vmess/kdf-known-vector",!core_vmess_kdf((const uint8_t *)"Demo Key for Auth ID Test",25,paths,3,digest));
    unhex("724ee1210c598a4e6c5f88c6e3a428b435d6e0dcd2909d498fb4a1c60cf073bd",golden,sizeof(golden));
    CHECK("vmess/kdf-matches-pinned-xray",!memcmp(digest,golden,32));
    core_vmess_header_t header={0};
    deterministic=1; random_position=random_calls=0;
    REQUIRE("vmess/request-header",!core_vmess_request(&header,uuid,"example.test",443,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length));
    CHECK("vmess/request-header-bounded",length > 42 && length <= CORE_VMESS_HEADER_MAX && header.ready);
    size_t expected_length=unhex("73b36bca5b3dd4b3c956f84fa7fda3be2223410792e513fc894c7d5b06fb80403747292a2b2c2d2e2f301bff440504622820eadc4f2506bb0d852a7cb8a339d0fdf5a713e848a57baeb7eb8d6b05242b98f5f6e868800088dbd0cb2efb166676a2430c7a4f8253fef03c48bcfa65d9bd4fc0a979",golden,sizeof(golden));
    CHECK("vmess/request-wire-matches-independent-oracle",length == expected_length && !memcmp(wire,golden,length));
    core_vmess_header_clear(&header);
    uint8_t zero[sizeof(header)]; memset(zero,0,sizeof(zero));
    CHECK("vmess/header-clear",!memcmp(&header,zero,sizeof(header)));
    unsigned successful_random=random_calls;
    for (unsigned stage=1;stage<=successful_random;stage++) {
        random_calls=random_position=0; random_fail=stage; memset(wire,0xa5,sizeof(wire)); length=99;
        CHECK("vmess/request-rng-failure",core_vmess_request(&header,uuid,"example.test",443,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length) < 0 && !length && wire[0] == 0xa5);
        CHECK("vmess/request-failure-cleans-state",!memcmp(&header,zero,sizeof(header)));
    }
    random_fail=0; crypto_calls=0;
    REQUIRE("vmess/request-recovers",!core_vmess_request(&header,uuid,"127.0.0.1",80,CORE_VMESS_CHACHA20_POLY1305,wire,sizeof(wire),&length));
    unsigned successful_crypto=crypto_calls; core_vmess_header_clear(&header);
    for (unsigned stage=1;stage<=successful_crypto;stage++) {
        crypto_calls=0; crypto_fail=stage; length=99;
        CHECK("vmess/request-crypto-allocation-failure",core_vmess_request(&header,uuid,"127.0.0.1",80,CORE_VMESS_CHACHA20_POLY1305,wire,sizeof(wire),&length) < 0 && !length);
        CHECK("vmess/request-crypto-failure-cleans-state",!memcmp(&header,zero,sizeof(header)));
    }
    crypto_fail=0; deterministic=0;
    CHECK("vmess/request-empty-target",core_vmess_request(&header,uuid,"",80,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length) < 0);
    CHECK("vmess/request-zero-port",core_vmess_request(&header,uuid,"localhost",0,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length) < 0);
    CHECK("vmess/request-short-output",core_vmess_request(&header,uuid,"localhost",80,CORE_VMESS_AES128_GCM,wire,1,&length) < 0 && !length);
    bad_time=1;
    CHECK("vmess/request-clock-failure",core_vmess_request(&header,uuid,"localhost",80,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length) < 0 && !length);
    bad_time=0;
    CHECK("vmess/request-ipv6",!core_vmess_request(&header,uuid,"::1",65535,CORE_VMESS_NONE,wire,sizeof(wire),&length));
    char host[257]; memset(host,'a',255); host[255]=0;
    CHECK("vmess/request-max-domain",!core_vmess_request(&header,uuid,host,65535,CORE_VMESS_ZERO,wire,sizeof(wire),&length));
    host[255]='a'; host[256]=0;
    CHECK("vmess/request-domain-overflow",core_vmess_request(&header,uuid,host,80,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length) < 0 && !length);
    CHECK("vmess/request-host-injection",core_vmess_request(&header,uuid,"bad\r\nHost: secret",80,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length) < 0 && !length);
    CHECK("vmess/request-unsupported-cipher",core_vmess_request(&header,uuid,"localhost",80,(core_vmess_security_t)1,wire,sizeof(wire),&length) < 0 && !length);
    core_vmess_header_clear(&header);
}

static void response_vectors(void) {
    const char *vectors[]={
        "dc0e6902de0ac0cc128a15fa7a2dbce8e547098c1d2776a32aa0d6c303e36cb4f4ee2321d750",
        "dc0e6902de0ac0cc128a15fa7a2dbce8e547088c1d2775f2ef7f4f2a3c35c7739e35725a28f6",
        "dc01d6432a2b799bd7c4ca22575a36af9c91098c7e2039a172b928ce39c5223a9048fcda32fde30ab3778dd14b",
        "dc01d6432a2b799bd7c4ca22575a36af9c91098c7e2038a172b928ce39a81832f387ad1fed640a3565dc4abb90",
        "dd0e9f2127bd03731f629b9b1553b0b595fc098c1d2776a32aa0d6c303e36cb4f4ee2321d750"};
    uint8_t uuid[16]={0},wire[CORE_VMESS_HEADER_MAX],response[512]; size_t length;
    uuid[15]=1; deterministic=1;
    for (unsigned sample=0;sample<5;sample++) for (size_t step=1;step<=64;step*=2) {
        core_vmess_header_t header={0}; random_position=random_calls=0;
        REQUIRE("vmess/response-request-state",!core_vmess_request(&header,uuid,"example.test",443,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length));
        size_t size=unhex(vectors[sample],response,sizeof(response)),offset=0; int result=0;
        response[size]=0xab;
        while (!result && offset<size+1) {
            size_t take=size+1-offset,consumed=0; if (take > step) take=step;
            result=core_vmess_response(&header,response+offset,take,&consumed); offset+=consumed;
            CHECK("vmess/response-consumption",consumed <= take);
        }
        CHECK("vmess/response-authenticated-incrementally",(sample == 0 || sample == 2) ? result == 1 && offset == size : result < 0 && header.failed);
        core_vmess_header_clear(&header);
    }
    for (size_t corrupt=0;corrupt<38;corrupt++) {
        core_vmess_header_t header={0}; random_position=random_calls=0;
        REQUIRE("vmess/corruption-request",!core_vmess_request(&header,uuid,"example.test",443,CORE_VMESS_AES128_GCM,wire,sizeof(wire),&length));
        size_t size=unhex(vectors[0],response,sizeof(response)),consumed=0; response[corrupt]^=1;
        CHECK("vmess/corrupt-response-tag-rejected",core_vmess_response(&header,response,size,&consumed) < 0 && !header.response_ready);
        core_vmess_header_clear(&header);
    }
    deterministic=0;
}

int main(void) {
    shake_vectors(); header_vectors(); response_vectors();
    return test_result();
}
