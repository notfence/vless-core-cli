#include "check.h"
#include "../src/tls12.c"
#include <openssl/kdf.h>
#include <openssl/core_names.h>
static void prf_vectors(void) {
    uint8_t secret[48],seed[64],expected[256],actual[256];
    memset(secret,7,sizeof(secret)); memset(seed,9,sizeof(seed));
    for (unsigned hash=4;hash<=5;hash++) {
        EVP_KDF *algorithm=EVP_KDF_fetch(NULL,"TLS1-PRF",NULL); EVP_KDF_CTX *context=algorithm ? EVP_KDF_CTX_new(algorithm) : NULL;
        REQUIRE("tls12/prf-reference",context != NULL);
        const char label[]="vless-core"; uint8_t input[sizeof(label)-1+sizeof(seed)]; memcpy(input,label,sizeof(label)-1); memcpy(input+sizeof(label)-1,seed,sizeof(seed));
        char *digest=hash == 4 ? "SHA256" : "SHA384";
        OSSL_PARAM parameters[]={OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,digest,0),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,secret,sizeof(secret)),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,input,sizeof(input)),OSSL_PARAM_construct_end()};
        REQUIRE("tls12/prf-independent-provider",EVP_KDF_derive(context,expected,sizeof(expected),parameters) == 1);
        CHECK("tls12/prf-standard-output",!core_tls12_prf(core_tls12_digest(hash),secret,sizeof(secret),label,seed,sizeof(seed),actual,sizeof(actual)) && !memcmp(actual,expected,sizeof(actual)));
        EVP_KDF_CTX_free(context); EVP_KDF_free(algorithm);
    }
}
static void cbc_mac_vectors(void) {
    uint8_t key[48],data[16640],expected[64],actual[64]; memset(key,7,sizeof(key));
    for (size_t i=0;i<sizeof(data);i++) data[i]=(uint8_t)(i%251);
    const unsigned hashes[]={1,4,5};
    const size_t sizes[]={0,1,42,43,44,50,51,52,63,64,100,106,107,108,114,115,116,127,128,255,256,16384};
    for (size_t h=0;h<3;h++) for (size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++) {
        size_t length=sizes[i];
        REQUIRE("tls12/cbc-reference-mac",!record_mac(core_tls12_digest(hashes[h]),key,0x0102030405060708,23,data,length,expected));
        for (size_t padding=1;padding<=256;padding++) {
            CHECK("tls12/cbc-constant-work-mac",!cbc_mac(hashes[h],key,0x0102030405060708,23,data,length+padding,length,actual) &&
                !memcmp(actual,expected,(size_t)EVP_MD_get_size(core_tls12_digest(hashes[h]))));
        }
    }
}
int main(void) {
    prf_vectors(); cbc_mac_vectors();
    uint8_t key[32],iv[12],mac_key[48],input[16384]; memset(key,7,sizeof(key)); memset(iv,9,sizeof(iv)); memset(mac_key,11,sizeof(mac_key));
    for (size_t i=0;i<sizeof(input);i++) input[i]=(uint8_t)(i%251);
    const size_t lengths[]={0,1,15,16,17,255,256,4095,16384};
    size_t count=0;
    for (;core_tls12_suite_at(count);count++) {
        const core_tls12_suite_t *suite=core_tls12_suite_at(count);
        CHECK("tls12/suite-lookup",core_tls12_suite(suite->id) == suite);
        for (int etm=0;etm< (suite->cipher == CORE_TLS12_CBC ? 2 : 1);etm++) for (size_t i=0;i<sizeof(lengths)/sizeof(*lengths);i++) {
            uint64_t sent=0,received=0; uint8_t *record=NULL,*plain=NULL; size_t size=0,plain_size=0,length=lengths[i];
            REQUIRE("tls12/record-encrypt",!core_tls12_record_seal(suite,etm,key,iv,mac_key,&sent,23,input,length,&record,&size));
            CHECK("tls12/record-sequence",sent == 1 && size>5 && record[0] == 23 && record[1] == 3 && record[2] == 3);
            REQUIRE("tls12/record-decrypt",!core_tls12_record_open(suite,etm,key,iv,mac_key,&received,23,record+5,size-5,&plain,&plain_size));
            CHECK("tls12/record-roundtrip",received == 1 && plain_size == length && !memcmp(plain,input,length));
            free(plain); plain=NULL;
            for (size_t index=5;index<size;index+=size>100 ? size/20 : 1) {
                record[index]^=1; received=0;
                CHECK("tls12/tampered-record-rejected",core_tls12_record_open(suite,etm,key,iv,mac_key,&received,23,record+5,size-5,&plain,&plain_size) < 0 && !plain && !plain_size && !received);
                record[index]^=1;
            }
            received=0;
            CHECK("tls12/record-type-authenticated",core_tls12_record_open(suite,etm,key,iv,mac_key,&received,21,record+5,size-5,&plain,&plain_size) < 0 && !plain && !received);
            CHECK("tls12/record-truncated",core_tls12_record_open(suite,etm,key,iv,mac_key,&received,23,record+5,size-6,&plain,&plain_size) < 0 && !plain && !received);
            received=UINT64_C(1)<<24;
            CHECK("tls12/receive-hard-key-limit",core_tls12_record_open(suite,etm,key,iv,mac_key,&received,23,record+5,size-5,&plain,&plain_size) < 0 && !plain);
            free(record); record=NULL; sent=UINT64_C(1)<<24;
            CHECK("tls12/send-hard-key-limit",core_tls12_record_seal(suite,etm,key,iv,mac_key,&sent,23,input,length,&record,&size) < 0 && !record);
        }
    }
    CHECK("tls12/all-applicable-cipher-suites",count == 27);
    CHECK("tls12/unknown-suite-rejected",!core_tls12_suite(0xffff));
    return test_result();
}
