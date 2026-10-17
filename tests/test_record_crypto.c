#include "check.h"
#include "tls_fixture.h"

static unsigned cipher_creations,fail_cipher,fail_resize;
static void *watched_buffer;
static unsigned watched_cleanses;
EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
void __real_OPENSSL_cleanse(void *,size_t);
void __wrap_OPENSSL_cleanse(void *data,size_t length) {
    if (data == watched_buffer && length) watched_cleanses++;
    __real_OPENSSL_cleanse(data,length);
}
void *__real_realloc(void *,size_t);
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void) {
    cipher_creations++;
    if (fail_cipher) { fail_cipher=0; errno=ENOMEM; return NULL; }
    return __real_EVP_CIPHER_CTX_new();
}
void *__wrap_realloc(void *data,size_t length) {
    if (fail_resize) { fail_resize=0; errno=ENOMEM; return NULL; }
    return __real_realloc(data,length);
}
int __wrap_RAND_bytes(unsigned char *data,int length) {
    for (int i=0;i<length;i++) data[i]=(unsigned char)i;
    return 1;
}

static void records(unsigned suite,int etm) {
    tls13_conn_t owner={.crypto_reuse=1,.tls_auth_state=4,.tls12_etm=etm};
    if (suite >= 0x1301 && suite <= 0x1303) REQUIRE("crypto/tls13-suite",!configure_tls_cipher(&owner,(uint16_t)suite));
    else { owner.tls12_suite=core_tls12_suite(suite); REQUIRE("crypto/tls12-suite",owner.tls12_suite != NULL); }
    uint8_t data[16384]; for (size_t i=0;i<sizeof(data);i++) data[i]=(uint8_t)i;
    const size_t lengths[]={0,1,63,1186,8192,16384,17,8192};
    for (size_t index=0;index<sizeof(lengths)/sizeof(*lengths);index++) {
        tls13_conn_t reference=owner; reference.crypto_reuse=0;
        uint8_t *expected=NULL,*wire=NULL,*plain=NULL,inner=0; size_t expected_length=0,wire_length=0,plain_length=0,length=lengths[index];
        REQUIRE("crypto/reference-seal",!encrypt_record(&reference,reference.c_app_key,reference.c_app_iv,&reference.c_app_seq,23,data,length,&expected,&expected_length));
        REQUIRE("crypto/owned-seal",!tls_record_seal_owned(&owner,23,data,length,&wire,&wire_length));
        CHECK("crypto/reused-context-preserves-wire",wire_length == expected_length && !memcmp(wire,expected,wire_length)); free(expected);
        EVP_CIPHER_CTX *writer=owner.record_encrypt; uint64_t sequence=owner.s_app_seq;
        wire[wire_length-1]^=1;
        CHECK("crypto/tag-failure-keeps-sequence",tls_record_open_owned(&owner,wire[0],wire+5,wire_length-5,&plain,&plain_length,&inner) < 0 && !plain && !plain_length && owner.s_app_seq == sequence);
        CHECK("crypto/tag-failure-resets-reader-only",owner.record_decrypt && !EVP_CIPHER_CTX_cipher(owner.record_decrypt) && owner.record_encrypt == writer && EVP_CIPHER_CTX_cipher(writer));
        unsigned dirty=0; for (size_t i=0;i<owner.record_plain.cap;i++) dirty|=owner.record_plain.data[i];
        CHECK("crypto/tag-failure-clears-capacity",!dirty);
        wire[wire_length-1]^=1;
        REQUIRE("crypto/owned-open-after-reset",!tls_record_open_owned(&owner,wire[0],wire+5,wire_length-5,&plain,&plain_length,&inner));
        CHECK("crypto/owned-roundtrip",inner == 23 && plain_length == length && !memcmp(plain,data,length));
        CHECK("crypto/directions-own-distinct-contexts",owner.record_encrypt != owner.record_decrypt);
        size_t used,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&used,&reserved);
        CHECK("crypto/work-capacity-is-accounted",used == owner.record_output.cap+owner.record_plain.cap && !reserved && owner.record_output.cap <= 18944 && owner.record_plain.cap <= 18944);
    }
    uint8_t *wire=NULL,*plain=NULL,inner; size_t length=0,plain_length=0;
    REQUIRE("crypto/warm-record",!tls_record_seal_owned(&owner,23,data,8192,&wire,&length) && !tls_record_open_owned(&owner,wire[0],wire+5,length-5,&plain,&plain_length,&inner));
    unsigned before=cipher_creations;
    for (unsigned i=0;i<64;i++) REQUIRE("crypto/warm-record-exchange",!tls_record_seal_owned(&owner,23,data,8192,&wire,&length) && !tls_record_open_owned(&owner,wire[0],wire+5,length-5,&plain,&plain_length,&inner));
    CHECK("crypto/warm-records-create-no-contexts",cipher_creations == before);
    uint8_t short_buffer[8]; uint64_t sequence=owner.c_app_seq; size_t count=99;
    CHECK("crypto/short-buffer-keeps-sequence",encrypt_record_into(&owner,owner.record_encrypt,owner.c_app_key,owner.c_app_iv,&owner.c_app_seq,23,data,8192,short_buffer,sizeof(short_buffer),&count) < 0 && !count && owner.c_app_seq == sequence);
    tls_handshake_material_clear(&owner);
    CHECK("crypto/handshake-exit-resets-contexts",!EVP_CIPHER_CTX_cipher(owner.record_encrypt) && !EVP_CIPHER_CTX_cipher(owner.record_decrypt));
    tls_record_work_clear(&owner);
    size_t used,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&used,&reserved);
    CHECK("crypto/close-releases-all-work-capacity",!used && !reserved && !owner.record_encrypt && !owner.record_decrypt);
}

static void failures(void) {
    for (unsigned fault=0;fault<2;fault++) {
        tls13_conn_t owner={.crypto_reuse=1,.tls_auth_state=4}; REQUIRE("crypto/fault-suite",!configure_tls_cipher(&owner,0x1303));
        uint8_t *wire=NULL; size_t length=0; fail_resize=!fault; fail_cipher=fault;
        CHECK("crypto/allocation-failure-no-result",tls_record_seal_owned(&owner,23,(const uint8_t *)"vless-core",10,&wire,&length) < 0 && !wire && !length && !owner.c_app_seq);
        fail_resize=fail_cipher=0; tls_record_work_clear(&owner);
        size_t used,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&used,&reserved);
        CHECK("crypto/allocation-failure-releases-budget",!used && !reserved);
    }
    core_buffer_budget_t pressure={0}; REQUIRE("crypto/pressure-budget",!core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,CORE_BUFFER_TOTAL_LIMIT));
    tls13_conn_t owner={.crypto_reuse=1,.tls_auth_state=4}; REQUIRE("crypto/pressure-suite",!configure_tls_cipher(&owner,0x1303));
    uint8_t *wire=NULL; size_t length=0;
    CHECK("crypto/pressure-no-unaccounted-allocation",tls_record_seal_owned(&owner,23,(const uint8_t *)"vless-core",10,&wire,&length) < 0 && errno == ENOBUFS && !owner.record_output.cap && !owner.c_app_seq);
    REQUIRE("crypto/pressure-release",!core_buffer_budget_clear(&pressure));
    REQUIRE("crypto/pressure-recovery",!tls_record_seal_owned(&owner,23,(const uint8_t *)"vless-core",10,&wire,&length));
    tls_record_work_clear(&owner);
}

static void key_and_owner_changes(void) {
    tls13_conn_t owner={.crypto_reuse=1,.tls_auth_state=3};
    REQUIRE("crypto/transition-suite",!configure_tls_cipher(&owner,0x1303));
    memset(owner.c_app_traffic,7,32); memcpy(owner.s_app_traffic,owner.c_app_traffic,32);
    REQUIRE("crypto/transition-keys",!derive_key_iv_md(owner.tls_md,owner.c_app_traffic,32,32,owner.c_app_key,owner.c_app_iv));
    memcpy(owner.s_app_key,owner.c_app_key,32); memcpy(owner.s_app_iv,owner.c_app_iv,12);
    uint8_t *wire=NULL,*plain=NULL,inner=0; size_t length=0,count=0;
    const uint8_t data[]="vless-core";
    REQUIRE("crypto/handshake-work-record",!tls_record_seal_owned(&owner,23,data,sizeof(data),&wire,&length) && !tls_record_open_owned(&owner,wire[0],wire+5,length-5,&plain,&count,&inner));
    CHECK("crypto/handshake-work-budget",owner.tls_handshake_bytes == owner.record_output.cap+owner.record_plain.cap && tls_buffer_bytes == owner.tls_handshake_bytes);
    EVP_CIPHER_CTX *writer=owner.record_encrypt,*reader=owner.record_decrypt;
    REQUIRE("crypto/rotate-retained-keys",!tls_update_keys(&owner,1) && !tls_update_keys(&owner,0));
    CHECK("crypto/rotate-resets-not-replaces-contexts",owner.record_encrypt == writer && owner.record_decrypt == reader && !EVP_CIPHER_CTX_cipher(writer) && !EVP_CIPHER_CTX_cipher(reader) && !owner.c_app_seq && !owner.s_app_seq);
    owner.tls_auth_state=4;
    core_buffer_budget_t input={0},output={0};
    REQUIRE("crypto/pool-work-budgets",!core_buffer_budget_init(&input,CORE_BUFFER_DOWNLOAD,0) && !core_buffer_budget_init(&output,CORE_BUFFER_UPLOAD,0));
    owner.input_memory=&input; owner.output_memory=&output;
    REQUIRE("crypto/rotated-record",!tls_record_seal_owned(&owner,23,data,sizeof(data),&wire,&length) && !tls_record_open_owned(&owner,wire[0],wire+5,length-5,&plain,&count,&inner));
    CHECK("crypto/rotated-record-payload",inner == 23 && count == sizeof(data) && !memcmp(plain,data,count));
    CHECK("crypto/work-moves-to-pool-budget",!owner.tls_handshake_bytes && !tls_buffer_bytes && output.allocated == owner.record_output.cap && input.allocated == owner.record_plain.cap && !owner.record_memory.allocated);
    watched_buffer=owner.record_output.data; watched_cleanses=0;
    REQUIRE("crypto/reuse-ciphertext-work",!tls_record_seal_owned(&owner,23,data,sizeof(data),&wire,&length));
    CHECK("crypto/ciphertext-needs-no-hot-wipe",!watched_cleanses);
    OPENSSL_cleanse(owner.record_plain.data,owner.record_plain.cap); owner.record_plain.len=0;
    watched_buffer=owner.record_plain.data; watched_cleanses=0;
    REQUIRE("crypto/reuse-clean-plaintext-work",!tls_record_open_owned(&owner,wire[0],wire+5,length-5,&plain,&count,&inner));
    CHECK("crypto/clean-plaintext-is-not-wiped-twice",!watched_cleanses && count == sizeof(data) && !memcmp(plain,data,count));
    watched_buffer=NULL;
    REQUIRE("crypto/change-cipher",!configure_tls_cipher(&owner,0x1301));
    REQUIRE("crypto/changed-cipher-record",!tls_record_seal_owned(&owner,23,data,sizeof(data),&wire,&length) && !tls_record_open_owned(&owner,wire[0],wire+5,length-5,&plain,&count,&inner));
    CHECK("crypto/change-cipher-reinitializes-contexts",owner.record_encrypt == writer && owner.record_decrypt == reader && EVP_CIPHER_CTX_nid(writer) == EVP_CIPHER_nid(EVP_aes_128_gcm()) && EVP_CIPHER_CTX_nid(reader) == EVP_CIPHER_CTX_nid(writer) && count == sizeof(data) && !memcmp(plain,data,count));
    tls_record_work_clear(&owner);
    CHECK("crypto/pool-close-releases-work",!input.allocated && !output.allocated && !owner.tls_handshake_bytes && !tls_buffer_bytes);
    REQUIRE("crypto/pool-budget-clear",!core_buffer_budget_clear(&input) && !core_buffer_budget_clear(&output));
}

int main(void) {
    for (unsigned suite=0x1301;suite<=0x1303;suite++) records(suite,0);
    for (size_t index=0;core_tls12_suite_at(index);index++) {
        const core_tls12_suite_t *suite=core_tls12_suite_at(index);
        for (int etm=0;etm<(suite->cipher == CORE_TLS12_CBC ? 2 : 1);etm++) records(suite->id,etm);
    }
    failures(); key_and_owner_changes(); return test_result();
}
