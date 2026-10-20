#include "check.h"
#include "vmess.h"
#include "utils.h"
#include "../src/vmess_internal.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

int __real_RAND_bytes(unsigned char *,int);
void *__real_malloc(size_t);
void *__real_realloc(void *,size_t);
EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
static int random_fail,allocation_fail,context_fail;
static unsigned random_position;
int __wrap_RAND_bytes(unsigned char *output,int length) {
    if (random_fail) return 0;
    for (int i=0;i<length;i++) output[i]=(uint8_t)random_position++;
    return 1;
}
void *__wrap_malloc(size_t size) { if (allocation_fail) { errno=ENOMEM; return NULL; } return __real_malloc(size); }
void *__wrap_realloc(void *data,size_t size) { if (allocation_fail) { errno=ENOMEM; return NULL; } return __real_realloc(data,size); }
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void) { return context_fail ? NULL : __real_EVP_CIPHER_CTX_new(); }

static core_vmess_header_t header(core_vmess_security_t security) {
    core_vmess_header_t value={.ready=1,.security=security};
    for (unsigned i=0;i<16;i++) value.request_key[i]=value.response_key[i]=(uint8_t)i,value.request_iv[i]=value.response_iv[i]=(uint8_t)(16+i);
    return value;
}

static int receive(core_vmess_body_t *body,const uint8_t *wire,size_t size,size_t fragment,uint8_t *output,size_t *written) {
    size_t offset=0; *written=0;
    while (offset<size || body->plain_length) {
        if (body->plain_length) {
            size_t got=0;
            if (core_vmess_body_read(body,output+*written,31,&got)) return -1;
            *written+=got; continue;
        }
        uint8_t *destination; size_t capacity;
        if (core_vmess_body_prepare(body,&destination,&capacity)) return -1;
        if (!capacity) { errno=EPROTO; return -1; }
        size_t take=size-offset;
        if (take > capacity) take=capacity;
        if (take > fragment) take=fragment;
        memcpy(destination,wire+offset,take); offset+=take;
        if (core_vmess_body_commit(body,take)) return -1;
    }
    return 0;
}

static void vectors(void) {
    const char *expected[]={
        "8e739d3ecdca9a91f13b0d502be14505dfbe2dd4de1d95f19597ba58acd8ab0183000102030405060708090a0b0c0d0e0f10",
        "8e73e9de6f49187cc2fd3924770f46360c94c95a8bc51bb435194c8de1c431c87f000102030405060708090a0b0c0d0e0f10",
        "fc9e564d657373204145414420626f6479","564d657373204145414420626f6479"};
    const uint8_t input[]="VMess AEAD body";
    for (unsigned mode=0;mode<4;mode++) {
        core_vmess_header_t config=header((core_vmess_security_t)(mode+3));
        core_vmess_body_t outgoing={0}; uint8_t wire[8192],golden[8192],plain[8192]; size_t consumed,written,length;
        REQUIRE("vmess/body-state",!core_vmess_body_init(&outgoing,&config,1,NULL)); random_position=0;
        REQUIRE("vmess/body-encode",!core_vmess_body_encode(&outgoing,input,sizeof(input)-1,&consumed,wire,sizeof(wire),&written,0));
        REQUIRE("vmess/body-vector-hex",!hex_to_bytes(expected[mode],golden,sizeof(golden),&length));
        CHECK("vmess/body-independent-wire-vector",consumed == sizeof(input)-1 && written == length && !memcmp(wire,golden,length));
        core_vmess_body_clear(&outgoing);
        for (size_t step=1;step<=8192;step*=4) {
            core_vmess_body_t incoming={0}; size_t decoded;
            REQUIRE("vmess/body-decoder",!core_vmess_body_init(&incoming,&config,0,NULL));
            REQUIRE("vmess/body-fragmented-record",!receive(&incoming,golden,length,step,plain,&decoded));
            CHECK("vmess/body-record-boundary",decoded == sizeof(input)-1 && !memcmp(plain,input,decoded) && !core_vmess_body_eof(&incoming));
            core_vmess_body_clear(&incoming);
        }
    }
}

static void exchanges(void) {
    uint8_t input[65536],plain[65536],wire[8192];
    for (size_t i=0;i<sizeof(input);i++) input[i]=(uint8_t)(i*13);
    for (unsigned mode=3;mode<=6;mode++) {
        core_vmess_header_t config=header((core_vmess_security_t)mode);
        core_vmess_body_t outgoing={0},incoming={0}; size_t sent=0,received=0;
        REQUIRE("vmess/body-roundtrip-states",!core_vmess_body_init(&outgoing,&config,1,NULL) && !core_vmess_body_init(&incoming,&config,0,NULL));
        while (sent<sizeof(input)) {
            size_t consumed,written,decoded;
            REQUIRE("vmess/body-bounded-chunks",!core_vmess_body_encode(&outgoing,input+sent,sizeof(input)-sent,&consumed,wire,sizeof(wire),&written,0) && written <= sizeof(wire) && consumed);
            REQUIRE("vmess/body-roundtrip-chunk",!receive(&incoming,wire,written,1,plain+received,&decoded)); sent+=consumed; received+=decoded;
        }
        CHECK("vmess/body-roundtrip-exact",received == sizeof(input) && !memcmp(plain,input,sizeof(input)));
        size_t consumed,written,decoded;
        REQUIRE("vmess/body-termination",!core_vmess_body_encode(&outgoing,NULL,0,&consumed,wire,sizeof(wire),&written,1));
        if (written) REQUIRE("vmess/body-termination-authenticated",!receive(&incoming,wire,written,1,plain,&decoded) && !decoded && incoming.finished);
        CHECK("vmess/body-terminal-boundary",!core_vmess_body_eof(&incoming));
        CHECK("vmess/body-no-data-after-end",core_vmess_body_encode(&outgoing,input,1,&consumed,wire,sizeof(wire),&written,0) < 0 && !written && !consumed);
        core_vmess_body_clear(&outgoing); core_vmess_body_clear(&incoming);
        uint8_t zero[sizeof(incoming)]; memset(zero,0,sizeof(zero));
        CHECK("vmess/body-secrets-cleared",!memcmp(&incoming,zero,sizeof(incoming)) && !memcmp(&outgoing,zero,sizeof(outgoing)));
    }
}

static void failures(void) {
    uint8_t input[32]={1},wire[8192],plain[8192]; size_t consumed,written,decoded;
    core_vmess_header_t config=header(CORE_VMESS_AES128_GCM);
    for (unsigned kind=0;kind<3;kind++) {
        core_vmess_body_t body={0}; REQUIRE("vmess/body-failure-state",!core_vmess_body_init(&body,&config,1,NULL));
        random_fail=kind == 0; context_fail=kind == 1; body.counter=kind == 2 ? 65535 : 0;
        CHECK("vmess/body-rng-context-counter-failures",core_vmess_body_encode(&body,input,sizeof(input),&consumed,wire,sizeof(wire),&written,0) < 0 && !consumed && !written && body.failed);
        random_fail=context_fail=0; core_vmess_body_clear(&body);
    }
    core_vmess_body_t sender={0};
    REQUIRE("vmess/body-corruption-sender",!core_vmess_body_init(&sender,&config,1,NULL)); random_position=0;
    REQUIRE("vmess/body-corruption-wire",!core_vmess_body_encode(&sender,input,sizeof(input),&consumed,wire,sizeof(wire),&written,0));
    for (size_t corrupt=2;corrupt<2+sizeof(input)+16;corrupt++) {
        core_vmess_body_t receiver={0}; REQUIRE("vmess/body-corruption-receiver",!core_vmess_body_init(&receiver,&config,0,NULL));
        wire[corrupt]^=1;
        CHECK("vmess/body-invalid-tag-no-plaintext",receive(&receiver,wire,written,1,plain,&decoded) < 0 && !decoded && receiver.failed && receiver.counter == 0);
        wire[corrupt]^=1; core_vmess_body_clear(&receiver);
    }
    for (size_t cut=1;cut<written;cut++) {
        core_vmess_body_t receiver={0}; REQUIRE("vmess/body-truncation-receiver",!core_vmess_body_init(&receiver,&config,0,NULL));
        REQUIRE("vmess/body-truncation-fragments",!receive(&receiver,wire,cut,1,plain,&decoded));
        CHECK("vmess/body-truncated-header-ciphertext-tag-padding",core_vmess_body_eof(&receiver) < 0 && !decoded);
        core_vmess_body_clear(&receiver);
    }
    core_vmess_body_clear(&sender);
    REQUIRE("vmess/body-counter-last-state",!core_vmess_body_init(&sender,&config,1,NULL)); sender.counter=65535;
    CHECK("vmess/body-last-nonce-for-termination",!core_vmess_body_encode(&sender,NULL,0,&consumed,wire,sizeof(wire),&written,1) && sender.counter == 65536);
    core_vmess_body_clear(&sender);
    REQUIRE("vmess/body-counter-exhausted-state",!core_vmess_body_init(&sender,&config,1,NULL)); sender.counter=65536;
    CHECK("vmess/body-no-nonce-wrap",core_vmess_body_encode(&sender,NULL,0,&consumed,wire,sizeof(wire),&written,1) < 0 && errno == EOVERFLOW);
    core_vmess_body_clear(&sender);
}

static void resources(void) {
    size_t used_before,reserved_before,used_after,reserved_after;
    core_buffer_snapshot(CORE_BUFFER_RELAY,&used_before,&reserved_before);
    core_buffer_budget_t memory={0},filler={0};
    REQUIRE("vmess/body-budgets",!core_buffer_budget_init(&memory,CORE_BUFFER_RELAY,0) && !core_buffer_budget_init(&filler,CORE_BUFFER_RELAY,0));
    core_vmess_header_t config=header(CORE_VMESS_NONE); core_vmess_body_t sender={0},receiver={0};
    uint8_t wire[8192],data[32]={0},*span; size_t consumed,written,capacity;
    REQUIRE("vmess/body-budget-encoder",!core_vmess_body_init(&sender,&config,1,NULL));
    REQUIRE("vmess/body-budget-wire",!core_vmess_body_encode(&sender,data,sizeof(data),&consumed,wire,sizeof(wire),&written,0));
    REQUIRE("vmess/body-budget-decoder",!core_vmess_body_init(&receiver,&config,0,&memory));
    REQUIRE("vmess/body-budget-header",!core_vmess_body_prepare(&receiver,&span,&capacity) && capacity == 2);
    memcpy(span,wire,2); REQUIRE("vmess/body-budget-length",!core_vmess_body_commit(&receiver,2));
    CHECK("vmess/body-no-preallocation",!memory.allocated);
    REQUIRE("vmess/body-fill-budget",!core_buffer_hold(&filler,core_buffer_available(CORE_BUFFER_RELAY)));
    CHECK("vmess/body-budget-waits-without-consuming",core_vmess_body_prepare(&receiver,&span,&capacity) < 0 && errno == ENOBUFS && !receiver.failed && !memory.allocated);
    core_buffer_drop(&filler,filler.allocated);
    REQUIRE("vmess/body-budget-recovers",!core_vmess_body_prepare(&receiver,&span,&capacity) && capacity == sizeof(data));
    memcpy(span,wire+2,capacity); REQUIRE("vmess/body-budget-resumed-record",!core_vmess_body_commit(&receiver,capacity));
    uint8_t output[sizeof(data)]; size_t got=0;
    CHECK("vmess/body-budget-resumed-data",!core_vmess_body_read(&receiver,output,sizeof(output),&got) && got == sizeof(data) && !memcmp(output,data,got));
    core_vmess_body_clear(&receiver);
    REQUIRE("vmess/body-allocator-new-state",!core_vmess_body_init(&receiver,&config,0,&memory) && !core_vmess_body_prepare(&receiver,&span,&capacity));
    memcpy(span,wire,2); REQUIRE("vmess/body-allocator-header",!core_vmess_body_commit(&receiver,2));
    allocation_fail=1;
    CHECK("vmess/body-allocation-failure",core_vmess_body_prepare(&receiver,&span,&capacity) < 0 && receiver.failed && !memory.allocated);
    allocation_fail=0;
    core_vmess_body_clear(&receiver); core_vmess_body_clear(&sender); core_buffer_budget_clear(&memory); core_buffer_budget_clear(&filler);
    core_buffer_snapshot(CORE_BUFFER_RELAY,&used_after,&reserved_after);
    CHECK("vmess/body-budget-restored",used_after == used_before && reserved_after == reserved_before);
}

static void boundaries(void) {
    core_vmess_header_t config=header(CORE_VMESS_AES128_GCM);
    uint8_t wire[16386],input[16384],plain[16384],nonce[12]={0},mask[4]; size_t count,decoded;
    for (size_t i=0;i<sizeof(input);i++) input[i]=(uint8_t)i;
    memcpy(nonce+2,config.request_iv+2,10);
    EVP_MD_CTX *hash=EVP_MD_CTX_new();
    REQUIRE("vmess/body-boundary-mask",hash && EVP_DigestInit_ex(hash,EVP_shake128(),NULL) == 1 && EVP_DigestUpdate(hash,config.request_iv,16) == 1 && EVP_DigestFinalXOF(hash,mask,sizeof(mask)) == 1);
    EVP_MD_CTX_free(hash);
    size_t padding=(((unsigned)mask[0]<<8)|mask[1])%64;
    unsigned size_mask=((unsigned)mask[2]<<8)|mask[3];
    unsigned size=16384^size_mask; wire[0]=(uint8_t)(size>>8); wire[1]=(uint8_t)size;
    EVP_CIPHER_CTX *cipher=EVP_CIPHER_CTX_new();
    REQUIRE("vmess/body-max-peer-record",cipher && !core_vmess_aead(cipher,EVP_aes_128_gcm(),1,config.request_key,nonce,NULL,0,input,16384-16-padding,wire+2,&count));
    EVP_CIPHER_CTX_free(cipher); memset(wire+2+count,0,padding);
    core_vmess_body_t receiver={0}; REQUIRE("vmess/body-max-peer-decoder",!core_vmess_body_init(&receiver,&config,0,NULL));
    CHECK("vmess/body-max-peer-data",!receive(&receiver,wire,sizeof(wire),7,plain,&decoded) && decoded == 16384-16-padding && !memcmp(plain,input,decoded));
    CHECK("vmess/body-large-capacity-released",!receiver.block.capacity && !core_vmess_body_eof(&receiver));
    core_vmess_body_clear(&receiver);
    for (unsigned invalid=0;invalid<2;invalid++) {
        REQUIRE("vmess/body-invalid-size-state",!core_vmess_body_init(&receiver,&config,0,NULL));
        size=(invalid ? 16385 : 0)^size_mask; wire[0]=(uint8_t)(size>>8); wire[1]=(uint8_t)size;
        CHECK("vmess/body-size-rejected-before-allocation",receive(&receiver,wire,2,2,plain,&decoded) < 0 && !decoded && !receiver.block.capacity);
        core_vmess_body_clear(&receiver);
    }
    REQUIRE("vmess/body-receive-exhausted-state",!core_vmess_body_init(&receiver,&config,0,NULL)); receiver.counter=65536;
    size=(16+(unsigned)padding)^size_mask; wire[0]=(uint8_t)(size>>8); wire[1]=(uint8_t)size;
    CHECK("vmess/body-receive-counter-checked-before-crypto",receive(&receiver,wire,2,2,plain,&decoded) < 0 && errno == EOVERFLOW && !receiver.context && !receiver.block.capacity);
    core_vmess_body_clear(&receiver);
    core_vmess_body_t sender={0}; REQUIRE("vmess/body-capacity-state",!core_vmess_body_init(&sender,&config,1,NULL));
    core_vmess_shake_t before=sender.mask; size_t consumed,written;
    CHECK("vmess/body-small-output-does-not-advance",core_vmess_body_encode(&sender,input,32,&consumed,wire,1,&written,0) < 0 && !written && !consumed && !sender.counter && !memcmp(&before,&sender.mask,sizeof(before)) && !sender.failed);
    CHECK("vmess/body-small-output-retry",!core_vmess_body_encode(&sender,input,32,&consumed,wire,sizeof(wire),&written,0) && consumed == 32);
    core_vmess_body_clear(&sender);
}

int main(void) {
    vectors(); exchanges(); failures(); resources(); boundaries();
    return test_result();
}
