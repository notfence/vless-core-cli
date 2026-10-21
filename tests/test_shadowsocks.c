#include "check.h"
#include "../src/shadowsocks_internal.h"
#include "utils.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <stdint.h>

static unsigned random_calls,random_fail;
static int allocation_fail,context_fail,random_mode;
static unsigned cipher_calls;
static int64_t fixed_time=INT64_C(1700000000);
int __real_RAND_bytes(unsigned char *,int);
void *__real_malloc(size_t);
void *__real_realloc(void *,size_t);
EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
int __real_EVP_CipherUpdate(EVP_CIPHER_CTX *,unsigned char *,int *,const unsigned char *,int);
int __wrap_RAND_bytes(unsigned char *output,int length) {
    if (++random_calls == random_fail) return 0;
    if (random_mode) memset(output,random_mode == 1 ? 0 : 255,(size_t)length);
    else if (length == 4) { uint32_t value=906; memcpy(output,&value,4); }
    else for (int i=0;i<length;i++) output[i]=(uint8_t)i;
    return 1;
}
void *__wrap_malloc(size_t size) { if (allocation_fail) { errno=ENOMEM; return NULL; } return __real_malloc(size); }
void *__wrap_realloc(void *data,size_t size) { if (allocation_fail) { errno=ENOMEM; return NULL; } return __real_realloc(data,size); }
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void) { return context_fail ? NULL : __real_EVP_CIPHER_CTX_new(); }
int __wrap_EVP_CipherUpdate(EVP_CIPHER_CTX *context,unsigned char *output,int *written,const unsigned char *input,int length) { cipher_calls++; return __real_EVP_CipherUpdate(context,output,written,input,length); }
int64_t __wrap_core_ss_time(void) { return fixed_time; }

static const struct { const char *request,*response,*identity; } vectors[]={
    {"000102030405060708090a0b0c0d0e0f6b81f713c964fddff8b62244a165686fbdbd8f8397234bbe9868572178b634eac27a8d21b4575c4f093a21b1e8ec052ee6f0f66fe77e0a7179dd53d098c83781036a3195c08d4c4e8786a7086a6710f2c547a2bc80b8f2df3162b5d13b63574d55c0f83ce64a556a2ef2589d60343c73ba50d122","404142434445464748494a4b4c4d4e4f266d2a80c7fd99dcfb3249967bd3313c87b484aba1bfca2a4f531230507f8c9a29cc6c1f2965dcd86e2c965e8072c5dfa53b96279ffa3143f473a0462602c5ebd29348ea83ef8091b9a031b6d9de1045955e660ab6bb5e90e265e429d9",""},
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f367981b56fb0ebaf09ef3dd3363e95ad0b12c3a18ce10c78e2651d862d8440dd98a83a4a1e8fcb67123664707f650b67b3b5c26f343841ad40ee797d0049cb2655618ec3846ddd8ebec22edbef905a9b6eb1d2363b56dc8d1901aadbf70fa26f47e374142f96029087ec3a5dcb7ddc712a24f963","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f97d9cda78b3058c4c80942593103c6be1ccfc0cabf16cf4b6c14c50609fdf2937d81f0cad506b0354484d5cba15bdd47a6f6ce1e154b43753f109974a8ec8d15f130647b33547bb95c2d23e6baa70ceb1b35a223a27867315c0394ce70",""},
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb8f5ac4545dc24c21c5e5be443754045823acfcb77ea23f4c1f905bffa8d43f419e5d459593d80cda9d1e2d80616be5012f6b570797a190d028d04a1b90ee142507f5a3595f9e103cb6961930b79d52521557eda721b12e83041f4ab7002bbb2f49081fc36f81df0fdd3de5d060639e2691ad356","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fdd1c85d79776394c72ca12d3c51cf04e1621df730e6229883f03a4d5773705f4d14be91717c769bd40f0f5f96df7036daf866ee3d2612e3ea8c1b54352433cde51278f818b3613ee7c381f4909f3870a065210c2cf3dd3c179df20b4cf",""},
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f3fb6a3744ebe7283ff69c3ea5e0df583a4f32a8c0b5ca3319f1c0d35f7398e8dedc88f3b8a5a8a1ae1142dcc31494d546ef245ea427881f0c4956beaf33e21836e9fe539abdf5f35f9119299c737c217342b3a43036c9d6ee4af22a29852ca5792aa5f2ba60641e3281abdabbc5c5e974c097ea0","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f20f2657210cfa465f93243672e22e04a1f817fb71e20f3f537840429124fbb18d804e65c599219403b6561e411e2946e7ae35f7efc725b8642b55d8909796c7642ab1ced2cee5024c72827d7edf4818d788ffa7fc60e18f83edfdd80e5",""},
    {"000102030405060708090a0b0c0d0e0f35862b4f511b18084f6b655144b66e4a58e0832eb8e26440e790ed47ff0442785a13da7d261e43c580e797e481c331b8994dcd928732ced0b895e681daf98636d79d3babc62b5180ac4e61ee0c86b835138d31b308dd206db40816e2e5eaadddfbaa05d1d1a066d59cabb00cc19bb10a6ce3966a24ebde48bf942cd9e0a40c75cca3de7d12b4","404142434445464748494a4b4c4d4e4fb2ccc846e965a2bc8775985da611ffac72d16ed35d9ee9508c17579870b357873c7c2d34fefcc1cae5b62d8d89307aff609adc567cf3332abade20c0087287def15fff9333c83a90a9baa63c07f795de3e3d985ed03519bacaef44ec5794369f1629e838ba7144e5beeb0b0239618cabcb2b217775be","e162f5cf066e0bc15e126a3ee18d0e0f"},
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f8ad2318b967481973d90942edda6673d56f87635ae2d97f8947262e3f71bb81b1f01b424be8c2b9a2affbb794c7aafafbaa1b80a8f958e6a174e8dba8c8d38f6de47cbc8c3c1854d613c89c9f6c2f2ed3f9854fcb96b74a1eae2b77b4a60c0cd10d8012f2dc6027ca57869fe3cd55ea1fd630e293f88cfdf086c5e040d0c40fb7eb84945e570","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6874e6d351c385cfdec5657e74cdd8d6e213ca4c516d9791abe084c67b686072adf59e1ba989c7d388a03b55da9dfcc993414b06bea8bee33b128dee3f9a95589ef11e29b1b4b65cd441ae72513e3fac4257631de3b76795a76c2aaa26b57fb3828fa64012b40823a74903e5332a1f3edfb09d378774b75f7dd01d162838281094c8165e2b03","56361b801fbd5f0ac55e86a29a328d5b"},
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f9f2a5c3e72a7e63734879afd4bf3b274c827f761d833124970d438c73a321806ec398693f7b4f020e461c208fae8d074b78dbc8b4f016949cb4f973f21657df8f515a6f0fee12b157db1b4acf5ea3825fad6b56970e6abbc58e6194a9f4ce8c5dcc0ff17a0693cd9a791fa8210cba2654013a916f954836fd48269942c0578201812b7c872c4","404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fd8b69a4c76f623b46df89be78ef143d0ce97372ce44fdcedd8b829ca033b1b58b6769b8a7aabf76667ef716640327662ec5d470d461740c24e50f6bec84bf80917d441239339744abb0ace2a45e9ab49067441e83d293f8d98e8b3a9891e8c69f8ac91b93387aa1582d5aaaf75e3a70dfbfb03a1e6d3408558f744443dbb6912f69c76ca14ca",""}
};

static size_t unhex(const char *text,uint8_t *output,size_t capacity) {
    size_t length=0; REQUIRE("shadowsocks/codec-vector-hex",!hex_to_bytes(text,output,capacity,&length)); return length;
}

static int receive(core_ss_body_t *body,const uint8_t *wire,size_t length,size_t fragment,uint8_t *plain,size_t capacity,size_t *written) {
    size_t offset=0; *written=0;
    while (offset<length || body->plain_length) {
        if (body->plain_length) {
            size_t take=capacity-*written,got=0; if (take>31) take=31;
            if (!take || core_ss_body_read(body,plain+*written,take,&got)) return -1;
            *written+=got; continue;
        }
        uint8_t *output=NULL; size_t available=0;
        if (core_ss_body_prepare(body,&output,&available) || !available) return -1;
        size_t take=length-offset; if (take>available) take=available; if (take>fragment) take=fragment;
        memcpy(output,wire+offset,take); offset+=take;
        if (core_ss_body_commit(body,take)) return -1;
    }
    return 0;
}

static void wire_vectors(void) {
    uint8_t keys[64],salt[32],wire[2048],expected[2048],plain[2048]; size_t written,consumed;
    for (size_t i=0;i<sizeof(keys);i++) keys[i]=(uint8_t)i;
    for (size_t i=0;i<sizeof(salt);i++) salt[i]=(uint8_t)i;
    const uint8_t first[]="\0\0Shadowsocks data",second[]="second payload",reply[]="\0\0first replysecond reply";
    for (unsigned method=0;method<7;method++) {
        core_ss_body_t outgoing={0};
        REQUIRE("shadowsocks/codec-sender",!core_ss_body_init(&outgoing,(core_ss_method_t)method,keys,1,NULL,NULL));
        random_calls=0;
        REQUIRE("shadowsocks/codec-request",!core_ss_request(&outgoing,keys,1,"example.test",443,first,sizeof(first)-1,wire,sizeof(wire),&written));
        size_t initial=written;
        REQUIRE("shadowsocks/codec-body",!core_ss_body_encode(&outgoing,second,sizeof(second)-1,&consumed,wire+initial,sizeof(wire)-initial,&written));
        size_t length=unhex(vectors[method].request,expected,sizeof(expected));
        CHECK("shadowsocks/codec-independent-request",consumed == sizeof(second)-1 && initial+written == length && !memcmp(wire,expected,length));
        core_ss_body_clear(&outgoing);
        for (size_t fragment=1;fragment<=2048;fragment*=4) {
            core_ss_body_t incoming={0}; size_t decoded=0;
            REQUIRE("shadowsocks/codec-receiver",!core_ss_body_init(&incoming,(core_ss_method_t)method,keys,0,salt,NULL));
            length=unhex(vectors[method].response,expected,sizeof(expected));
            REQUIRE("shadowsocks/codec-fragmented-response",!receive(&incoming,expected,length,fragment,plain,sizeof(plain),&decoded));
            CHECK("shadowsocks/codec-response-exact",decoded == sizeof(reply)-1 && !memcmp(plain,reply,decoded) && !core_ss_body_eof(&incoming));
            CHECK("shadowsocks/codec-response-authenticated",!core_ss_is_2022((core_ss_method_t)method) || incoming.response_ready);
            core_ss_body_clear(&incoming);
        }
        for (size_t truncate=1;truncate<length;truncate++) {
            core_ss_body_t incoming={0}; size_t decoded=0;
            REQUIRE("shadowsocks/codec-truncation-state",!core_ss_body_init(&incoming,(core_ss_method_t)method,keys,0,salt,NULL));
            int result=receive(&incoming,expected,truncate,3,plain,sizeof(plain),&decoded);
            int boundary=truncate == length-(sizeof("second reply")-1+34) || (!core_ss_is_2022((core_ss_method_t)method) && truncate == core_ss_key_size((core_ss_method_t)method));
            if (!result && !boundary) CHECK("shadowsocks/codec-truncated-elements",core_ss_body_eof(&incoming) < 0);
            core_ss_body_clear(&incoming);
        }
        for (size_t corrupt=0;corrupt<length;corrupt++) {
            core_ss_body_t incoming={0}; size_t decoded=0;
            REQUIRE("shadowsocks/codec-corruption-state",!core_ss_body_init(&incoming,(core_ss_method_t)method,keys,0,salt,NULL));
            expected[corrupt]^=1;
            CHECK("shadowsocks/codec-corrupt-record-rejected",receive(&incoming,expected,length,5,plain,sizeof(plain),&decoded) < 0);
            expected[corrupt]^=1; core_ss_body_clear(&incoming);
        }
        if (method == 4 || method == 5) {
            size_t key_size=core_ss_key_size((core_ss_method_t)method); uint8_t chain[64];
            for (size_t i=0;i<key_size;i++) chain[i]=(uint8_t)(i+32),chain[key_size+i]=(uint8_t)i;
            REQUIRE("shadowsocks/eih-sender",!core_ss_body_init(&outgoing,(core_ss_method_t)method,keys,1,NULL,NULL));
            REQUIRE("shadowsocks/eih-request",!core_ss_request(&outgoing,chain,2,"example.test",443,first,sizeof(first)-1,wire,sizeof(wire),&written));
            size_t identity=unhex(vectors[method].identity,expected,sizeof(expected));
            CHECK("shadowsocks/eih-independent-vector",identity == 16 && !memcmp(wire+key_size,expected,16));
            length=unhex(vectors[method].request,expected,sizeof(expected));
            CHECK("shadowsocks/eih-does-not-advance-aead-nonce",!memcmp(wire,expected,key_size) && !memcmp(wire+key_size+16,expected+key_size,initial-key_size));
            core_ss_body_clear(&outgoing);
        }
    }
}

static size_t seal(core_ss_method_t method,EVP_CIPHER_CTX *context,const uint8_t *key,uint8_t nonce[24],const uint8_t *plain,size_t length,uint8_t *wire) {
    size_t written=0;
    REQUIRE("shadowsocks/controlled-server-seal",!core_ss_crypt(context,method,key,nonce,1,plain,length,wire,length+16,&written));
    for (size_t i=0;i<core_ss_nonce_size(method);i++) if (++nonce[i]) break;
    return written;
}

static size_t response(core_ss_method_t method,const uint8_t *key,const uint8_t *request_salt,const uint8_t *plain,size_t length,int delta,int kind,int mismatch,int extra,uint8_t *wire) {
    uint8_t salt[32],subkey[32],nonce[24]={0},header[64]; size_t size=core_ss_key_size(method),written=size;
    for (size_t i=0;i<size;i++) salt[i]=(uint8_t)(i+64);
    memcpy(wire,salt,size);
    REQUIRE("shadowsocks/controlled-server-subkey",!core_ss_subkey(method,key,salt,subkey));
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new(); REQUIRE("shadowsocks/controlled-server-context",context != NULL);
    if (core_ss_is_2022(method)) {
        header[0]=(uint8_t)kind; uint64_t epoch=(uint64_t)(INT64_C(1700000000)+delta);
        for (unsigned i=0;i<8;i++) header[i+1]=(uint8_t)(epoch>>(56-i*8));
        memcpy(header+9,request_salt,size);
        if (mismatch) header[9]=(uint8_t)(header[9]+mismatch);
        header[9+size]=(uint8_t)(length>>8); header[10+size]=(uint8_t)length;
        written+=seal(method,context,subkey,nonce,header,11+size,wire+written);
    } else {
        header[0]=(uint8_t)(length>>8); header[1]=(uint8_t)length;
        written+=seal(method,context,subkey,nonce,header,2,wire+written);
    }
    written+=seal(method,context,subkey,nonce,plain,length,wire+written);
    if (extra) {
        const uint8_t next[]="after empty";
        header[0]=0; header[1]=sizeof(next)-1;
        written+=seal(method,context,subkey,nonce,header,2,wire+written);
        written+=seal(method,context,subkey,nonce,next,sizeof(next)-1,wire+written);
    }
    EVP_CIPHER_CTX_free(context); OPENSSL_cleanse(subkey,sizeof(subkey)); return written;
}

static void boundaries(void) {
    uint8_t *plain=malloc(70000),*wire=malloc(140000),*output=malloc(70000),key[32],salt[32];
    REQUIRE("shadowsocks/boundary-buffers",plain && wire && output);
    for (size_t i=0;i<70000;i++) plain[i]=(uint8_t)i;
    for (size_t i=0;i<32;i++) key[i]=(uint8_t)i,salt[i]=(uint8_t)i;
    const size_t lengths[]={0,1,15,16,255,8191,8192,8193,16383,16384,65535};
    for (unsigned method=0;method<7;method++) for (size_t sample=0;sample<sizeof(lengths)/sizeof(*lengths);sample++) {
        size_t length=lengths[sample],decoded=0;
        size_t size=response((core_ss_method_t)method,key,salt,plain,length,0,1,0,!length,wire);
        core_ss_body_t incoming={0};
        REQUIRE("shadowsocks/boundary-receiver",!core_ss_body_init(&incoming,(core_ss_method_t)method,key,0,salt,NULL));
        int result=receive(&incoming,wire,size,127,output,70000,&decoded);
        if (length>16383 && method<4) CHECK("shadowsocks/2017-length-cap",result<0 && incoming.failed && !decoded);
        else {
            CHECK("shadowsocks/record-size-boundaries",!result && decoded == (length ? length : sizeof("after empty")-1) && !memcmp(output,length ? plain : (const uint8_t *)"after empty",decoded));
            CHECK("shadowsocks/record-boundary-eof",!core_ss_body_eof(&incoming));
            CHECK("shadowsocks/large-buffer-released",incoming.block.capacity <= 8192);
        }
        core_ss_body_clear(&incoming);
    }
    for (unsigned method=4;method<7;method++) for (int kind=0;kind<6;kind++) {
        size_t length=response((core_ss_method_t)method,key,salt,plain,32,kind == 1 ? 31 : kind == 2 ? -31 : kind == 5 ? 30 : 0,kind == 0 ? 0 : 1,kind == 3 ? 1 : kind == 4 ? -1 : 0,0,wire),decoded;
        core_ss_body_t incoming={0};
        REQUIRE("shadowsocks/header-validation-state",!core_ss_body_init(&incoming,(core_ss_method_t)method,key,0,salt,NULL));
        int result=receive(&incoming,wire,length,1,output,70000,&decoded);
        CHECK("shadowsocks/authenticated-header-validation",kind == 5 ? !result && incoming.response_ready && decoded == 32 : result < 0 && !incoming.response_ready && !decoded);
        core_ss_body_clear(&incoming);
    }
    for (unsigned method=0;method<7;method++) {
        size_t length=response((core_ss_method_t)method,key,salt,plain,0,0,1,0,0,wire),decoded;
        wire[length-1]^=1;
        core_ss_body_t incoming={0};
        REQUIRE("shadowsocks/empty-tag-state",!core_ss_body_init(&incoming,(core_ss_method_t)method,key,0,salt,NULL));
        CHECK("shadowsocks/empty-record-tag-required",receive(&incoming,wire,length,1,output,70000,&decoded)<0 && !decoded && incoming.failed);
        core_ss_body_clear(&incoming);
    }
    free(output); free(wire); free(plain);
}

static void nonce_limits(void) {
    uint8_t key[32]={0},wire[2048],plain[32],saved[32]; size_t written,consumed,decoded;
    for (unsigned method=0;method<7;method++) {
        core_ss_body_t sender={0},receiver={0};
        REQUIRE("shadowsocks/nonce-sender",!core_ss_body_init(&sender,(core_ss_method_t)method,key,1,NULL,NULL));
        REQUIRE("shadowsocks/nonce-initial-header",!core_ss_request(&sender,key,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written));
        REQUIRE("shadowsocks/nonce-receiver",!core_ss_body_init(&receiver,(core_ss_method_t)method,key,0,sender.salt,NULL));
        receiver.stage=CORE_SS_LENGTH; receiver.needed=18; receiver.response_ready=receiver.started=1;
        memcpy(receiver.key,sender.key,32); memcpy(saved,sender.key,32);
        size_t size=core_ss_nonce_size((core_ss_method_t)method);
        memset(sender.nonce,255,size); sender.nonce[0]=254; memcpy(receiver.nonce,sender.nonce,size);
        REQUIRE("shadowsocks/nonce-final-complete-record",!core_ss_body_encode(&sender,(const uint8_t *)"last",4,&consumed,wire,sizeof(wire),&written) && sender.exhausted);
        REQUIRE("shadowsocks/nonce-final-receive",!receive(&receiver,wire,written,1,plain,sizeof(plain),&decoded));
        CHECK("shadowsocks/nonce-final-data-preserved",decoded==4 && !memcmp(plain,"last",4) && receiver.exhausted && !core_ss_body_eof(&receiver));
        unsigned before=cipher_calls;
        CHECK("shadowsocks/nonce-transmit-never-repeats",core_ss_body_encode(&sender,(const uint8_t *)"next",4,&consumed,wire,sizeof(wire),&written)<0 && !consumed && !written && errno==EOVERFLOW && cipher_calls==before);
        uint8_t *span=NULL; size_t capacity=0;
        REQUIRE("shadowsocks/nonce-receive-length-buffer",!core_ss_body_prepare(&receiver,&span,&capacity) && capacity==18);
        memset(span,0,18); before=cipher_calls;
        CHECK("shadowsocks/nonce-receive-never-repeats",core_ss_body_commit(&receiver,18)<0 && errno==EOVERFLOW && cipher_calls==before);
        core_ss_body_clear(&receiver); core_ss_body_clear(&sender);
        REQUIRE("shadowsocks/nonce-insufficient-state",!core_ss_body_init(&sender,(core_ss_method_t)method,key,1,NULL,NULL));
        REQUIRE("shadowsocks/nonce-insufficient-request",!core_ss_request(&sender,key,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written));
        memset(sender.nonce,255,size); before=cipher_calls;
        CHECK("shadowsocks/nonce-reserves-both-operations",core_ss_body_encode(&sender,(const uint8_t *)"data",4,&consumed,wire,sizeof(wire),&written)<0 && errno==EOVERFLOW && cipher_calls==before);
        core_ss_body_clear(&sender);
    }
    OPENSSL_cleanse(saved,sizeof(saved));
}

static void failures(void) {
    uint8_t keys[64]={0},wire[4096],zero[sizeof(core_ss_body_t)]={0}; size_t written;
    for (unsigned method=0;method<7;method++) {
        core_ss_body_t sender={0}; random_calls=0;
        REQUIRE("shadowsocks/rng-baseline-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
        REQUIRE("shadowsocks/rng-baseline-request",!core_ss_request(&sender,keys,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written));
        unsigned calls=random_calls; core_ss_body_clear(&sender);
        for (unsigned stage=1;stage<=calls;stage++) {
            random_fail=stage; random_calls=0;
            REQUIRE("shadowsocks/rng-failure-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
            CHECK("shadowsocks/rng-failure-aborts-request",core_ss_request(&sender,keys,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written)<0 && !written && sender.failed);
            uint8_t empty[sizeof(wire)]={0}; CHECK("shadowsocks/request-failure-wipes-wire",!memcmp(wire,empty,sizeof(wire)));
            random_fail=0; core_ss_body_clear(&sender);
            CHECK("shadowsocks/codec-clear-erases-secrets",!memcmp(&sender,zero,sizeof(sender)));
        }
        context_fail=1;
        CHECK("shadowsocks/context-failure-clears-state",core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL)<0 && !memcmp(&sender,zero,sizeof(sender)));
        context_fail=0;
        REQUIRE("shadowsocks/recovers-after-failure",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL) && !core_ss_request(&sender,keys,1,"::1",443,NULL,0,wire,sizeof(wire),&written));
        core_ss_body_clear(&sender);
    }
    for (unsigned method=4;method<7;method++) {
        core_ss_body_t sender={0}; random_mode=1; random_calls=0;
        REQUIRE("shadowsocks/rejected-rng-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
        CHECK("shadowsocks/rejected-rng-bounded",core_ss_request(&sender,keys,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written)<0 && random_calls==129);
        core_ss_body_clear(&sender); random_mode=2;
        REQUIRE("shadowsocks/constant-successful-rng-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
        CHECK("shadowsocks/constant-accepted-rng-works",!core_ss_request(&sender,keys,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written));
        core_ss_body_clear(&sender); random_mode=0;
        fixed_time=-1;
        REQUIRE("shadowsocks/clock-failure-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
        CHECK("shadowsocks/clock-failure-aborts",core_ss_request(&sender,keys,1,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written)<0 && !written);
        core_ss_body_clear(&sender); fixed_time=INT64_C(1700000000);
    }
    const char *hosts[]={"127.0.0.1","::1","example.test"}; const unsigned types[]={1,4,3};
    for (unsigned method=0;method<7;method++) for (unsigned target=0;target<3;target++) {
        core_ss_body_t sender={0}; uint8_t decoded[2048],nonce[24]={0}; size_t decoded_length=0;
        REQUIRE("shadowsocks/target-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
        REQUIRE("shadowsocks/target-request",!core_ss_request(&sender,keys,1,hosts[target],65535,NULL,0,wire,sizeof(wire),&written));
        EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new(); REQUIRE("shadowsocks/target-reference-context",context != NULL);
        size_t offset=core_ss_key_size((core_ss_method_t)method)+(core_ss_is_2022((core_ss_method_t)method) ? 27 : 18); nonce[0]=1;
        REQUIRE("shadowsocks/target-decrypt",!core_ss_crypt(context,(core_ss_method_t)method,sender.key,nonce,0,wire+offset,written-offset,decoded,sizeof(decoded),&decoded_length));
        size_t address_size=target == 0 ? 5 : target == 1 ? 17 : 2+strlen(hosts[target]);
        CHECK("shadowsocks/socks-address-types",decoded[0]==types[target] && decoded_length>=address_size+2 && decoded[address_size]==255 && decoded[address_size+1]==255);
        if (core_ss_is_2022((core_ss_method_t)method)) CHECK("shadowsocks/server-first-has-padding",decoded_length == address_size+4+7 && decoded[address_size+2]==0 && decoded[address_size+3]==7);
        EVP_CIPHER_CTX_free(context); core_ss_body_clear(&sender);
    }
    const char *bad_hosts[]={"","bad\r\nHost: value","[::1]","bad/path"};
    for (size_t i=0;i<sizeof(bad_hosts)/sizeof(*bad_hosts);i++) {
        core_ss_body_t sender={0}; random_calls=0;
        REQUIRE("shadowsocks/bad-target-state",!core_ss_body_init(&sender,CORE_SS_AES128_GCM,keys,1,NULL,NULL));
        CHECK("shadowsocks/bad-target-before-rng",core_ss_request(&sender,keys,1,bad_hosts[i],80,NULL,0,wire,sizeof(wire),&written)<0 && !random_calls && !written);
        core_ss_body_clear(&sender);
    }
    for (unsigned method=0;method<7;method++) {
        core_ss_body_t sender={0}; random_calls=0;
        REQUIRE("shadowsocks/oversized-chain-state",!core_ss_body_init(&sender,(core_ss_method_t)method,keys,1,NULL,NULL));
        CHECK("shadowsocks/oversized-chain-before-read",core_ss_request(&sender,keys,SIZE_MAX,"127.0.0.1",80,NULL,0,wire,sizeof(wire),&written)<0 && !written && !random_calls);
        core_ss_body_clear(&sender);
    }
}

static void sender_limits(void) {
    uint8_t *input=malloc(70000),*output=malloc(70000),*wire=malloc(65601),key[32]={0};
    REQUIRE("shadowsocks/sender-limit-buffers",input && output && wire);
    for (size_t i=0;i<70000;i++) input[i]=(uint8_t)(i*17);
    for (unsigned method=0;method<7;method++) {
        core_ss_body_t sender={0},receiver={0}; size_t written,consumed,sent=0,received=0;
        REQUIRE("shadowsocks/sender-limit-state",!core_ss_body_init(&sender,(core_ss_method_t)method,key,1,NULL,NULL));
        REQUIRE("shadowsocks/sender-limit-request",!core_ss_request(&sender,key,1,"example.test",443,NULL,0,wire,65569,&written));
        REQUIRE("shadowsocks/sender-limit-receiver",!core_ss_body_init(&receiver,(core_ss_method_t)method,key,0,sender.salt,NULL));
        receiver.stage=CORE_SS_LENGTH; receiver.needed=18; receiver.started=receiver.response_ready=1;
        memcpy(receiver.key,sender.key,32); memcpy(receiver.nonce,sender.nonce,24);
        while (sent<70000) {
            memset(wire+65569,0xa5,32);
            REQUIRE("shadowsocks/sender-bounded-record",!core_ss_body_encode(&sender,input+sent,70000-sent,&consumed,wire,65569,&written));
            CHECK("shadowsocks/sender-protocol-limit",consumed && consumed <= (method<4 ? 16383U : 65535U) && written==consumed+34);
            uint8_t guard[32]; memset(guard,0xa5,sizeof(guard)); CHECK("shadowsocks/sender-capacity-guard",!memcmp(wire+65569,guard,sizeof(guard)));
            size_t decoded=0;
            REQUIRE("shadowsocks/sender-fragmented-roundtrip",!receive(&receiver,wire,written,61,output+received,70000-received,&decoded));
            sent+=consumed; received+=decoded;
        }
        CHECK("shadowsocks/sender-large-exact",received==70000 && !memcmp(input,output,70000));
        uint8_t nonce[24]; memcpy(nonce,sender.nonce,24);
        CHECK("shadowsocks/empty-write-is-not-termination",!core_ss_body_encode(&sender,NULL,0,&consumed,wire,65569,&written) && !consumed && !written && !memcmp(nonce,sender.nonce,24));
        CHECK("shadowsocks/no-space-before-nonce",core_ss_body_encode(&sender,input,1,&consumed,wire,34,&written)<0 && !consumed && !written && !memcmp(nonce,sender.nonce,24));
        REQUIRE("shadowsocks/minimal-record-space",!core_ss_body_encode(&sender,input,10,&consumed,wire,35,&written) && consumed==1 && written==35);
        core_ss_body_clear(&sender); core_ss_body_clear(&receiver);
    }
    free(wire); free(output); free(input);
}

static void memory_budget(void) {
    uint8_t key[32]={0},salt[32]={0},plain[65535]={0},wire[66000],output[65535];
    size_t length=response(CORE_SS_2022_AES256_GCM,key,salt,plain,sizeof(plain),0,1,0,0,wire),decoded=0;
    core_buffer_budget_t memory={0},blocker={0}; core_ss_body_t receiver={0};
    REQUIRE("shadowsocks/budget-state",!core_buffer_budget_init(&memory,CORE_BUFFER_RELAY,0) && !core_ss_body_init(&receiver,CORE_SS_2022_AES256_GCM,key,0,salt,&memory));
    CHECK("shadowsocks/no-eager-record-allocation",!memory.allocated && !receiver.block.data);
    size_t prefix=32+59;
    REQUIRE("shadowsocks/header-before-body-allocation",!receive(&receiver,wire,prefix,1,output,sizeof(output),&decoded) && receiver.response_ready && !memory.allocated);
    REQUIRE("shadowsocks/exhaust-budget",!core_buffer_budget_init(&blocker,CORE_BUFFER_RELAY,CORE_BUFFER_TOTAL_LIMIT));
    uint8_t *span=NULL; size_t capacity=0;
    CHECK("shadowsocks/budget-waits-without-state-loss",core_ss_body_prepare(&receiver,&span,&capacity)==1 && !span && !capacity && !receiver.failed && !receiver.used);
    REQUIRE("shadowsocks/release-budget",!core_buffer_budget_clear(&blocker));
    REQUIRE("shadowsocks/budget-recovers",!receive(&receiver,wire+prefix,length-prefix,131,output,sizeof(output),&decoded));
    CHECK("shadowsocks/budget-large-data-correct",decoded==sizeof(plain) && !memcmp(plain,output,sizeof(plain)) && !memory.allocated);
    core_ss_body_clear(&receiver); REQUIRE("shadowsocks/budget-clear",!core_buffer_budget_clear(&memory));
    REQUIRE("shadowsocks/allocator-failure-state",!core_ss_body_init(&receiver,CORE_SS_2022_AES256_GCM,key,0,salt,&memory) && !receive(&receiver,wire,prefix,1,output,sizeof(output),&decoded));
    allocation_fail=1;
    CHECK("shadowsocks/allocator-failure-local",core_ss_body_prepare(&receiver,&span,&capacity)<0 && receiver.failed && !memory.allocated);
    allocation_fail=0; core_ss_body_clear(&receiver); REQUIRE("shadowsocks/allocator-budget-recovered",!core_buffer_budget_clear(&memory));
    size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
    CHECK("shadowsocks/budget-returns-to-zero",!bytes && !reserved);
}

int main(void) { wire_vectors(); boundaries(); nonce_limits(); failures(); sender_limits(); memory_budget(); return test_result(); }

