#define tls13_start_relay fixture_start
#define tls13_write_app fixture_write
#define tls13_read_app fixture_read
#define tls13_set_request_fence fixture_fence
#define tls13_request_pending fixture_request_pending
#define tls13_finish_write fixture_finish
#define tls13_finish_pending fixture_pending
#include "../src/shadowsocks_stream.c"
#include "check.h"

static uint8_t receive_wire[70000],send_wire[140000];
static size_t receive_length,receive_offset,send_length,fragment=70000;
static int at_eof,write_fail,start_fail,finish_calls,fences,read_fail,request_pending;
static int fail_allocation,fail_random,fail_context;
static size_t fail_size;
void *__real_calloc(size_t,size_t);
void *__real_malloc(size_t);
void *__real_realloc(void *,size_t);
int __real_RAND_bytes(unsigned char *,int);
EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
void *__wrap_calloc(size_t count,size_t size) {
    if (fail_allocation && count==1 && size==sizeof(core_ss_conn_t)) { fail_allocation=0; errno=ENOMEM; return NULL; }
    return __real_calloc(count,size);
}
void *__wrap_malloc(size_t size) {
    if (fail_size && size==fail_size) { fail_size=0; errno=ENOMEM; return NULL; }
    return __real_malloc(size);
}
void *__wrap_realloc(void *data,size_t size) {
    if (fail_size && size==fail_size) { fail_size=0; errno=ENOMEM; return NULL; }
    return __real_realloc(data,size);
}
int __wrap_RAND_bytes(unsigned char *data,int length) { return fail_random ? 0 : __real_RAND_bytes(data,length); }
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void) {
    if (fail_context && !--fail_context) return NULL;
    return __real_EVP_CIPHER_CTX_new();
}

int fixture_start(tls13_conn_t *transport) { (void)transport; if (start_fail) { errno=EIO; return -1; } return 0; }
int fixture_write(tls13_conn_t *transport,const uint8_t *input,size_t length) {
    (void)transport;
    if (write_fail || length>sizeof(send_wire)-send_length) { errno=EIO; return -1; }
    memcpy(send_wire+send_length,input,length); send_length+=length; return 0;
}
int fixture_read(tls13_conn_t *transport,uint8_t *output,size_t capacity,size_t *written) {
    (void)transport; *written=0;
    if (read_fail) { errno=EPROTO; return -1; }
    size_t take=receive_length-receive_offset;
    if (!take && !at_eof) { errno=EAGAIN; return 1; }
    if (take>capacity) take=capacity;
    if (take>fragment) take=fragment;
    memcpy(output,receive_wire+receive_offset,take); receive_offset+=take; *written=take; return 0;
}
void fixture_fence(tls13_conn_t *transport) { (void)transport; fences++; }
int fixture_request_pending(const tls13_conn_t *transport) { (void)transport; return request_pending; }
int fixture_finish(tls13_conn_t *transport,int raw) { (void)transport; (void)raw; finish_calls++; return 0; }
int fixture_pending(const tls13_conn_t *transport) { (void)transport; return 0; }

static void reset(void) {
    receive_length=receive_offset=send_length=0; fragment=sizeof(receive_wire);
    at_eof=write_fail=start_fail=finish_calls=fences=read_fail=request_pending=0;
    fail_allocation=fail_random=fail_context=0; fail_size=0;
}

static core_ss_conn_t *open_stream(core_ss_method_t method) {
    vless_config_t *config=calloc(1,sizeof(*config)); core_ss_conn_t *connection=NULL;
    REQUIRE("ss/stream-config-allocation",config);
    config->protocol=CORE_PROTOCOL_SHADOWSOCKS; config->ss.method=method; config->ss.count=1;
    for (size_t i=0;i<core_ss_key_size(method);i++) config->ss.keys[i]=(uint8_t)i;
    REQUIRE("ss/stream-open",!core_ss_open(config,(tls13_conn_t *)(uintptr_t)1,"127.0.0.1",443,NULL,0,&connection));
    OPENSSL_cleanse(config,sizeof(*config)); free(config); return connection;
}

static void response(core_ss_conn_t *connection,const uint8_t *plain,size_t length) {
    size_t size=core_ss_key_size(connection->incoming.method),written=0;
    uint8_t master[32]={0},key[32],nonce[24]={0},header[64];
    for (size_t i=0;i<size;i++) master[i]=(uint8_t)i;
    memset(receive_wire,0xaa,size); receive_length=size;
    REQUIRE("ss/stream-response-key",!core_ss_subkey(connection->incoming.method,master,receive_wire,key));
    size_t header_length=2;
    if (core_ss_is_2022(connection->incoming.method)) {
        int64_t now=core_ss_time(); header[0]=1;
        for (unsigned i=0;i<8;i++) header[1+i]=(uint8_t)((uint64_t)now>>(56-8*i));
        memcpy(header+9,connection->outgoing.salt,size); header_length=11+size;
    }
    header[header_length-2]=(uint8_t)(length>>8); header[header_length-1]=(uint8_t)length;
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new(); REQUIRE("ss/stream-response-context",context);
    REQUIRE("ss/stream-response-header",!core_ss_crypt(context,connection->incoming.method,key,nonce,1,header,header_length,receive_wire+receive_length,sizeof(receive_wire)-receive_length,&written));
    receive_length+=written; nonce[0]=1;
    REQUIRE("ss/stream-response-body",!core_ss_crypt(context,connection->incoming.method,key,nonce,1,plain,length,receive_wire+receive_length,sizeof(receive_wire)-receive_length,&written));
    receive_length+=written; EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(master,sizeof(master)); OPENSSL_cleanse(key,sizeof(key));
}

static void exchange_states(void) {
    for (unsigned method=0;method<7;method++) {
        reset(); request_pending=1; core_ss_conn_t *connection=open_stream(method);
        CHECK("ss/stream-request-sent-without-payload",send_length>32 && fences==1 && !core_ss_response_ready(connection));
        request_pending=0;
        CHECK("ss/stream-classic-ready-after-physical-fence",core_ss_response_ready(connection)==!core_ss_is_2022(method));
        const uint8_t data[]={0,0,'r','e','p','l','y'}; response(connection,data,sizeof(data)); fragment=1;
        uint8_t output[sizeof(data)]; size_t used=0,got=0;
        while (used<sizeof(output)) {
            int result=core_ss_read(connection,output+used,sizeof(output)-used,&got);
            REQUIRE("ss/stream-fragmented-read-progress",result>=0);
            if (core_ss_is_2022(method) && connection->incoming.stage == CORE_SS_BLOCK && !connection->incoming.used) CHECK("ss/stream-ready-after-header-before-body",core_ss_response_ready(connection) && !got);
            used+=got;
        }
        CHECK("ss/stream-exact-application-data",!memcmp(output,data,sizeof(data)) && core_ss_response_ready(connection));
        CHECK("ss/stream-partial-wire-not-pending",!core_ss_pending(connection) && core_ss_response_started(connection));
        CHECK("ss/stream-finish-idempotent",!core_ss_finish(connection) && !core_ss_finish(connection) && finish_calls==1 && !core_ss_finish_pending(connection));
        CHECK("ss/stream-finished-write-rejected",core_ss_prepare_write(connection,10)<0 && errno==EPIPE && core_ss_write(connection,data,sizeof(data))<0 && errno==EPIPE);
        at_eof=1; CHECK("ss/stream-boundary-eof",!core_ss_read(connection,output,sizeof(output),&got) && !got);
        core_ss_close(connection);
        size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
        CHECK("ss/stream-buffers-and-reservations-released",!bytes && !reserved);
    }
}

static void pressure(void) {
    reset(); core_ss_conn_t *connection=open_stream(CORE_SS_2022_AES128_GCM);
    uint8_t *data=malloc(65535),*output=malloc(65535); REQUIRE("ss/stream-pressure-data",data && output);
    memset(data,0x5b,65535); response(connection,data,65535);
    core_buffer_budget_t occupied={0};
    REQUIRE("ss/stream-pressure-reserve",!core_buffer_budget_init(&occupied,CORE_BUFFER_RELAY,core_buffer_available(CORE_BUFFER_RELAY)));
    CHECK("ss/stream-send-falls-back-to-reserved-buffer",!core_ss_prepare_write(connection,65535) && connection->wire.capacity==8192 && !core_ss_write(connection,data,65535));
    size_t got=0,used=0;
    while (used<65535) { REQUIRE("ss/stream-reserved-full-block-progress",core_ss_read(connection,output+used,65535-used,&got)>=0); used+=got; }
    CHECK("ss/stream-full-block-at-exhausted-global-budget",!memcmp(data,output,65535) && !connection->incoming.block.data);
    vless_config_t config={0}; core_ss_conn_t *other=NULL;
    config.ss.method=CORE_SS_AES128_GCM; config.ss.count=1;
    size_t before=send_length;
    CHECK("ss/stream-admission-waits-before-network",core_ss_open(&config,(tls13_conn_t *)(uintptr_t)1,"localhost",80,NULL,0,&other)==-2 && !other && before==send_length);
    REQUIRE("ss/stream-pressure-release",!core_buffer_budget_clear(&occupied)); core_ss_close(connection); free(data); free(output);
    CHECK("ss/stream-admission-recovers",!core_ss_open(&config,(tls13_conn_t *)(uintptr_t)1,"localhost",80,NULL,0,&other)); core_ss_close(other);
}

static void failures(void) {
    for (unsigned failure=0;failure<5;failure++) {
        reset(); core_ss_conn_t *connection=open_stream(CORE_SS_2022_AES128_GCM);
        uint8_t output[64]; size_t got=0;
        if (failure<3) {
            response(connection,(const uint8_t *)"reply",5);
            if (failure==0) receive_wire[receive_length-1]^=1;
            if (failure==1) { receive_length--; at_eof=1; }
            if (failure==2) { receive_length=0; at_eof=1; }
        } else if (failure==3) read_fail=1;
        else { write_fail=1; CHECK("ss/stream-write-error",core_ss_write(connection,(const uint8_t *)"reply",5)<0); }
        if (failure<4) {
            int result; unsigned steps=0;
            do { result=core_ss_read(connection,output,sizeof(output),&got); REQUIRE("ss/stream-failure-does-not-expose-plaintext",!got && ++steps<10); } while (result>=0);
            CHECK("ss/stream-safe-protocol-error",strstr(core_ss_error(connection),"Shadowsocks") && !strstr(core_ss_error(connection),"VLESS"));
        }
        core_ss_close(connection); size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
        CHECK("ss/stream-failure-releases-budget",!bytes && !reserved);
    }
}

static void open_failures(void) {
    for (unsigned failure=0;failure<7;failure++) {
        reset(); vless_config_t config={0}; core_ss_conn_t *connection=NULL;
        config.ss.method=CORE_SS_2022_AES128_GCM; config.ss.count=1;
        if (!failure) fail_allocation=1;
        else if (failure==1) fail_size=8192;
        else if (failure==2) fail_random=1;
        else if (failure<5) fail_context=(int)failure-2;
        else if (failure==5) start_fail=1;
        else write_fail=1;
        CHECK("ss/stream-open-failure-does-not-send",core_ss_open(&config,(tls13_conn_t *)(uintptr_t)1,"localhost",80,NULL,0,&connection)<0 && !connection && !send_length && !fences);
        core_ss_close(connection); connection=NULL;
        size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
        CHECK("ss/stream-open-failure-releases-resources",!bytes && !reserved);
        reset();
        CHECK("ss/stream-open-recovers-after-failure",!core_ss_open(&config,(tls13_conn_t *)(uintptr_t)1,"localhost",80,NULL,0,&connection)); core_ss_close(connection);
    }
}

int main(void) { exchange_states(); pressure(); failures(); open_failures(); return test_result(); }
