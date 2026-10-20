#define tls13_start_relay fixture_start
#define tls13_write_app fixture_write
#define tls13_read_app fixture_read
#define tls13_set_request_fence fixture_fence
#define tls13_send_stopped fixture_stopped
#define tls13_write_capacity fixture_capacity
#define tls13_reserve_write fixture_reserve
#define tls13_release_write fixture_release
#define tls13_finish_write fixture_finish
#define tls13_finish_pending fixture_pending
#include "../src/vmess_stream.c"
#include "check.h"

static uint8_t receive_wire[32768],send_wire[32768];
static size_t receive_length,receive_offset,send_length,fragment=32768;
static int at_eof,send_stopped,write_fail,start_fail,finish_calls,fences,read_fail;

int fixture_start(tls13_conn_t *transport) { (void)transport; return start_fail ? -1 : 0; }
int fixture_write(tls13_conn_t *transport,const uint8_t *input,size_t length) {
    (void)transport;
    if (write_fail || length > sizeof(send_wire)-send_length) { errno=EIO; return -1; }
    memcpy(send_wire+send_length,input,length); send_length+=length; return 0;
}
int fixture_read(tls13_conn_t *transport,uint8_t *output,size_t capacity,size_t *written) {
    (void)transport; *written=0;
    if (read_fail) { errno=EPROTO; return -1; }
    size_t take=receive_length-receive_offset;
    if (!take && !at_eof) { errno=EAGAIN; return 1; }
    if (take > capacity) take=capacity;
    if (take > fragment) take=fragment;
    memcpy(output,receive_wire+receive_offset,take); receive_offset+=take; *written=take; return 0;
}
void fixture_fence(tls13_conn_t *transport) { (void)transport; fences++; }
int fixture_stopped(const tls13_conn_t *transport) { (void)transport; return send_stopped; }
size_t fixture_capacity(const tls13_conn_t *transport) { (void)transport; return 32768; }
int fixture_reserve(tls13_conn_t *transport,size_t length) { (void)transport; (void)length; return 1; }
void fixture_release(tls13_conn_t *transport) { (void)transport; }
int fixture_finish(tls13_conn_t *transport,int raw) { (void)transport; (void)raw; finish_calls++; return 0; }
int fixture_pending(const tls13_conn_t *transport) { (void)transport; return 0; }

static void reset(void) {
    receive_length=receive_offset=send_length=0; fragment=32768;
    at_eof=send_stopped=write_fail=start_fail=finish_calls=fences=read_fail=0;
}

static void response(core_vmess_conn_t *connection) {
    const uint8_t size[]={0,4},content[]={connection->header.authentication,0,0,0};
    const char *key_labels[]={"AEAD Resp Header Len Key","AEAD Resp Header Key"};
    const char *iv_labels[]={"AEAD Resp Header Len IV","AEAD Resp Header IV"};
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new();
    REQUIRE("vmess/stream-response-context",context);
    for (unsigned i=0;i<2;i++) {
        uint8_t key[32],iv[32]; core_vmess_slice_t label={key_labels[i],strlen(key_labels[i])}; size_t length;
        REQUIRE("vmess/stream-response-key",!core_vmess_kdf(connection->header.response_key,16,&label,1,key));
        label=(core_vmess_slice_t){iv_labels[i],strlen(iv_labels[i])};
        REQUIRE("vmess/stream-response-iv",!core_vmess_kdf(connection->header.response_iv,16,&label,1,iv));
        REQUIRE("vmess/stream-response-seal",!core_vmess_aead(context,EVP_aes_128_gcm(),1,key,iv,NULL,0,i ? content : size,i ? sizeof(content) : sizeof(size),receive_wire+receive_length,&length));
        receive_length+=length;
    }
    EVP_CIPHER_CTX_free(context);
}

static core_vmess_conn_t *open_stream(core_vmess_security_t security,int framed) {
    vless_config_t *config=calloc(1,sizeof(*config)); core_vmess_conn_t *connection=NULL;
    REQUIRE("vmess/stream-config-allocation",config);
    config->protocol=CORE_PROTOCOL_VMESS; config->vmess_security=security; config->uuid[15]=1;
    config->transport_mode=framed ? TRANSPORT_GRPC : TRANSPORT_VISION;
    REQUIRE("vmess/stream-open",!core_vmess_open(config,(tls13_conn_t *)(uintptr_t)1,"127.0.0.1",443,NULL,0,&connection));
    OPENSSL_cleanse(config,sizeof(*config)); free(config); return connection;
}

static void exchange_states(void) {
    for (unsigned mode=3;mode<=6;mode++) {
        reset(); core_vmess_conn_t *connection=open_stream(mode,1);
        CHECK("vmess/request-without-app-data",send_length > 42 && fences == 1 && !core_vmess_response_ready(connection));
        response(connection); fragment=1;
        uint8_t plain[64]; size_t got=0;
        while (!core_vmess_response_ready(connection)) REQUIRE("vmess/fragmented-response-progress",core_vmess_read(connection,plain,sizeof(plain),&got) == 1 && !got);
        CHECK("vmess/complete-header-without-payload",core_vmess_response_started(connection) && !core_vmess_pending(connection));
        core_vmess_header_t opposite=connection->header;
        memcpy(opposite.request_key,opposite.response_key,16); memcpy(opposite.request_iv,opposite.response_iv,16);
        core_vmess_body_t server={0};
        REQUIRE("vmess/stream-server-state",!core_vmess_body_init(&server,&opposite,1,NULL));
        size_t consumed,written,total=0; const uint8_t payload[]={0,0,1,2,3,4,5};
        receive_length=receive_offset=0;
        REQUIRE("vmess/stream-server-body",!core_vmess_body_encode(&server,payload,sizeof(payload),&consumed,receive_wire,sizeof(receive_wire),&written,0));
        receive_length=written;
        REQUIRE("vmess/stream-server-end",!core_vmess_body_encode(&server,NULL,0,&consumed,receive_wire+receive_length,sizeof(receive_wire)-receive_length,&written,1));
        receive_length+=written;
        for (unsigned attempts=0;attempts<512 && !connection->eof_reported;attempts++) {
            int result=core_vmess_read(connection,plain+total,sizeof(plain)-total,&got);
            REQUIRE("vmess/stream-checked-read",result >= 0); total+=got;
            if (mode == CORE_VMESS_ZERO && receive_offset == receive_length) at_eof=1;
        }
        CHECK("vmess/stream-exact-payload",total == sizeof(payload) && !memcmp(plain,payload,total) && connection->eof_reported);
        if (mode != CORE_VMESS_ZERO) {
            CHECK("vmess/stream-validates-outer-finish",core_vmess_drain_pending(connection));
            at_eof=1; REQUIRE("vmess/stream-outer-eof",!core_vmess_read(connection,plain,sizeof(plain),&got) && !got && !core_vmess_drain_pending(connection));
        }
        REQUIRE("vmess/stream-finish",!core_vmess_finish(connection) && !core_vmess_finish(connection));
        CHECK("vmess/stream-idempotent-finish",finish_calls == 1);
        core_vmess_body_clear(&server); core_vmess_close(connection);
    }
}

static void failures(void) {
    size_t before,after,allocated; core_buffer_snapshot(CORE_BUFFER_RELAY,&before,&allocated);
    reset(); core_vmess_conn_t *connection=open_stream(CORE_VMESS_AES128_GCM,0); response(connection);
    receive_wire[receive_length-1]^=1; uint8_t plain[64]; size_t got=0; int result=1;
    while (result > 0) result=core_vmess_read(connection,plain,sizeof(plain),&got);
    CHECK("vmess/stream-bad-tag-no-plaintext",result < 0 && !got && !core_vmess_response_ready(connection));
    core_vmess_close(connection);
    reset(); connection=open_stream(CORE_VMESS_AES128_GCM,0);
    connection->incoming.finished=connection->eof_reported=1;
    CHECK("vmess/raw-half-close-keeps-transport-control-readable",core_vmess_drain_pending(connection));
    REQUIRE("vmess/raw-half-close-local-finish",!core_vmess_finish(connection));
    CHECK("vmess/raw-both-directions-finished-can-close",!core_vmess_drain_pending(connection));
    core_vmess_close(connection);
    reset(); connection=open_stream(CORE_VMESS_AES128_GCM,1);
    connection->incoming.finished=connection->eof_reported=1; read_fail=1;
    CHECK("vmess/inner-eof-does-not-bypass-outer-grpc-status",core_vmess_drain_pending(connection) && core_vmess_read(connection,plain,sizeof(plain),&got) < 0 && errno == EPROTO && !connection->transport_eof && !got);
    core_vmess_close(connection);
    reset(); connection=open_stream(CORE_VMESS_AES128_GCM,0); at_eof=1;
    CHECK("vmess/stream-no-header-error",core_vmess_read(connection,plain,sizeof(plain),&got) < 0 && strstr(core_vmess_error(connection),"not received"));
    core_vmess_close(connection);
    reset(); connection=open_stream(CORE_VMESS_AES128_GCM,0); send_stopped=1;
    size_t previous=send_length;
    REQUIRE("vmess/stream-reset-finish",!core_vmess_finish(connection));
    CHECK("vmess/stream-no-frames-after-reset",send_length == previous && core_vmess_write(connection,plain,1) < 0 && errno == EPIPE);
    core_vmess_close(connection);
    reset(); connection=open_stream(CORE_VMESS_AES128_GCM,0); connection->outgoing.counter=65535;
    CHECK("vmess/stream-nonce-limit-error",core_vmess_write(connection,plain,1) < 0 && errno == EOVERFLOW && strstr(core_vmess_error(connection),"nonce limit"));
    core_vmess_close(connection);
    core_buffer_budget_t blocker={0};
    REQUIRE("vmess/stream-saturate-budget",!core_buffer_budget_init(&blocker,CORE_BUFFER_RELAY,CORE_BUFFER_TOTAL_LIMIT-before));
    vless_config_t *config=calloc(1,sizeof(*config)); config->vmess_security=CORE_VMESS_AES128_GCM; connection=NULL; previous=send_length;
    CHECK("vmess/stream-admission-waits-before-request",core_vmess_open(config,(tls13_conn_t *)(uintptr_t)1,"127.0.0.1",443,NULL,0,&connection) == -2 && !connection && send_length == previous);
    core_buffer_budget_clear(&blocker); free(config);
    reset(); connection=open_stream(CORE_VMESS_AES128_GCM,0); core_vmess_close(connection);
    core_buffer_snapshot(CORE_BUFFER_RELAY,&after,&allocated);
    CHECK("vmess/stream-budget-recovered",before == after && !allocated);
}

int main(void) { exchange_states(); failures(); return test_result(); }
