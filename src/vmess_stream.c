#include "vmess_internal.h"
#include "vmess_stream.h"
#include "tls13_reality.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct core_vmess_conn {
    tls13_conn_t *transport;
    core_vmess_header_t header;
    core_vmess_body_t incoming,outgoing;
    core_buffer_budget_t memory;
    core_relay_buffer_t wire;
    const char *error;
    int response_started,framed,websocket,eof_reported,transport_eof;
    int finish_requested,termination_sent,finish_sent;
};

static int stream_error(core_vmess_conn_t *connection,const char *error) {
    connection->error=error; return -1;
}

void core_vmess_close(core_vmess_conn_t *connection) {
    if (!connection) return;
    int cause=errno;
    core_vmess_body_clear(&connection->incoming); core_vmess_body_clear(&connection->outgoing);
    if (connection->wire.data) OPENSSL_cleanse(connection->wire.data,connection->wire.capacity);
    core_relay_buffer_clear(&connection->wire); core_buffer_budget_clear(&connection->memory);
    core_vmess_header_clear(&connection->header); OPENSSL_cleanse(connection,sizeof(*connection)); free(connection);
    errno=cause;
}

int core_vmess_open(const vless_config_t *config,tls13_conn_t *transport,const char *target,uint16_t port,const uint8_t *first,size_t first_length,core_vmess_conn_t **output) {
    if (!output) { errno=EINVAL; return -1; }
    *output=NULL;
    core_vmess_conn_t *connection=calloc(1,sizeof(*connection));
    if (!connection) return -1;
    connection->transport=transport; connection->framed=config->transport_mode != TRANSPORT_VISION; connection->websocket=config->transport_mode == TRANSPORT_WS;
    connection->wire=(core_relay_buffer_t){.memory=&connection->memory,.minimum=8192,.limit=16384};
    if (first_length > 8192 || (!first && first_length)) { errno=EINVAL; goto failure; }
    if (core_buffer_budget_init(&connection->memory,CORE_BUFFER_RELAY,32768)) {
        int result=errno == ENOBUFS ? -2 : -1;
        core_vmess_close(connection); return result;
    }
    if (core_relay_buffer_reserve(&connection->wire,CORE_VMESS_HEADER_MAX+first_length+162) != 1) goto failure;
    size_t length=0;
    if (core_vmess_request(&connection->header,config->uuid,target,port,config->vmess_security,connection->wire.data,connection->wire.capacity,&length) ||
        core_vmess_body_init(&connection->outgoing,&connection->header,1,&connection->memory) || core_vmess_body_init(&connection->incoming,&connection->header,0,&connection->memory)) goto failure;
    size_t offset=0;
    while (offset<first_length) {
        size_t consumed=0,written=0;
        if (core_vmess_body_encode(&connection->outgoing,first+offset,first_length-offset,&consumed,connection->wire.data+length,connection->wire.capacity-length,&written,0) || !consumed) goto failure;
        length+=written; offset+=consumed;
    }
    if (tls13_start_relay(transport) || tls13_write_app(transport,connection->wire.data,length)) goto failure;
    OPENSSL_cleanse(connection->wire.data,connection->wire.capacity);
    if (connection->wire.capacity > 8192) core_relay_buffer_clear(&connection->wire);
    tls13_set_request_fence(transport); *output=connection; return 0;
failure:
    core_vmess_close(connection); return -1;
}

int core_vmess_prepare_write(core_vmess_conn_t *connection) {
    if (!connection || connection->finish_requested || connection->outgoing.failed) { errno=EPIPE; return -1; }
    return core_relay_buffer_reserve(&connection->wire,8192) == 1 ? 0 : -1;
}

int core_vmess_write(core_vmess_conn_t *connection,const uint8_t *input,size_t length) {
    if (core_vmess_prepare_write(connection)) return -1;
    for (size_t offset=0;offset<length;) {
        size_t consumed=0,written=0;
        if (core_vmess_body_encode(&connection->outgoing,input+offset,length-offset,&consumed,connection->wire.data,connection->wire.capacity,&written,0))
            return stream_error(connection,errno == EOVERFLOW ? "VMess nonce limit reached" : "VMess body encoding failed");
        if (!consumed || tls13_write_app(connection->transport,connection->wire.data,written)) {
            OPENSSL_cleanse(connection->wire.data,connection->wire.capacity); return stream_error(connection,"VMess transport write failed");
        }
        OPENSSL_cleanse(connection->wire.data,connection->wire.capacity); offset+=consumed;
    }
    return 0;
}

int core_vmess_response_ready(const core_vmess_conn_t *connection) { return connection && connection->header.response_ready; }
int core_vmess_response_started(const core_vmess_conn_t *connection) { return connection && connection->response_started; }
int core_vmess_pending(const core_vmess_conn_t *connection) { return connection && (connection->incoming.plain_length || (connection->incoming.finished && !connection->eof_reported)); }
int core_vmess_drain_pending(const core_vmess_conn_t *connection) { return connection && connection->eof_reported && !connection->transport_eof && (connection->framed || !connection->finish_requested); }
const char *core_vmess_error(const core_vmess_conn_t *connection) { return connection && connection->error ? connection->error : "VMess exchange failed"; }

int core_vmess_read(core_vmess_conn_t *connection,uint8_t *output,size_t capacity,size_t *written) {
    *written=0;
    if (!capacity || connection->transport_eof) return 0;
    if (!connection->header.response_ready) {
        uint8_t input[CORE_VMESS_RESPONSE_MAX]; size_t got=0,consumed=0;
        size_t needed=connection->header.response_needed-connection->header.response_used;
        int result=tls13_read_app(connection->transport,input,needed,&got);
        if (result) return result;
        if (!got) { errno=EBADMSG; return stream_error(connection,!connection->header.response_used ? "VMess response not received" : "truncated VMess response header"); }
        connection->response_started=1;
        result=core_vmess_response(&connection->header,input,got,&consumed); OPENSSL_cleanse(input,sizeof(input));
        if (result < 0 || consumed != got) return stream_error(connection,"invalid VMess response header");
        return 1;
    }
    if (connection->incoming.plain_length) return core_vmess_body_read(&connection->incoming,output,capacity,written);
    if (connection->incoming.finished) {
        if (!connection->eof_reported) { connection->eof_reported=1; return 0; }
        uint8_t extra; size_t got=0;
        int result=tls13_read_app(connection->transport,&extra,1,&got);
        if (result) return result;
        if (got) { OPENSSL_cleanse(&extra,sizeof(extra)); errno=EPROTO; return stream_error(connection,"data after VMess termination"); }
        connection->transport_eof=1; return 0;
    }
    uint8_t *span; size_t available=0,got=0;
    if (core_vmess_body_prepare(&connection->incoming,&span,&available)) return stream_error(connection,"VMess receive buffer unavailable");
    int result=tls13_read_app(connection->transport,span,available,&got);
    if (result) return result;
    if (!got) {
        if (core_vmess_body_eof(&connection->incoming)) return stream_error(connection,"truncated VMess body");
        connection->transport_eof=connection->eof_reported=1; return 0;
    }
    if (core_vmess_body_commit(&connection->incoming,got)) return stream_error(connection,errno == EOVERFLOW ? "VMess nonce limit reached" : "invalid VMess body");
    if (connection->incoming.finished) { connection->eof_reported=1; return 0; }
    if (connection->incoming.plain_length) return core_vmess_body_read(&connection->incoming,output,capacity,written);
    return 1;
}

int core_vmess_tick(core_vmess_conn_t *connection) {
    if (!connection || !connection->finish_requested || connection->finish_sent) return 0;
    if (tls13_send_stopped(connection->transport)) { connection->termination_sent=connection->finish_sent=1; return tls13_finish_write(connection->transport,0); }
    if (!connection->termination_sent) {
        if (tls13_write_capacity(connection->transport)<96 || !tls13_reserve_write(connection->transport,96)) return 0;
        if (core_relay_buffer_reserve(&connection->wire,8192) != 1) { tls13_release_write(connection->transport); return stream_error(connection,"VMess termination buffer unavailable"); }
        size_t consumed=0,written=0;
        int result=core_vmess_body_encode(&connection->outgoing,NULL,0,&consumed,connection->wire.data,connection->wire.capacity,&written,1);
        if (!result && written) result=tls13_write_app(connection->transport,connection->wire.data,written);
        OPENSSL_cleanse(connection->wire.data,connection->wire.capacity); tls13_release_write(connection->transport);
        if (result) return stream_error(connection,"VMess termination send failed");
        connection->termination_sent=1;
    }
    if (connection->websocket && connection->header.security != CORE_VMESS_ZERO && !connection->eof_reported) return 0;
    if (tls13_finish_write(connection->transport,0)) return stream_error(connection,"VMess transport finish failed");
    connection->finish_sent=1; return 0;
}

int core_vmess_finish(core_vmess_conn_t *connection) {
    connection->finish_requested=1; return core_vmess_tick(connection);
}

int core_vmess_finish_pending(const core_vmess_conn_t *connection) {
    int result=tls13_finish_pending(connection->transport);
    if (result) return result;
    return connection->finish_requested && !connection->finish_sent &&
        (!connection->termination_sent || !connection->websocket || connection->header.security == CORE_VMESS_ZERO || connection->eof_reported);
}
