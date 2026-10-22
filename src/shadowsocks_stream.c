#include "shadowsocks_internal.h"
#include "shadowsocks_stream.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct core_ss_conn {
    tls13_conn_t *transport;
    core_ss_body_t incoming,outgoing;
    core_buffer_budget_t memory;
    core_relay_buffer_t wire;
    const char *error;
    int response_started,transport_eof,finish_requested,finish_sent;
};

static int stream_error(core_ss_conn_t *connection,const char *error) {
    connection->error=error; return -1;
}

void core_ss_close(core_ss_conn_t *connection) {
    if (!connection) return;
    int cause=errno;
    core_ss_body_clear(&connection->incoming); core_ss_body_clear(&connection->outgoing);
    core_relay_buffer_clear(&connection->wire); core_buffer_budget_clear(&connection->memory);
    OPENSSL_cleanse(connection,sizeof(*connection)); free(connection); errno=cause;
}

int core_ss_open(const vless_config_t *config,tls13_conn_t *transport,const char *target,uint16_t port,const uint8_t *first,size_t first_length,core_ss_conn_t **output) {
    if (!output) { errno=EINVAL; return -1; }
    *output=NULL;
    size_t size=config ? core_ss_key_size(config->ss.method) : 0;
    if (!size || !config->ss.count || config->ss.count>CORE_SS_KEY_BYTES/size || first_length>8192 || (!first && first_length)) { errno=EINVAL; return -1; }
    core_ss_conn_t *connection=calloc(1,sizeof(*connection));
    if (!connection) return -1;
    connection->transport=transport;
    size_t maximum=core_ss_is_2022(config->ss.method) ? 65535 : 16383;
    connection->wire=(core_relay_buffer_t){.memory=&connection->memory,.minimum=8192,.limit=maximum+34,.cleanse=1};
    if (core_buffer_budget_init(&connection->memory,CORE_BUFFER_RELAY,maximum+16+8192)) {
        int result=errno == ENOBUFS ? -2 : -1;
        core_ss_close(connection); return result;
    }
    const uint8_t *key=config->ss.keys+(config->ss.count-1)*size;
    size_t length=0,needed=size+(config->ss.count-1)*16+27+260+2+900+first_length+16;
    if (core_relay_buffer_reserve(&connection->wire,needed)!=1 ||
        core_ss_body_init(&connection->outgoing,config->ss.method,key,1,NULL,&connection->memory) ||
        core_ss_request(&connection->outgoing,config->ss.keys,config->ss.count,target,port,first,first_length,connection->wire.data,connection->wire.capacity,&length) ||
        core_ss_body_init(&connection->incoming,config->ss.method,key,0,connection->outgoing.salt,&connection->memory)) goto failure;
    if (tls13_start_relay(transport) || tls13_write_app(transport,connection->wire.data,length)) goto failure;
    OPENSSL_cleanse(connection->wire.data,connection->wire.capacity);
    if (connection->wire.capacity>8192) core_relay_buffer_clear(&connection->wire);
    tls13_set_request_fence(transport); *output=connection; return 0;
failure:
    core_ss_close(connection); return -1;
}

int core_ss_prepare_write(core_ss_conn_t *connection,size_t requested) {
    if (!connection || connection->finish_requested || connection->outgoing.failed) { errno=EPIPE; return -1; }
    if (core_relay_buffer_reserve(&connection->wire,8192)!=1) return -1;
    size_t maximum=connection->wire.limit-34;
    if (requested>maximum) requested=maximum;
    int result=core_relay_buffer_reserve(&connection->wire,requested+34);
    return result<0 ? -1 : 0;
}

int core_ss_write(core_ss_conn_t *connection,const uint8_t *input,size_t length) {
    if (!connection || connection->finish_requested || connection->outgoing.failed) { errno=EPIPE; return -1; }
    if (core_relay_buffer_reserve(&connection->wire,8192)!=1) return -1;
    for (size_t offset=0;offset<length;) {
        size_t consumed=0,written=0;
        if (core_ss_body_encode(&connection->outgoing,input+offset,length-offset,&consumed,connection->wire.data,connection->wire.capacity,&written))
            return stream_error(connection,errno == EOVERFLOW ? "Shadowsocks nonce limit reached" : "Shadowsocks body encoding failed");
        if (!consumed || tls13_write_app(connection->transport,connection->wire.data,written)) {
            OPENSSL_cleanse(connection->wire.data,connection->wire.capacity); return stream_error(connection,"Shadowsocks transport write failed");
        }
        OPENSSL_cleanse(connection->wire.data,connection->wire.capacity); offset+=consumed;
    }
    if (connection->wire.capacity>8192) core_relay_buffer_clear(&connection->wire);
    return 0;
}

int core_ss_response_ready(const core_ss_conn_t *connection) {
    return connection && (core_ss_is_2022(connection->incoming.method) ? connection->incoming.response_ready : !tls13_request_pending(connection->transport));
}
int core_ss_response_started(const core_ss_conn_t *connection) { return connection && connection->response_started; }
int core_ss_pending(const core_ss_conn_t *connection) { return connection && connection->incoming.plain_length; }
int core_ss_drain_pending(const core_ss_conn_t *connection) { (void)connection; return 0; }
const char *core_ss_error(const core_ss_conn_t *connection) { return connection && connection->error ? connection->error : "Shadowsocks exchange failed"; }

int core_ss_read(core_ss_conn_t *connection,uint8_t *output,size_t capacity,size_t *written) {
    *written=0;
    if (!capacity || connection->transport_eof) return 0;
    if (connection->incoming.plain_length) return core_ss_body_read(&connection->incoming,output,capacity,written);
    uint8_t *span=NULL; size_t available=0,got=0;
    if (core_ss_body_prepare(&connection->incoming,&span,&available)) return stream_error(connection,"Shadowsocks receive buffer unavailable");
    int result=tls13_read_app(connection->transport,span,available,&got);
    if (result) return result;
    if (!got) {
        if (core_ss_body_eof(&connection->incoming)) return stream_error(connection,"truncated Shadowsocks response");
        connection->transport_eof=1; return 0;
    }
    connection->response_started=1;
    if (core_ss_body_commit(&connection->incoming,got)) return stream_error(connection,errno == EOVERFLOW ? "Shadowsocks nonce limit reached" : "invalid Shadowsocks response");
    if (connection->incoming.plain_length) return core_ss_body_read(&connection->incoming,output,capacity,written);
    return 1;
}

int core_ss_tick(core_ss_conn_t *connection) {
    if (!connection || !connection->finish_requested || connection->finish_sent) return 0;
    if (tls13_finish_write(connection->transport,0)) return stream_error(connection,"Shadowsocks transport finish failed");
    connection->finish_sent=1; return 0;
}
int core_ss_finish(core_ss_conn_t *connection) { connection->finish_requested=1; return core_ss_tick(connection); }
int core_ss_finish_pending(const core_ss_conn_t *connection) {
    int result=tls13_finish_pending(connection->transport);
    return result ? result : connection->finish_requested && !connection->finish_sent;
}
