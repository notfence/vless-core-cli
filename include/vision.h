#ifndef VLESS_CORE_VISION_H
#define VLESS_CORE_VISION_H

#include <stddef.h>
#include <stdint.h>
#include "relay_memory.h"

typedef struct {
    uint8_t record[5],message[4],prefix[72],field[4];
    size_t record_used,message_used,prefix_used,prefix_need,field_used;
    uint32_t record_left,message_left,skip_left,extensions_left,extension_left,records;
    unsigned phase,extension,version,cipher;
    int interested,version_seen,compression_seen,retry,last_application;
} vision_tls_reader_t;

typedef struct {
    uint8_t uuid[16];
    int uuid_sent;
    int padding_active;
    int packets_left;
    int bootstrap_sent;
    int client_hello_seen;
    int client_tls_app_records;
    int direct_sent;
    int server_hello_seen,tls13_confirmed,tls_disabled;
    vision_tls_reader_t client_tls,server_tls;
} vision_wrap_t;

typedef struct {
    uint8_t uuid[16];

    int32_t remaining_command;
    int32_t remaining_content;
    int32_t remaining_padding;
    int current_command;
    int completed_block;

    uint8_t *stash;
    size_t stash_len;
    size_t stash_cap;
    core_buffer_budget_t *memory;
} vision_unpad_t;

void vision_wrap_init(vision_wrap_t *ctx, const uint8_t uuid[16]);
void vision_observe_tls(vision_wrap_t *ctx, int server, const uint8_t *data, size_t length);
int vision_wrap_bootstrap(vision_wrap_t *ctx, uint8_t **out, size_t *out_len);
int vision_wrap_payload(vision_wrap_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
int vision_wrap_bootstrap_buffer(vision_wrap_t *,core_relay_buffer_t *);
int vision_wrap_payload_buffer(vision_wrap_t *,const uint8_t *,size_t,core_relay_buffer_t *);
size_t vision_wrap_buffer_bound(size_t);

void vision_unpad_init(vision_unpad_t *ctx, const uint8_t uuid[16]);
void vision_unpad_free(vision_unpad_t *ctx);
int vision_unpad_complete(const vision_unpad_t *ctx);
int vision_unpad_feed(vision_unpad_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, int *switch_to_direct);
int vision_unpad_feed_buffer(vision_unpad_t *,const uint8_t *,size_t,core_relay_buffer_t *,int *);
size_t vision_unpad_buffer_bound(const vision_unpad_t *,size_t);
int vision_unpad_is_raw(const vision_unpad_t *);

#endif
