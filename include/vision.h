#ifndef VLESS_CORE_VISION_H
#define VLESS_CORE_VISION_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t uuid[16];
    int uuid_sent;
    int padding_active;
    int packets_left;
    int bootstrap_sent;
    int client_hello_seen;
    int client_tls_app_records;
    int direct_sent;
} vision_wrap_t;

typedef struct {
    uint8_t uuid[16];

    int32_t remaining_command;
    int32_t remaining_content;
    int32_t remaining_padding;
    int current_command;

    uint8_t *stash;
    size_t stash_len;
    size_t stash_cap;
} vision_unpad_t;

void vision_wrap_init(vision_wrap_t *ctx, const uint8_t uuid[16]);
int vision_wrap_bootstrap(vision_wrap_t *ctx, uint8_t **out, size_t *out_len);
int vision_wrap_payload(vision_wrap_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

void vision_unpad_init(vision_unpad_t *ctx, const uint8_t uuid[16]);
void vision_unpad_free(vision_unpad_t *ctx);
int vision_unpad_feed(vision_unpad_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, int *switch_to_direct);

#endif
