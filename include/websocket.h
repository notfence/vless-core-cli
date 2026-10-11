#ifndef VLESS_CORE_WEBSOCKET_H
#define VLESS_CORE_WEBSOCKET_H
#include <stddef.h>
#include <stdint.h>
#include "types.h"

#define CORE_WS_MESSAGE_LIMIT (16U*1024U*1024U)
typedef struct {
    uint8_t header[10], control[125];
    size_t header_used, control_used;
    uint64_t remaining, message_length;
    unsigned active, opcode, fin, fragmented, text;
    unsigned utf_left, utf_min, utf_max, closed, failed;
} core_ws_decoder_t;
typedef struct { unsigned opcode; const uint8_t *data; size_t length; } core_ws_event_t;
int core_ws_decode(core_ws_decoder_t *state, const uint8_t *input, size_t length, size_t *consumed, core_ws_event_t *event);
int core_ws_parameter(vless_config_t *config, const char *key, const char *value, char *error, size_t capacity);
int core_ws_configure(vless_config_t *config, char *error, size_t capacity);
#endif
