#ifndef VLESS_CORE_VLESS_H
#define VLESS_CORE_VLESS_H

#include <stddef.h>
#include <stdint.h>

#include "tls13_reality.h"
#include "types.h"
#include "vless_encryption.h"
typedef struct { unsigned header_bytes, addon_bytes, complete; } vless_response_t;
int vless_consume_response(vless_response_t *, const uint8_t *, size_t, size_t *);

int vless_build_request(uint8_t *packet, size_t cap, size_t *out_len, const vless_config_t *cfg, const char *target_host, uint16_t target_port);
int vless_send_request(tls13_conn_t *tls, vless_encryption_conn_t *encryption,
                       const vless_config_t *cfg, const char *target_host,
                       uint16_t target_port);
int vless_read_response(tls13_conn_t *tls,
                        vless_encryption_conn_t *encryption);

#endif
