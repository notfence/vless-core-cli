#ifndef VLESS_CORE_TLS13_REALITY_H
#define VLESS_CORE_TLS13_REALITY_H

#include <stddef.h>
#include <stdint.h>

#include "types.h"

typedef struct tls13_conn tls13_conn_t;

int tls13_reality_connect(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap);
void tls13_reality_close(tls13_conn_t *c);

int tls13_get_fd(const tls13_conn_t *c);
int tls13_reality_is_raw_direct(const tls13_conn_t *c);
int tls13_has_pending_app(const tls13_conn_t *c);
void tls13_mark_raw_direct(tls13_conn_t *c);

int tls13_write_app(tls13_conn_t *c, const uint8_t *buf, size_t len);
int tls13_read_app(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len);
int tls13_read_exact_app(tls13_conn_t *c, uint8_t *buf, size_t len);

#endif
