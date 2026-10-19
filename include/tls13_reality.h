#ifndef VLESS_CORE_TLS13_REALITY_H
#define VLESS_CORE_TLS13_REALITY_H

#include <stddef.h>
#include <stdint.h>

#include "types.h"

typedef struct tls13_conn tls13_conn_t;

int tls13_reality_set_xray_version(const char *value);
int tls13_reality_connect(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap);
void tls13_reality_close(tls13_conn_t *c);

int tls13_get_fd(const tls13_conn_t *c);
int tls13_reality_is_raw_direct(const tls13_conn_t *c);
int tls13_has_pending_app(const tls13_conn_t *c);
int tls13_has_pending_input(const tls13_conn_t *c);
int tls13_needs_write(const tls13_conn_t *c);
int tls13_idle_timeout(const tls13_conn_t *c);
int tls13_tick(tls13_conn_t *c);
int tls13_start_relay(tls13_conn_t *c);
int tls13_flush(tls13_conn_t *c);
void tls13_set_request_fence(tls13_conn_t *c);
int tls13_request_pending(const tls13_conn_t *c);
int tls13_write_raw(tls13_conn_t *c, const uint8_t *buf, size_t len);
int tls13_read_raw(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len);
int tls13_has_pending_raw(const tls13_conn_t *c);
int tls13_finish_write(tls13_conn_t *c, int raw);
int tls13_finish_pending(const tls13_conn_t *c);
int tls13_full_close(const tls13_conn_t *c);
int tls13_send_stopped(const tls13_conn_t *c);
int tls13_uses_h2(const tls13_conn_t *c);
int tls13_uses_async_io(const tls13_conn_t *c);
int tls13_drain_h2_input(tls13_conn_t *c);
size_t tls13_write_batch_size(const tls13_conn_t *c);
size_t tls13_write_capacity(const tls13_conn_t *c);
int tls13_reserve_write(tls13_conn_t *c, size_t capacity);
void tls13_release_write(tls13_conn_t *c);
void tls13_mark_raw_direct(tls13_conn_t *c);

int tls13_write_app(tls13_conn_t *c, const uint8_t *buf, size_t len);
/* Returns 1 after consuming a transport control frame without app data. */
int tls13_read_app(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len);
int tls13_read_exact_app(tls13_conn_t *c, uint8_t *buf, size_t len);
int tls13_read_exact_or_eof(tls13_conn_t *c, uint8_t *buf, size_t len);

#endif
