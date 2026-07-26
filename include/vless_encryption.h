#ifndef VLESS_CORE_VLESS_ENCRYPTION_H
#define VLESS_CORE_VLESS_ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

#include "tls13_reality.h"
#include "types.h"

typedef struct vless_encryption_conn vless_encryption_conn_t;

int vless_encryption_connect(const vless_config_t *cfg, tls13_conn_t *transport,
                             vless_encryption_conn_t **out,
                             char *err, size_t err_cap);
void vless_encryption_close(vless_encryption_conn_t *conn);
int vless_encryption_write(vless_encryption_conn_t *conn,
                           const uint8_t *buf, size_t len);
int vless_encryption_write_raw(vless_encryption_conn_t *conn,
                               const uint8_t *buf, size_t len);
int vless_encryption_read(vless_encryption_conn_t *conn,
                          uint8_t *buf, size_t cap, size_t *out_len);
int vless_encryption_read_raw(vless_encryption_conn_t *conn,
                              uint8_t *buf, size_t cap, size_t *out_len);
int vless_encryption_read_exact(vless_encryption_conn_t *conn,
                                uint8_t *buf, size_t len);

#endif
