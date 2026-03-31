#ifndef VLESS_CORE_VLESS_H
#define VLESS_CORE_VLESS_H

#include <stdint.h>

#include "tls13_reality.h"
#include "types.h"

int vless_send_request(tls13_conn_t *tls, const vless_config_t *cfg, const char *target_host, uint16_t target_port);
int vless_read_response(tls13_conn_t *tls);

#endif
