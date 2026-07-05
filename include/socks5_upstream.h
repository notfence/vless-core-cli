#ifndef VLESS_CORE_SOCKS5_UPSTREAM_H
#define VLESS_CORE_SOCKS5_UPSTREAM_H

#include <stddef.h>
#include <stdint.h>

#include "types.h"

int socks5_upstream_connect(const vless_config_t *cfg, const char *target_host, uint16_t target_port, char *err, size_t err_cap);

#endif
