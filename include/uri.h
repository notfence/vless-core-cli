#ifndef VLESS_CORE_URI_H
#define VLESS_CORE_URI_H

#include <stddef.h>

#include "types.h"

int parse_vless_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap);
int parse_core_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap);

#endif
