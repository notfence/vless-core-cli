#ifndef V2RAYIOS6_URI_H
#define V2RAYIOS6_URI_H

#include <stddef.h>

#include "types.h"

int parse_vless_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap);

#endif
