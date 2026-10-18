#ifndef VLESS_CORE_URI_H
#define VLESS_CORE_URI_H

#include <stddef.h>

#include "types.h"

#define CORE_URI_MAX_LENGTH 4095

int parse_vless_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap);
int parse_core_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap);
void core_config_defaults(vless_config_t *);
int core_server_host_valid(const char *);
int core_http_authority_format(const char *, char *, size_t);

#endif
