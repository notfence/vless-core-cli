#ifndef CORE_XHTTP_CONFIG_H
#define CORE_XHTTP_CONFIG_H
#include "types.h"
#include "json.h"

int core_xhttp_extra(vless_config_t *config, const char *json, char *error, size_t capacity);
int core_xhttp_parameter(vless_config_t *config, const char *key, const char *text, char *error, size_t capacity);
int core_xhttp_range(const core_json_t *value, core_range_t *range, int maximum);
#endif
