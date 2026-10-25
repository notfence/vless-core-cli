#ifndef CORE_HTTPUPGRADE_H
#define CORE_HTTPUPGRADE_H
#include "types.h"

int core_httpupgrade_parameter(vless_config_t *, const char *, const char *, char *, size_t);
int core_httpupgrade_configure(vless_config_t *, char *, size_t);
int core_httpupgrade_path(const char *, char *, size_t);
int core_httpupgrade_validate(const uint8_t *, size_t);
#endif
