#ifndef CORE_XHTTP_DOWNLOAD_H
#define CORE_XHTTP_DOWNLOAD_H
#include "types.h"
#include "json.h"

int core_xhttp_download_parse(const core_json_t *, vless_config_t *, char *, size_t);
int core_xhttp_download_config(const vless_config_t *, vless_config_t *, char *, size_t);
#endif
