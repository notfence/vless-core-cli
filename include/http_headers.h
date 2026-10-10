#ifndef CORE_HTTP_HEADERS_H
#define CORE_HTTP_HEADERS_H
#include "json.h"
#include <stddef.h>

const char *core_http_header_get(const char *, const char *, size_t *);
int core_http_header_set(char *, size_t, const char *, const char *);
int core_http_header_append_cookie(char *, size_t, const char *);
int core_http_headers_parse(const core_json_t *, char *, size_t, char *, size_t);
int core_http_header_allowed(const char *);
#endif
