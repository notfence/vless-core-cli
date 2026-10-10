#ifndef CORE_XHTTP_PAYLOAD_H
#define CORE_XHTTP_PAYLOAD_H
#include "types.h"

typedef struct {
    const char *placement, *key;
    core_range_t chunks;
} core_xhttp_payload_options_t;
typedef struct {
    char *headers;
    size_t consumed, body_size;
} core_xhttp_payload_t;
int core_http_token(const char *);
int core_xhttp_payload_build(const core_xhttp_payload_options_t *, const uint8_t *, size_t, const char *, size_t, core_xhttp_payload_t *, char *, size_t);
#endif
