#ifndef CORE_XHTTP_PAYLOAD_H
#define CORE_XHTTP_PAYLOAD_H
#include "types.h"
#include "buffer_budget.h"

typedef struct {
    const char *placement, *key;
    core_range_t chunks;
    core_buffer_budget_t *memory;
} core_xhttp_payload_options_t;
typedef struct {
    char *headers;
    size_t consumed, body_size;
    size_t header_capacity;
    core_buffer_budget_t *memory;
} core_xhttp_payload_t;
void core_xhttp_payload_clear(core_xhttp_payload_t *);
int core_http_token(const char *);
int core_xhttp_payload_build(const core_xhttp_payload_options_t *, const uint8_t *, size_t, const char *, size_t, core_xhttp_payload_t *, char *, size_t);
#endif
