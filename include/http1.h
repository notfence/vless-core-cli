#ifndef CORE_HTTP1_H
#define CORE_HTTP1_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int state, chunked, close_connection;
    uint64_t remaining;
    size_t header_bytes;
} core_http1_response_t;
typedef struct {
    int kind, status, close_connection;
    size_t consumed, offset, length;
} core_http1_event_t;
int core_http1_next(core_http1_response_t *, const uint8_t *, size_t, int, size_t, core_http1_event_t *);
#endif
