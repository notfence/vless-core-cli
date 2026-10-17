#ifndef CORE_HTTP2_H
#define CORE_HTTP2_H
#include "hpack.h"
#include <stddef.h>
#include <stdint.h>

typedef struct { uint32_t continuation; unsigned settings_received, settings_pending; } core_http2_validation_t;
typedef struct {
    uint32_t table_size,concurrency,initial_window,max_frame,header_limit;
    unsigned received;
} core_http2_settings_t;
int core_http2_alps_parse(const uint8_t *,size_t,core_http2_settings_t *);
typedef struct {
    uint64_t content_length, received;
    unsigned headers, ended, has_content_length, no_body;
} core_http2_response_t;
int core_http2_validate_frame(core_http2_validation_t *, uint8_t, uint8_t, uint32_t, const uint8_t *, size_t);
int core_http2_response_headers(core_http2_response_t *, const core_hpack_headers_t *, int);
int core_http2_response_data(core_http2_response_t *, size_t, int);
#endif
