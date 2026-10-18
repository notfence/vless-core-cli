#ifndef CORE_HTTP2_QUEUE_H
#define CORE_HTTP2_QUEUE_H
#include "buffer_budget.h"
#include <stddef.h>
#include <stdint.h>

#define CORE_HTTP2_QUEUE_BLOCK 16384U
#define CORE_HTTP2_QUEUE_CACHE (256U*1024U)
typedef struct core_http2_block core_http2_block_t;
typedef struct {
    uint8_t *data;
    size_t start, length, capacity;
    core_http2_block_t *head, *tail;
    core_buffer_budget_t memory;
    core_buffer_budget_t *account;
} core_http2_queue_t;
int core_http2_queue_append(core_http2_queue_t *, const uint8_t *, size_t, size_t);
int core_http2_queue_append_parts(core_http2_queue_t *, const uint8_t *, size_t, const uint8_t *, size_t, size_t);
void core_http2_queue_consume(core_http2_queue_t *, size_t);
void core_http2_queue_clear(core_http2_queue_t *);
size_t core_http2_queue_span(const core_http2_queue_t *);
void core_http2_queue_copy(const core_http2_queue_t *, uint8_t *, size_t);
size_t core_http2_queue_reservation(size_t);
void core_http2_queue_cache_clear(void);
#endif
