#ifndef CORE_HTTP2_POOL_H
#define CORE_HTTP2_POOL_H
#include "types.h"
#include <stddef.h>
#include <stdint.h>

typedef struct core_http2_stream core_http2_stream_t;
typedef struct {
    uint8_t type, flags;
    int event, status, close_connection;
    uint32_t id;
    uint8_t *data;
    size_t length;
} core_http2_frame_t;
typedef struct {
    int (*open)(const vless_config_t *, void **, int *, char *, size_t);
    void (*close)(void *);
    int (*fd)(void *);
    short (*events)(void *);
    int (*collect)(void *);
    int (*read_frame)(void *, core_http2_frame_t *, size_t);
    int (*send_frame)(void *, uint8_t, uint8_t, uint32_t, const uint8_t *, size_t);
    int (*flush)(void *);
    size_t (*pending)(void *);
    uint64_t (*enqueued)(void *);
    uint64_t (*flushed)(void *);
    int (*request)(void *, const vless_config_t *, const char *, uint64_t, int, const uint8_t *, size_t, uint32_t *, uint32_t, size_t *, size_t *);
    int (*session)(const vless_config_t *, char *, size_t);
} core_http2_backend_t;

core_http2_stream_t *core_http2_connect(const vless_config_t *, const core_http2_backend_t *, char *, size_t);
int core_http2_fd(const core_http2_stream_t *);
int core_http2_pending(const core_http2_stream_t *);
int core_http2_start_relay(core_http2_stream_t *);
void core_http2_drain_notifications(core_http2_stream_t *);
size_t core_http2_write_capacity(const core_http2_stream_t *);
int core_http2_reserve_write(core_http2_stream_t *, size_t);
void core_http2_release_write(core_http2_stream_t *);
int core_http2_write(core_http2_stream_t *, const uint8_t *, size_t);
int core_http2_read(core_http2_stream_t *, uint8_t *, size_t, size_t *);
int core_http2_finish_write(core_http2_stream_t *);
int core_http2_finish_pending(const core_http2_stream_t *);
void core_http2_close(core_http2_stream_t *);
#endif
