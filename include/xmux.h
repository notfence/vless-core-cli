#ifndef CORE_XMUX_H
#define CORE_XMUX_H
#include "types.h"
#include <stddef.h>
#include <stdint.h>

typedef struct core_xmux_stream core_xmux_stream_t;
typedef struct {
    uint8_t type, flags;
    int event, status, close_connection;
    uint32_t id;
    uint8_t *data;
    size_t length;
} core_xmux_frame_t;
typedef struct {
    int (*open)(const vless_config_t *, void **, int *, char *, size_t);
    void (*close)(void *);
    int (*fd)(void *);
    short (*events)(void *);
    int (*collect)(void *);
    int (*read_frame)(void *, core_xmux_frame_t *, size_t);
    int (*send_frame)(void *, uint8_t, uint8_t, uint32_t, const uint8_t *, size_t);
    int (*flush)(void *);
    size_t (*pending)(void *);
    uint64_t (*enqueued)(void *);
    uint64_t (*flushed)(void *);
    int (*request)(void *, const vless_config_t *, const char *, uint64_t, int, const uint8_t *, size_t, uint32_t *, uint32_t, size_t *, size_t *);
    int (*session)(const vless_config_t *, char *, size_t);
} core_xmux_backend_t;

core_xmux_stream_t *core_xmux_connect(const vless_config_t *, const core_xmux_backend_t *, char *, size_t);
int core_xmux_fd(const core_xmux_stream_t *);
int core_xmux_pending(const core_xmux_stream_t *);
void core_xmux_drain_notifications(core_xmux_stream_t *);
size_t core_xmux_write_capacity(const core_xmux_stream_t *);
int core_xmux_reserve_write(core_xmux_stream_t *, size_t);
void core_xmux_release_write(core_xmux_stream_t *);
int core_xmux_write(core_xmux_stream_t *, const uint8_t *, size_t);
int core_xmux_read(core_xmux_stream_t *, uint8_t *, size_t, size_t *);
void core_xmux_close(core_xmux_stream_t *);
#endif
