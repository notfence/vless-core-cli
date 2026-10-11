#ifndef CORE_XMUX_H
#define CORE_XMUX_H
#include "types.h"
#include <stddef.h>
#include <stdint.h>

#include "http2_pool.h"
typedef core_http2_stream_t core_xmux_stream_t;
typedef core_http2_frame_t core_xmux_frame_t;
typedef core_http2_backend_t core_xmux_backend_t;

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
