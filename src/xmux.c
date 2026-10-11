#include "xmux.h"
core_xmux_stream_t *core_xmux_connect(const vless_config_t *config, const core_xmux_backend_t *backend, char *error, size_t capacity) {
    return core_http2_connect(config,backend,error,capacity);
}
int core_xmux_fd(const core_xmux_stream_t *stream) { return core_http2_fd(stream); }
int core_xmux_pending(const core_xmux_stream_t *stream) { return core_http2_pending(stream); }
void core_xmux_drain_notifications(core_xmux_stream_t *stream) { core_http2_drain_notifications(stream); }
size_t core_xmux_write_capacity(const core_xmux_stream_t *stream) { return core_http2_write_capacity(stream); }
int core_xmux_reserve_write(core_xmux_stream_t *stream, size_t capacity) { return core_http2_reserve_write(stream,capacity); }
void core_xmux_release_write(core_xmux_stream_t *stream) { core_http2_release_write(stream); }
int core_xmux_write(core_xmux_stream_t *stream, const uint8_t *data, size_t length) { return core_http2_write(stream,data,length); }
int core_xmux_read(core_xmux_stream_t *stream, uint8_t *data, size_t capacity, size_t *length) { return core_http2_read(stream,data,capacity,length); }
void core_xmux_close(core_xmux_stream_t *stream) { core_http2_close(stream); }
