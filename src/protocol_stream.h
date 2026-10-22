#ifndef CORE_PROTOCOL_STREAM_H
#define CORE_PROTOCOL_STREAM_H
#include "tls13_reality.h"
typedef struct core_protocol_ops core_protocol_ops_t;
typedef struct { void *state; const core_protocol_ops_t *ops; } core_protocol_stream_t;
int core_protocol_open(const vless_config_t *,tls13_conn_t *,const char *,uint16_t,const uint8_t *,size_t,core_protocol_stream_t *);
void core_protocol_close(core_protocol_stream_t *);
int core_protocol_prepare_write(core_protocol_stream_t *,size_t);
int core_protocol_write(core_protocol_stream_t *,const uint8_t *,size_t);
int core_protocol_read(core_protocol_stream_t *,uint8_t *,size_t,size_t *);
int core_protocol_response_ready(const core_protocol_stream_t *);
int core_protocol_response_started(const core_protocol_stream_t *);
int core_protocol_pending(const core_protocol_stream_t *);
int core_protocol_drain_pending(const core_protocol_stream_t *);
const char *core_protocol_error(const core_protocol_stream_t *);
int core_protocol_tick(core_protocol_stream_t *);
int core_protocol_finish(core_protocol_stream_t *);
int core_protocol_finish_pending(const core_protocol_stream_t *);
#endif
