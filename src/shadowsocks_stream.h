#ifndef CORE_SHADOWSOCKS_STREAM_H
#define CORE_SHADOWSOCKS_STREAM_H
#include "tls13_reality.h"
typedef struct core_ss_conn core_ss_conn_t;
int core_ss_open(const vless_config_t *,tls13_conn_t *,const char *,uint16_t,const uint8_t *,size_t,core_ss_conn_t **);
void core_ss_close(core_ss_conn_t *);
int core_ss_prepare_write(core_ss_conn_t *,size_t);
int core_ss_write(core_ss_conn_t *,const uint8_t *,size_t);
int core_ss_read(core_ss_conn_t *,uint8_t *,size_t,size_t *);
int core_ss_response_ready(const core_ss_conn_t *);
int core_ss_response_started(const core_ss_conn_t *);
int core_ss_pending(const core_ss_conn_t *);
int core_ss_drain_pending(const core_ss_conn_t *);
const char *core_ss_error(const core_ss_conn_t *);
int core_ss_tick(core_ss_conn_t *);
int core_ss_finish(core_ss_conn_t *);
int core_ss_finish_pending(const core_ss_conn_t *);
#endif
