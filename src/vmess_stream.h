#ifndef CORE_VMESS_STREAM_H
#define CORE_VMESS_STREAM_H
#include "tls13_reality.h"
typedef struct core_vmess_conn core_vmess_conn_t;
int core_vmess_open(const vless_config_t *,tls13_conn_t *,const char *,uint16_t,const uint8_t *,size_t,core_vmess_conn_t **);
void core_vmess_close(core_vmess_conn_t *);
int core_vmess_prepare_write(core_vmess_conn_t *);
int core_vmess_write(core_vmess_conn_t *,const uint8_t *,size_t);
int core_vmess_read(core_vmess_conn_t *,uint8_t *,size_t,size_t *);
int core_vmess_response_ready(const core_vmess_conn_t *);
int core_vmess_response_started(const core_vmess_conn_t *);
int core_vmess_pending(const core_vmess_conn_t *);
int core_vmess_drain_pending(const core_vmess_conn_t *);
const char *core_vmess_error(const core_vmess_conn_t *);
int core_vmess_tick(core_vmess_conn_t *);
int core_vmess_finish(core_vmess_conn_t *);
int core_vmess_finish_pending(const core_vmess_conn_t *);
#endif
