#include "protocol_stream.h"
#include "vmess_stream.h"
#include "shadowsocks_stream.h"
#include <errno.h>

struct core_protocol_ops {
    void (*close)(void *);
    int (*prepare)(void *,size_t);
    int (*write)(void *,const uint8_t *,size_t);
    int (*read)(void *,uint8_t *,size_t,size_t *);
    int (*ready)(const void *);
    int (*started)(const void *);
    int (*pending)(const void *);
    int (*drain)(const void *);
    const char *(*error)(const void *);
    int (*tick)(void *);
    int (*finish)(void *);
    int (*finishing)(const void *);
};

static void vmess_close(void *state) { core_vmess_close(state); }
static int vmess_prepare(void *state,size_t size) { (void)size; return core_vmess_prepare_write(state); }
static int vmess_write(void *state,const uint8_t *data,size_t size) { return core_vmess_write(state,data,size); }
static int vmess_read(void *state,uint8_t *data,size_t size,size_t *written) { return core_vmess_read(state,data,size,written); }
static int vmess_ready(const void *state) { return core_vmess_response_ready(state); }
static int vmess_started(const void *state) { return core_vmess_response_started(state); }
static int vmess_pending(const void *state) { return core_vmess_pending(state); }
static int vmess_drain(const void *state) { return core_vmess_drain_pending(state); }
static const char *vmess_error(const void *state) { return core_vmess_error(state); }
static int vmess_tick(void *state) { return core_vmess_tick(state); }
static int vmess_finish(void *state) { return core_vmess_finish(state); }
static int vmess_finishing(const void *state) { return core_vmess_finish_pending(state); }
static const core_protocol_ops_t vmess_ops={vmess_close,vmess_prepare,vmess_write,vmess_read,vmess_ready,vmess_started,vmess_pending,vmess_drain,vmess_error,vmess_tick,vmess_finish,vmess_finishing};

static void ss_close(void *state) { core_ss_close(state); }
static int ss_prepare(void *state,size_t size) { return core_ss_prepare_write(state,size); }
static int ss_write(void *state,const uint8_t *data,size_t size) { return core_ss_write(state,data,size); }
static int ss_read(void *state,uint8_t *data,size_t size,size_t *written) { return core_ss_read(state,data,size,written); }
static int ss_ready(const void *state) { return core_ss_response_ready(state); }
static int ss_started(const void *state) { return core_ss_response_started(state); }
static int ss_pending(const void *state) { return core_ss_pending(state); }
static int ss_drain(const void *state) { return core_ss_drain_pending(state); }
static const char *ss_error(const void *state) { return core_ss_error(state); }
static int ss_tick(void *state) { return core_ss_tick(state); }
static int ss_finish(void *state) { return core_ss_finish(state); }
static int ss_finishing(const void *state) { return core_ss_finish_pending(state); }
static const core_protocol_ops_t ss_ops={ss_close,ss_prepare,ss_write,ss_read,ss_ready,ss_started,ss_pending,ss_drain,ss_error,ss_tick,ss_finish,ss_finishing};

int core_protocol_open(const vless_config_t *config,tls13_conn_t *transport,const char *target,uint16_t port,const uint8_t *first,size_t length,core_protocol_stream_t *output) {
    if (!output || output->state) { errno=EINVAL; return -1; }
    int result;
    if (config->protocol == CORE_PROTOCOL_VMESS) {
        core_vmess_conn_t *state=NULL;
        result=core_vmess_open(config,transport,target,port,first,length,&state);
        if (!result) { output->state=state; output->ops=&vmess_ops; }
    } else if (config->protocol == CORE_PROTOCOL_SHADOWSOCKS) {
        core_ss_conn_t *state=NULL;
        result=core_ss_open(config,transport,target,port,first,length,&state);
        if (!result) { output->state=state; output->ops=&ss_ops; }
    } else { errno=EINVAL; return -1; }
    return result;
}

void core_protocol_close(core_protocol_stream_t *stream) { if (stream && stream->state) { stream->ops->close(stream->state); stream->state=NULL; stream->ops=NULL; } }
int core_protocol_prepare_write(core_protocol_stream_t *stream,size_t size) { return stream->ops->prepare(stream->state,size); }
int core_protocol_write(core_protocol_stream_t *stream,const uint8_t *data,size_t size) { return stream->ops->write(stream->state,data,size); }
int core_protocol_read(core_protocol_stream_t *stream,uint8_t *data,size_t size,size_t *written) { return stream->ops->read(stream->state,data,size,written); }
int core_protocol_response_ready(const core_protocol_stream_t *stream) { return stream && stream->state && stream->ops->ready(stream->state); }
int core_protocol_response_started(const core_protocol_stream_t *stream) { return stream && stream->state && stream->ops->started(stream->state); }
int core_protocol_pending(const core_protocol_stream_t *stream) { return stream && stream->state && stream->ops->pending(stream->state); }
int core_protocol_drain_pending(const core_protocol_stream_t *stream) { return stream && stream->state && stream->ops->drain(stream->state); }
const char *core_protocol_error(const core_protocol_stream_t *stream) { return stream->ops->error(stream->state); }
int core_protocol_tick(core_protocol_stream_t *stream) { return stream && stream->state ? stream->ops->tick(stream->state) : 0; }
int core_protocol_finish(core_protocol_stream_t *stream) { return stream->ops->finish(stream->state); }
int core_protocol_finish_pending(const core_protocol_stream_t *stream) { return stream->ops->finishing(stream->state); }
