#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "http2_pool.h"
#include "core_random.h"
#include "deadline.h"
#include "connection_trace.h"
#include "socket_util.h"
#include "hpack.h"
#include "http2.h"
#include "http2_queue.h"
#include "grpc.h"
#include "core_log.h"
#include "server_ips.h"
#include "xhttp_config.h"
#include "xhttp_download.h"
#include "blake3.h"
#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define XMUX_STREAM_LIMIT CORE_HTTP2_STREAM_LIMIT
#define XMUX_TOTAL_LIMIT (16U*1024U*1024U)
#define XMUX_TX_RESERVE (64U*1024U)
#define XMUX_CANCEL_DRAIN_MS 2000U
#define XMUX_PACKET_IDLE_MS 8U
#define XMUX_PACKET_AGE_MS 100U

typedef core_http2_queue_t mux_queue_t;
typedef struct mux_actor mux_actor_t;
typedef struct mux_manager mux_manager_t;
typedef struct mux_group mux_group_t;
typedef struct mux_request {
    struct mux_request *next;
    core_http2_stream_t *stream;
    uint32_t id;
    int role, ended, reset, send_ended;
    core_http2_response_t response;
    int64_t send_window, receive_window;
    size_t remaining;
    uint64_t packet_idle_ms,packet_until_ms;
} mux_request_t;

struct core_http2_stream {
    struct core_http2_stream *next;
    mux_actor_t *download, *upload;
    vless_config_t config;
    char session[256], error[160];
    uint64_t sequence, until_ms;
    uint64_t download_fence, upload_fence, write_fence;
    uint64_t last_post_ms, next_post_ms;
    int packet_limit;
    mux_queue_t tx, rx;
    uint32_t down_id, up_id;
    size_t consumed, reserved_upload;
    size_t permanent_upload;
    int notify[2], notified, ready, failed, eof, closed, references;
    int first_actor;
    mux_manager_t *waiting_manager;
    mux_manager_t *waiting_download;
    int finish_requested, finish_sent, relay_async, send_stopped;
    uint64_t finish_fence;
    core_connection_trace_t trace;
    core_connection_error_t failure;
    int trace_present;
};

struct mux_actor {
    mux_actor_t *next;
    mux_manager_t *manager;
    mux_group_t *group;
    void *physical;
    mux_request_t *requests;
    core_hpack_decoder_t hpack;
    core_http2_validation_t validation;
    mux_queue_t header_block;
    core_connection_trace_t trace;
    core_trace_stage_t progress_stage;
    uint32_t header_id;
    uint32_t latest_stream;
    uint8_t header_flags, trace_present;
    int wake[2], opening, failed, draining, stopped, http2;
    int thread_started,closing,close_waiters;
    uint32_t pending_credit;
    int alive_period, receive_slots;
    uint64_t connect_until_ms, last_input_ms, ping_deadline_ms;
    uint8_t ping[8];
    int64_t send_window, receive_window;
    uint32_t peer_window, peer_frame, peer_concurrency, peer_header_limit;
    size_t net_accounted;
    core_buffer_budget_t input_memory, output_memory;
    core_buffer_waiter_t memory_waiter;
    uint64_t enqueued, flushed;
    uint64_t idle_pending_ms;
    char error[160];
    core_connection_error_t failure;
};

struct mux_group {
    mux_group_t *next;
    mux_manager_t *manager;
    int uses, running, requests, reuse_limit, request_limit, retired;
    uint64_t expires_ms;
};

struct mux_manager {
    mux_manager_t *next;
    vless_config_t config;
    const core_http2_backend_t *backend;
    mux_actor_t *actors;
    mux_group_t *groups;
    int concurrency, connections;
    uint8_t pins[32];
};

static pthread_mutex_t mux_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t workers_stopped=PTHREAD_COND_INITIALIZER;
static mux_manager_t *managers;
static core_http2_stream_t *streams;
static size_t upload_bytes, download_bytes, actor_count, stream_count;
static void signal_stream(core_http2_stream_t *stream);
static int update_upload_budget(core_http2_stream_t *stream);
static size_t last_upload_room=CORE_BUFFER_TOTAL_LIMIT;

static void wake_admission(void) {
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
        if (stream->waiting_manager) signal_stream(stream);
}

static int grpc_manager(const mux_manager_t *manager) { return manager->config.transport_mode == TRANSPORT_GRPC; }

static int actor_failed(mux_actor_t *actor) {
    pthread_mutex_lock(&mux_lock); int failed=actor->failed || actor->closing; pthread_mutex_unlock(&mux_lock); return failed;
}

static void mark_failed(mux_actor_t *actor, core_failure_kind_t kind, int cause) {
    pthread_mutex_lock(&mux_lock);
    if (!actor->failure.kind) actor->failure=core_connection_error(CORE_TRACE_TRANSPORT,kind,cause ? cause : EIO);
    actor->failed=1; pthread_mutex_unlock(&mux_lock);
}

static void trace_progress(core_trace_stage_t stage, void *opaque) {
    mux_actor_t *actor=opaque;
    pthread_mutex_lock(&mux_lock); actor->progress_stage=stage;
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
        if ((stream->download == actor || stream->upload == actor) && stream->ready != 1) signal_stream(stream);
    pthread_mutex_unlock(&mux_lock);
}

static void collect_stopped_actors(void) {
    for (mux_manager_t *manager=managers;manager;manager=manager->next) {
        mux_actor_t **cursor=&manager->actors;
        while (*cursor) {
            mux_actor_t *actor=*cursor; int used=0;
            for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
                if (stream->download == actor || stream->upload == actor) { used=1; break; }
            if (actor->stopped && !used && !actor->close_waiters) { *cursor=actor->next; free(actor); }
            else cursor=&actor->next;
        }
        mux_group_t **group=&manager->groups;
        while (*group) {
            int used=0;
            for (mux_actor_t *actor=manager->actors;actor;actor=actor->next) if (actor->group == *group) used=1;
            if (!used && !(*group)->running) { mux_group_t *old=*group; *group=old->next; free(old); }
            else group=&(*group)->next;
        }
    }
}

static int random_range(core_range_t range) {
    uint32_t value;
    if (range.min < 0 || range.max < range.min) { errno=EINVAL; return -1; }
    if (core_random_range((uint32_t)range.min,(uint32_t)range.max,&value)) return -1;
    return (int)value;
}

static int queue_append(mux_queue_t *queue, const uint8_t *data, size_t length, size_t limit) {
    return core_http2_queue_append(queue,data,length,limit);
}

static void queue_consume(mux_queue_t *queue, size_t length) {
    core_http2_queue_consume(queue,length);
}

static int notification_pair(int pair[2]) {
    if (socketpair(AF_UNIX,SOCK_STREAM,0,pair) != 0) return -1;
    for (size_t i=0;i<2;i++) {
        int flags=fcntl(pair[i],F_GETFL,0);
        if (flags < 0 || fcntl(pair[i],F_SETFL,flags|O_NONBLOCK) != 0 || fcntl(pair[i],F_SETFD,FD_CLOEXEC) != 0) {
            close(pair[0]); close(pair[1]); return -1;
        }
    }
    return 0;
}

static void wake_actor(mux_actor_t *actor) {
    if (actor && !actor->stopped) core_notify_socket(actor->wake[1]);
}

static void wake_channels(mux_manager_t *manager,mux_actor_t *source) {
    for (mux_actor_t *actor=manager->actors;actor;actor=actor->next) if (actor != source) wake_actor(actor);
}

static void signal_stream(core_http2_stream_t *stream) {
    if (!stream->closed && !stream->notified) {
        if (core_notify_socket(stream->notify[1])) stream->notified=1;
    }
}

static void notify_write_capacity(size_t previous) {
    size_t boundary=XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE;
    size_t room=core_buffer_available(CORE_BUFFER_UPLOAD);
    size_t threshold=core_http2_queue_reservation(128U*1024U);
    if (room < threshold) { core_http2_queue_cache_clear(); room=core_buffer_available(CORE_BUFFER_UPLOAD); }
    if ((previous >= boundary && upload_bytes < boundary) ||
        (previous > boundary-128U*1024U && upload_bytes <= boundary-128U*1024U) ||
        (last_upload_room < threshold && room >= threshold))
        for (core_http2_stream_t *stream=streams;stream;stream=stream->next) signal_stream(stream);
    last_upload_room=room;
}

static void fail_stream_error(core_http2_stream_t *stream, const char *error, core_connection_error_t failure) {
    if (!stream->failed) {
        stream->failure=failure;
        stream->failed=1; snprintf(stream->error,sizeof(stream->error),"%s",error);
        vc_log_warning(stream->config.transport_mode == TRANSPORT_GRPC ? "grpc" : "xhttp","%s id=%llu stage=%s category=%s system=%d",
            error,(unsigned long long)stream->trace.id,core_trace_stage_name(failure.stage),core_failure_name(failure.kind),failure.system_error);
        signal_stream(stream);
    }
}

static void stop_upload(core_http2_stream_t *stream) {
    if (stream->send_stopped) return;
    size_t previous=upload_bytes;
    stream->send_stopped=stream->finish_sent=1; stream->finish_fence=0;
    upload_bytes-=stream->tx.length+stream->reserved_upload;
    stream->reserved_upload=stream->permanent_upload=0;
    core_http2_queue_clear(&stream->tx); update_upload_budget(stream);
    stream->write_fence=stream->upload_fence=0;
    notify_write_capacity(previous); signal_stream(stream);
}

static void fail_stream(core_http2_stream_t *stream, const char *error) {
    fail_stream_error(stream,error,core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_PROTOCOL,EPROTO));
}

static void stream_error(const core_http2_stream_t *stream) {
    core_connection_error_t failure=stream->failure.kind ? stream->failure : core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_SYSTEM,ECANCELED);
    core_trace_error_set(failure); errno=failure.system_error;
}

static void release_stream(core_http2_stream_t *stream) {
    if (--stream->references || !stream->closed) return;
    core_http2_stream_t **cursor=&streams;
    while (*cursor && *cursor != stream) cursor=&(*cursor)->next;
    if (*cursor) *cursor=stream->next;
    size_t previous=upload_bytes;
    upload_bytes-=stream->tx.length+stream->reserved_upload; download_bytes-=stream->rx.length;
    notify_write_capacity(previous);
    core_http2_queue_clear(&stream->tx); core_http2_queue_clear(&stream->rx); free(stream); stream_count--;
    wake_admission();
}

static void account_output(mux_actor_t *actor) {
    size_t pending=actor->physical ? actor->manager->backend->pending(actor->physical) : 0;
    size_t previous=upload_bytes;
    size_t previous_actor=actor->net_accounted;
    uint64_t previous_flushed=actor->flushed;
    if (actor->physical && actor->manager->backend->enqueued && actor->manager->backend->flushed) {
        actor->enqueued=actor->manager->backend->enqueued(actor->physical);
        actor->flushed=actor->manager->backend->flushed(actor->physical);
    }
    upload_bytes-=actor->net_accounted; upload_bytes+=pending; actor->net_accounted=pending;
    notify_write_capacity(previous);
    if (previous_actor)
        for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
            if (stream->upload == actor && stream->write_fence > previous_flushed && stream->write_fence <= actor->flushed) signal_stream(stream);
}

static int send_frame(mux_actor_t *actor, uint8_t type, uint8_t flags, uint32_t id, const uint8_t *data, size_t length) {
    int result=actor->manager->backend->send_frame(actor->physical,type,flags,id,data,length);
    account_output(actor); return result;
}

static int window_update(mux_actor_t *actor, uint32_t id, uint32_t bytes) {
    uint8_t data[4]={(uint8_t)(bytes>>24),(uint8_t)(bytes>>16),(uint8_t)(bytes>>8),(uint8_t)bytes};
    return bytes ? send_frame(actor,8,0,id,data,4) : 0;
}

static mux_request_t *find_request(mux_actor_t *actor, uint32_t id) {
    for (mux_request_t *request=actor->requests;request;request=request->next) if (request->id == id) return request;
    return NULL;
}

static int request_active(mux_actor_t *actor) {
    int count=0;
    for (mux_request_t *request=actor->requests;request;request=request->next)
        if (!request->reset && !(request->ended && request->send_ended)) count++;
    return count;
}

static int packet_role(int role) { return role == 3 || role == 4; }

static int start_request(mux_actor_t *actor, core_http2_stream_t *stream, int role, size_t payload) {
    if ((unsigned)request_active(actor) >= actor->peer_concurrency || upload_bytes > XMUX_TOTAL_LIMIT-65536 || actor->net_accounted >= 64U*1024U) return 1;
    size_t minimum=actor->output_memory.minimum;
    if (actor->manager->backend->open_budgeted && core_buffer_budget_init(&actor->output_memory,CORE_BUFFER_UPLOAD,CORE_BUFFER_REQUEST_RESERVE)) return 1;
    mux_request_t *request=calloc(1,sizeof(*request));
    if (!request) { core_buffer_budget_init(&actor->output_memory,CORE_BUFFER_UPLOAD,minimum); return -1; }
    if (role == 3 && strcmp(stream->config.xhttp_uplink_data_placement,"body") && strcmp(stream->config.xhttp_uplink_data_placement,"auto") &&
        stream->config.xhttp_uplink_data_placement[0] && payload > 49152) payload=49152;
    uint8_t *copy=NULL;
    const uint8_t *data=payload ? stream->tx.data+stream->tx.start : NULL;
    if (payload > core_http2_queue_span(&stream->tx)) {
        copy=core_buffer_alloc(&actor->output_memory,payload);
        if (!copy) { free(request); core_buffer_budget_init(&actor->output_memory,CORE_BUFFER_UPLOAD,minimum); return -1; }
        core_http2_queue_copy(&stream->tx,copy,payload); data=copy;
    }
    size_t consumed=payload,body=payload;
    const vless_config_t *config=role == 0 ? &actor->manager->config : &stream->config;
    int result=actor->manager->backend->request(actor->physical,config,stream->session,stream->sequence,role,data,payload,&request->id,actor->peer_header_limit,&consumed,&body);
    core_buffer_free(&actor->output_memory,copy,payload);
    core_buffer_budget_init(&actor->output_memory,CORE_BUFFER_UPLOAD,minimum);
    if (!result && (role == 4 ? consumed || body != SIZE_MAX : consumed > payload || (payload && !consumed) || (body && body != consumed))) result=-1;
    if (!result && role == 3 && !body) {
        size_t previous=upload_bytes;
        queue_consume(&stream->tx,consumed); upload_bytes-=consumed; update_upload_budget(stream); notify_write_capacity(previous);
    }
    account_output(actor);
    if (result) { free(request); return -1; }
    request->stream=stream; request->role=role; request->remaining=role == 4 ? (size_t)stream->packet_limit : body;
    request->response.no_body=!grpc_manager(actor->manager) && role != 0 && !strcmp(config->xhttp_uplink_method,"HEAD");
    if (role == 4) { uint64_t now=core_now_ms(); request->packet_until_ms=now > UINT64_MAX-XMUX_PACKET_AGE_MS ? UINT64_MAX : now+XMUX_PACKET_AGE_MS; }
    request->send_ended=role == 0 || (role == 3 && !body);
    request->send_window=actor->peer_window;
    unsigned initial_window=grpc_manager(actor->manager) ? (unsigned)actor->manager->config.grpc_initial_window : CORE_HTTP2_STREAM_LIMIT;
    if (!initial_window) initial_window=256U*1024U;
    request->receive_window=initial_window;
    if (role == 0 || role == 1) {
        int downloads=1;
        for (mux_request_t *entry=actor->requests;entry;entry=entry->next) if (entry->role == 0 || entry->role == 1) downloads++;
        if (downloads > actor->receive_slots) {
            uint64_t target=(uint64_t)downloads*initial_window;
            if (target > XMUX_TOTAL_LIMIT) target=XMUX_TOTAL_LIMIT;
            uint64_t previous=(uint64_t)actor->receive_slots*initial_window;
            if (previous < 65535) previous=65535;
            if (previous > XMUX_TOTAL_LIMIT) previous=XMUX_TOTAL_LIMIT;
            uint32_t increment=target > previous ? (uint32_t)(target-previous) : 0;
            if (increment && window_update(actor,0,increment) != 0) { free(request); return -1; }
            actor->receive_window+=increment;
            actor->receive_slots=downloads;
        }
    }
    request->next=actor->requests; actor->requests=request; stream->references++;
    actor->latest_stream=request->id;
    actor->group->requests++;
    if (role == 0 || role == 1) stream->down_id=request->id;
    if (role == 1 || role == 2) stream->up_id=request->id;
    if (role == 0 || role == 1) stream->download_fence=actor->enqueued;
    if (role == 1 || role == 2) stream->upload_fence=actor->enqueued;
    if (role == 3 && !body) stream->write_fence=actor->enqueued;
    if (packet_role(role)) { stream->sequence++; stream->last_post_ms=core_now_ms(); stream->next_post_ms=0; }
    return 0;
}

static void *actor_worker(void *opaque);

static mux_actor_t *new_actor(mux_group_t *group, int budget, core_http2_stream_t *source) {
    mux_manager_t *manager=group->manager;
    if (actor_count >= 512) { errno=EAGAIN; return NULL; }
    mux_actor_t *actor=calloc(1,sizeof(*actor));
    if (!actor) return NULL;
    actor->header_block.memory.direction=CORE_BUFFER_DOWNLOAD;
    actor->input_memory.direction=CORE_BUFFER_DOWNLOAD;
    actor->header_block.account=&actor->input_memory;
    actor->hpack.memory=&actor->input_memory;
    if (manager->backend->open_budgeted &&
        (core_buffer_budget_init(&actor->input_memory,CORE_BUFFER_DOWNLOAD,CORE_BUFFER_PROTOCOL_RESERVE) ||
         core_buffer_budget_init(&actor->output_memory,CORE_BUFFER_UPLOAD,CORE_BUFFER_OUTPUT_RESERVE))) {
        core_buffer_budget_clear(&actor->input_memory); core_buffer_budget_clear(&actor->output_memory);
        free(actor); errno=EAGAIN; return NULL;
    }
    actor->manager=manager; actor->group=group; actor->opening=1; actor->http2=1; actor->connect_until_ms=core_now_ms()+(unsigned)budget;
    actor->send_window=65535; actor->receive_window=65535;
    actor->peer_window=65535; actor->peer_frame=16384; actor->peer_concurrency=UINT32_MAX;
    actor->peer_header_limit=8192;
    if (notification_pair(actor->wake) != 0) { core_buffer_budget_clear(&actor->input_memory); core_buffer_budget_clear(&actor->output_memory); free(actor); return NULL; }
    actor->alive_period=manager->config.xmux.keep_alive_period;
    if (grpc_manager(manager)) actor->alive_period=manager->config.grpc_idle_timeout;
    else if (!actor->alive_period) actor->alive_period=45;
    if (actor->alive_period < 0) actor->alive_period=0;
    struct sockaddr_storage numeric; socklen_t numeric_length;
    actor->progress_stage=core_ip_count(core_config_ip_source(&manager->config)) ||
        core_numeric_address(manager->config.server_host,manager->config.server_port,&numeric,&numeric_length) == 1 ? CORE_TRACE_TCP : CORE_TRACE_DNS;
    core_trace_stage(actor->progress_stage);
    actor->trace_present=core_trace_snapshot(&actor->trace);
    if (!actor->trace_present && source && source->trace_present) { actor->trace=source->trace; actor->trace_present=1; }
    if (source) source->first_actor=1;
    actor->next=manager->actors; manager->actors=actor; actor_count++;
    pthread_t thread;
    int status=pthread_create(&thread,NULL,actor_worker,actor);
    if (status != 0) {
        manager->actors=actor->next; actor_count--; close(actor->wake[0]); close(actor->wake[1]);
        core_buffer_budget_clear(&actor->input_memory); core_buffer_budget_clear(&actor->output_memory); free(actor); errno=status; return NULL;
    }
    actor->thread_started=1; pthread_detach(thread); return actor;
}

static mux_group_t *choose_group(mux_manager_t *manager) {
    mux_group_t *available[512]; size_t count=0,usable=0;
    uint64_t now=core_now_ms();
    collect_stopped_actors();
    for (mux_group_t *group=manager->groups;group;group=group->next) {
        if (grpc_manager(manager)) { group->uses++; return group; }
        if (!manager->config.xmux.present) continue;
        if (group->uses >= group->reuse_limit || group->requests >= group->request_limit || now >= group->expires_ms) group->retired=1;
        if (group->retired) {
            for (mux_actor_t *actor=manager->actors;actor;actor=actor->next) if (actor->group == group) wake_actor(actor);
            continue;
        }
        usable++;
        if ((!manager->concurrency || group->running < manager->concurrency) && count < 512) available[count++]=group;
    }
    mux_group_t *group=NULL;
    if (!usable || (manager->connections && usable < (size_t)manager->connections) || !count) {
        if (actor_count >= 512) { errno=EAGAIN; return NULL; }
        group=calloc(1,sizeof(*group));
        if (!group) return NULL;
        group->manager=manager;
        group->reuse_limit=random_range(manager->config.xmux.reuse_times);
        group->request_limit=random_range(manager->config.xmux.request_times);
        int age=random_range(manager->config.xmux.reusable_secs);
        if (group->reuse_limit < 0 || group->request_limit < 0 || age < 0) { free(group); return NULL; }
        if (!group->reuse_limit) group->reuse_limit=INT_MAX;
        if (!group->request_limit) group->request_limit=INT_MAX;
        group->expires_ms=age ? now+(uint64_t)age*1000 : UINT64_MAX;
        group->next=manager->groups; manager->groups=group;
    } else {
        int choice=random_range((core_range_t){0,(int)count-1});
        if (choice < 0) return NULL;
        group=available[choice];
    }
    group->uses++; return group;
}

static mux_actor_t *group_channel(mux_group_t *group, int budget, core_http2_stream_t *source, int needed) {
    for (mux_actor_t *actor=group->manager->actors;actor;actor=actor->next) {
        if (actor->group != group || actor->failed || actor->stopped || actor->draining) continue;
        int active=request_active(actor);
        if (actor->opening || (actor->http2 && (uint64_t)active+(unsigned)needed <= actor->peer_concurrency) ||
            (!actor->http2 && !active && !actor->net_accounted)) return actor;
    }
    if (grpc_manager(group->manager)) {
        unsigned count=0;
        for (mux_actor_t *actor=group->manager->actors;actor;actor=actor->next) if (!actor->stopped) count++;
        if (count >= 4) { errno=EAGAIN; return NULL; }
    }
    return new_actor(group,budget,source);
}

static mux_actor_t *choose_actor(mux_manager_t *manager, int budget, core_http2_stream_t *source) {
    mux_group_t *group=choose_group(manager);
    return group ? group_channel(group,budget,source,1) : NULL;
}

static mux_manager_t *get_manager(const vless_config_t *config, const core_http2_backend_t *backend) {
    uint8_t pins[32]={0};
    int source=core_config_ip_source(config);
    for (size_t i=0;i<core_ip_count(source);i++) {
        struct sockaddr_storage address={0}; socklen_t length=0;
        if (core_ip_address_at(source,i,config->server_port,&address,&length)) continue;
        uint8_t material[32+sizeof(address)]; memcpy(material,pins,32); memcpy(material+32,&address,length);
        blake3_hash(material,32+length,pins);
    }
    size_t count=0;
    for (mux_manager_t *manager=managers;manager;manager=manager->next) {
        if (manager->backend == backend && !memcmp(&manager->config,config,sizeof(*config)) && !memcmp(manager->pins,pins,32)) return manager;
        count++;
    }
    if (count >= 64) { errno=EAGAIN; return NULL; }
    mux_manager_t *manager=calloc(1,sizeof(*manager));
    if (!manager) return NULL;
    manager->config=*config; manager->backend=backend;
    memcpy(manager->pins,pins,32);
    manager->concurrency=random_range(config->xmux.max_concurrency); manager->connections=random_range(config->xmux.max_connections);
    if (manager->concurrency < 0 || manager->connections < 0) { free(manager); return NULL; }
    manager->next=managers; managers=manager; return manager;
}

static int reject_stream(mux_actor_t *actor, uint32_t id, const char *error, uint32_t code) {
    mux_request_t *request=find_request(actor,id);
    if (request) { fail_stream(request->stream,error); request->ended=request->reset=1; }
    const uint8_t payload[]={(uint8_t)(code>>24),(uint8_t)(code>>16),(uint8_t)(code>>8),(uint8_t)code};
    return send_frame(actor,3,0,id,payload,sizeof(payload));
}

static int reject_response(mux_actor_t *actor, uint32_t id, const char *error) {
    return reject_stream(actor,id,error,1);
}

static int reject_data(mux_actor_t *actor, uint32_t id, size_t length, const char *error, uint8_t code) {
    if (window_update(actor,0,(uint32_t)length)) return -1;
    return reject_stream(actor,id,error,code);
}

static int finish_headers(mux_actor_t *actor, uint32_t id, uint8_t flags, const uint8_t *data, size_t length) {
    core_hpack_headers_t headers;
    int decoded=core_hpack_decode(&actor->hpack,data,length,&headers);
    if (decoded == -1) {
        snprintf(actor->error,sizeof(actor->error),"invalid h2 header block"); return -1;
    }
    mux_request_t *request=find_request(actor,id);
    if (!request || request->reset) return 0;
    int initial=!request->response.headers;
    if (decoded || core_http2_response_headers(&request->response,&headers,flags&1)) return reject_response(actor,id,grpc_manager(actor->manager) ? "invalid gRPC response headers" : "invalid h2 response headers");
    if (headers.status >= 100 && headers.status < 200) return 0;
    if (grpc_manager(actor->manager)) {
        char error[128];
        if (core_grpc_response_headers(&headers,initial,flags&1,error,sizeof(error))) return reject_response(actor,id,error);
    }
    if (headers.status && headers.status != 200) {
        char error[96]; snprintf(error,sizeof(error),"%s h2 stream %u returned non-200: %d",grpc_manager(actor->manager) ? "grpc" : "xhttp",id,headers.status);
        fail_stream(request->stream,error); request->ended=1; return 0;
    }
    if (flags&1) { request->ended=1; if (request->role == 0 || request->role == 1) { request->stream->eof=1; signal_stream(request->stream); } }
    return 0;
}

static int process_frame(mux_actor_t *actor, const core_http2_frame_t *frame) {
    if (frame->event == 4) {
        if (actor->http2 || request_active(actor)) return -1;
        actor->draining=1; return 0;
    }
    if (frame->event) {
        mux_request_t *request=find_request(actor,frame->id);
        if (!request) return -1;
        if (frame->event == 1) {
            if (frame->status >= 100 && frame->status < 200 && frame->status != 101) return 0;
            if (frame->status != 200 || request->response.headers) return -1;
            request->response.headers=1;
            if (frame->close_connection) actor->draining=1;
            return 0;
        }
        if (!request->response.headers || request->ended) return -1;
        if (frame->event == 3) {
            request->ended=1;
            if (frame->close_connection) actor->draining=1;
            if (request->role == 0 || request->role == 1) { request->stream->eof=1; signal_stream(request->stream); }
            return 0;
        }
        if (frame->event != 2) return -1;
        core_http2_frame_t data=*frame; data.event=0; data.type=0;
        return process_frame(actor,&data);
    }
    if (actor->header_id && frame->type != 9) return -1;
    if (actor->http2) {
        int validation=core_http2_validate_frame(&actor->validation,frame->type,frame->flags,frame->id,frame->data,frame->length);
        if (validation == -1) { snprintf(actor->error,sizeof(actor->error),"invalid h2 frame sequence"); return -1; }
        if (validation == -2) {
            if (reject_stream(actor,frame->id,"invalid h2 stream frame",actor->validation.error.code)) return -1;
            if (frame->type != 1) return 0;
        }
        if ((frame->type == 0 || frame->type == 1 || frame->type == 3 || frame->type == 8) && frame->id && (!(frame->id&1) || frame->id > actor->latest_stream)) return -1;
    }
    mux_request_t *request=find_request(actor,frame->id);
    const uint8_t *data=frame->data; size_t length=frame->length;
    if (frame->type == 0) {
        if (!frame->id || !(frame->id&1) || frame->id > actor->latest_stream) return -1;
        if ((int64_t)length > actor->receive_window) return -1;
        if (!request) {
            return window_update(actor,0,(uint32_t)length);
        }
        if (request->reset) return window_update(actor,0,(uint32_t)length);
        if (!request->response.headers || request->ended) return reject_data(actor,frame->id,length,"invalid h2 response data order",1);
        size_t skip=0,body=length;
        if (frame->flags&8) { if (!length || data[0] >= length) return -1; skip=1; body-=1+data[0]; }
        if (actor->http2 && core_http2_response_data(&request->response,body,frame->flags&1)) return reject_data(actor,frame->id,length,"invalid h2 response content-length",1);
        if ((int64_t)length > request->receive_window) return reject_data(actor,frame->id,length,"h2 stream receive window exceeded",3);
        actor->receive_window-=(int64_t)length; request->receive_window-=(int64_t)length;
        core_http2_stream_t *stream=request->stream;
        if ((request->role == 0 || request->role == 1) && !stream->closed) {
            if (!stream->rx.memory.charged) stream->rx.memory.direction=CORE_BUFFER_DOWNLOAD;
            if (body > XMUX_TOTAL_LIMIT-download_bytes || queue_append(&stream->rx,skip ? data+skip : data,body,XMUX_STREAM_LIMIT) != 0) return -1;
            download_bytes+=body; stream->consumed+=length-body; signal_stream(stream);
        } else {
            if (window_update(actor,0,(uint32_t)length) != 0 || window_update(actor,frame->id,(uint32_t)length) != 0) return -1;
            actor->receive_window+=(int64_t)length; request->receive_window+=(int64_t)length;
        }
        if (frame->flags&1) {
            if (grpc_manager(actor->manager)) return reject_response(actor,frame->id,"gRPC DATA ended without grpc-status");
            request->ended=1; if (request->role == 0 || request->role == 1) { stream->eof=1; signal_stream(stream); }
        }
    } else if (frame->type == 1 || frame->type == 9) {
        if (!frame->id) return -1;
        uint8_t flags=frame->flags;
        if (frame->type == 1) {
            size_t skip=0;
            if (flags&8) { if (!length || data[0] >= length) return -1; length-=data[0]; skip=1; }
            if (flags&0x20) skip+=5;
            if (length < skip) return -1;
            if (skip) data+=skip;
            length-=skip;
            if (flags&4) return finish_headers(actor,frame->id,flags,data,length);
            actor->header_id=frame->id; actor->header_flags=flags;
        } else if (actor->header_id != frame->id) return -1;
        if (!actor->header_block.memory.charged) actor->header_block.memory.direction=CORE_BUFFER_DOWNLOAD;
        if (queue_append(&actor->header_block,data,length,1024U*1024U) != 0) return -1;
        if (flags&4) {
            const uint8_t *block=actor->header_block.length ? actor->header_block.data+actor->header_block.start : NULL;
            int result=finish_headers(actor,frame->id,actor->header_flags,block,actor->header_block.length);
            actor->header_id=0; queue_consume(&actor->header_block,actor->header_block.length); return result;
        }
    } else if (frame->type == 4) {
        if (frame->id || (frame->flags&1 ? length != 0 : length%6 != 0)) return -1;
        if (frame->flags&1) return 0;
        for (size_t i=0;i<length;i+=6) {
            unsigned id=((unsigned)data[i]<<8)|data[i+1];
            uint32_t value=((uint32_t)data[i+2]<<24)|((uint32_t)data[i+3]<<16)|((uint32_t)data[i+4]<<8)|data[i+5];
            if (id == 3) actor->peer_concurrency=value;
            else if (id == 6) actor->peer_header_limit=value;
            else if (id == 4) {
                if (value > INT_MAX) return -1;
                int64_t delta=(int64_t)value-actor->peer_window;
                for (mux_request_t *entry=actor->requests;entry;entry=entry->next) if (entry->send_window+delta > INT_MAX) return -1;
                actor->peer_window=value;
                for (mux_request_t *entry=actor->requests;entry;entry=entry->next) entry->send_window+=delta;
            } else if (id == 5) { if (value < 16384 || value > 16777215) return -1; actor->peer_frame=value; }
        }
        return send_frame(actor,4,1,0,NULL,0);
    } else if (frame->type == 8) {
        if (length != 4) return -1;
        uint32_t increment=(((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3])&INT_MAX;
        if (!increment) return -1;
        int64_t *window=!frame->id ? &actor->send_window : request ? &request->send_window : NULL;
        if (window) {
            if (*window > INT_MAX-(int64_t)increment) return frame->id ? reject_stream(actor,frame->id,"h2 stream window overflow",3) : -1;
            *window+=increment;
        }
    } else if (frame->type == 3) {
        if (!frame->id || length != 4) return -1;
        if (request) {
            uint32_t code=((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3];
            if (code || !request->ended) fail_stream(request->stream,grpc_manager(actor->manager) ? "gRPC stream reset" : "xhttp h2 stream reset");
            else if (!packet_role(request->role) && request->stream->upload == actor && request->id == request->stream->up_id)
                stop_upload(request->stream);
            request->ended=request->reset=request->send_ended=1;
        }
    } else if (frame->type == 7) {
        if (frame->id || length < 8) return -1;
        actor->draining=1;
        uint32_t last=(((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3])&INT_MAX;
        uint32_t error=((uint32_t)data[4]<<24)|((uint32_t)data[5]<<16)|((uint32_t)data[6]<<8)|data[7];
        for (mux_request_t *entry=actor->requests;entry;entry=entry->next)
            if (error || entry->id > last) { fail_stream(entry->stream,"xhttp h2 GOAWAY rejected stream"); entry->ended=1; }
    } else if (frame->type == 6) {
        if (frame->id || length != 8) return -1;
        if (!(frame->flags&1)) return send_frame(actor,6,1,0,data,8);
        if (!memcmp(data,actor->ping,8)) actor->ping_deadline_ms=0;
    } else if (frame->type == 5) return -1;
    return 0;
}

static int move_waiting_streams(mux_actor_t *actor) {
    uint64_t now=core_now_ms();
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next) {
        if (stream->closed || stream->failed || (stream->download != actor && stream->upload != actor)) continue;
        if ((stream->download == actor && stream->down_id) || (stream->upload == actor && stream->up_id)) continue;
        int in_flight=0;
        for (mux_request_t *request=actor->requests;request;request=request->next)
            if (request->stream == stream && !request->ended) in_flight=1;
        if (in_flight) continue;
        int budget=stream->ready == 1 ? 30000 : stream->until_ms > now ? (int)(stream->until_ms-now) : 1;
        mux_actor_t *replacement=group_channel(actor->group,budget,stream,1);
        if (!replacement) {
            if (grpc_manager(actor->manager) && errno == EAGAIN) continue;
            return -1;
        }
        if (stream->download == actor) stream->download=replacement;
        if (stream->upload == actor) { stream->upload=replacement; stream->write_fence=stream->upload_fence=0; }
        wake_actor(replacement);
    }
    return 0;
}

static int receive_credit_due(const mux_actor_t *actor, const core_http2_stream_t *stream, const mux_request_t *request) {
    return !actor->http2 || actor->manager->config.transport_mode != TRANSPORT_XHTTP ||
        stream->consumed >= 16384 || actor->receive_window <= 16384 || !request || request->receive_window <= 16384 ||
        request->ended || stream->closed || stream->failed;
}

static int advance_streams(mux_actor_t *actor) {
    uint64_t now=core_now_ms();
    if (!actor->http2) {
        actor->send_window=INT_MAX;
        for (mux_request_t *request=actor->requests;request;request=request->next) request->send_window=INT_MAX;
    }
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next) {
        if (stream->download == actor && (stream->consumed || actor->pending_credit) && stream->down_id) {
            uint32_t amount=(uint32_t)stream->consumed;
            mux_request_t *request=find_request(actor,stream->down_id);
            if (receive_credit_due(actor,stream,request)) {
                uint32_t connection_amount=amount+actor->pending_credit;
                if (window_update(actor,0,connection_amount) != 0 || (request && !request->ended && !stream->closed && window_update(actor,stream->down_id,amount) != 0)) return -1;
                actor->receive_window+=connection_amount; actor->pending_credit=0; if (request) request->receive_window+=amount; stream->consumed=0;
            }
        }
        if (stream->failed || (stream->closed && !stream->tx.length)) continue;
        if (stream->upload == actor) {
            for (mux_request_t *request=actor->requests;request;request=request->next) {
                if (request->stream != stream || request->role != 4 || request->send_ended || request->ended) continue;
                int idle=!stream->tx.length && (stream->finish_requested || (request->packet_idle_ms && now >= request->packet_idle_ms));
                if (!idle && now < request->packet_until_ms) continue;
                if (send_frame(actor,0,1,request->id,NULL,0)) return -1;
                request->send_ended=1; request->remaining=0; stream->write_fence=actor->enqueued; signal_stream(stream);
            }
        }
        if (stream->download == actor && !stream->down_id) {
            if (now >= stream->until_ms) { fail_stream_error(stream,"XHTTP connection deadline expired",core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_DEADLINE,ETIMEDOUT)); continue; }
            int role=grpc_manager(actor->manager) || !strcmp(stream->config.xhttp_mode,"stream-one") ? 1 : 0;
            if ((unsigned)request_active(actor) >= actor->peer_concurrency || actor->draining) {
                mux_actor_t *replacement=group_channel(actor->group,(int)(stream->until_ms-now),stream,1);
                if (!replacement) {
                    if (errno == EAGAIN) continue;
                    fail_stream(stream,"XHTTP download channel allocation failed"); continue;
                }
                stream->download=replacement;
                if (stream->upload == actor) { stream->upload=replacement; stream->write_fence=stream->upload_fence=0; }
                wake_actor(replacement); continue;
            }
            int result=start_request(actor,stream,role,0);
            if (result < 0) return -1;
            if (result > 0) continue;
            if (strcmp(stream->config.xhttp_mode,"stream-up")) stream->ready=2;
        }
        if (!grpc_manager(actor->manager) && stream->upload == actor && stream->down_id && !stream->up_id && !strcmp(stream->config.xhttp_mode,"stream-up")) {
            if ((unsigned)request_active(actor) >= actor->peer_concurrency || actor->draining) {
                mux_actor_t *replacement=group_channel(actor->group,(int)(stream->until_ms > now ? stream->until_ms-now : 1),stream,1);
                if (!replacement) { if (errno != EAGAIN) fail_stream(stream,"XHTTP upload channel allocation failed"); continue; }
                stream->upload=replacement; stream->write_fence=stream->upload_fence=0; wake_actor(replacement); continue;
            }
            int result=start_request(actor,stream,2,0);
            if (result < 0) return -1;
            if (result > 0) continue;
            stream->ready=2;
        }
        if (stream->upload != actor || stream->ready != 1 || !stream->tx.length) continue;
        mux_request_t *request=NULL;
        if (!strcmp(stream->config.xhttp_mode,"packet-up")) {
            for (mux_request_t *entry=actor->requests;entry;entry=entry->next)
                if (entry->stream == stream && packet_role(entry->role) && !entry->ended && (entry->remaining || !actor->http2)) request=entry;
            if (request && !request->remaining) continue;
            if (!request) {
                if (stream->write_fence > actor->flushed) continue;
                if (!stream->next_post_ms && core_xhttp_post_due((core_range_t){stream->config.xhttp_min_posts_interval_min,stream->config.xhttp_min_posts_interval_max},
                    stream->last_post_ms,now,&stream->next_post_ms) != 0) { fail_stream(stream,"XHTTP packet interval sampling failed"); continue; }
                if (now < stream->next_post_ms) continue;
                if (actor->group->retired || actor->group->requests >= actor->group->request_limit || now >= actor->group->expires_ms) {
                    if (stream->write_fence > actor->flushed) continue;
                    actor->group->retired=1;
                    mux_actor_t *replacement=choose_actor(actor->manager,30000,NULL);
                    if (!replacement) { if (errno != EAGAIN) fail_stream(stream,"XHTTP upload rotation failed"); continue; }
                    if (stream->upload->group != stream->download->group) stream->upload->group->running--;
                    stream->upload=replacement;
                    stream->write_fence=stream->upload_fence=0;
                    if (replacement->group != stream->download->group) replacement->group->running++;
                    wake_actor(replacement); continue;
                }
                if (actor->draining || (!actor->http2 && request_active(actor))) {
                    if (stream->write_fence > actor->flushed) continue;
                    mux_actor_t *replacement=group_channel(actor->group,30000,NULL,1);
                    if (!replacement) { if (errno != EAGAIN) fail_stream(stream,"XHTTP packet channel allocation failed"); continue; }
                    stream->upload=replacement; stream->write_fence=stream->upload_fence=0; wake_actor(replacement); continue;
                }
                int streamed=stream->relay_async && stream->packet_limit > 128*1024 && stream->tx.length >= 64U*1024U &&
                    (!stream->config.xhttp_uplink_data_placement[0] || !strcmp(stream->config.xhttp_uplink_data_placement,"body") || !strcmp(stream->config.xhttp_uplink_data_placement,"auto"));
                size_t packet=streamed ? 0 : stream->tx.length;
                if (packet > (size_t)stream->packet_limit) packet=(size_t)stream->packet_limit;
                if (packet > 128U*1024U) packet=128U*1024U;
                int result=start_request(actor,stream,streamed ? 4 : 3,packet);
                if (result < 0) return -1;
                if (result > 0) continue;
                request=actor->requests;
            }
        } else request=find_request(actor,stream->up_id);
        if (!request || request->reset || request->send_ended || (packet_role(request->role) && (request->ended || !request->remaining)) || actor->send_window <= 0 || request->send_window <= 0 || actor->net_accounted >= 64U*1024U) continue;
        size_t length=stream->tx.length;
        size_t span=core_http2_queue_span(&stream->tx);
        if (length > span) length=span;
        if (packet_role(request->role) && length > request->remaining) length=request->remaining;
        if (length > actor->peer_frame) length=actor->peer_frame;
        if (length > 16384) length=16384;
        if ((int64_t)length > actor->send_window) length=(size_t)actor->send_window;
        if ((int64_t)length > request->send_window) length=(size_t)request->send_window;
        uint8_t flags=packet_role(request->role) && length == request->remaining ? 1 : 0;
        size_t previous=upload_bytes;
        upload_bytes-=length;
        if (send_frame(actor,0,flags,request->id,stream->tx.data+stream->tx.start,length) != 0) { upload_bytes+=length; return -1; }
        stream->write_fence=actor->enqueued;
        queue_consume(&stream->tx,length); update_upload_budget(stream); notify_write_capacity(previous);
        actor->send_window-=length; request->send_window-=length;
        if (packet_role(request->role)) request->remaining-=length;
        if (request->role == 4) request->packet_idle_ms=stream->tx.length ? 0 : now > UINT64_MAX-XMUX_PACKET_IDLE_MS ? UINT64_MAX : now+XMUX_PACKET_IDLE_MS;
        if (flags&1) request->send_ended=1;
        signal_stream(stream);
    }
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next) {
        if (stream->upload != actor || stream->failed || stream->closed || !stream->finish_requested || stream->finish_sent || stream->tx.length) continue;
        int packet=!grpc_manager(actor->manager) && !strcmp(stream->config.xhttp_mode,"packet-up");
        if (packet) {
            int pending=0;
            for (mux_request_t *request=actor->requests;request;request=request->next)
                if (request->stream == stream && packet_role(request->role) && !request->send_ended) pending=1;
            if (pending) continue;
        } else {
            mux_request_t *request=find_request(actor,stream->up_id);
            if (!request) continue;
            if (!request->reset && !request->send_ended && send_frame(actor,0,1,request->id,NULL,0)) return -1;
            request->send_ended=1;
        }
        stream->finish_sent=1; stream->finish_fence=actor->enqueued;
        stream->write_fence=actor->enqueued; signal_stream(stream);
    }
    mux_request_t **cursor=&actor->requests;
    while (*cursor) {
        mux_request_t *request=*cursor; core_http2_stream_t *stream=request->stream;
        if (stream->closed || stream->failed || (request->ended && (packet_role(request->role) || request->send_ended))) {
            if (!actor->http2 && !request->ended) {
                actor->draining=1;
                if (move_waiting_streams(actor) != 0) return -1;
            }
            if (!(request->ended && request->send_ended) && !request->reset && send_frame(actor,3,0,request->id,(const uint8_t[]){0,0,0,8},4) != 0) return -1;
            *cursor=request->next; free(request); signal_stream(stream); release_stream(stream); wake_channels(actor->manager,actor);
        } else cursor=&request->next;
    }
    return 0;
}

static int maintain_ping(mux_actor_t *actor, uint64_t now) {
    if (actor->ping_deadline_ms && now >= actor->ping_deadline_ms) {
        snprintf(actor->error,sizeof(actor->error),"%s keepalive acknowledgement deadline expired",grpc_manager(actor->manager) ? "gRPC" : "XHTTP"); return -1;
    }
    int permitted=!grpc_manager(actor->manager) || actor->manager->config.grpc_permit_without_stream || request_active(actor);
    if (!actor->ping_deadline_ms && permitted && actor->alive_period && now-actor->last_input_ms >= (uint64_t)actor->alive_period*1000) {
        memcpy(actor->ping,&now,8);
        if (send_frame(actor,6,0,0,actor->ping,8) != 0) return -1;
        actor->ping_deadline_ms=now+(grpc_manager(actor->manager) ? (uint64_t)(actor->manager->config.grpc_health_timeout ? actor->manager->config.grpc_health_timeout : 20)*1000 : 15000);
    }
    return 0;
}

static int stop_idle_actor(mux_actor_t *actor, int in_use, uint64_t now) {
    if (in_use || actor->requests) { actor->idle_pending_ms=0; return 0; }
    if (grpc_manager(actor->manager) && !actor->draining) {
        if (!actor->idle_pending_ms) actor->idle_pending_ms=now;
        if (now-actor->idle_pending_ms < 60000) return 0;
        actor->draining=1; return 1;
    }
    if (!actor->draining && !actor->group->retired && actor->manager->config.xmux.present) {
        if (!actor->net_accounted) { actor->idle_pending_ms=0; return 0; }
        if (!actor->idle_pending_ms) actor->idle_pending_ms=now;
        if (now-actor->idle_pending_ms < XMUX_CANCEL_DRAIN_MS) return 0;
    }
    actor->draining=1; return 1;
}

static int actor_wait_timeout(mux_actor_t *actor,int progressed,uint64_t now) {
    if (progressed) return 0;
    uint64_t due=UINT64_MAX;
    if (actor->ping_deadline_ms) due=actor->ping_deadline_ms;
    else if (actor->alive_period && (!grpc_manager(actor->manager) || actor->manager->config.grpc_permit_without_stream || request_active(actor))) {
        uint64_t period=(uint64_t)actor->alive_period*1000;
        due=actor->last_input_ms > UINT64_MAX-period ? UINT64_MAX : actor->last_input_ms+period;
    }
    if (actor->idle_pending_ms) {
        uint64_t period=grpc_manager(actor->manager) ? 60000 : XMUX_CANCEL_DRAIN_MS;
        uint64_t idle=actor->idle_pending_ms > UINT64_MAX-period ? UINT64_MAX : actor->idle_pending_ms+period;
        if (idle < due) due=idle;
    }
    for (mux_request_t *request=actor->requests;request;request=request->next) {
        if (request->role != 4 || request->send_ended || request->ended) continue;
        uint64_t packet=request->packet_until_ms;
        if (!request->stream->tx.length && request->packet_idle_ms && request->packet_idle_ms < packet) packet=request->packet_idle_ms;
        if (packet < due) due=packet;
    }
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next) {
        if (stream->failed || stream->closed) continue;
        if (stream->download == actor && !stream->down_id && stream->until_ms < due) due=stream->until_ms;
        if (stream->upload == actor && stream->ready == 1 && stream->tx.length && stream->next_post_ms > now && stream->next_post_ms < due) due=stream->next_post_ms;
    }
    if (due == UINT64_MAX) return -1;
    return due <= now ? 0 : due-now > INT_MAX ? INT_MAX : (int)(due-now);
}

static void *actor_worker(void *opaque) {
    mux_actor_t *actor=opaque; const core_http2_backend_t *backend=actor->manager->backend;
    core_deadline_t deadline; int http2=0;
    if (core_deadline_attach(&deadline) != 0) {
        snprintf(actor->error,sizeof(actor->error),"failed to attach connection deadline");
        actor->failure=core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_RESOURCE,ENOMEM);
    }
    else {
        uint64_t now=core_now_ms();
        core_deadline_begin(now < actor->connect_until_ms ? (int)(actor->connect_until_ms-now) : 1);
        if (actor->trace_present) { core_trace_bind(&actor->trace); core_trace_observe(trace_progress,actor); }
        if (now >= actor->connect_until_ms) {
            snprintf(actor->error,sizeof(actor->error),"XHTTP connection deadline expired");
            actor->failure=core_connection_error(actor->progress_stage,CORE_FAILURE_DEADLINE,ETIMEDOUT);
        }
        else {
            int opened=backend->open_budgeted ? backend->open_budgeted(&actor->manager->config,&actor->physical,&http2,actor->error,sizeof(actor->error),&actor->output_memory,&actor->input_memory) :
                backend->open(&actor->manager->config,&actor->physical,&http2,actor->error,sizeof(actor->error));
            if (opened && !actor->error[0]) snprintf(actor->error,sizeof(actor->error),"XMUX physical connection failed");
            if (opened && !core_trace_error_get(&actor->failure)) actor->failure=core_connection_error(actor->progress_stage,CORE_FAILURE_SYSTEM,errno ? errno : EIO);
        }
        core_trace_detach(); core_deadline_end();
    }
    core_buffer_watch(&actor->memory_waiter,actor->wake[1],(1U<<CORE_BUFFER_UPLOAD)|(1U<<CORE_BUFFER_DOWNLOAD));
    pthread_mutex_lock(&mux_lock); actor->opening=0;
    if (actor->error[0]) actor->failed=1;
    actor->http2=http2;
    if (http2 && actor->physical && backend->initial_settings) {
        core_http2_settings_t settings={0}; core_http2_validation_t validation={0};
        if (backend->initial_settings(actor->physical,&settings,&validation)) {
            actor->validation=validation;
            if (settings.received) {
                actor->peer_window=settings.initial_window; actor->peer_frame=settings.max_frame;
                actor->peer_concurrency=settings.concurrency; actor->peer_header_limit=settings.header_limit;
            }
        }
    }
    if (!http2) { actor->peer_concurrency=1; actor->alive_period=0; }
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next) if (!stream->closed && (stream->download == actor || stream->upload == actor)) {
        if (stream->download != actor) wake_actor(stream->download);
        if (stream->upload != actor) wake_actor(stream->upload);
        signal_stream(stream);
    }
    actor->last_input_ms=core_now_ms(); pthread_mutex_unlock(&mux_lock);
    while (!actor_failed(actor)) {
        pthread_mutex_lock(&mux_lock);
        uint64_t enqueued_before=actor->enqueued,flushed_before=actor->flushed;
        int received_frame=0;
        if (backend->retire && backend->retire(actor->physical)) actor->draining=1;
        int result=advance_streams(actor);
        int in_use=0;
        for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
            if (!stream->closed && (stream->download == actor || stream->upload == actor)) in_use=1;
        if (result < 0) { actor->failed=1; actor->failure=core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_PROTOCOL,errno ? errno : EPROTO); }
        int done=stop_idle_actor(actor,in_use,core_now_ms());
        pthread_mutex_unlock(&mux_lock);
        if (actor_failed(actor) || done) break;
        if (backend->flush(actor->physical) < 0) { int cause=errno; snprintf(actor->error,sizeof(actor->error),"XHTTP physical send failed"); mark_failed(actor,CORE_FAILURE_SYSTEM,cause); break; }
        pthread_mutex_lock(&mux_lock); account_output(actor);
        for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
            if ((stream->download == actor || stream->upload == actor) && stream->ready == 2 &&
                !stream->download->opening && !stream->upload->opening && stream->download_fence <= stream->download->flushed && stream->upload_fence <= stream->upload->flushed) { stream->ready=1; signal_stream(stream); }
        pthread_mutex_unlock(&mux_lock);
        int collected=backend->collect(actor->physical);
        if (collected < 0) { int cause=errno; snprintf(actor->error,sizeof(actor->error),"XHTTP physical receive failed"); mark_failed(actor,CORE_FAILURE_SYSTEM,cause); break; }
        core_http2_frame_t frame;
        for (;;) {
            size_t capacity=65535;
            pthread_mutex_lock(&mux_lock);
            if (!actor->http2 && actor->requests) capacity=(size_t)actor->requests->receive_window;
            if (capacity > XMUX_TOTAL_LIMIT-download_bytes) capacity=XMUX_TOTAL_LIMIT-download_bytes;
            pthread_mutex_unlock(&mux_lock);
            result=backend->read_frame(actor->physical,&frame,capacity);
            if (result != 0) break;
            received_frame=1;
            pthread_mutex_lock(&mux_lock); actor->last_input_ms=core_now_ms();
            result=process_frame(actor,&frame); pthread_mutex_unlock(&mux_lock);
            if (backend->release_frame) backend->release_frame(actor->physical,&frame); else free(frame.data);
            if (result < 0) { if (!actor->error[0]) snprintf(actor->error,sizeof(actor->error),"XHTTP response frame %u rejected",frame.type); break; }
        }
        if (result < 0) { if (!actor->error[0]) snprintf(actor->error,sizeof(actor->error),"XHTTP response decoding failed"); mark_failed(actor,CORE_FAILURE_PROTOCOL,EPROTO); break; }
        uint64_t now=core_now_ms();
        pthread_mutex_lock(&mux_lock);
        if (maintain_ping(actor,now) != 0) actor->failed=1;
        size_t pending=actor->net_accounted;
        int progressed=collected == CORE_HTTP2_INPUT_PROGRESS || received_frame || actor->enqueued != enqueued_before || actor->flushed != flushed_before;
        int wait=actor_wait_timeout(actor,progressed,now);
        pthread_mutex_unlock(&mux_lock);
        short events=backend->events ? backend->events(actor->physical) : (short)(POLLIN|(pending ? POLLOUT : 0));
        if (result == CORE_HTTP2_INPUT_BLOCKED) events&=(short)~POLLIN;
        struct pollfd descriptors[2]={{.fd=actor->wake[0],.events=POLLIN},{.fd=backend->fd(actor->physical),.events=events}};
        if (core_poll(descriptors,2,wait) < 0) { mark_failed(actor,CORE_FAILURE_SYSTEM,errno); break; }
        if (descriptors[0].revents) core_drain_socket(actor->wake[0]);
    }
    pthread_mutex_lock(&mux_lock);
    if (actor->failed) vc_log_warning("xhttp","%s",actor->error[0] ? actor->error : "XHTTP channel state failed");
    for (core_http2_stream_t *stream=streams;stream;stream=stream->next)
        if (!stream->closed && (stream->download == actor || stream->upload == actor)) fail_stream_error(stream,actor->error[0] ? actor->error : "XHTTP physical connection failed",
            actor->failure.kind ? actor->failure : core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_PROTOCOL,EPROTO));
    mux_request_t *request=actor->requests; actor->requests=NULL;
    while (request) { mux_request_t *next=request->next; release_stream(request->stream); free(request); request=next; }
    pthread_mutex_unlock(&mux_lock);
    core_buffer_unwatch(&actor->memory_waiter);
    if (actor->physical) backend->close(actor->physical);
    actor->physical=NULL; core_hpack_clear(&actor->hpack); core_http2_queue_clear(&actor->header_block);
    core_buffer_budget_clear(&actor->input_memory); core_buffer_budget_clear(&actor->output_memory); core_deadline_detach();
    OPENSSL_thread_stop();
    pthread_mutex_lock(&mux_lock); size_t previous=upload_bytes; upload_bytes-=actor->net_accounted; actor->net_accounted=0;
    notify_write_capacity(previous);
    actor->stopped=1; close(actor->wake[0]); close(actor->wake[1]); actor_count--;
    pthread_cond_broadcast(&workers_stopped);
    wake_admission();
    wake_channels(actor->manager,actor);
    collect_stopped_actors();
    pthread_mutex_unlock(&mux_lock); return NULL;
}

static int allocate_channels(core_http2_stream_t *stream, mux_manager_t *manager, mux_manager_t *download_manager, int budget) {
    size_t window=grpc_manager(manager) && stream->config.grpc_initial_window ? (size_t)stream->config.grpc_initial_window : CORE_HTTP2_STREAM_LIMIT;
    size_t credit=core_http2_queue_reservation(window);
    size_t protocol=manager->backend->open_budgeted ? CORE_BUFFER_PROTOCOL_RESERVE*(download_manager != manager ? 2U : 1U) : 0;
    size_t output_protocol=manager->backend->open_budgeted ? CORE_BUFFER_OUTPUT_RESERVE*(download_manager != manager ? 2U : 1U)+CORE_BUFFER_REQUEST_RESERVE-CORE_BUFFER_OUTPUT_RESERVE : 0;
    size_t upload_credit=core_http2_queue_reservation(CORE_HTTP2_STREAM_LIMIT);
    size_t room=core_buffer_available(CORE_BUFFER_DOWNLOAD);
    size_t output_room=core_buffer_available(CORE_BUFFER_UPLOAD);
    if (credit > room || protocol > room-credit || upload_credit > output_room || output_protocol > output_room-upload_credit) {
        core_http2_queue_cache_clear(); room=core_buffer_available(CORE_BUFFER_DOWNLOAD);
        output_room=core_buffer_available(CORE_BUFFER_UPLOAD);
    }
    if (credit > room || protocol > room-credit || upload_credit > output_room || output_protocol > output_room-upload_credit ||
        core_buffer_budget_init(&stream->rx.memory,CORE_BUFFER_DOWNLOAD,credit)) { errno=EAGAIN; return -1; }
    if (core_buffer_budget_init(&stream->tx.memory,CORE_BUFFER_UPLOAD,upload_credit)) {
        core_buffer_budget_clear(&stream->rx.memory); errno=EAGAIN; return -1;
    }
    stream->permanent_upload=upload_credit;
    mux_actor_t *upload=choose_actor(manager,budget,stream);
    mux_actor_t *download=upload && download_manager != manager ? choose_actor(download_manager,budget,stream) : upload;
    if (!upload || !download) {
        int saved=errno;
        if (upload && !upload->group->running && !request_active(upload)) { upload->failed=1; wake_actor(upload); }
        core_buffer_budget_clear(&stream->rx.memory); core_buffer_budget_clear(&stream->tx.memory); stream->permanent_upload=0; errno=saved; return -1;
    }
    stream->download=download; stream->upload=upload; upload->group->running++;
    if (download->group != upload->group) download->group->running++;
    wake_actor(upload); wake_actor(download); return 0;
}

core_http2_stream_t *core_http2_connect(const vless_config_t *config, const core_http2_backend_t *backend, char *error, size_t capacity) {
    vless_config_t download_config;
    int independent=config->transport_mode == TRANSPORT_XHTTP && config->xhttp_download_settings[0] != 0;
    if (independent && core_xhttp_download_config(config,&download_config,error,capacity) != 0) return NULL;
    core_http2_stream_t *stream=calloc(1,sizeof(*stream));
    if (!stream) { if (error && capacity) snprintf(error,capacity,"XHTTP client allocation failed"); return NULL; }
    stream->config=*config; stream->references=1;
    stream->packet_limit=config->transport_mode == TRANSPORT_GRPC ? 0 : core_xhttp_post_limit(config);
    if (stream->packet_limit < 0) { if (error && capacity) snprintf(error,capacity,"XHTTP packet size sampling failed"); free(stream); return NULL; }
    stream->trace_present=core_trace_snapshot(&stream->trace);
    stream->until_ms=core_now_ms()+(unsigned)(core_deadline_active() ? core_deadline_remaining() : 30000);
    if (notification_pair(stream->notify) != 0) { if (error && capacity) snprintf(error,capacity,"XHTTP notification channel failed: %s",strerror(errno)); free(stream); return NULL; }
    if (config->transport_mode != TRANSPORT_GRPC && backend->session(config,stream->session,sizeof(stream->session)) != 0) { if (error && capacity) snprintf(error,capacity,"XHTTP session generation failed"); close(stream->notify[0]); close(stream->notify[1]); free(stream); return NULL; }
    pthread_mutex_lock(&mux_lock);
    mux_manager_t *manager=stream_count < 256 ? get_manager(config,backend) : NULL;
    if (stream_count >= 256) errno=EAGAIN;
    mux_manager_t *down_manager=manager && independent ? get_manager(&download_config,backend) : manager;
    int bound=manager && down_manager && !allocate_channels(stream,manager,down_manager,core_deadline_active() ? core_deadline_remaining() : 30000);
    int waiting=manager && down_manager && !bound && errno == EAGAIN;
    if (bound || waiting) {
        if (waiting) { stream->waiting_manager=manager; stream->waiting_download=down_manager; }
        stream->next=streams; streams=stream; stream_count++;
    }
    mux_actor_t *actor=stream->download;
    pthread_mutex_unlock(&mux_lock);
    if (!bound && !waiting) { if (error && capacity) snprintf(error,capacity,"XHTTP channel allocation failed: %s",strerror(errno)); core_buffer_budget_clear(&stream->rx.memory); close(stream->notify[0]); close(stream->notify[1]); free(stream); return NULL; }
    for (;;) {
        pthread_mutex_lock(&mux_lock);
        if (stream->waiting_manager && !stream->download) {
            int budget=core_deadline_active() ? core_deadline_remaining() : 30000;
            if (!allocate_channels(stream,stream->waiting_manager,stream->waiting_download,budget)) {
                stream->waiting_manager=stream->waiting_download=NULL;
            } else if (errno != EAGAIN) fail_stream(stream,"physical channel allocation failed");
        }
        int ready=stream->ready == 1,failed=stream->failed;
        actor=stream->download;
        if (actor && failed && !actor->failed && stream->upload->failed) actor=stream->upload;
        if (actor && stream->trace_present && actor->trace.id != stream->trace.id && stream->upload->trace.id == stream->trace.id) actor=stream->upload;
        if (actor && stream->first_actor && actor->opening) core_trace_stage(actor->progress_stage);
        if (actor && stream->first_actor && !actor->opening && actor->trace.id == stream->trace.id && (ready || failed)) core_trace_restore(&actor->trace);
        if (failed && error && capacity) snprintf(error,capacity,"%s",stream->error);
        if (!stream->first_actor) core_trace_stage(CORE_TRACE_TRANSPORT);
        pthread_mutex_unlock(&mux_lock);
        if (ready) return stream;
        if (failed) { core_trace_error_set(stream->failure); errno=stream->failure.system_error; break; }
        if (core_now_ms() >= stream->until_ms) {
            if (error && capacity) snprintf(error,capacity,"XHTTP connection deadline expired");
            core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_DEADLINE,ETIMEDOUT));
            errno=ETIMEDOUT; break;
        }
        int notified=core_wait_socket(stream->notify[0],POLLIN,100);
        if (!notified && core_now_ms() < stream->until_ms && (!core_deadline_active() || core_deadline_remaining())) continue;
        if (notified <= 0) {
            if (error && capacity) snprintf(error,capacity,"XHTTP connection deadline expired");
            pthread_mutex_lock(&mux_lock); core_trace_error_set(core_connection_error(actor ? actor->progress_stage : CORE_TRACE_TRANSPORT,CORE_FAILURE_DEADLINE,ETIMEDOUT)); pthread_mutex_unlock(&mux_lock);
            errno=ETIMEDOUT; break;
        }
        core_drain_socket(stream->notify[0]);
        pthread_mutex_lock(&mux_lock); stream->notified=0; pthread_mutex_unlock(&mux_lock);
    }
    int saved=errno; core_http2_close(stream); errno=saved; return NULL;
}

int core_http2_fd(const core_http2_stream_t *stream) { return stream ? stream->notify[0] : -1; }

int core_http2_pending(const core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock); int pending=stream && (stream->rx.length || stream->eof || stream->failed);
    pthread_mutex_unlock(&mux_lock); return pending;
}

int core_http2_start_relay(core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    int result=!stream || stream->failed || stream->closed ? -1 : 0;
    if (!result) stream->relay_async=1;
    pthread_mutex_unlock(&mux_lock); return result;
}

int core_http2_write_pending(const core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    int pending=stream && !stream->failed && !stream->closed && !stream->send_stopped &&
        (stream->tx.length || stream->upload->opening || stream->write_fence > stream->upload->flushed);
    pthread_mutex_unlock(&mux_lock); return pending;
}

void core_http2_drain_notifications(core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    core_drain_socket(stream->notify[0]);
    stream->notified=0;
    pthread_mutex_unlock(&mux_lock);
}

static size_t allocated_write_capacity(const core_http2_stream_t *stream) {
    size_t available=core_buffer_available(CORE_BUFFER_UPLOAD);
    if (available < core_http2_queue_reservation(128U*1024U)) {
        core_http2_queue_cache_clear(); available=core_buffer_available(CORE_BUFFER_UPLOAD);
    }
    available+=stream->tx.memory.charged;
    if (available >= core_http2_queue_reservation(XMUX_STREAM_LIMIT)) return XMUX_STREAM_LIMIT-stream->tx.length;
    size_t low=0,high=XMUX_STREAM_LIMIT-stream->tx.length;
    while (low < high) {
        size_t middle=low+(high-low+1)/2;
        if (core_http2_queue_reservation(stream->tx.length+middle) <= available) low=middle;
        else high=middle-1;
    }
    return low;
}

static int update_upload_budget(core_http2_stream_t *stream) {
    size_t minimum=stream->reserved_upload ? core_http2_queue_reservation(stream->tx.length+stream->reserved_upload) : 0;
    if (minimum < stream->permanent_upload && !stream->closed) minimum=stream->permanent_upload;
    return core_buffer_budget_init(&stream->tx.memory,CORE_BUFFER_UPLOAD,minimum);
}

size_t core_http2_write_capacity(const core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    size_t capacity=stream && !stream->closed && !stream->failed && !stream->finish_requested && !stream->send_stopped ? XMUX_STREAM_LIMIT-stream->tx.length-stream->reserved_upload : 0;
    size_t global=upload_bytes < XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE ? XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE-upload_bytes : 0;
    if (capacity > global) capacity=global;
    if (capacity) { size_t actual=allocated_write_capacity(stream); if (capacity > actual) capacity=actual; }
    pthread_mutex_unlock(&mux_lock); return capacity;
}

int core_http2_reserve_write(core_http2_stream_t *stream, size_t capacity) {
    pthread_mutex_lock(&mux_lock);
    size_t global=upload_bytes < XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE ? XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE-upload_bytes : 0;
    int available=stream && !stream->closed && !stream->failed && !stream->finish_requested && !stream->send_stopped && !stream->reserved_upload &&
        capacity <= XMUX_STREAM_LIMIT-stream->tx.length && capacity <= global;
    if (available && capacity > allocated_write_capacity(stream)) available=0;
    if (available) {
        stream->reserved_upload=capacity;
        if (update_upload_budget(stream)) { stream->reserved_upload=0; available=0; }
        else upload_bytes+=capacity;
    }
    pthread_mutex_unlock(&mux_lock); return available;
}

void core_http2_release_write(core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    size_t previous=upload_bytes;
    upload_bytes-=stream->reserved_upload; stream->reserved_upload=0;
    update_upload_budget(stream); notify_write_capacity(previous);
    pthread_mutex_unlock(&mux_lock);
}

static int wait_for_output(core_http2_stream_t *stream) {
    int result=core_wait_socket(stream->notify[0],POLLIN,-1);
    if (!result) errno=ETIMEDOUT;
    return result;
}

static size_t output_room(core_http2_stream_t *stream) {
    size_t available=XMUX_STREAM_LIMIT-stream->tx.length;
    size_t global=upload_bytes < XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE ? XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE-upload_bytes : 0;
    global+=stream->reserved_upload;
    if (available > global) available=global;
    size_t actual=allocated_write_capacity(stream);
    return available > actual ? actual : available;
}

int core_http2_write_parts(core_http2_stream_t *stream, const uint8_t *prefix, size_t prefix_length, const uint8_t *data, size_t data_length) {
    if (prefix_length > SIZE_MAX-data_length) { errno=EOVERFLOW; return -1; }
    if (!stream || (prefix_length && !prefix) || (data_length && !data)) { errno=EINVAL; return -1; }
    size_t length=prefix_length+data_length;
    size_t offset=0;
    int wait_ack=!stream->config.xmux.present && stream->config.transport_mode == TRANSPORT_XHTTP &&
        !strcmp(stream->config.xhttp_mode,"packet-up");
    while (offset < length) {
        if (core_deadline_active() && !core_deadline_remaining()) { errno=ETIMEDOUT; core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_DEADLINE,errno)); return -1; }
        pthread_mutex_lock(&mux_lock);
        if (stream->failed || stream->closed) { pthread_mutex_unlock(&mux_lock); stream_error(stream); return -1; }
        if (stream->send_stopped) {
            pthread_mutex_unlock(&mux_lock); errno=EPIPE;
            core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_SYSTEM,EPIPE)); return -1;
        }
        if (stream->finish_requested) { pthread_mutex_unlock(&mux_lock); stream_error(stream); return -1; }
        size_t block=length-offset;
        size_t available=stream->reserved_upload >= block ? block : output_room(stream);
        if (block > available) block=available;
        size_t head=offset < prefix_length ? prefix_length-offset : 0;
        if (head > block) head=block;
        const uint8_t *first=head ? prefix+offset : NULL;
        const uint8_t *second=block > head ? data+(offset > prefix_length ? offset-prefix_length : 0) : NULL;
        if (block && core_http2_queue_append_parts(&stream->tx,first,head,second,block-head,XMUX_STREAM_LIMIT) != 0) {
            int cause=errno; pthread_mutex_unlock(&mux_lock); core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_SYSTEM,cause)); errno=cause; return -1;
        }
        size_t reserved=block < stream->reserved_upload ? block : stream->reserved_upload;
        stream->reserved_upload-=reserved; upload_bytes+=block-reserved; offset+=block; wake_actor(stream->upload);
        update_upload_budget(stream);
        core_buffer_waiter_t waiter={0}; int waiting=offset < length;
        if (waiting) {
            core_drain_socket(stream->notify[0]); stream->notified=0;
            if (stream->tx.length < XMUX_STREAM_LIMIT) core_buffer_watch(&waiter,stream->notify[1],1U<<CORE_BUFFER_UPLOAD);
            waiting=output_room(stream) == 0;
        }
        pthread_mutex_unlock(&mux_lock);
        int waited=waiting ? wait_for_output(stream) : 1;
        int cause=errno; if (waiter.registered) core_buffer_unwatch(&waiter); errno=cause;
        if (waited <= 0) { core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_SYSTEM,errno ? errno : ETIMEDOUT)); return -1; }
    }
    while (!stream->relay_async && (core_deadline_active() || wait_ack)) {
        pthread_mutex_lock(&mux_lock);
        int failed=stream->failed || stream->closed;
        int pending=stream->tx.length || stream->upload->opening || stream->write_fence > stream->upload->flushed;
        if (wait_ack) for (mux_request_t *request=stream->upload->requests;request;request=request->next)
            if (request->stream == stream && packet_role(request->role) && !request->ended) pending=1;
        if (!pending && stream->rx.length) signal_stream(stream);
        pthread_mutex_unlock(&mux_lock);
        if (failed) { stream_error(stream); return -1; }
        if (!pending) break;
        if (wait_for_output(stream) <= 0) { core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_SYSTEM,errno ? errno : ETIMEDOUT)); return -1; }
        pthread_mutex_lock(&mux_lock);
        core_drain_socket(stream->notify[0]);
        stream->notified=0; pthread_mutex_unlock(&mux_lock);
    }
    return 0;
}

int core_http2_write(core_http2_stream_t *stream, const uint8_t *data, size_t length) {
    return core_http2_write_parts(stream,NULL,0,data,length);
}

int core_http2_read(core_http2_stream_t *stream, uint8_t *data, size_t capacity, size_t *length) {
    if (!capacity) { *length=0; return 0; }
    pthread_mutex_lock(&mux_lock); *length=0;
    core_drain_socket(stream->notify[0]);
    stream->notified=0;
    size_t take=stream->rx.length < capacity ? stream->rx.length : capacity;
    if (take) {
        core_http2_queue_copy(&stream->rx,data,take); queue_consume(&stream->rx,take);
        download_bytes-=take; stream->consumed+=take; *length=take; wake_actor(stream->download);
    }
    int result=take ? 0 : stream->failed ? -1 : stream->eof ? 0 : 1;
    if (stream->rx.length || stream->failed || stream->eof) signal_stream(stream);
    if (result < 0) stream_error(stream);
    pthread_mutex_unlock(&mux_lock); return result;
}

int core_http2_finish_write(core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    int result=!stream || stream->failed || stream->closed ? -1 : 0;
    if (!result) { stream->finish_requested=1; if (!stream->send_stopped) wake_actor(stream->upload); }
    else if (stream) stream_error(stream);
    pthread_mutex_unlock(&mux_lock); return result;
}

int core_http2_finish_pending(const core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock);
    int result=!stream ? -1 : stream->failed ? stream->rx.length ? 0 : -1 : stream->finish_requested &&
        (!stream->finish_sent || stream->finish_fence > stream->upload->flushed);
    if (result < 0 && stream) stream_error(stream);
    pthread_mutex_unlock(&mux_lock); return result;
}

int core_http2_send_stopped(const core_http2_stream_t *stream) {
    pthread_mutex_lock(&mux_lock); int stopped=stream && stream->send_stopped; pthread_mutex_unlock(&mux_lock); return stopped;
}

void core_http2_close(core_http2_stream_t *stream) {
    if (!stream) return;
    int saved=errno;
    pthread_mutex_lock(&mux_lock);
    mux_actor_t *private_actors[2]={0}; size_t private_count=0;
    if (!stream->closed && stream->config.transport_mode == TRANSPORT_XHTTP) {
        mux_actor_t *actors[]={stream->download,stream->upload};
        for (size_t i=0;i<2;i++) if (actors[i] && actors[i]->thread_started && !actors[i]->manager->config.xmux.present && (!i || actors[i] != actors[0])) {
            private_actors[private_count++]=actors[i]; actors[i]->close_waiters++; actors[i]->closing=1; wake_actor(actors[i]);
        }
    }
    if (!stream->closed) {
        stream->closed=1; close(stream->notify[0]); close(stream->notify[1]);
        size_t previous=upload_bytes;
        upload_bytes-=stream->tx.length+stream->reserved_upload; stream->reserved_upload=0; core_http2_queue_clear(&stream->tx);
        notify_write_capacity(previous);
        stream->consumed+=stream->rx.length; download_bytes-=stream->rx.length; core_http2_queue_clear(&stream->rx);
        if (stream->download && stream->download->http2) {
            stream->download->pending_credit+=(uint32_t)stream->consumed;
            stream->consumed=0;
        }
        wake_admission();
        if (stream->download) {
            stream->download->group->running--; wake_actor(stream->download); wake_actor(stream->upload);
            if (stream->upload->group != stream->download->group) stream->upload->group->running--;
        }
        release_stream(stream);
        collect_stopped_actors();
    }
    for (size_t i=0;i<private_count;i++) {
        while (!private_actors[i]->stopped) pthread_cond_wait(&workers_stopped,&mux_lock);
        private_actors[i]->close_waiters--;
    }
    if (private_count) collect_stopped_actors();
    pthread_mutex_unlock(&mux_lock); errno=saved;
}
