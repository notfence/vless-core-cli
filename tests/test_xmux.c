#include "xmux.h"
#include "../src/http2_pool.c"
#include "check.h"
#include <signal.h>
#include <sys/wait.h>

typedef struct { size_t pending; int frames, last_type, flags[16]; uint32_t last_id, ids[16], increment, request_id, reset_code; uint64_t enqueued, flushed; size_t payload_bytes,packet_requests; int last_role,end_frames; } wire_t;
static int session_failure;
static uint64_t pacing_clock;
static uint32_t pacing_random;
static mux_actor_t *scheduling_actor;
static int retiring_probe;
static int scheduling_retire(void *physical) { (void)physical; return retiring_probe; }
static int scheduling_waits[3],scheduling_polls;
static int scheduling_alps;
static int scheduling_read_progress,scheduling_collections;
uint64_t __real_core_now_ms(void);
int __real_RAND_bytes(unsigned char *,int);
int __real_core_poll(struct pollfd *,nfds_t,int);
int __wrap_core_poll(struct pollfd *descriptors,nfds_t count,int timeout) {
    if (!scheduling_actor) return __real_core_poll(descriptors,count,timeout);
    if (scheduling_alps) CHECK("alps/actor-applies-authenticated-settings",scheduling_actor->validation.settings_received && scheduling_actor->validation.settings_pending == 1 && scheduling_actor->peer_window == 1024 && scheduling_actor->peer_frame == 32768 && scheduling_actor->peer_concurrency == 2 && scheduling_actor->peer_header_limit == 65536);
    for (nfds_t i=0;i<count;i++) descriptors[i].revents=0;
    if (scheduling_read_progress == 2) CHECK("h2/blocked-consumer-does-not-poll-readable-socket",count == 2 && !(descriptors[1].events&POLLIN));
    scheduling_waits[scheduling_polls++]=timeout;
    if (scheduling_polls == 3) scheduling_actor->failed=1;
    return 0;
}
uint64_t __wrap_core_now_ms(void) { return pacing_clock ? pacing_clock : __real_core_now_ms(); }
int __wrap_RAND_bytes(unsigned char *data,int length) {
    if (!pacing_clock) return __real_RAND_bytes(data,length);
    if (length != (int)sizeof(pacing_random)) return 0;
    memcpy(data,&pacing_random,sizeof(pacing_random)); return 1;
}
static int pacing_request(void *physical,const vless_config_t *config,const char *session,uint64_t sequence,int role,const uint8_t *data,size_t length,uint32_t *id,uint32_t limit,size_t *consumed,size_t *body) {
    (void)physical; (void)config; (void)session; (void)sequence; (void)role; (void)data; (void)limit;
    *id=3; *consumed=*body=length; return 0;
}
static int fixture_session(const vless_config_t *config, char *session, size_t capacity) {
    (void)config;
    if (session_failure) { errno=EIO; return -1; }
    return snprintf(session,capacity,"vless-core") >= (int)capacity ? -1 : 0;
}
static size_t fixture_pending(void *opaque) { return ((wire_t *)opaque)->pending; }
static int fixture_send(void *opaque, uint8_t type, uint8_t flags, uint32_t id, const uint8_t *data, size_t length) {
    wire_t *wire=opaque; wire->pending+=length+9; wire->enqueued+=length+9;
    if (type == 8 && length == 4) wire->increment=((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3];
    if (type == 3 && length == 4) wire->reset_code=((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3];
    if (wire->frames < 16) { wire->flags[wire->frames]=flags; wire->ids[wire->frames]=id; }
    wire->frames++; wire->last_type=type; wire->last_id=id; return 0;
}
static int packet_send(void *opaque,uint8_t type,uint8_t flags,uint32_t id,const uint8_t *data,size_t length) {
    wire_t *wire=opaque;
    if (!type) wire->payload_bytes+=length;
    if (!type && (flags&1)) wire->end_frames++;
    return fixture_send(opaque,type,flags,id,data,length);
}
static int packet_request(void *opaque,const vless_config_t *config,const char *session,uint64_t sequence,int role,const uint8_t *data,size_t length,uint32_t *id,uint32_t limit,size_t *consumed,size_t *body) {
    wire_t *wire=opaque; wire->packet_requests++; wire->last_role=role;
    int result=pacing_request(opaque,config,session,sequence,role,data,length,id,limit,consumed,body);
    *id=wire->request_id+=2;
    if (role == 4) { *consumed=0; *body=SIZE_MAX; }
    return result;
}
static const core_xmux_backend_t fixture_backend={.send_frame=fixture_send,.pending=fixture_pending,.session=fixture_session};

static uint64_t fixture_enqueued(void *opaque) { return ((wire_t *)opaque)->enqueued; }
static uint64_t fixture_flushed(void *opaque) { return ((wire_t *)opaque)->flushed; }
static const core_http2_backend_t finish_backend={.send_frame=fixture_send,.pending=fixture_pending,.enqueued=fixture_enqueued,.flushed=fixture_flushed};

static wire_t scheduling_wire;
static int scheduling_open(const vless_config_t *config,void **physical,int *http2,char *error,size_t capacity) {
    (void)config; (void)error; (void)capacity; *physical=&scheduling_wire; *http2=1; return 0;
}
static void scheduling_close(void *physical) { (void)physical; }
static int scheduling_fd(void *physical) { (void)physical; return -1; }
static int scheduling_collect(void *physical) { (void)physical; return scheduling_read_progress == 2 ? CORE_HTTP2_INPUT_READY : scheduling_read_progress && scheduling_collections++ < 2 ? CORE_HTTP2_INPUT_PROGRESS : 0; }
static int scheduling_frame(void *physical,core_http2_frame_t *frame,size_t capacity) {
    (void)physical; (void)frame; (void)capacity; return scheduling_read_progress == 2 ? CORE_HTTP2_INPUT_BLOCKED : 1;
}
static int scheduling_flush(void *physical) {
    wire_t *wire=physical; wire->flushed=wire->enqueued; wire->pending=0; return 0;
}
static int scheduling_settings(void *physical,core_http2_settings_t *settings,core_http2_validation_t *validation) {
    (void)physical;
    if (!scheduling_alps) return 0;
    *settings=(core_http2_settings_t){.received=1,.initial_window=1024,.max_frame=32768,.concurrency=2,.header_limit=65536};
    *validation=(core_http2_validation_t){.settings_received=1,.settings_pending=1}; return 1;
}

static pthread_mutex_t close_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t close_ready=PTHREAD_COND_INITIALIZER;
static int close_entered,close_allowed,close_returned;
static void private_close(void *physical) {
    (void)physical;
    pthread_mutex_lock(&close_lock); close_entered=1; pthread_cond_broadcast(&close_ready);
    while (!close_allowed) pthread_cond_wait(&close_ready,&close_lock);
    pthread_mutex_unlock(&close_lock);
}
static void *private_close_owner(void *stream) {
    errno=ENOTTY; core_http2_close(stream);
    pthread_mutex_lock(&close_lock); close_returned=1; pthread_cond_broadcast(&close_ready); pthread_mutex_unlock(&close_lock);
    return (void *)(uintptr_t)(errno != ENOTTY);
}
static void private_close_completes_cleanup(void) {
    static core_http2_backend_t backend;
    backend=finish_backend; backend.open=scheduling_open; backend.close=private_close; backend.fd=scheduling_fd;
    backend.collect=scheduling_collect; backend.read_frame=scheduling_frame; backend.flush=scheduling_flush;
    backend.request=pacing_request; backend.session=fixture_session; scheduling_wire=(wire_t){0};
    vless_config_t config={.transport_mode=TRANSPORT_XHTTP,.server_port=1};
    strcpy(config.server_host,"127.0.0.1"); strcpy(config.xhttp_mode,"stream-one");
    char error[160]; core_http2_stream_t *stream=core_http2_connect(&config,&backend,error,sizeof(error));
    REQUIRE("xmux/private-close-connect",stream != NULL);
    pthread_t owner; REQUIRE("xmux/private-close-owner",pthread_create(&owner,NULL,private_close_owner,stream) == 0);
    pthread_mutex_lock(&close_lock);
    while (!close_entered) pthread_cond_wait(&close_ready,&close_lock);
    CHECK("xmux/private-close-waits-for-physical-cleanup",!close_returned);
    close_allowed=1; pthread_cond_broadcast(&close_ready); pthread_mutex_unlock(&close_lock);
    void *result=NULL; pthread_join(owner,&result);
    CHECK("xmux/private-close-preserves-error",!result);
    pthread_mutex_lock(&mux_lock); size_t actors=actor_count,clients=stream_count; pthread_mutex_unlock(&mux_lock);
    CHECK("xmux/private-close-releases-worker-and-stream",!actors && !clients);
    uint64_t until=core_now_ms()+1000;
    while (actors && core_now_ms() < until) {
        core_poll(NULL,0,1); pthread_mutex_lock(&mux_lock); actors=actor_count; pthread_mutex_unlock(&mux_lock);
    }
    REQUIRE("xmux/private-close-fixture-drained",!actors);
}

static void worker_progress_policy(void) {
    core_http2_backend_t backend=finish_backend;
    backend.open=scheduling_open; backend.close=scheduling_close; backend.fd=scheduling_fd;
    backend.collect=scheduling_collect; backend.read_frame=scheduling_frame; backend.flush=scheduling_flush;
    backend.retire=scheduling_retire;
    backend.initial_settings=scheduling_settings;
    for (int reading=0;reading<3;reading++) for (int retiring=0;retiring<2;retiring++) for (int blocked=0;blocked<2;blocked++) {
        scheduling_read_progress=reading; scheduling_collections=0;
        retiring_probe=retiring;
        scheduling_alps=blocked;
        mux_manager_t manager={.backend=&backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
        mux_group_t group={.manager=&manager};
        mux_actor_t actor={.manager=&manager,.group=&group,.peer_frame=16384,.peer_concurrency=UINT32_MAX,
            .send_window=blocked ? 0 : 65535,.connect_until_ms=core_now_ms()+1000};
        core_http2_stream_t stream={.download=&actor,.upload=&actor,.ready=1,.references=2,.down_id=1,.up_id=1};
        strcpy(stream.config.xhttp_mode,"stream-one");
        mux_request_t *request=calloc(1,sizeof(*request));
        REQUIRE("xmux/worker-progress-request",request != NULL);
        request->stream=&stream; request->id=1; request->role=1; request->send_window=65535; actor.requests=request;
        REQUIRE("xmux/worker-progress-notifications",notification_pair(stream.notify) == 0 && notification_pair(actor.wake) == 0);
        uint8_t payload[32768]={0};
        REQUIRE("xmux/worker-progress-upload",queue_append(&stream.tx,payload,sizeof(payload),XMUX_STREAM_LIMIT) == 0);
        memset(&scheduling_wire,0,sizeof(scheduling_wire)); scheduling_polls=0;
        streams=&stream; upload_bytes=sizeof(payload); actor_count=1; scheduling_actor=&actor;
        actor_worker(&actor); scheduling_actor=NULL;
        CHECK("tls12/pool-rotation-keeps-active-transfer",actor.draining == retiring);
        CHECK("xmux/worker-progress-bounded-passes",scheduling_polls == 3 && !actor_count && upload_bytes == stream.tx.length);
        if (blocked) {
            CHECK("xmux/worker-blocked-upload-still-waits",scheduling_waits[0] == (reading == 1 ? 0 : -1) && scheduling_waits[1] == (reading == 1 ? 0 : -1) && scheduling_waits[2] == -1 && stream.tx.length == sizeof(payload));
        } else {
            CHECK("xmux/worker-ready-upload-no-poll-delay",scheduling_waits[0] == 0 && scheduling_waits[1] == 0);
            CHECK("xmux/worker-idle-does-not-spin",scheduling_waits[2] == -1 && !stream.tx.length);
        }
        core_http2_queue_clear(&stream.tx); close(stream.notify[0]); close(stream.notify[1]); streams=NULL; upload_bytes=0;
    }
    retiring_probe=0;
    scheduling_alps=0;
    scheduling_read_progress=0;
}

static int receive_request(void *physical,const vless_config_t *config,const char *session,uint64_t sequence,int role,const uint8_t *data,size_t length,uint32_t *id,uint32_t limit,size_t *consumed,size_t *body) {
    int result=pacing_request(physical,config,session,sequence,role,data,length,id,limit,consumed,body);
    wire_t *wire=physical; *id=wire->request_id+=2; return result;
}

static void worker_timer_policy(void) {
    mux_manager_t manager={0}; manager.config.transport_mode=TRANSPORT_XHTTP;
    mux_actor_t actor={.manager=&manager,.last_input_ms=1000};
    CHECK("h2/idle-worker-event-only",actor_wait_timeout(&actor,0,2000) == -1);
    CHECK("h2/runnable-worker-immediate",actor_wait_timeout(&actor,1,2000) == 0);
    actor.alive_period=10;
    CHECK("h2/keepalive-next-real-deadline",actor_wait_timeout(&actor,0,2000) == 9000);
    actor.ping_deadline_ms=2500;
    CHECK("h2/keepalive-ack-next-deadline",actor_wait_timeout(&actor,0,2000) == 500);
    CHECK("h2/keepalive-ack-expired",actor_wait_timeout(&actor,0,2500) == 0);
    actor.alive_period=0; actor.ping_deadline_ms=0; actor.idle_pending_ms=1000;
    CHECK("h2/cancel-drain-timer",actor_wait_timeout(&actor,0,2000) == 1000);
    manager.config.transport_mode=TRANSPORT_GRPC;
    CHECK("h2/grpc-idle-timer",actor_wait_timeout(&actor,0,2000) == 59000);
    actor.idle_pending_ms=0; actor.alive_period=1;
    CHECK("h2/grpc-no-idle-ping",actor_wait_timeout(&actor,0,2000) == -1);
    manager.config.grpc_permit_without_stream=1;
    CHECK("h2/grpc-permitted-idle-ping",actor_wait_timeout(&actor,0,1500) == 500);
    manager.config.transport_mode=TRANSPORT_XHTTP; actor.alive_period=0;
    core_http2_stream_t stream={.upload=&actor,.ready=1,.down_id=1,.next_post_ms=2017};
    mux_request_t request={.stream=&stream,.role=4,.packet_until_ms=2100,.packet_idle_ms=2008}; actor.requests=&request;
    CHECK("h2/packet-idle-timer",actor_wait_timeout(&actor,0,2000) == 8);
    stream.tx.length=1; streams=&stream;
    CHECK("h2/post-interval-timer",actor_wait_timeout(&actor,0,2000) == 17);
    stream.next_post_ms=0;
    CHECK("h2/packet-max-age-timer",actor_wait_timeout(&actor,0,2000) == 100);
    request.send_ended=1;
    CHECK("h2/ended-packet-no-repeated-timer",actor_wait_timeout(&actor,0,2000) == -1);
    stream.download=&actor; stream.down_id=0; stream.until_ms=2500;
    CHECK("h2/unstarted-stream-own-deadline",actor_wait_timeout(&actor,0,2000) == 500);
    stream.until_ms=UINT64_MAX-1;
    CHECK("h2/timer-overflow-clamped",actor_wait_timeout(&actor,0,2000) == INT_MAX);
    streams=NULL;
}

static void receive_capacity_policy(void) {
    wire_t wire={.request_id=UINT32_MAX};
    core_http2_backend_t backend=finish_backend; backend.request=receive_request;
    mux_manager_t manager={.backend=&backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
    mux_group_t group={.manager=&manager};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_concurrency=UINT32_MAX,.peer_window=65535,.receive_window=65535};
    actor.validation.settings_received=1;
    core_http2_stream_t stream={.download=&actor,.upload=&actor,.ready=1,.references=1},sibling={.download=&actor,.upload=&actor,.ready=1,.references=1};
    REQUIRE("xmux/receive-window-notifications",notification_pair(stream.notify) == 0 && notification_pair(sibling.notify) == 0 && notification_pair(actor.wake) == 0);
    REQUIRE("xmux/receive-window-request",start_request(&actor,&stream,1,0) == 0);
    mux_request_t *request=actor.requests; request->response.headers=1;
    CHECK("xmux/receive-window-matches-bounded-queue",request->receive_window == 256U*1024U && actor.receive_window == 256U*1024U && wire.increment == 256U*1024U-65535);
    if (request->receive_window == 256U*1024U) {
        uint8_t payload[16384]={0}; core_http2_frame_t data={.type=0,.id=request->id,.data=payload,.length=sizeof(payload)};
        for (size_t i=0;i<16;i++) REQUIRE("xmux/receive-window-full-credit",process_frame(&actor,&data) == 0);
        CHECK("xmux/receive-window-no-early-refund",stream.rx.length == 256U*1024U && !request->receive_window && !actor.receive_window && download_bytes == stream.rx.length && wire.frames == 1);
        streams=&stream; uint8_t output[16384]; size_t received;
        for (size_t i=0;i<8;i++) REQUIRE("xmux/receive-window-consumption",core_http2_read(&stream,output,sizeof(output),&received) == 0 && received == sizeof(output));
        CHECK("xmux/receive-window-consumption-only-credit",!request->receive_window && stream.consumed == 128U*1024U && download_bytes == 128U*1024U);
        REQUIRE("xmux/receive-window-replenishment",advance_streams(&actor) == 0);
        CHECK("xmux/receive-window-replenishes-consumed-bytes",request->receive_window == 128U*1024U && actor.receive_window == 128U*1024U && wire.frames == 3 && wire.increment == 128U*1024U && !stream.consumed);
        REQUIRE("xmux/receive-window-second-request",start_request(&actor,&sibling,1,0) == 0);
        CHECK("xmux/receive-window-connection-scales-with-streams",actor.requests->receive_window == 256U*1024U && actor.receive_window == 384U*1024U && wire.increment == 256U*1024U && actor.receive_slots == 2);
    }
    while (actor.requests) { mux_request_t *next=actor.requests->next; free(actor.requests); actor.requests=next; }
    core_http2_queue_clear(&stream.rx); close(stream.notify[0]); close(stream.notify[1]); close(sibling.notify[0]); close(sibling.notify[1]); close(actor.wake[0]); close(actor.wake[1]);
    streams=NULL; upload_bytes=download_bytes=0;
}

static void empty_response_frames(void) {
    for (int grpc=0;grpc<2;grpc++) for (int headers=0;headers<3;headers++) {
        wire_t wire={0}; mux_manager_t manager={.backend=&finish_backend};
        manager.config.transport_mode=grpc ? TRANSPORT_GRPC : TRANSPORT_XHTTP;
        mux_actor_t actor={.manager=&manager,.physical=&wire,.http2=1,.latest_stream=1,.receive_window=65535};
        actor.validation.settings_received=1;
        core_http2_stream_t stream={.download=&actor,.upload=&actor,.ready=1,.references=1};
        mux_request_t request={.stream=&stream,.id=1,.role=1,.receive_window=65535,.response.headers=!headers};
        actor.requests=&request;
        REQUIRE("h2/empty-response-notifications",notification_pair(stream.notify) == 0 && notification_pair(actor.wake) == 0);
        core_http2_frame_t frame={.type=headers ? 1 : 0,.flags=headers == 2 ? 0 : headers ? 4 : 1,.id=1};
        REQUIRE("h2/empty-response-no-null-arithmetic",process_frame(&actor,&frame) == 0);
        if (headers == 2) {
            frame.type=9; frame.flags=4;
            REQUIRE("h2/empty-continuation-no-null-arithmetic",process_frame(&actor,&frame) == 0);
        }
        CHECK("h2/empty-response-correct-state",headers || grpc ? stream.failed : stream.eof && request.ended);
        CHECK("h2/empty-response-no-buffer",!stream.rx.length && !stream.rx.capacity && !actor.header_block.capacity && !download_bytes);
        core_http2_queue_clear(&stream.rx); core_http2_queue_clear(&actor.header_block); core_hpack_clear(&actor.hpack);
        close(stream.notify[0]); close(stream.notify[1]); close(actor.wake[0]); close(actor.wake[1]);
    }
}

static void flush_notification_policy(void) {
    wire_t wire={.enqueued=113,.flushed=113}; mux_manager_t manager={.backend=&finish_backend};
    mux_actor_t actor={.manager=&manager,.physical=&wire,.net_accounted=13,.flushed=100};
    core_http2_stream_t complete={.upload=&actor,.write_fence=110},future={.upload=&actor,.write_fence=120},idle={.upload=&actor,.write_fence=90};
    REQUIRE("h2/flush-notification-channels",notification_pair(complete.notify) == 0 && notification_pair(future.notify) == 0 && notification_pair(idle.notify) == 0);
    complete.next=&future; future.next=&idle; streams=&complete; upload_bytes=13;
    account_output(&actor);
    CHECK("h2/flush-notifies-completed-write",complete.notified && core_wait_socket(complete.notify[0],POLLIN,0) == 1);
    CHECK("h2/flush-does-not-wake-unfinished-write",!future.notified && core_wait_socket(future.notify[0],POLLIN,0) == 0);
    CHECK("h2/control-flush-does-not-wake-idle-reader",!idle.notified && core_wait_socket(idle.notify[0],POLLIN,0) == 0);
    core_http2_drain_notifications(&complete); wire.enqueued=wire.flushed=126; actor.net_accounted=13; upload_bytes=13;
    account_output(&actor);
    CHECK("h2/next-flush-notifies-next-write",future.notified && !complete.notified && !idle.notified);
    close(complete.notify[0]); close(complete.notify[1]); close(future.notify[0]); close(future.notify[1]); close(idle.notify[0]); close(idle.notify[1]);
    streams=NULL; upload_bytes=0;
}

static void receive_credit_batching(void) {
    wire_t wire={0}; mux_manager_t manager={.backend=&finish_backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
    mux_group_t group={.manager=&manager};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_frame=16384,.send_window=65535,.receive_window=256U*1024U-5};
    core_http2_stream_t stream={.download=&actor,.upload=&actor,.ready=1,.down_id=1,.up_id=1,.references=1,.consumed=5};
    strcpy(stream.config.xhttp_mode,"stream-one");
    mux_request_t request={.stream=&stream,.id=1,.role=1,.send_window=65535,.receive_window=256U*1024U-5}; actor.requests=&request;
    REQUIRE("xmux/credit-batch-notifications",notification_pair(stream.notify) == 0 && notification_pair(actor.wake) == 0);
    REQUIRE("xmux/credit-batch-upload",queue_append(&stream.tx,(const uint8_t *)"up",2,XMUX_STREAM_LIMIT) == 0);
    streams=&stream; upload_bytes=2;
    REQUIRE("xmux/credit-batch-small-consumption",advance_streams(&actor) == 0);
    CHECK("xmux/credit-batch-retains-small-refund",stream.consumed == 5 && request.receive_window == 256U*1024U-5 && actor.receive_window == 256U*1024U-5);
    CHECK("xmux/credit-batch-does-not-block-upload",!stream.tx.length && wire.frames == 1 && wire.last_type == 0);
    if (stream.consumed == 5) {
        stream.consumed+=16379; request.receive_window-=16379; actor.receive_window-=16379;
        REQUIRE("xmux/credit-batch-threshold",advance_streams(&actor) == 0);
        CHECK("xmux/credit-batch-refunds-consumed-block",!stream.consumed && request.receive_window == 256U*1024U && actor.receive_window == 256U*1024U && wire.frames == 3 && wire.increment == 16384);
        stream.consumed=5; request.receive_window=256U*1024U-5; actor.receive_window=16384;
        REQUIRE("xmux/credit-batch-low-connection-window",advance_streams(&actor) == 0);
        CHECK("xmux/credit-batch-connection-no-deadlock",!stream.consumed && actor.receive_window == 16389 && request.receive_window == 256U*1024U && wire.increment == 5);
        stream.consumed=7; request.receive_window=16384; actor.receive_window=256U*1024U-7;
        REQUIRE("xmux/credit-batch-low-stream-window",advance_streams(&actor) == 0);
        CHECK("xmux/credit-batch-stream-no-deadlock",!stream.consumed && request.receive_window == 16391 && actor.receive_window == 256U*1024U && wire.increment == 7);
        stream.consumed=3; request.receive_window=256U*1024U-3; actor.receive_window=256U*1024U-3; request.ended=1;
        int frames=wire.frames;
        REQUIRE("xmux/credit-batch-ended-stream",advance_streams(&actor) == 0);
        CHECK("xmux/credit-batch-ended-refunds-connection-only",!stream.consumed && actor.receive_window == 256U*1024U && wire.frames == frames+1 && !wire.last_id);
    }
    core_http2_queue_clear(&stream.tx); close(stream.notify[0]); close(stream.notify[1]); close(actor.wake[0]); close(actor.wake[1]);
    streams=NULL; upload_bytes=0;
}

static void directional_finish(void) {
    wire_t wire={0}; mux_manager_t manager={.backend=&finish_backend}; manager.config.transport_mode=TRANSPORT_GRPC;
    mux_group_t group={.manager=&manager};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_frame=2,.send_window=65535};
    core_http2_stream_t stream={.upload=&actor,.download=&actor,.ready=1,.down_id=1,.up_id=1,.references=2};
    core_http2_stream_t sibling={.upload=&actor,.download=&actor,.ready=1,.down_id=3,.up_id=3,.references=2};
    mux_request_t *request=calloc(1,sizeof(*request)),*other=calloc(1,sizeof(*other));
    REQUIRE("h2/finish-fixture-requests",request && other);
    *request=(mux_request_t){.stream=&stream,.id=1,.role=1,.send_window=65535,.response={.headers=1}};
    *other=(mux_request_t){.stream=&sibling,.id=3,.role=1,.send_window=65535,.response={.headers=1}};
    request->next=other; actor.requests=request;
    REQUIRE("h2/finish-fixture-notifications",notification_pair(actor.wake) == 0 && notification_pair(stream.notify) == 0 && notification_pair(sibling.notify) == 0);
    REQUIRE("h2/finish-queued-payload",queue_append(&stream.tx,(const uint8_t *)"vless-core",10,XMUX_STREAM_LIMIT) == 0);
    stream.next=&sibling; streams=&stream; upload_bytes=10;
    CHECK("h2/finish-idempotent-request",core_http2_finish_write(&stream) == 0 && core_http2_finish_write(&stream) == 0 && !wire.frames);
    CHECK("h2/finish-rejects-new-writes",!core_http2_write_capacity(&stream) && !core_http2_reserve_write(&stream,1) && core_http2_write(&stream,(const uint8_t *)"x",1) < 0);
    for (int i=0;i<5;i++) {
        REQUIRE("h2/finish-drains-before-end-stream",advance_streams(&actor) == 0);
        CHECK("h2/finish-payload-order",wire.flags[i] == 0 && wire.ids[i] == 1);
        CHECK("h2/finish-awaits-complete-drain",i == 4 ? wire.frames == 6 && wire.flags[5] == 1 && stream.finish_sent : wire.frames == i+1 && !stream.finish_sent);
    }
    CHECK("h2/finish-awaits-wire-flush",core_http2_finish_pending(&stream) == 1);
    REQUIRE("h2/finish-remains-idempotent",advance_streams(&actor) == 0 && wire.frames == 6);
    wire.pending=0; wire.flushed=wire.enqueued; account_output(&actor);
    CHECK("h2/finish-flush-completes",core_http2_finish_pending(&stream) == 0);
    CHECK("h2/finish-keeps-sibling-open",!other->send_ended && !sibling.finish_requested && !sibling.failed && !stream.eof);
    stream.eof=1; request->ended=1;
    uint8_t output[3]; size_t received=99;
    REQUIRE("h2/finish-final-buffer",queue_append(&stream.rx,(const uint8_t *)"end",3,XMUX_STREAM_LIMIT) == 0); download_bytes=3;
    CHECK("h2/finish-final-buffer-before-eof",core_http2_read(&stream,output,sizeof(output),&received) == 0 && received == 3 && !memcmp(output,"end",3));
    CHECK("h2/finish-clean-eof",core_http2_read(&stream,output,sizeof(output),&received) == 0 && !received);
    stream.failed=1;
    CHECK("h2/finish-error-not-clean-eof",core_http2_read(&stream,output,sizeof(output),&received) < 0);
    stream.failed=0; stream.consumed=0;
    CHECK("h2/finish-does-not-reset-complete-stream",advance_streams(&actor) == 0 && actor.requests == other && wire.frames == 6);
    other->ended=1; sibling.eof=1;
    CHECK("h2/half-closed-stream-counts-toward-peer-limit",request_active(&actor) == 1);
    REQUIRE("h2/finish-upload-after-server-end",queue_append(&sibling.tx,(const uint8_t *)"up",2,XMUX_STREAM_LIMIT) == 0); upload_bytes=2;
    CHECK("h2/finish-server-end-preserves-upload",advance_streams(&actor) == 0 && !sibling.tx.length && wire.frames == 7 && wire.ids[6] == 3 && !wire.flags[6]);
    free(other); core_http2_queue_clear(&stream.tx); core_http2_queue_clear(&stream.rx); core_http2_queue_clear(&sibling.tx);
    close(actor.wake[0]); close(actor.wake[1]); close(stream.notify[0]); close(stream.notify[1]); close(sibling.notify[0]); close(sibling.notify[1]);
    streams=NULL; upload_bytes=download_bytes=0;
}
static void asynchronous_relay_deadline(void) {
    core_http2_stream_t stream={0}; mux_actor_t actor={0};
    stream.download=stream.upload=&actor;
    REQUIRE("h2/relay-deadline-notifications",notification_pair(stream.notify) == 0 && notification_pair(actor.wake) == 0);
    core_deadline_t deadline; REQUIRE("h2/relay-deadline-attach",core_deadline_attach(&deadline) == 0); core_deadline_begin(100);
    CHECK("h2/relay-start-idempotent",core_http2_start_relay(&stream) == 0 && core_http2_start_relay(&stream) == 0 && stream.relay_async);
    CHECK("h2/relay-queues-without-blocking-response",core_http2_write(&stream,(const uint8_t *)"vless-core",10) == 0 && stream.tx.length == 10 && core_deadline_active() && core_deadline_remaining() > 0);
    CHECK("h2/relay-rejects-invalid-stream",core_http2_start_relay(NULL) < 0);
    stream.closed=1; CHECK("h2/relay-rejects-closed-stream",core_http2_start_relay(&stream) < 0);
    core_deadline_end(); core_deadline_detach(); core_http2_queue_clear(&stream.tx); upload_bytes=0;
    close(stream.notify[0]); close(stream.notify[1]); close(actor.wake[0]); close(actor.wake[1]);
}

static void grpc_pool_policy(void) {
    wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend};
    manager.config.transport_mode=TRANSPORT_GRPC; manager.config.grpc_initial_window=262144;
    manager.config.grpc_health_timeout=2;
    mux_group_t group={.manager=&manager}; mux_actor_t actors[4]={0}; mux_request_t requests[4]={0};
    manager.actors=actors;
    for (unsigned i=0;i<4;i++) {
        actors[i].manager=&manager; actors[i].group=&group; actors[i].http2=1;
        actors[i].peer_concurrency=1;
        actors[i].validation.settings_received=1; actors[i].validation.settings_pending=1;
        actors[i].requests=&requests[i]; actors[i].next=i<3 ? &actors[i+1] : NULL;
    }
    errno=0;
    CHECK("grpc/pool-four-physical-limit",!group_channel(&group,100,NULL,1) && errno == EAGAIN);
    actors[0].peer_concurrency=2;
    CHECK("grpc/pool-server-stream-capacity",group_channel(&group,100,NULL,1) == &actors[0]);
    actors[0].requests=NULL; actors[0].physical=&wire; actors[0].alive_period=1; actors[0].last_input_ms=1000;
    CHECK("grpc/keepalive-disabled-without-stream",maintain_ping(&actors[0],2000) == 0 && !wire.frames);
    manager.config.grpc_permit_without_stream=1;
    CHECK("grpc/keepalive-explicit-idle-permission",maintain_ping(&actors[0],2000) == 0 && wire.frames == 1 && actors[0].ping_deadline_ms == 4000);
    CHECK("grpc/keepalive-ack-budget",maintain_ping(&actors[0],4000) < 0);
    core_xmux_frame_t acknowledgement={.type=6,.flags=1,.length=8,.data=actors[0].ping};
    CHECK("grpc/keepalive-acknowledged",process_frame(&actors[0],&acknowledgement) == 0 && !actors[0].ping_deadline_ms);
    CHECK("grpc/idle-pool-retained",stop_idle_actor(&actors[0],0,5000) == 0 && stop_idle_actor(&actors[0],0,64999) == 0);
    CHECK("grpc/idle-pool-closed-at-sixty-seconds",stop_idle_actor(&actors[0],0,65000) == 1);
    actors[0].draining=0; actors[0].receive_window=262144; actors[0].latest_stream=3;
    core_xmux_stream_t first={.download=&actors[0],.upload=&actors[0],.down_id=1,.up_id=1,.ready=1},second={.download=&actors[0],.upload=&actors[0],.down_id=3,.up_id=3,.ready=1};
    REQUIRE("grpc/policy-notification-channels",notification_pair(first.notify) == 0 && notification_pair(second.notify) == 0 && notification_pair(actors[0].wake) == 0);
    mux_request_t request_a={.stream=&first,.id=1,.role=1,.receive_window=262144},request_b={.stream=&second,.id=3,.role=1,.response={.headers=1},.receive_window=262144};
    request_a.next=&request_b; actors[0].requests=&request_a;
    uint8_t status[]={0x88,0,11,'g','r','p','c','-','s','t','a','t','u','s',1,'7'};
    core_xmux_frame_t trailer={.type=1,.flags=5,.id=1,.data=status,.length=sizeof(status)};
    CHECK("grpc/nonzero-status-isolated",process_frame(&actors[0],&trailer) == 0 && first.failed && !second.failed);
    actors[0].requests=&request_b; streams=&second;
    core_xmux_frame_t data={.type=0,.id=3,.data=(uint8_t *)"abc",.length=3};
    CHECK("grpc/window-not-replenished-before-consumption",process_frame(&actors[0],&data) == 0 && !second.consumed && request_b.receive_window == 262141);
    uint8_t output[3]; size_t received=0;
    CHECK("grpc/window-consumption-accounted",core_http2_read(&second,output,3,&received) == 0 && received == 3 && second.consumed == 3);
    REQUIRE("grpc/failure-queued-data",process_frame(&actors[0],&data) == 0);
    second.failed=1;
    CHECK("grpc/failure-defers-until-buffer-drained",core_http2_finish_pending(&second) == 0);
    CHECK("grpc/failed-stream-still-drains",core_http2_read(&second,output,3,&received) == 0 && received == 3);
    CHECK("grpc/failure-after-drain",core_http2_finish_pending(&second) == -1);
    second.failed=0;
    CHECK("grpc/window-update-after-consumption",advance_streams(&actors[0]) == 0 && !second.consumed && request_b.receive_window == 262144);
    streams=NULL; core_http2_queue_clear(&second.rx); core_hpack_clear(&actors[0].hpack);
    close(first.notify[0]); close(first.notify[1]); close(second.notify[0]); close(second.notify[1]); close(actors[0].wake[0]); close(actors[0].wake[1]);
    upload_bytes=download_bytes=0;
}

static void paced_stream_isolation(void) {
    wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend}; mux_group_t group={.manager=&manager};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_frame=16384,.send_window=65535},downloading={0};
    core_xmux_stream_t delayed={.download=&downloading,.upload=&actor,.ready=1,.down_id=1,.packet_limit=1024,.next_post_ms=core_now_ms()+10000};
    core_xmux_stream_t active={.download=&downloading,.upload=&actor,.ready=1,.down_id=3,.up_id=5};
    strcpy(delayed.config.xhttp_mode,"packet-up"); strcpy(active.config.xhttp_mode,"stream-up");
    mux_request_t request={.stream=&active,.id=5,.role=2,.send_window=65535}; actor.requests=&request;
    REQUIRE("xmux/pacing-notification-channels",notification_pair(delayed.notify) == 0 && notification_pair(active.notify) == 0);
    REQUIRE("xmux/pacing-queued-payloads",queue_append(&delayed.tx,(uint8_t *)"delayed",7,XMUX_STREAM_LIMIT) == 0 && queue_append(&active.tx,(uint8_t *)"active",6,XMUX_STREAM_LIMIT) == 0);
    delayed.next=&active; streams=&delayed; upload_bytes=13;
    CHECK("xmux/pacing-does-not-block-another-stream",advance_streams(&actor) == 0 && delayed.tx.length == 7 && !active.tx.length && wire.frames == 1 && wire.last_id == 5);
    core_http2_queue_clear(&delayed.tx); core_http2_queue_clear(&active.tx); close(delayed.notify[0]); close(delayed.notify[1]); close(active.notify[0]); close(active.notify[1]);
    streams=NULL; upload_bytes=0;
}
static void zero_minimum_packet_interval(void) {
    wire_t wire={0}; const core_xmux_backend_t backend={.send_frame=fixture_send,.pending=fixture_pending,.request=pacing_request};
    mux_manager_t manager={.backend=&backend}; mux_group_t group={.manager=&manager,.request_limit=100,.expires_ms=UINT64_MAX};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_frame=16384,.peer_concurrency=100,.peer_window=65535,.send_window=65535},downloading={0};
    core_xmux_stream_t stream={.download=&downloading,.upload=&actor,.ready=1,.down_id=1,.packet_limit=1024,.last_post_ms=1000,.references=2};
    strcpy(stream.config.xhttp_mode,"packet-up"); stream.config.xhttp_min_posts_interval_max=100;
    REQUIRE("xmux/zero-minimum-notifications",notification_pair(stream.notify) == 0);
    REQUIRE("xmux/zero-minimum-payload",queue_append(&stream.tx,(const uint8_t *)"vless-core",10,XMUX_STREAM_LIMIT) == 0);
    streams=&stream; upload_bytes=10; pacing_clock=1001; pacing_random=201;
    CHECK("xmux/zero-minimum-honors-upper-endpoint",advance_streams(&actor) == 0 && stream.tx.length == 10 && stream.next_post_ms == 1100 && !actor.requests && !wire.frames);
    pacing_random=101; pacing_clock=1099;
    CHECK("xmux/interval-not-resampled-before-due",advance_streams(&actor) == 0 && stream.tx.length == 10 && stream.next_post_ms == 1100 && !actor.requests);
    pacing_clock=1100;
    CHECK("xmux/packet-sent-at-monotonic-due",advance_streams(&actor) == 0 && !stream.tx.length && stream.last_post_ms == 1100 && wire.frames == 1 && wire.last_id == 3);
    free(actor.requests); core_http2_queue_clear(&stream.tx); close(stream.notify[0]); close(stream.notify[1]);
    streams=NULL; upload_bytes=0; pacing_clock=0;
}

static void packet_batching_policy(void) {
    for (int finish=0;finish<4;finish++) {
        wire_t wire={.request_id=1}; core_http2_backend_t backend=finish_backend;
        backend.send_frame=packet_send; backend.request=packet_request;
        mux_manager_t manager={.backend=&backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
        mux_group_t group={.manager=&manager,.request_limit=INT_MAX,.expires_ms=UINT64_MAX};
        mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_frame=16384,
            .peer_window=INT_MAX,.peer_concurrency=UINT32_MAX,.send_window=INT_MAX};
        core_http2_stream_t stream={.download=&actor,.upload=&actor,.ready=1,.references=1,.down_id=1,.packet_limit=1048576,.relay_async=1};
        stream.config.transport_mode=TRANSPORT_XHTTP; strcpy(stream.config.xhttp_mode,"packet-up");
        if (finish == 1) strcpy(stream.config.xhttp_uplink_data_placement,"body");
        if (finish == 2) strcpy(stream.config.xhttp_uplink_data_placement,"auto");
        REQUIRE("xmux/packet-batch-notifications",notification_pair(actor.wake) == 0 && notification_pair(stream.notify) == 0);
        streams=&stream; upload_bytes=0; pacing_clock=1000;
        uint8_t payload[131072]={0};
        size_t expected=finish ? sizeof(payload)+17 : 8*sizeof(payload);
        for (unsigned chunk=0;chunk<(finish ? 1U : 8U);chunk++) {
            REQUIRE("xmux/packet-batch-queue",queue_append(&stream.tx,payload,sizeof(payload),XMUX_STREAM_LIMIT) == 0); upload_bytes+=sizeof(payload);
            for (unsigned frame=0;frame<8;frame++) {
                REQUIRE("xmux/packet-batch-frame",advance_streams(&actor) == 0);
                scheduling_flush(&wire); account_output(&actor);
            }
        }
        CHECK("xmux/packet-batch-uses-streamed-body",wire.last_role == 4 && wire.packet_requests == 1);
        CHECK("xmux/packet-batch-does-not-grow-queue",!stream.tx.length && !stream.tx.capacity && wire.payload_bytes == (finish ? sizeof(payload) : expected));
        if (wire.last_role == 4 && actor.requests) {
            mux_request_t *request=actor.requests;
            if (finish) {
                REQUIRE("xmux/packet-batch-short-tail",queue_append(&stream.tx,payload,17,XMUX_STREAM_LIMIT) == 0); upload_bytes+=17;
                if (finish == 3) actor.send_window=0;
                REQUIRE("xmux/packet-batch-tail-frame",advance_streams(&actor) == 0);
                scheduling_flush(&wire); account_output(&actor);
                if (finish == 1) stream.finish_requested=1;
                else if (finish == 3) {
                    pacing_clock=1100;
                    REQUIRE("xmux/packet-batch-age-bound",advance_streams(&actor) == 0 && request->send_ended && stream.tx.length == 17);
                    scheduling_flush(&wire); account_output(&actor); actor.send_window=INT_MAX;
                }
                else {
                    pacing_clock=1001; REQUIRE("xmux/packet-batch-idle-grace",advance_streams(&actor) == 0 && !request->send_ended);
                    pacing_clock=1008;
                }
                REQUIRE("xmux/packet-batch-finalize",advance_streams(&actor) == 0);
            }
            CHECK("xmux/packet-batch-preserves-last-byte",wire.payload_bytes == expected && request->send_ended && wire.end_frames == (finish == 3 ? 2 : 1));
            CHECK("xmux/packet-batch-one-sequence",stream.sequence == (finish == 3 ? 2U : 1U));
        }
        mux_request_t *request=actor.requests;
        while (request) { mux_request_t *next=request->next; free(request); request=next; }
        core_http2_queue_clear(&stream.tx); core_http2_queue_clear(&stream.rx);
        close(actor.wake[0]); close(actor.wake[1]); close(stream.notify[0]); close(stream.notify[1]);
        streams=NULL; upload_bytes=0; pacing_clock=0;
    }
}

static void cancelled_stream_cleanup(void) {
    wire_t wire={.pending=23}; mux_manager_t manager={.backend=&fixture_backend,.config.xmux.present=1};
    mux_group_t group={.manager=&manager,.running=1};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.send_window=0,.net_accounted=23};
    core_xmux_stream_t *stream=calloc(1,sizeof(*stream)); mux_request_t *request=calloc(1,sizeof(*request));
    REQUIRE("xmux/cancelled-stream-allocation",stream && request);
    REQUIRE("xmux/cancelled-stream-notifications",notification_pair(stream->notify) == 0 && notification_pair(actor.wake) == 0);
    stream->download=stream->upload=&actor; stream->references=2; stream->ready=1; stream->down_id=stream->up_id=3;
    strcpy(stream->config.xhttp_mode,"packet-up"); stream->packet_limit=1024;
    request->stream=stream; request->role=3; request->id=3; request->remaining=10; request->response.headers=1;
    actor.requests=request; streams=stream; stream_count=1;
    REQUIRE("xmux/cancelled-stream-pending-upload",queue_append(&stream->tx,(uint8_t *)"vless-core",10,XMUX_STREAM_LIMIT) == 0);
    upload_bytes=33; core_xmux_close(stream);
    CHECK("xmux/cancellation-releases-unsent-upload",upload_bytes == 23 && !stream->tx.length);
    CHECK("xmux/cancellation-does-not-wait-for-shared-output",advance_streams(&actor) == 0 && !actor.requests && !streams && !stream_count && wire.last_type == 3 && wire.last_id == 3);
    CHECK("xmux/cancellation-keeps-physical-output-accounted",upload_bytes == wire.pending);
    CHECK("xmux/cancellation-allows-healthy-output-to-drain",!stop_idle_actor(&actor,0,1000) && !actor.draining);
    CHECK("xmux/cancellation-keeps-channel-for-active-neighbours",!stop_idle_actor(&actor,1,1200) && !actor.draining && !actor.idle_pending_ms);
    CHECK("xmux/cancellation-bounds-orphaned-output-drain",!stop_idle_actor(&actor,0,2000) && !stop_idle_actor(&actor,0,3999));
    CHECK("xmux/cancellation-closes-orphaned-physical-output",stop_idle_actor(&actor,0,4000) && actor.draining);
    actor.draining=0; actor.net_accounted=0;
    CHECK("xmux/healthy-idle-channel-remains-reusable",!stop_idle_actor(&actor,0,5000) && !actor.draining);
    if (actor.requests) { actor.net_accounted=wire.pending=0; upload_bytes=stream->tx.length; queue_consume(&stream->tx,stream->tx.length); upload_bytes=0; advance_streams(&actor); }
    close(actor.wake[0]); close(actor.wake[1]); streams=NULL; stream_count=0; upload_bytes=0;
}

static void http2_wire_vectors(void) {
    wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend};
    manager.config.transport_mode=TRANSPORT_XHTTP;
    mux_actor_t actor={.manager=&manager,.physical=&wire,.http2=1,.latest_stream=1,.receive_window=65535,.peer_window=65535};
    core_http2_stream_t stream={0}; REQUIRE("h2/wire-notifications",notification_pair(stream.notify) == 0);
    mux_request_t request={.stream=&stream,.id=1,.role=1,.response={.headers=1},.receive_window=65535}; actor.requests=&request;
    core_http2_frame_t data={.type=0,.id=1,.data=(uint8_t *)"x",.length=1};
    CHECK("h2/wire-initial-settings-required",process_frame(&actor,&data) < 0);
    request.response.headers=0;
    const uint8_t wrong_response[]={0x88,0,5,':','p','a','t','h',1,'/'};
    int result=finish_headers(&actor,1,4,wrong_response,sizeof(wrong_response));
    CHECK("h2/wire-request-pseudo-is-stream-error",result == 0 && stream.failed && !actor.failed);
    core_http2_queue_clear(&stream.rx); core_hpack_clear(&actor.hpack); close(stream.notify[0]); close(stream.notify[1]); download_bytes=0;
}

static int budgeted_fixture_open(const vless_config_t *config, void **physical, int *http2, char *error, size_t capacity,
                                core_buffer_budget_t *upload, core_buffer_budget_t *download) {
    (void)upload; (void)download;
    return scheduling_open(config,physical,http2,error,capacity);
}

static void memory_admission_policy(void) {
    core_http2_queue_cache_clear();
    wire_t wire={.request_id=UINT32_MAX}; core_http2_backend_t backend=finish_backend;
    backend.open_budgeted=budgeted_fixture_open; backend.request=receive_request;
    mux_manager_t manager={.backend=&backend}; manager.config.transport_mode=TRANSPORT_GRPC;
    mux_group_t group={.manager=&manager};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_concurrency=UINT32_MAX,
        .peer_window=65535,.receive_window=65535};
    manager.actors=&actor; manager.groups=&group;
    REQUIRE("h2/budget-admission-notification",notification_pair(actor.wake) == 0);
    REQUIRE("h2/budget-physical-input-reserve",core_buffer_budget_init(&actor.input_memory,CORE_BUFFER_DOWNLOAD,CORE_BUFFER_PROTOCOL_RESERVE) == 0);
    REQUIRE("h2/budget-physical-output-reserve",core_buffer_budget_init(&actor.output_memory,CORE_BUFFER_UPLOAD,CORE_BUFFER_OUTPUT_RESERVE) == 0);
    core_http2_stream_t clients[64]={0}; size_t count=0;
    REQUIRE("h2/budget-client-notification",notification_pair(clients[0].notify) == 0);
    for (;count<64;count++) {
        clients[count].config=manager.config;
        if (allocate_channels(clients+count,&manager,&manager,100)) break;
    }
    CHECK("h2/admission-waits-before-advertising",count >= 32 && count < 64 && errno == EAGAIN && !wire.frames && !clients[count].download);
    size_t bytes,reserved;
    core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("h2/admission-reserves-without-large-allocation",!bytes && reserved <= CORE_BUFFER_TOTAL_LIMIT && reserved >= count*CORE_HTTP2_STREAM_LIMIT);
    REQUIRE("h2/advertises-only-reserved-window",start_request(&actor,clients,1,0) == 0);
    uint8_t payload[16384]={0}; mux_request_t *request=actor.requests; request->response.headers=1;
    actor.validation.settings_received=1;
    core_http2_frame_t frame={.type=0,.id=request->id,.data=payload,.length=sizeof(payload)};
    for (unsigned i=0;i<16;i++) REQUIRE("h2/reserved-window-can-fill",process_frame(&actor,&frame) == 0);
    CHECK("h2/full-queue-keeps-control-reserve",clients[0].rx.length == CORE_HTTP2_STREAM_LIMIT && !request->receive_window);
    core_http2_frame_t ping={.type=6,.data=(uint8_t *)"12345678",.length=8};
    CHECK("h2/control-frame-progress-with-full-queue",process_frame(&actor,&ping) == 0 && wire.last_type == 6);
    core_http2_queue_clear(&clients[1].rx); core_http2_queue_clear(&clients[1].tx);
    CHECK("h2/admission-recovers-after-release",allocate_channels(clients+count,&manager,&manager,100) == 0);
    free(request); actor.requests=NULL;
    for (size_t i=0;i<=count;i++) { core_http2_queue_clear(&clients[i].rx); core_http2_queue_clear(&clients[i].tx); }
    core_http2_queue_cache_clear();
    REQUIRE("h2/physical-input-reserve-released",core_buffer_budget_clear(&actor.input_memory) == 0);
    REQUIRE("h2/physical-output-reserve-released",core_buffer_budget_clear(&actor.output_memory) == 0);
    core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("h2/admission-all-resources-restored",!bytes && !reserved);
    core_buffer_snapshot(CORE_BUFFER_UPLOAD,&bytes,&reserved);
    CHECK("h2/admission-output-resources-restored",!bytes && !reserved);
    close(actor.wake[0]); close(actor.wake[1]); close(clients[0].notify[0]); close(clients[0].notify[1]); upload_bytes=download_bytes=0;
}

static void drained_queue_memory(void) {
    mux_queue_t queues[256]={0}; uint8_t payload[16384]={0}; size_t retained=0;
    for (size_t i=0;i<256;i++) {
        for (size_t j=0;j<16;j++) REQUIRE("xmux/drained-queue-fill",queue_append(queues+i,payload,sizeof(payload),XMUX_STREAM_LIMIT) == 0);
        queue_consume(queues+i,queues[i].length); retained+=queues[i].capacity;
    }
    CHECK("xmux/drained-queues-do-not-retain-per-client-capacity",retained <= 256U*1024U);
    for (size_t i=0;i<256;i++) core_http2_queue_clear(&queues[i]);
}

static void head_upload_response(void) {
    core_http2_backend_t backend=finish_backend; backend.request=pacing_request;
    mux_manager_t manager={.backend=&backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
    mux_group_t group={.manager=&manager}; wire_t wire={0};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_window=65535,.peer_concurrency=16,.peer_header_limit=8192};
    actor.validation.settings_received=1;
    for (int role=2;role<=3;role++) {
        core_http2_stream_t stream={0}; stream.config.transport_mode=TRANSPORT_XHTTP;
        strcpy(stream.config.xhttp_uplink_method,"HEAD"); strcpy(stream.config.xhttp_mode,role == 2 ? "stream-up" : "packet-up");
        REQUIRE("xmux/head-notifications",notification_pair(stream.notify) == 0);
        REQUIRE("xmux/head-start-request",start_request(&actor,&stream,role,0) == 0);
        mux_request_t *request=actor.requests;
        CHECK("xmux/head-response-method-state",request->response.no_body && !stream.eof);
        const uint8_t headers[]={0x88,0x0f,0x0d,3,'1','2','3'};
        core_http2_frame_t frame={.type=1,.flags=5,.id=request->id,.data=(uint8_t *)headers,.length=sizeof(headers)};
        CHECK("xmux/head-ack-preserves-download-and-upload",process_frame(&actor,&frame) == 0 && request->ended && !stream.failed && !stream.eof && (role != 2 || !request->send_ended));
        free(request); actor.requests=NULL; close(stream.notify[0]); close(stream.notify[1]);
    }
    core_hpack_clear(&actor.hpack); core_buffer_budget_clear(&actor.output_memory);
}

static void priority_stream_isolation(void) {
    const struct { uint8_t type; size_t length; uint32_t code; } cases[]={{2,4,6},{2,6,6},{2,5,1},{8,4,1}};
    for (size_t i=0;i<sizeof(cases)/sizeof(*cases);i++) {
        wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
        mux_actor_t actor={.manager=&manager,.physical=&wire,.http2=1,.latest_stream=3,.receive_window=65535}; actor.validation.settings_received=1;
        core_http2_stream_t first={0},second={0};
        REQUIRE("xmux/priority-notifications",notification_pair(first.notify) == 0 && notification_pair(second.notify) == 0);
        mux_request_t a={.stream=&first,.id=1,.role=1,.response.headers=1},b={.stream=&second,.id=3,.role=1,.receive_window=65535,.response.headers=1}; a.next=&b; actor.requests=&a;
        uint8_t payload[]={0,0,0,1,0,0}; if (cases[i].type == 8) payload[3]=0;
        core_http2_frame_t frame={.type=cases[i].type,.id=1,.data=payload,.length=cases[i].length};
        CHECK("xmux/priority-error-code-and-scope",process_frame(&actor,&frame) == 0 && wire.last_type == 3 && wire.last_id == 1 && wire.reset_code == cases[i].code && first.failed && !second.failed && !actor.failed);
        frame=(core_http2_frame_t){.type=0,.id=3,.data=(uint8_t *)"vless-core",.length=10};
        CHECK("xmux/priority-neighbor-still-receives",process_frame(&actor,&frame) == 0 && second.rx.length == 10 && !second.failed);
        core_http2_queue_clear(&second.rx); download_bytes=0;
        close(first.notify[0]); close(first.notify[1]); close(second.notify[0]); close(second.notify[1]);
    }
}

static void random_range_bound(void) {
    pid_t child=fork(); REQUIRE("xmux/random-rejection-child",child >= 0);
    if (!child) { alarm(1); pacing_clock=1000; pacing_random=0; _exit(random_range((core_range_t){1,3}) < 0 ? 0 : 1); }
    int status; REQUIRE("xmux/random-rejection-wait",waitpid(child,&status,0) == child);
    CHECK("xmux/random-rejection-has-finite-bound",WIFEXITED(status) && WEXITSTATUS(status) == 0);
    vless_config_t config; core_config_defaults(&config); config.transport_mode=TRANSPORT_XHTTP;
    config.xmux.present=1; config.xmux.max_concurrency=(core_range_t){1,3};
    char error[160]; pacing_clock=1000; pacing_random=0;
    CHECK("xmux/random-manager-failure",!core_xmux_connect(&config,&fixture_backend,error,sizeof(error)) && errno == EIO && !managers && !streams && !stream_count);
    int unlocked=pthread_mutex_trylock(&mux_lock);
    CHECK("xmux/random-failure-releases-pool-lock",!unlocked);
    if (!unlocked) pthread_mutex_unlock(&mux_lock);
    pacing_random=1;
    mux_manager_t *manager=get_manager(&config,&fixture_backend);
    REQUIRE("xmux/random-manager-recovers",manager && manager->concurrency == 2 && managers == manager);
    CHECK("xmux/random-group-recovers",choose_group(manager) != NULL);
    while (manager->groups) { mux_group_t *next=manager->groups->next; free(manager->groups); manager->groups=next; }
    managers=manager->next; free(manager); pacing_clock=0;
}

static void rejected_priority_headers_keep_hpack(void) {
    wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend}; manager.config.transport_mode=TRANSPORT_XHTTP;
    mux_actor_t actor={.manager=&manager,.physical=&wire,.http2=1,.latest_stream=3}; actor.validation.settings_received=1;
    core_http2_stream_t first={0},second={0};
    REQUIRE("xmux/priority-header-notifications",notification_pair(first.notify) == 0 && notification_pair(second.notify) == 0);
    mux_request_t a={.stream=&first,.id=1,.role=1},b={.stream=&second,.id=3,.role=1}; a.next=&b; actor.requests=&a;
    const uint8_t start[]={0,0,0,1,0,0x88,0x40},finish[]={1,'x',1,'v'},neighbor[]={0x88,0xbe};
    core_http2_frame_t frame={.type=1,.flags=32,.id=1,.data=(uint8_t *)start,.length=sizeof(start)};
    CHECK("xmux/priority-header-error-preserves-continuation",process_frame(&actor,&frame) == 0 && first.failed && !second.failed && wire.reset_code == 1 && actor.validation.continuation == 1);
    frame=(core_http2_frame_t){.type=9,.flags=4,.id=1,.data=(uint8_t *)finish,.length=sizeof(finish)};
    CHECK("xmux/rejected-priority-header-updates-hpack",process_frame(&actor,&frame) == 0 && actor.hpack.count == 1 && !actor.validation.continuation);
    frame=(core_http2_frame_t){.type=1,.flags=4,.id=3,.data=(uint8_t *)neighbor,.length=sizeof(neighbor)};
    CHECK("xmux/neighbor-uses-rejected-stream-dynamic-entry",process_frame(&actor,&frame) == 0 && b.response.headers && !second.failed && !actor.failed);
    core_http2_queue_clear(&actor.header_block); core_hpack_clear(&actor.hpack);
    close(first.notify[0]); close(first.notify[1]); close(second.notify[0]); close(second.notify[1]);
}

int main(void) {
    random_range_bound();
    rejected_priority_headers_keep_hpack();
    priority_stream_isolation();
    head_upload_response();
    private_close_completes_cleanup();
    memory_admission_policy();
    drained_queue_memory();
    worker_progress_policy();
    worker_timer_policy();
    receive_capacity_policy();
    flush_notification_policy();
    receive_credit_batching();
    asynchronous_relay_deadline();
    http2_wire_vectors();
    cancelled_stream_cleanup();
    paced_stream_isolation();
    zero_minimum_packet_interval();
    packet_batching_policy();
    empty_response_frames();
    mux_queue_t queue={0}; uint8_t bytes[4096]={0};
    for (size_t i=0;i<64;i++) REQUIRE("xmux/queue-fill", queue_append(&queue,bytes,sizeof(bytes),XMUX_STREAM_LIMIT) == 0);
    CHECK("xmux/queue-hard-limit", queue.length == XMUX_STREAM_LIMIT && queue_append(&queue,bytes,1,XMUX_STREAM_LIMIT) != 0);
    queue_consume(&queue,12345); CHECK("xmux/queue-reuse", queue_append(&queue,bytes,4096,XMUX_STREAM_LIMIT) == 0 && queue.length == XMUX_STREAM_LIMIT-12345+4096);
    core_http2_queue_clear(&queue);
    wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend,.config.xmux.present=1};
    mux_group_t group={.manager=&manager,.reuse_limit=4,.request_limit=8,.expires_ms=UINT64_MAX};
    mux_actor_t actor={.manager=&manager,.group=&group,.http2=1,.physical=&wire,.latest_stream=5,.send_window=65535,.receive_window=65535,.peer_window=65535,.peer_frame=16384};
    actor.validation.settings_received=1; actor.validation.settings_pending=1;
    core_xmux_stream_t stream={.references=1,.down_id=3,.up_id=3,.until_ms=UINT64_MAX}; REQUIRE("xmux/notifications", notification_pair(stream.notify) == 0);
    snprintf(stream.config.xhttp_mode,sizeof(stream.config.xhttp_mode),"stream-one");
    mux_request_t first={.stream=&stream,.id=3,.role=1,.response={.headers=1},.send_window=65535,.receive_window=65535};
    actor.requests=&first;
    core_xmux_frame_t data={.type=0,.id=3,.data=(uint8_t *)"vless-core",.length=10};
    CHECK("xmux/receive-data", process_frame(&actor,&data) == 0 && stream.rx.length == 10 && download_bytes == 10);
    CHECK("xmux/window-not-refunded-before-consumption", actor.receive_window == 65525 && first.receive_window == 65525 && wire.frames == 0);
    stream.download=&actor; stream.upload=&actor; stream.ready=1; streams=&stream;
    uint8_t output[32]; size_t length;
    CHECK("xmux/client-consumes-data", core_xmux_read(&stream,output,sizeof(output),&length) == 0 && length == 10 && !memcmp(output,"vless-core",10));
    CHECK("xmux/consumption-refunds-windows", advance_streams(&actor) == 0 && actor.receive_window == 65535 && first.receive_window == 65535 && wire.frames == 2);
    core_xmux_frame_t zero_window={.type=8,.id=3,.data=(uint8_t[]){0,0,0,0},.length=4};
    CHECK("xmux/zero-window-increment", process_frame(&actor,&zero_window) == 0 && stream.failed && first.reset && !actor.failed);
    stream.failed=first.reset=first.ended=0;
    first.send_window=INT_MAX;
    zero_window.data=(uint8_t[]){0,0,0,1}; CHECK("xmux/window-overflow", process_frame(&actor,&zero_window) == 0 && stream.failed && !actor.failed);
    stream.failed=first.reset=first.ended=0;
    first.send_window=65535;
    core_xmux_stream_t sibling={0}; REQUIRE("xmux/sibling-notifications", notification_pair(sibling.notify) == 0);
    mux_request_t second={.stream=&sibling,.id=5,.role=1,.response={.headers=1},.send_window=65535,.receive_window=65535}; first.next=&second;
    core_xmux_frame_t reset={.type=3,.id=3,.data=(uint8_t[]){0,0,0,8},.length=4};
    CHECK("xmux/reset-isolated", process_frame(&actor,&reset) == 0 && stream.failed && !sibling.failed && !actor.failed);
    core_connection_trace_t trace; core_connection_error_t failure;
    REQUIRE("xmux/failure-trace",core_trace_attach(&trace) == 0); core_trace_stage(CORE_TRACE_PROTOCOL); errno=ECONNREFUSED;
    CHECK("xmux/stream-failure-preserves-category-and-cause",core_xmux_read(&stream,output,sizeof(output),&length) < 0 && errno == EPROTO &&
        core_trace_error_get(&failure) && failure.kind == CORE_FAILURE_PROTOCOL && failure.stage == CORE_TRACE_TRANSPORT && failure.system_error == EPROTO && !sibling.failed);
    core_trace_detach();
    stream.failed=0; first.ended=first.reset=0;
    core_xmux_frame_t goaway={.type=7,.data=(uint8_t[]){0,0,0,3,0,0,0,0},.length=8};
    CHECK("xmux/goaway-drains-accepted-streams", process_frame(&actor,&goaway) == 0 && actor.draining && !stream.failed && sibling.failed);
    sibling.failed=0; second.ended=0; actor.draining=0; first.ended=0; first.response.headers=0;
    core_xmux_frame_t upgrade={.type=1,.flags=4,.id=3,.data=(uint8_t[]){0x48,3,'1','0','1'},.length=5};
    CHECK("xmux/http2-protocol-upgrade-rejected",process_frame(&actor,&upgrade) == 0 && stream.failed && !actor.failed);
    stream.failed=first.ended=first.reset=0; first.response=(core_http2_response_t){0};
    core_hpack_clear(&actor.hpack);
    core_xmux_frame_t initial={.type=1,.flags=4,.id=3,.data=(uint8_t[]){0x48,3,'2','0','0'},.length=5};
    CHECK("xmux/stateful-initial-headers", process_frame(&actor,&initial) == 0 && first.response.headers && actor.hpack.count == 1);
    second.response.headers=0;
    initial.id=5; initial.data=(uint8_t[]){0xbe}; initial.length=1;
    CHECK("xmux/dynamic-index-other-stream", process_frame(&actor,&initial) == 0 && second.response.headers);
    initial.id=3; initial.flags=4|1; initial.data=(uint8_t[]){0,1,'x',1,'v'}; initial.length=5;
    CHECK("xmux/trailers-complete-stream", process_frame(&actor,&initial) == 0 && first.ended && stream.eof);
    stream.failed=0; stream.eof=0;
    upload_bytes=XMUX_TOTAL_LIMIT-XMUX_TX_RESERVE;
    CHECK("xmux/aggregate-backpressure", core_xmux_write_capacity(&stream) == 0);
    upload_bytes=0; wire.pending=0; actor.net_accounted=0;
    CHECK("xmux/per-stream-backpressure-capacity", core_xmux_write_capacity(&stream) == XMUX_STREAM_LIMIT);
    CHECK("xmux/reservation-is-atomic", core_xmux_reserve_write(&stream,128U*1024U) == 1 && upload_bytes == 128U*1024U && core_xmux_reserve_write(&stream,1) == 0);
    CHECK("xmux/reserved-room-not-double-counted", core_xmux_write(&stream,(uint8_t *)"vless-core",10) == 0 && upload_bytes == 128U*1024U && stream.reserved_upload == 128U*1024U-10);
    core_xmux_release_write(&stream);
    CHECK("xmux/unused-reservation-released", upload_bytes == 10 && !stream.reserved_upload);
    signal_stream(&stream); core_xmux_drain_notifications(&stream);
    CHECK("xmux/write-notification-is-not-input", !core_xmux_pending(&stream) && !stream.notified && core_wait_socket(stream.notify[0],POLLIN,0) == 0);
    actor.alive_period=1; actor.last_input_ms=1000; wire.frames=0;
    CHECK("xmux/keepalive-waits-until-idle-period", maintain_ping(&actor,1999) == 0 && !wire.frames);
    CHECK("xmux/keepalive-sends-ping", maintain_ping(&actor,2000) == 0 && wire.last_type == 6 && actor.ping_deadline_ms == 17000);
    CHECK("xmux/keepalive-not-repeated-before-pong", maintain_ping(&actor,3000) == 0 && wire.frames == 1);
    core_xmux_frame_t pong={.type=6,.flags=1,.data=actor.ping,.length=8};
    CHECK("xmux/keepalive-pong-clears-deadline", process_frame(&actor,&pong) == 0 && !actor.ping_deadline_ms);
    actor.last_input_ms=3000;
    CHECK("xmux/keepalive-next-idle-period", maintain_ping(&actor,3999) == 0 && wire.frames == 1 && maintain_ping(&actor,4000) == 0 && wire.frames == 2);
    CHECK("xmux/keepalive-missing-pong-fails", maintain_ping(&actor,19000) != 0);
    actor.ping_deadline_ms=0; actor.alive_period=0;
    CHECK("xmux/keepalive-disabled", maintain_ping(&actor,UINT64_MAX) == 0 && wire.frames == 2);
    upload_bytes-=stream.tx.length; queue_consume(&stream.tx,stream.tx.length);
    core_xmux_drain_notifications(&stream);
    core_deadline_t deadline; REQUIRE("xmux/completed-write-deadline", core_deadline_attach(&deadline) == 0);
    core_deadline_begin(5);
    CHECK("xmux/other-stream-output-does-not-block-completed-write", core_xmux_write(&stream,NULL,0) == 0);
    stream.write_fence=100; actor.flushed=99; core_deadline_begin(5);
    CHECK("xmux/own-unflushed-output-still-waits", core_xmux_write(&stream,NULL,0) != 0 && errno == ETIMEDOUT);
    actor.flushed=100; core_deadline_begin(5);
    CHECK("xmux/own-fence-completes-with-other-output-pending", core_xmux_write(&stream,NULL,0) == 0);
    core_deadline_end(); core_deadline_detach();
    core_hpack_clear(&actor.hpack); core_http2_queue_clear(&stream.rx); core_http2_queue_clear(&stream.tx); core_http2_queue_clear(&actor.header_block);
    close(stream.notify[0]); close(stream.notify[1]); close(sibling.notify[0]); close(sibling.notify[1]);
    streams=NULL; upload_bytes=download_bytes=0;
    mux_actor_t busy={.manager=&manager,.group=&group,.http2=0,.draining=1},idle={.manager=&manager,.group=&group,.http2=0,.peer_concurrency=1},downloading={0};
    busy.next=&idle; manager.actors=&busy;
    core_xmux_stream_t waiting={.download=&downloading,.upload=&busy,.sequence=7,.ready=1},sent={.download=&downloading,.upload=&busy,.sequence=8,.ready=1};
    REQUIRE("xmux/cancellation-pending-payload", queue_append(&waiting.tx,(const uint8_t *)"vless-core",10,XMUX_STREAM_LIMIT) == 0);
    waiting.next=&sent; streams=&waiting;
    mux_request_t transmitting={.stream=&sent,.role=3,.id=3}; busy.requests=&transmitting;
    CHECK("xmux/cancellation-moves-only-unstarted-requests", move_waiting_streams(&busy) == 0 && waiting.upload == &idle && sent.upload == &busy);
    CHECK("xmux/cancellation-keeps-payload-and-sequence", waiting.sequence == 7 && waiting.tx.length == 10 && !memcmp(waiting.tx.data,"vless-core",10));
    core_http2_queue_clear(&waiting.tx); streams=NULL;
    mux_actor_t reused={.manager=&manager,.group=&group,.http2=1,.peer_concurrency=UINT32_MAX}; manager.actors=&reused; manager.groups=&group; manager.connections=1;
    CHECK("xmux/select-reusable-physical-client", choose_actor(&manager,100,NULL) == &reused);
    CHECK("xmux/sample-single-value", random_range((core_range_t){7,7}) == 7);
    for (int i=0;i<100;i++) { int random=random_range((core_range_t){1,3}); CHECK("xmux/sample-within-range", random >= 1 && random <= 3); }
    vless_config_t config={0}; char error[160]; session_failure=1;
    CHECK("xmux/session-failure-reported", !core_xmux_connect(&config,&fixture_backend,error,sizeof(error)) && strstr(error,"session generation"));
    session_failure=0; stream_count=256;
    CHECK("xmux/client-limit-reported", !core_xmux_connect(&config,&fixture_backend,error,sizeof(error)) && errno == EAGAIN && strstr(error,"channel allocation"));
    stream_count=0;
    grpc_pool_policy();
    directional_finish();
    return test_result();
}
