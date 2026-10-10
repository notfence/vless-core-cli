#include "../src/xmux.c"
#include "check.h"

typedef struct { size_t pending; int frames, last_type; uint32_t last_id; } wire_t;
static int session_failure;
static int fixture_session(const vless_config_t *config, char *session, size_t capacity) {
    (void)config;
    if (session_failure) { errno=EIO; return -1; }
    return snprintf(session,capacity,"vless-core") >= (int)capacity ? -1 : 0;
}
static size_t fixture_pending(void *opaque) { return ((wire_t *)opaque)->pending; }
static int fixture_send(void *opaque, uint8_t type, uint8_t flags, uint32_t id, const uint8_t *data, size_t length) {
    (void)flags; (void)data;
    wire_t *wire=opaque; wire->pending+=length+9; wire->frames++; wire->last_type=type; wire->last_id=id; return 0;
}
static const core_xmux_backend_t fixture_backend={.send_frame=fixture_send,.pending=fixture_pending,.session=fixture_session};

static void cancelled_stream_cleanup(void) {
    wire_t wire={.pending=23}; mux_manager_t manager={.backend=&fixture_backend,.config.xmux.present=1};
    mux_group_t group={.manager=&manager,.running=1};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.send_window=0,.net_accounted=23};
    core_xmux_stream_t *stream=calloc(1,sizeof(*stream)); mux_request_t *request=calloc(1,sizeof(*request));
    REQUIRE("xmux/cancelled-stream-allocation",stream && request);
    REQUIRE("xmux/cancelled-stream-notifications",notification_pair(stream->notify) == 0 && notification_pair(actor.wake) == 0);
    stream->download=stream->upload=&actor; stream->references=2; stream->ready=1; stream->down_id=stream->up_id=3;
    strcpy(stream->config.xhttp_mode,"packet-up");
    request->stream=stream; request->role=3; request->id=3; request->remaining=10; request->headers=1;
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

int main(void) {
    cancelled_stream_cleanup();
    mux_queue_t queue={0}; uint8_t bytes[4096]={0};
    for (size_t i=0;i<64;i++) REQUIRE("xmux/queue-fill", queue_append(&queue,bytes,sizeof(bytes),XMUX_STREAM_LIMIT) == 0);
    CHECK("xmux/queue-hard-limit", queue.length == XMUX_STREAM_LIMIT && queue_append(&queue,bytes,1,XMUX_STREAM_LIMIT) != 0);
    queue_consume(&queue,12345); CHECK("xmux/queue-reuse", queue_append(&queue,bytes,4096,XMUX_STREAM_LIMIT) == 0 && queue.length == XMUX_STREAM_LIMIT-12345+4096);
    free(queue.data);
    wire_t wire={0}; mux_manager_t manager={.backend=&fixture_backend};
    mux_group_t group={.manager=&manager,.reuse_limit=4,.request_limit=8,.expires_ms=UINT64_MAX};
    mux_actor_t actor={.manager=&manager,.group=&group,.http2=1,.physical=&wire,.latest_stream=5,.send_window=65535,.receive_window=65535,.peer_window=65535,.peer_frame=16384};
    core_xmux_stream_t stream={.references=1,.down_id=3,.up_id=3,.until_ms=UINT64_MAX}; REQUIRE("xmux/notifications", notification_pair(stream.notify) == 0);
    snprintf(stream.config.xhttp_mode,sizeof(stream.config.xhttp_mode),"stream-one");
    mux_request_t first={.stream=&stream,.id=3,.role=1,.headers=1,.send_window=65535,.receive_window=65535};
    actor.requests=&first;
    core_xmux_frame_t data={.type=0,.id=3,.data=(uint8_t *)"vless-core",.length=10};
    CHECK("xmux/receive-data", process_frame(&actor,&data) == 0 && stream.rx.length == 10 && download_bytes == 10);
    CHECK("xmux/window-not-refunded-before-consumption", actor.receive_window == 65525 && first.receive_window == 65525 && wire.frames == 0);
    stream.download=&actor; stream.upload=&actor; stream.ready=1; streams=&stream;
    uint8_t output[32]; size_t length;
    CHECK("xmux/client-consumes-data", core_xmux_read(&stream,output,sizeof(output),&length) == 0 && length == 10 && !memcmp(output,"vless-core",10));
    CHECK("xmux/consumption-refunds-windows", advance_streams(&actor) == 0 && actor.receive_window == 65535 && first.receive_window == 65535 && wire.frames == 2);
    core_xmux_frame_t zero_window={.type=8,.id=3,.data=(uint8_t[]){0,0,0,0},.length=4};
    CHECK("xmux/zero-window-increment", process_frame(&actor,&zero_window) != 0);
    first.send_window=INT_MAX;
    zero_window.data=(uint8_t[]){0,0,0,1}; CHECK("xmux/window-overflow", process_frame(&actor,&zero_window) != 0);
    first.send_window=65535;
    core_xmux_stream_t sibling={0}; REQUIRE("xmux/sibling-notifications", notification_pair(sibling.notify) == 0);
    mux_request_t second={.stream=&sibling,.id=5,.role=1,.headers=1,.send_window=65535,.receive_window=65535}; first.next=&second;
    core_xmux_frame_t reset={.type=3,.id=3,.data=(uint8_t[]){0,0,0,8},.length=4};
    CHECK("xmux/reset-isolated", process_frame(&actor,&reset) == 0 && stream.failed && !sibling.failed && !actor.failed);
    stream.failed=0; first.ended=0;
    core_xmux_frame_t goaway={.type=7,.data=(uint8_t[]){0,0,0,3,0,0,0,0},.length=8};
    CHECK("xmux/goaway-drains-accepted-streams", process_frame(&actor,&goaway) == 0 && actor.draining && !stream.failed && sibling.failed);
    sibling.failed=0; second.ended=0; actor.draining=0; first.ended=0; first.headers=0;
    core_xmux_frame_t upgrade={.type=1,.flags=4,.id=3,.data=(uint8_t[]){0x48,3,'1','0','1'},.length=5};
    CHECK("xmux/http2-protocol-upgrade-rejected",process_frame(&actor,&upgrade) != 0);
    core_hpack_clear(&actor.hpack);
    core_xmux_frame_t initial={.type=1,.flags=4,.id=3,.data=(uint8_t[]){0x48,3,'2','0','0'},.length=5};
    CHECK("xmux/stateful-initial-headers", process_frame(&actor,&initial) == 0 && first.headers && actor.hpack.count == 1);
    second.headers=0;
    initial.id=5; initial.data=(uint8_t[]){0xbe}; initial.length=1;
    CHECK("xmux/dynamic-index-other-stream", process_frame(&actor,&initial) == 0 && second.headers);
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
    core_hpack_clear(&actor.hpack); free(stream.rx.data); free(stream.tx.data); free(actor.header_block.data);
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
    free(waiting.tx.data); streams=NULL;
    mux_actor_t reused={.manager=&manager,.group=&group,.http2=1,.peer_concurrency=UINT32_MAX}; manager.actors=&reused; manager.groups=&group; manager.connections=1;
    CHECK("xmux/select-reusable-physical-client", choose_actor(&manager,100,NULL) == &reused);
    CHECK("xmux/sample-single-value", random_range((core_range_t){7,7}) == 7);
    for (int i=0;i<100;i++) { int random=random_range((core_range_t){1,3}); CHECK("xmux/sample-within-range", random >= 1 && random <= 3); }
    vless_config_t config={0}; char error[160]; session_failure=1;
    CHECK("xmux/session-failure-reported", !core_xmux_connect(&config,&fixture_backend,error,sizeof(error)) && strstr(error,"session generation"));
    session_failure=0; stream_count=256;
    CHECK("xmux/client-limit-reported", !core_xmux_connect(&config,&fixture_backend,error,sizeof(error)) && errno == EAGAIN && strstr(error,"channel allocation"));
    stream_count=0;
    return test_result();
}
