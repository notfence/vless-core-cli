#define _POSIX_C_SOURCE 200809L
#include "../src/http2_pool.c"

typedef struct { size_t pending; uint64_t enqueued,flushed; uint32_t request_id; unsigned reset_streams; } fuzz_wire_t;
static int fuzz_send(void *opaque, uint8_t type, uint8_t flags, uint32_t id, const uint8_t *data, size_t length) {
    (void)type; (void)flags; (void)id; (void)data;
    fuzz_wire_t *wire=opaque;
    if (type == 0 && id < 8 && (wire->reset_streams&(1U<<id))) abort();
    wire->pending+=length+9; wire->enqueued+=length+9; return 0;
}
static size_t fuzz_pending(void *opaque) { return ((fuzz_wire_t *)opaque)->pending; }
static uint64_t fuzz_enqueued(void *opaque) { return ((fuzz_wire_t *)opaque)->enqueued; }
static uint64_t fuzz_flushed(void *opaque) { return ((fuzz_wire_t *)opaque)->flushed; }
static int fuzz_request(void *opaque,const vless_config_t *config,const char *session,uint64_t sequence,int role,const uint8_t *data,size_t length,uint32_t *id,uint32_t limit,size_t *consumed,size_t *body) {
    (void)config; (void)session; (void)sequence; (void)data; (void)limit;
    fuzz_wire_t *wire=opaque; *id=wire->request_id+=2; *consumed=length; *body=role == 4 ? SIZE_MAX : length; return 0;
}
static const core_http2_backend_t fuzz_backend={.send_frame=fuzz_send,.pending=fuzz_pending,.enqueued=fuzz_enqueued,.flushed=fuzz_flushed,.request=fuzz_request};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length) {
    if (length > 65536) return 0;
    int packet=length&1;
    fuzz_wire_t wire={.request_id=3}; mux_manager_t manager={.backend=&fuzz_backend};
    manager.config.transport_mode=packet ? TRANSPORT_XHTTP : TRANSPORT_GRPC; manager.config.grpc_initial_window=1024;
    mux_group_t group={.manager=&manager,.request_limit=INT_MAX,.expires_ms=UINT64_MAX};
    mux_actor_t actor={.manager=&manager,.group=&group,.physical=&wire,.http2=1,.peer_frame=16384,
        .latest_stream=3,.send_window=65535,.receive_window=65535,.peer_window=1024,.peer_concurrency=100};
    core_http2_stream_t first={.download=&actor,.upload=&actor,.down_id=1,.up_id=1,.ready=1,.references=65536};
    core_http2_stream_t second={.download=&actor,.upload=&actor,.down_id=3,.up_id=3,.ready=1,.references=65536};
    first.next=&second; streams=&first;
    if (packet) {
        first.config.transport_mode=second.config.transport_mode=TRANSPORT_XHTTP;
        strcpy(first.config.xhttp_mode,"packet-up"); strcpy(second.config.xhttp_mode,"packet-up");
        first.packet_limit=second.packet_limit=1000000;
    }
    manager.groups=&group; manager.actors=&actor; actor_count=512;
    if (core_http2_start_relay(&first) || core_http2_start_relay(&second)) abort();
    mux_request_t *a=calloc(1,sizeof(*a)),*b=calloc(1,sizeof(*b));
    if (!a || !b || notification_pair(first.notify) || notification_pair(second.notify) || notification_pair(actor.wake)) abort();
    *a=(mux_request_t){.next=b,.stream=&first,.id=1,.role=packet ? 4 : 1,.send_window=1024,.receive_window=1024,.remaining=1000000,.packet_until_ms=core_now_ms()+100};
    *b=(mux_request_t){.stream=&second,.id=3,.role=packet ? 4 : 1,.send_window=1024,.receive_window=1024,.remaining=1000000,.packet_until_ms=core_now_ms()+100}; actor.requests=a;
    for (size_t offset=0;length-offset >= 9;) {
        const uint8_t *header=data+offset;
        size_t size=((size_t)header[0]<<16)|((size_t)header[1]<<8)|header[2]; offset+=9;
        if (size > length-offset) break;
        core_http2_frame_t frame={.type=header[3],.flags=header[4],
            .id=(((uint32_t)header[5]<<24)|((uint32_t)header[6]<<16)|((uint32_t)header[7]<<8)|header[8])&0x7fffffffU,
            .length=size,.data=(uint8_t *)data+offset};
        int result=process_frame(&actor,&frame); offset+=size;
        if (result < 0) break;
        if (frame.type == 3 && frame.id < 8) wire.reset_streams|=1U<<frame.id;
        core_http2_stream_t *stream=frame.id&2 ? &second : &first;
        uint8_t output[31]; size_t received=0;
        if (frame.flags&2) (void)core_http2_read(stream,output,sizeof(output),&received);
        if (frame.flags&8) (void)core_http2_finish_write(stream);
        if (frame.flags&16) {
            size_t capacity=core_http2_write_capacity(stream),take=size < capacity ? size : capacity;
            if (take) (void)core_http2_write(stream,frame.data,take);
        }
        if (frame.flags&32) {
            const uint8_t prefix[]={0,0,0,0,2,10,0};
            size_t capacity=core_http2_write_capacity(stream),take=capacity > sizeof(prefix) ? capacity-sizeof(prefix) : 0;
            if (take > size) take=size;
            if (take) (void)core_http2_write_parts(stream,prefix,sizeof(prefix),frame.data,take);
        }
        if (packet && (frame.flags&64)) for (mux_request_t *request=actor.requests;request;request=request->next) request->packet_until_ms=core_now_ms();
        if (advance_streams(&actor)) break;
        wire.pending=0; wire.flushed=wire.enqueued; account_output(&actor);
        (void)core_http2_finish_pending(stream);
    }
    while (actor.requests) { mux_request_t *next=actor.requests->next; free(actor.requests); actor.requests=next; }
    core_http2_queue_clear(&first.rx); core_http2_queue_clear(&first.tx); core_http2_queue_clear(&second.rx); core_http2_queue_clear(&second.tx);
    core_http2_queue_clear(&actor.header_block); core_hpack_clear(&actor.hpack);
    close(first.notify[0]); close(first.notify[1]); close(second.notify[0]); close(second.notify[1]); close(actor.wake[0]); close(actor.wake[1]);
    streams=NULL; upload_bytes=download_bytes=actor_count=0;
    return 0;
}
