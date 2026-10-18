#include "buffer_budget.h"
#include "http2_pool.h"
#include "http2_queue.h"
#include "hpack.h"
#include "xhttp_payload.h"
#include "check.h"
#include "socket_util.h"
#include "deadline.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static int fail_allocation;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    if (fail_allocation && !--fail_allocation) { errno=ENOMEM; return NULL; }
    return __real_malloc(size);
}

static void queue_parts_policy(void) {
    uint8_t prefix[16385],data[65536],output[3+sizeof(prefix)+sizeof(data)];
    memset(prefix,'p',sizeof(prefix)); for (size_t i=0;i<sizeof(data);i++) data[i]=(uint8_t)(i%251);
    size_t prefixes[]={0,1,7,11,16383,16384,16385},lengths[]={0,1,127,128,16383,16384,65536};
    for (unsigned direction=0;direction<2;direction++) for (unsigned blocked=0;blocked<2;blocked++)
        for (size_t i=0;i<sizeof(prefixes)/sizeof(*prefixes);i++) for (size_t j=0;j<sizeof(lengths)/sizeof(*lengths);j++) {
            core_http2_queue_t queue={.memory.direction=direction}; size_t limit=blocked ? CORE_HTTP2_STREAM_LIMIT : 1024U*1024U;
            REQUIRE("buffers/parts-existing-data",core_http2_queue_append(&queue,(const uint8_t *)"saved",5,limit) == 0);
            core_http2_queue_consume(&queue,2);
            REQUIRE("buffers/parts-appended",core_http2_queue_append_parts(&queue,prefix,prefixes[i],data,lengths[j],limit) == 0);
            core_http2_queue_copy(&queue,output,queue.length);
            CHECK("buffers/parts-order-and-boundaries",queue.length == 3+prefixes[i]+lengths[j] && !memcmp(output,"ved",3) &&
                !memcmp(output+3,prefix,prefixes[i]) && !memcmp(output+3+prefixes[i],data,lengths[j]));
            core_http2_queue_clear(&queue);
        }
    core_http2_queue_cache_clear();
    core_http2_queue_t queue={0};
    REQUIRE("buffers/parts-failure-existing",core_http2_queue_append(&queue,(const uint8_t *)"saved",5,CORE_HTTP2_STREAM_LIMIT) == 0);
    size_t allocated=queue.memory.allocated;
    fail_allocation=2;
    CHECK("buffers/parts-allocation-failure-atomic",core_http2_queue_append_parts(&queue,prefix,11,data,49152,CORE_HTTP2_STREAM_LIMIT) < 0 && errno == ENOMEM && queue.length == 5 && queue.memory.allocated == allocated);
    fail_allocation=0; core_http2_queue_copy(&queue,output,5);
    CHECK("buffers/parts-failure-keeps-bytes",!memcmp(output,"saved",5));
    core_http2_queue_cache_clear();
    core_buffer_budget_t other={0};
    REQUIRE("buffers/parts-saturated-budget",core_buffer_budget_init(&other,CORE_BUFFER_UPLOAD,CORE_BUFFER_TOTAL_LIMIT-queue.memory.charged) == 0);
    CHECK("buffers/parts-budget-failure-atomic",core_http2_queue_append_parts(&queue,prefix,11,data,49152,CORE_HTTP2_STREAM_LIMIT) < 0 && errno == ENOBUFS && queue.length == 5);
    REQUIRE("buffers/parts-budget-released",core_buffer_budget_clear(&other) == 0);
    REQUIRE("buffers/parts-recovers",core_http2_queue_append_parts(&queue,prefix,11,data,49152,CORE_HTTP2_STREAM_LIMIT) == 0);
    core_http2_queue_copy(&queue,output,queue.length);
    CHECK("buffers/parts-recovered-content",queue.length == 5+11+49152 && !memcmp(output,"saved",5) && !memcmp(output+5,prefix,11) && !memcmp(output+16,data,49152));
    size_t previous=queue.length;
    CHECK("buffers/parts-overflow-before-mutation",core_http2_queue_append_parts(&queue,prefix,SIZE_MAX,data,1,CORE_HTTP2_STREAM_LIMIT) < 0 && errno == EOVERFLOW && queue.length == previous);
    CHECK("buffers/parts-null-before-mutation",core_http2_queue_append_parts(&queue,NULL,1,data,1,CORE_HTTP2_STREAM_LIMIT) < 0 && errno == EINVAL && queue.length == previous);
    core_http2_queue_clear(&queue); core_http2_queue_cache_clear(); size_t bytes,reserved;
    core_buffer_snapshot(CORE_BUFFER_UPLOAD,&bytes,&reserved);
    CHECK("buffers/parts-all-memory-released",!bytes && !reserved);
}

static void *watcher_release(void *unused) {
    (void)unused; core_buffer_budget_t memory={0};
    for (unsigned i=0;i<1000;i++) {
        if (core_buffer_budget_init(&memory,CORE_BUFFER_UPLOAD,1) || core_buffer_budget_clear(&memory)) return (void *)1;
    }
    return NULL;
}

static void notification_policy(void) {
    core_buffer_waiter_t first={0},second={0}; int channels[2][2];
    for (unsigned i=0;i<2;i++) {
        REQUIRE("buffers/wake-pair",!socketpair(AF_UNIX,SOCK_STREAM,0,channels[i]));
        for (unsigned j=0;j<2;j++) REQUIRE("buffers/wake-nonblocking",!fcntl(channels[i][j],F_SETFL,O_NONBLOCK));
    }
    core_buffer_watch(&first,channels[0][1],1U<<CORE_BUFFER_UPLOAD);
    core_buffer_watch(&second,channels[1][1],1U<<CORE_BUFFER_DOWNLOAD);
    core_buffer_budget_t memory={0};
    REQUIRE("buffers/wake-reserve",!core_buffer_budget_init(&memory,CORE_BUFFER_UPLOAD,32));
    core_deadline_t deadline; REQUIRE("buffers/wake-deadline",!core_deadline_attach(&deadline)); core_deadline_begin(1);
    struct pollfd idle={.fd=-1}; (void)core_poll(&idle,1,4);
    REQUIRE("buffers/wake-release-after-expiry",!core_buffer_budget_clear(&memory));
    uint8_t byte;
    CHECK("buffers/wake-ignores-releasing-deadline",recv(channels[0][0],&byte,1,0) == 1);
    CHECK("buffers/wake-direction-isolated",recv(channels[1][0],&byte,1,0) < 0 && errno == EAGAIN);
    core_deadline_end(); core_deadline_detach();
    uint8_t fill[4096]={0}; while (send(channels[0][1],fill,sizeof(fill),0) > 0) {}
    REQUIRE("buffers/full-wake-reserve",!core_buffer_budget_init(&memory,CORE_BUFFER_UPLOAD,32));
    REQUIRE("buffers/full-wake-release",!core_buffer_budget_clear(&memory));
    core_drain_socket(channels[0][0]);
    REQUIRE("buffers/full-wake-recovery-reserve",!core_buffer_budget_init(&memory,CORE_BUFFER_UPLOAD,32));
    REQUIRE("buffers/full-wake-recovery-release",!core_buffer_budget_clear(&memory));
    CHECK("buffers/full-wake-recovers",recv(channels[0][0],&byte,1,0) == 1);
    core_buffer_unwatch(&first); core_buffer_watch(&first,channels[0][1],1U<<CORE_BUFFER_DOWNLOAD);
    REQUIRE("buffers/multiple-wake-reserve",!core_buffer_budget_init(&memory,CORE_BUFFER_DOWNLOAD,32));
    REQUIRE("buffers/multiple-wake-release",!core_buffer_budget_clear(&memory));
    CHECK("buffers/all-relevant-waiters-woken",recv(channels[0][0],&byte,1,0) == 1 && recv(channels[1][0],&byte,1,0) == 1);
    core_buffer_unwatch(&first); core_buffer_unwatch(&second);
    for (unsigned i=0;i<2;i++) for (unsigned j=0;j<2;j++) close(channels[i][j]);
    pthread_t releasing; REQUIRE("buffers/wake-close-worker",!pthread_create(&releasing,NULL,watcher_release,NULL));
    for (unsigned i=0;i<100;i++) {
        int pair[2]; REQUIRE("buffers/wake-close-pair",!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
        REQUIRE("buffers/wake-close-nonblocking",!fcntl(pair[1],F_SETFL,O_NONBLOCK));
        core_buffer_watch(&first,pair[1],1U<<CORE_BUFFER_UPLOAD); core_buffer_unwatch(&first); close(pair[0]); close(pair[1]);
    }
    void *result=NULL; pthread_join(releasing,&result);
    CHECK("buffers/wake-close-no-stale-registration",!result && !first.registered && !second.registered);
    size_t used,reserved; core_buffer_snapshot(CORE_BUFFER_UPLOAD,&used,&reserved);
    CHECK("buffers/wake-close-budget-drained",!used && !reserved);
}

int main(void) {
    queue_parts_policy();
    notification_policy();
    core_buffer_budget_t account={0},other={0}; size_t bytes,reserved;
    REQUIRE("buffers/reserve-without-allocation",core_buffer_budget_init(&account,CORE_BUFFER_DOWNLOAD,CORE_BUFFER_TOTAL_LIMIT) == 0);
    core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("buffers/reservation-is-not-preallocation",!bytes && reserved == CORE_BUFFER_TOTAL_LIMIT);
    CHECK("buffers/reservation-cannot-overcommit",core_buffer_budget_init(&other,CORE_BUFFER_DOWNLOAD,1) != 0 && errno == ENOBUFS);
    uint8_t *data=core_buffer_alloc(&account,16384); REQUIRE("buffers/allocate-from-reservation",data);
    memset(data,0x6a,16384); core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("buffers/allocation-consumes-reservation",bytes == 16384 && bytes+reserved == CORE_BUFFER_TOTAL_LIMIT);
    uint8_t *replacement=core_buffer_realloc(&account,data,16384,32768); REQUIRE("buffers/reallocation",replacement);
    CHECK("buffers/reallocation-preserves-data",replacement[0] == 0x6a && replacement[16383] == 0x6a);
    core_buffer_free(&account,replacement,32768); REQUIRE("buffers/reservation-release",core_buffer_budget_clear(&account) == 0);
    data=core_buffer_alloc(&account,CORE_BUFFER_TOTAL_LIMIT); REQUIRE("buffers/maximum-allocation",data);
    data[0]=0x35;
    CHECK("buffers/reallocation-peak-is-counted",core_buffer_realloc(&account,data,CORE_BUFFER_TOTAL_LIMIT,16384) == NULL && errno == ENOBUFS && data[0] == 0x35);
    core_buffer_free(&account,data,CORE_BUFFER_TOTAL_LIMIT);
    core_http2_queue_t queues[64]={0}; uint8_t block[16384];
    for (size_t i=0;i<sizeof(block);i++) block[i]=(uint8_t)i;
    size_t count=0;
    for (;count<64;count++) {
        if (core_http2_queue_append(queues+count,block,sizeof(block),CORE_HTTP2_STREAM_LIMIT)) break;
        for (size_t i=1;i<16;i++) {
            if (core_http2_queue_append(queues+count,block,sizeof(block),CORE_HTTP2_STREAM_LIMIT)) goto exhausted;
        }
    }
exhausted:
    core_buffer_snapshot(CORE_BUFFER_UPLOAD,&bytes,&reserved);
    CHECK("buffers/actual-capacity-is-limited",count >= 32 && count < 64 && bytes+reserved <= CORE_BUFFER_TOTAL_LIMIT);
    for (size_t i=0;i<64;i++) core_http2_queue_clear(queues+i);
    core_buffer_snapshot(CORE_BUFFER_UPLOAD,&bytes,&reserved);
    CHECK("buffers/drained-cache-is-bounded",bytes <= CORE_HTTP2_QUEUE_CACHE && !reserved);
    core_http2_queue_cache_clear(); core_buffer_snapshot(CORE_BUFFER_UPLOAD,&bytes,&reserved);
    CHECK("buffers/cache-release-recovers-budget",!bytes && !reserved);
    core_http2_queue_t queue={0};
    REQUIRE("buffers/receive-credit-reservation",core_buffer_budget_init(&queue.memory,CORE_BUFFER_DOWNLOAD,core_http2_queue_reservation(CORE_HTTP2_STREAM_LIMIT)) == 0);
    REQUIRE("buffers/first-block",core_http2_queue_append(&queue,block,sizeof(block),CORE_HTTP2_STREAM_LIMIT) == 0);
    core_http2_queue_consume(&queue,15300);
    REQUIRE("buffers/second-block",core_http2_queue_append(&queue,block,sizeof(block),CORE_HTTP2_STREAM_LIMIT) == 0);
    uint8_t output[17468]; core_http2_queue_copy(&queue,output,sizeof(output));
    CHECK("buffers/partial-blocks-preserve-order",!memcmp(output,block+15300,1084) && !memcmp(output+1084,block,sizeof(block)));
    core_http2_queue_consume(&queue,queue.length); core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("buffers/receive-credit-survives-consumption",bytes+reserved >= core_http2_queue_reservation(CORE_HTTP2_STREAM_LIMIT));
    core_http2_queue_clear(&queue); core_http2_queue_cache_clear(); core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("buffers/receive-close-releases-credit",!bytes && !reserved);
    core_hpack_decoder_t decoder={.memory=&account}; core_hpack_headers_t headers;
    const uint8_t header[]={0x88,0x40,1,'x',1,'v'};
    REQUIRE("buffers/hpack-accounted-decode",core_hpack_decode(&decoder,header,sizeof(header),&headers) == 0);
    CHECK("buffers/hpack-retained-allocation",account.allocated == 4);
    core_hpack_clear(&decoder);
    CHECK("buffers/hpack-clear-releases-capacity",!account.allocated);
    core_xhttp_payload_options_t options={.placement="header",.key="X-Data",.chunks={64,64},.memory=&account};
    core_xhttp_payload_t packet={0}; char error[160];
    REQUIRE("buffers/xhttp-header-accounted",core_xhttp_payload_build(&options,block,sizeof(block),"",65536,&packet,error,sizeof(error)) == 0);
    CHECK("buffers/xhttp-temporary-encoding-freed",account.allocated == packet.header_capacity && packet.header_capacity == 65537);
    core_xhttp_payload_clear(&packet);
    REQUIRE("buffers/xhttp-result-released",!account.allocated && core_buffer_budget_clear(&account) == 0);
    REQUIRE("buffers/xhttp-limited-account",core_buffer_budget_init(&other,CORE_BUFFER_DOWNLOAD,CORE_BUFFER_TOTAL_LIMIT-8192) == 0);
    CHECK("buffers/xhttp-allocation-failure",core_xhttp_payload_build(&options,block,sizeof(block),"",65536,&packet,error,sizeof(error)) != 0 && !account.allocated);
    REQUIRE("buffers/xhttp-error-releases-capacity",core_buffer_budget_clear(&other) == 0);
    REQUIRE("buffers/control-reserve",core_buffer_budget_init(&account,CORE_BUFFER_DOWNLOAD,CORE_BUFFER_PROTOCOL_RESERVE) == 0);
    REQUIRE("buffers/saturated-queue-reserves",core_buffer_budget_init(&other,CORE_BUFFER_DOWNLOAD,CORE_BUFFER_TOTAL_LIMIT-CORE_BUFFER_PROTOCOL_RESERVE) == 0);
    core_http2_queue_t control={.account=&account};
    REQUIRE("buffers/control-header-progress",core_http2_queue_append(&control,header,sizeof(header),1024U*1024U) == 0);
    core_hpack_decoder_t control_decoder={.memory=&account};
    CHECK("buffers/control-decode-progress",core_hpack_decode(&control_decoder,control.data,control.length,&headers) == 0);
    core_hpack_clear(&control_decoder); core_http2_queue_clear(&control);
    REQUIRE("buffers/control-cleanup-retains-service-reserve",!account.allocated && account.minimum == CORE_BUFFER_PROTOCOL_RESERVE);
    REQUIRE("buffers/saturated-reserves-released",core_buffer_budget_clear(&account) == 0 && core_buffer_budget_clear(&other) == 0);
    return test_result();
}
