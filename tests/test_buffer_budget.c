#include "buffer_budget.h"
#include "http2_pool.h"
#include "http2_queue.h"
#include "hpack.h"
#include "xhttp_payload.h"
#include "check.h"
#include <errno.h>
#include <string.h>

int main(void) {
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
