#include "relay_memory.h"
#include "check.h"
#include <errno.h>

static void *watched;
static size_t watched_size,cleared_frees;
static int allocation_failure;
void __real_free(void *);
void *__real_realloc(void *,size_t);
void __wrap_free(void *pointer) {
    if (pointer && pointer == watched) {
        const uint8_t *bytes=pointer; int zero=1;
        for (size_t i=0;i<watched_size;i++) if (bytes[i]) zero=0;
        CHECK("vmess/relay-cleanse-before-free",zero); watched=NULL; cleared_frees++;
    }
    __real_free(pointer);
}
void *__wrap_realloc(void *pointer,size_t size) {
    if (allocation_failure) { allocation_failure=0; errno=ENOMEM; return NULL; }
    return __real_realloc(pointer,size);
}

int main(void) {
    core_buffer_budget_t memory={0};
    REQUIRE("vmess/secure-relay-budget",!core_buffer_budget_init(&memory,CORE_BUFFER_RELAY,8192));
    core_relay_buffer_t buffer={.minimum=8192,.limit=65536,.memory=&memory,.cleanse=1};
    REQUIRE("vmess/secure-relay-minimum",core_relay_buffer_reserve(&buffer,8192) == 1);
    memset(buffer.data,0x71,buffer.capacity); buffer.length=8192;
    watched=buffer.data; watched_size=buffer.capacity;
    core_buffer_budget_t pressure={0};
    REQUIRE("vmess/secure-relay-budget-pressure",!core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,core_buffer_available(CORE_BUFFER_RELAY)));
    CHECK("vmess/secure-relay-growth-peak-budget",core_relay_buffer_reserve(&buffer,16384) == 0 && errno == ENOBUFS && buffer.data == watched && buffer.data[8191] == 0x71 && memory.allocated == 8192);
    REQUIRE("vmess/secure-relay-budget-pressure-release",!core_buffer_budget_clear(&pressure));
    allocation_failure=1;
    CHECK("vmess/secure-relay-failed-growth-retains-data",core_relay_buffer_reserve(&buffer,16384) < 0 && errno == ENOMEM && buffer.data == watched && buffer.data[8191] == 0x71 && memory.allocated == 8192);
    REQUIRE("vmess/secure-relay-growth",core_relay_buffer_reserve(&buffer,16384) == 1);
    CHECK("vmess/secure-relay-growth-preserves-data-and-accounting",cleared_frees == 1 && buffer.data[0] == 0x71 && buffer.data[8191] == 0x71 && memory.allocated == 16384);
    core_relay_buffer_consume(&buffer,4096);
    CHECK("vmess/secure-relay-consume-clears-tail",buffer.length == 4096 && buffer.data[0] == 0x71 && !memcmp(buffer.data+4096,(uint8_t[4096]){0},4096));
    watched=buffer.data; watched_size=buffer.capacity; buffer.length=0;
    REQUIRE("vmess/secure-relay-trim",core_relay_buffer_trim(&buffer) == 1);
    CHECK("vmess/secure-relay-trim-keeps-policy",cleared_frees == 2 && buffer.capacity == 8192 && buffer.cleanse && memory.allocated == 8192);
    memset(buffer.data,0x73,buffer.capacity); watched=buffer.data; watched_size=buffer.capacity;
    core_relay_buffer_clear(&buffer);
    CHECK("vmess/secure-relay-close-clears-allocation",cleared_frees == 3 && !buffer.data && !memory.allocated);
    REQUIRE("vmess/secure-relay-release-reservation",!core_buffer_budget_clear(&memory));
    size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
    CHECK("vmess/secure-relay-budget-restored",!bytes && !reserved);
    return test_result();
}
