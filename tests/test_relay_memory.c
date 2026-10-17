#include "relay_memory.h"
#include "vision.h"
#include "check.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail_allocation,fail_notification;
void *__real_realloc(void *,size_t);
int __real_socketpair(int,int,int,int[2]);
void *__wrap_realloc(void *pointer,size_t size) {
    if (fail_allocation) { fail_allocation=0; errno=ENOMEM; return NULL; }
    return __real_realloc(pointer,size);
}
int __wrap_socketpair(int domain,int type,int protocol,int descriptors[2]) {
    if (fail_notification) { fail_notification=0; errno=EMFILE; return -1; }
    return __real_socketpair(domain,type,protocol,descriptors);
}

static void empty_budget(void) {
    size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
    CHECK("relay-memory/all-capacity-and-credit-released",bytes == 0 && reserved == 0);
}

static void minimum_and_growth(void) {
    core_relay_memory_t clients[256]={0};
    for (size_t i=0;i<256;i++) {
        REQUIRE("relay-memory/256-minimum-reservations",core_relay_memory_init(clients+i,128U*1024U) == 1);
        CHECK("relay-memory/minimum-no-extra-descriptors",!clients[i].registered && core_relay_memory_fd(clients+i) == -1);
        CHECK("relay-memory/both-directions-start-at-8k",clients[i].input.capacity == 8192 && clients[i].output.capacity == 8192);
    }
    size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
    CHECK("relay-memory/256-minimum-is-4mb",bytes == 4U*1024U*1024U && !reserved);
    core_buffer_snapshot(CORE_BUFFER_UPLOAD,&bytes,&reserved);
    CHECK("relay-memory/upload-http2-budget-independent",!bytes && !reserved);
    core_buffer_snapshot(CORE_BUFFER_DOWNLOAD,&bytes,&reserved);
    CHECK("relay-memory/download-http2-budget-independent",!bytes && !reserved);
    uint8_t data[8192]; memset(data,0xa7,sizeof(data));
    REQUIRE("relay-memory/append-minimum",core_relay_buffer_append(&clients[0].output,data,sizeof(data)) == 0);
    REQUIRE("relay-memory/grow-on-demand",core_relay_buffer_append(&clients[0].output,data,sizeof(data)) == 0);
    CHECK("relay-memory/growth-preserves-data",clients[0].output.capacity == 16384 && clients[0].output.data[0] == 0xa7 && clients[0].output.data[16383] == 0xa7);
    core_relay_buffer_consume(&clients[0].output,8191);
    CHECK("relay-memory/partial-consumption",clients[0].output.length == 8193 && clients[0].output.data[8192] == 0xa7);
    CHECK("relay-memory/trim-preserves-pending-data",core_relay_buffer_trim(&clients[0].output) == 1 && clients[0].output.capacity == 16384);
    core_relay_buffer_consume(&clients[0].output,8193);
    CHECK("relay-memory/drained-output-shrinks",core_relay_buffer_trim(&clients[0].output) == 1 && clients[0].output.capacity == 8192);
    CHECK("relay-memory/output-limit",core_relay_buffer_reserve(&clients[0].output,CORE_RELAY_OUTPUT_LIMIT+1) == -1 && errno == EMSGSIZE);
    CHECK("relay-memory/input-batch-limit",core_relay_buffer_reserve(&clients[0].input,128U*1024U+1) == -1 && errno == EMSGSIZE);
    for (size_t i=0;i<256;i++) core_relay_memory_clear(clients+i);
    empty_budget();
}

static void limits_and_notifications(void) {
    core_relay_memory_t memory={0}; core_buffer_budget_t pressure={0};
    REQUIRE("relay-memory/pressure-initialize",core_relay_memory_init(&memory,128U*1024U) == 1);
    REQUIRE("relay-memory/growth-before-pressure",core_relay_buffer_reserve(&memory.output,16384) == 1);
    memory.output.data[0]=0x73;
    size_t available=core_buffer_available(CORE_BUFFER_RELAY);
    REQUIRE("relay-memory/exhaust-separate-budget",core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,available) == 0);
    CHECK("relay-memory/realloc-peak-refused-before-allocation",core_relay_buffer_reserve(&memory.output,32768) == 0 && errno == ENOBUFS && memory.output.capacity == 16384 && memory.output.data[0] == 0x73);
    REQUIRE("relay-memory/watch-pressure",core_relay_memory_watch(&memory,CORE_RELAY_OUTPUT_WAIT) == 0);
    int descriptor=core_relay_memory_fd(&memory);
    CHECK("relay-memory/notification-descriptor-contract",descriptor >= 0 && (fcntl(descriptor,F_GETFD)&FD_CLOEXEC) && (fcntl(descriptor,F_GETFL)&O_NONBLOCK));
    struct pollfd notification={.fd=descriptor,.events=POLLIN};
    CHECK("relay-memory/no-active-polling",poll(&notification,1,0) == 0);
    REQUIRE("relay-memory/release-wakes-waiter",core_buffer_budget_clear(&pressure) == 0);
    REQUIRE("relay-memory/notification-received",poll(&notification,1,100) == 1 && (notification.revents&POLLIN));
    core_relay_memory_released(); core_relay_memory_released();
    CHECK("relay-memory/coalesced-notification",core_relay_memory_ack(&memory) == CORE_RELAY_OUTPUT_WAIT && poll(&notification,1,0) == 0);
    CHECK("relay-memory/growth-recovers-after-release",core_relay_buffer_reserve(&memory.output,32768) == 1);
    fail_allocation=1;
    CHECK("relay-memory/allocator-failure-preserves-buffer",core_relay_buffer_reserve(&memory.output,65536) == -1 && errno == ENOMEM && memory.output.capacity == 32768 && memory.output.data[0] == 0x73);
    CHECK("relay-memory/allocator-failure-rolls-back-charge",memory.download.allocated == 32768 && memory.download.charged == 32768);
    CHECK("relay-memory/allocator-recovery",core_relay_buffer_reserve(&memory.output,65536) == 1);
    REQUIRE("relay-memory/credit-without-allocation",core_relay_memory_credit(&memory,1024U*1024U) == 1);
    core_buffer_snapshot(CORE_BUFFER_RELAY,&available,NULL);
    CHECK("relay-memory/temporary-credit-is-not-allocated",available == memory.upload.allocated+memory.download.allocated);
    core_relay_memory_clear(&memory);
    CHECK("relay-memory/notification-close",fcntl(descriptor,F_GETFD) == -1 && errno == EBADF);
    empty_budget();
    fail_allocation=1;
    CHECK("relay-memory/minimum-allocation-failure",core_relay_memory_init(&memory,128U*1024U) == -1);
    core_relay_memory_clear(&memory); empty_budget();
    REQUIRE("relay-memory/minimum-recovery",core_relay_memory_init(&memory,128U*1024U) == 1);
    fail_notification=1;
    CHECK("relay-memory/notification-resource-failure",core_relay_memory_watch(&memory,CORE_RELAY_INPUT_WAIT) == -1 && errno == EMFILE && !memory.registered);
    REQUIRE("relay-memory/notification-resource-recovery",core_relay_memory_watch(&memory,3) == 0);
    core_relay_memory_unwatch(&memory,CORE_RELAY_INPUT_WAIT);
    CHECK("relay-memory/opposite-direction-still-waits",memory.waiting == CORE_RELAY_OUTPUT_WAIT);
    core_relay_memory_clear(&memory); empty_budget();
}

static void transformation_capacity(void) {
    const size_t lengths[]={0,1,8,899,900,8192,65535,65536,128U*1024U};
    uint8_t uuid[16]={1},input[128U*1024U];
    for (size_t i=0;i<sizeof(input);i++) input[i]=(uint8_t)(i*37U);
    for (size_t i=0;i<sizeof(lengths)/sizeof(*lengths);i++) {
        core_relay_memory_t memory={0}; vision_wrap_t wrap; vision_unpad_t unpad;
        REQUIRE("relay-memory/vision-initialize",core_relay_memory_init(&memory,sizeof(input)) == 1);
        vision_wrap_init(&wrap,uuid); vision_unpad_init(&unpad,uuid); unpad.memory=&memory.temporary;
        REQUIRE("relay-memory/vision-reserve-before-transform",core_relay_memory_credit(&memory,vision_wrap_buffer_bound(lengths[i])) == 1);
        REQUIRE("relay-memory/vision-accounted-wrap",vision_wrap_payload_buffer(&wrap,input,lengths[i],&memory.wrapped) == 0);
        size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
        CHECK("relay-memory/vision-wrap-within-reserved-bound",memory.temporary.allocated <= memory.temporary.minimum && bytes+reserved <= CORE_BUFFER_TOTAL_LIMIT);
        core_relay_buffer_t wire=memory.wrapped; memory.wrapped=(core_relay_buffer_t){.memory=&memory.temporary};
        size_t decoded=0;
        for (size_t offset=0;offset<wire.length;) {
            size_t size=wire.length-offset; if (size > 8192) size=8192;
            REQUIRE("relay-memory/vision-reserve-before-read",core_relay_memory_credit(&memory,wire.capacity+vision_unpad_buffer_bound(&unpad,size)) == 1);
            int direct;
            REQUIRE("relay-memory/vision-accounted-unpad",vision_unpad_feed_buffer(&unpad,wire.data+offset,size,&memory.plain,&direct) == 0);
            CHECK("relay-memory/vision-does-not-lose-data",memory.plain.length <= lengths[i]-decoded && (!memory.plain.length || !memcmp(input+decoded,memory.plain.data,memory.plain.length)));
            decoded+=memory.plain.length; offset+=size;
            core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
            CHECK("relay-memory/vision-unpad-within-reserved-bound",memory.temporary.allocated <= memory.temporary.minimum && bytes+reserved <= CORE_BUFFER_TOTAL_LIMIT);
            core_relay_buffer_clear(&memory.plain);
        }
        CHECK("relay-memory/vision-exact-total",decoded == lengths[i]);
        vision_unpad_free(&unpad); core_relay_buffer_clear(&wire); core_relay_memory_clear(&memory); empty_budget();
    }
}

static void allocated_saturation(void) {
    core_relay_memory_t clients[128]={0};
    for (size_t i=0;i<128;i++) REQUIRE("relay-memory/saturation-minimum",core_relay_memory_init(clients+i,128U*1024U) == 1);
    size_t count=0;
    for (;count<128;count++) {
        int result=core_relay_buffer_reserve(&clients[count].output,CORE_RELAY_OUTPUT_LIMIT);
        if (!result) break;
        REQUIRE("relay-memory/saturation-real-allocation",result == 1);
        memset(clients[count].output.data,0x46,CORE_RELAY_OUTPUT_LIMIT);
        clients[count].output.length=CORE_RELAY_OUTPUT_LIMIT;
    }
    size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
    CHECK("relay-memory/actual-allocated-capacity-limited",count > 40 && count < 64 && bytes+reserved <= CORE_BUFFER_TOTAL_LIMIT);
    REQUIRE("relay-memory/saturation-waiter",core_relay_memory_watch(clients+count,CORE_RELAY_OUTPUT_WAIT) == 0);
    struct pollfd fd={.fd=core_relay_memory_fd(clients+count),.events=POLLIN};
    CHECK("relay-memory/saturation-retains-data",clients[count-1].output.data[CORE_RELAY_OUTPUT_LIMIT-1] == 0x46);
    core_relay_buffer_consume(&clients[0].output,CORE_RELAY_OUTPUT_LIMIT);
    REQUIRE("relay-memory/saturation-drain-shrinks",core_relay_buffer_trim(&clients[0].output) == 1);
    CHECK("relay-memory/saturation-release-notifies",poll(&fd,1,100) == 1 && core_relay_memory_ack(clients+count) == CORE_RELAY_OUTPUT_WAIT);
    CHECK("relay-memory/saturation-next-client-recovers",core_relay_buffer_reserve(&clients[count].output,CORE_RELAY_OUTPUT_LIMIT) == 1);
    for (size_t i=0;i<128;i++) core_relay_memory_clear(clients+i);
    empty_budget();
}

static void *wait_for_release(void *opaque) {
    core_relay_memory_t *memory=opaque;
    struct pollfd fd={.fd=core_relay_memory_fd(memory),.events=POLLIN};
    return (void *)(intptr_t)(poll(&fd,1,1000) == 1 && core_relay_memory_ack(memory) == 3);
}

static void parallel_recovery(void) {
    core_relay_memory_t memory[16]={0}; pthread_t threads[16]; core_buffer_budget_t pressure={0};
    for (size_t i=0;i<16;i++) {
        REQUIRE("relay-memory/parallel-minimum",core_relay_memory_init(memory+i,128U*1024U) == 1);
        REQUIRE("relay-memory/parallel-watch",core_relay_memory_watch(memory+i,3) == 0);
    }
    REQUIRE("relay-memory/parallel-saturation",core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,core_buffer_available(CORE_BUFFER_RELAY)) == 0);
    for (size_t i=0;i<16;i++) REQUIRE("relay-memory/parallel-wait-thread",pthread_create(threads+i,NULL,wait_for_release,memory+i) == 0);
    REQUIRE("relay-memory/parallel-release",core_buffer_budget_clear(&pressure) == 0);
    for (size_t i=0;i<16;i++) {
        void *result=NULL; pthread_join(threads[i],&result);
        CHECK("relay-memory/parallel-waiters-woken",(intptr_t)result == 1);
        core_relay_memory_clear(memory+i);
    }
    empty_budget();
}

int main(void) {
    minimum_and_growth(); limits_and_notifications(); transformation_capacity(); allocated_saturation(); parallel_recovery();
    return test_result();
}
