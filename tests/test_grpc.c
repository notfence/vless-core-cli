#include "check.h"
#include "grpc.h"
#include "../src/grpc.c"
#include "uri.h"

static int allocation_failure;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t length) { if (allocation_failure) { allocation_failure=0; errno=ENOMEM; return NULL; } return __real_malloc(length); }

static int feed(core_grpc_decoder_t *state, const uint8_t *input, size_t length) {
    size_t consumed=0,payload_length=0; const uint8_t *payload=NULL;
    int result=core_grpc_decode(state,input,length,&consumed,&payload,&payload_length);
    CHECK("grpc/decoder-consumption-bounded",consumed <= length);
    return result;
}

static void gun_resources(void) {
    core_grpc_decoder_t state={0},denied={0},multi={.multi=1};
    const uint8_t maximum[]={0,1,0,0,0},small[]={0,0,0,0,3},valid[]={0,0,0,0,3,10,1,'x'};
    CHECK("grpc/reserve-announced-maximum",feed(&state,maximum,sizeof(maximum)) == 0 && state.reserved == GRPC_BUFFER_LIMIT && grpc_reserved == GRPC_BUFFER_LIMIT);
    CHECK("grpc/header-does-not-allocate-body",!state.head && !state.tail);
    CHECK("grpc/process-budget-failure",feed(&denied,small,sizeof(small)) < 0 && denied.failed == 2 && !denied.reserved && grpc_reserved == GRPC_BUFFER_LIMIT);
    CHECK("grpc/multi-does-not-reserve-gun-budget",feed(&multi,maximum,sizeof(maximum)) == 0 && !multi.reserved);
    core_grpc_clear(&multi); core_grpc_clear(&denied);
    CHECK("grpc/invalid-message-releases-budget",feed(&state,(const uint8_t *)"\x00",1) < 0 && !grpc_reserved);
    core_grpc_clear(&state); core_grpc_clear(&state);
    allocation_failure=1;
    CHECK("grpc/allocation-failure-releases-budget",feed(&state,valid,sizeof(valid)) < 0 && state.failed == 3 && !grpc_reserved && !state.head);
    core_grpc_clear(&state);
    CHECK("grpc/resource-recovery",feed(&state,valid,sizeof(valid)) == 1 && state.ready && grpc_reserved == 3);
    uint8_t output[1024]; size_t length=0;
    CHECK("grpc/drain-releases-reservation",core_grpc_read(&state,output,sizeof(output),&length) == 0 && length == 1 && output[0] == 'x' && !grpc_reserved && !state.ready);
    core_grpc_clear(&state);
    const uint8_t large[]={0,0,0,0x27,0x10,10,0x8d,0x4e};
    CHECK("grpc/gradual-large-header",feed(&state,large,sizeof(large)) == 0 && !state.head && state.reserved == 10000);
    CHECK("grpc/gradual-first-byte",feed(&state,(const uint8_t *)"x",1) == 0 && state.head && state.head->capacity == 8192 && state.head->length == 1);
    memset(output,'x',sizeof(output));
    size_t pending=9996;
    while (pending) { size_t take=pending < sizeof(output) ? pending : sizeof(output); REQUIRE("grpc/gradual-buffer-feed",feed(&state,output,take) >= 0); pending-=take; }
    CHECK("grpc/large-message-ready",state.ready && state.reserved == 10000 && state.head && state.tail && state.tail->capacity == 1805);
    size_t total=0;
    while (core_grpc_pending(&state)) {
        REQUIRE("grpc/chunked-memory-drain",core_grpc_read(&state,output,sizeof(output),&length) == 0);
        for (size_t i=0;i<length;i++) CHECK("grpc/chunked-payload-preserved",output[i] == 'x');
        total+=length;
    }
    CHECK("grpc/chunked-drain-complete",total == 9997 && !grpc_reserved && !state.head);
    core_grpc_clear(&state);
}

typedef struct { int result; } reservation_worker_t;
static pthread_mutex_t worker_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t worker_condition=PTHREAD_COND_INITIALIZER;
static unsigned worker_ready,worker_release;
static void *reservation_worker(void *opaque) {
    reservation_worker_t *worker=opaque; core_grpc_decoder_t state={0};
    const uint8_t header[]={0,0,0x10,0,0}; size_t consumed=0,length=0; const uint8_t *payload=NULL;
    worker->result=core_grpc_decode(&state,header,sizeof(header),&consumed,&payload,&length);
    pthread_mutex_lock(&worker_lock); worker_ready++; pthread_cond_broadcast(&worker_condition);
    while (!worker_release) pthread_cond_wait(&worker_condition,&worker_lock);
    pthread_mutex_unlock(&worker_lock); core_grpc_clear(&state); return NULL;
}

static void concurrent_reservations(void) {
    for (unsigned repetition=0;repetition<5;repetition++) {
        pthread_t workers[16]; reservation_worker_t results[16]; worker_ready=worker_release=0;
        for (unsigned i=0;i<16;i++) REQUIRE("grpc/parallel-worker-start",pthread_create(&workers[i],NULL,reservation_worker,&results[i]) == 0);
        pthread_mutex_lock(&worker_lock);
        while (worker_ready < 16) pthread_cond_wait(&worker_condition,&worker_lock);
        CHECK("grpc/parallel-budget-exhausted",grpc_reserved == GRPC_BUFFER_LIMIT);
        core_grpc_decoder_t denied={0}; const uint8_t small[]={0,0,0,0,1};
        CHECK("grpc/parallel-over-budget-isolated",feed(&denied,small,sizeof(small)) < 0 && denied.failed == 2);
        core_grpc_clear(&denied); worker_release=1; pthread_cond_broadcast(&worker_condition); pthread_mutex_unlock(&worker_lock);
        for (unsigned i=0;i<16;i++) CHECK("grpc/parallel-workers-release",pthread_join(workers[i],NULL) == 0 && results[i].result == 0);
        CHECK("grpc/parallel-budget-recovered",!grpc_reserved);
    }
}

static int decode_mode(const uint8_t *input, size_t size, size_t step, size_t *total, unsigned multi) {
    core_grpc_decoder_t decoder={.multi=multi}; *total=0; int final=0;
    for (size_t offset=0;offset<size;) {
        size_t consumed=0,length=0,take=size-offset < step ? size-offset : step;
        const uint8_t *payload;
        int result=core_grpc_decode(&decoder,input+offset,take,&consumed,&payload,&length);
        if (result < 0) { final=-1; break; }
        if ((!consumed && !core_grpc_pending(&decoder)) || consumed > take) { final=-2; break; }
        *total+=length; offset+=consumed;
        while (core_grpc_pending(&decoder)) {
            uint8_t output[37]; REQUIRE("grpc/drain-output",core_grpc_read(&decoder,output,sizeof(output),&length) == 0); *total+=length;
        }
    }
    if (!final && !core_grpc_complete(&decoder)) final=1;
    core_grpc_clear(&decoder); return final;
}

static int decode(const uint8_t *input, size_t size, size_t step, size_t *total) { return decode_mode(input,size,step,total,0); }
int main(void) {
    gun_resources(); concurrent_reservations();
    const char *content_types[]={"application/grpc","application/grpc+proto","APPLICATION/GRPC+json","application/grpc; charset=utf-8","application/grpc+proto; key=\"vless-core\""};
    for (size_t i=0;i<sizeof(content_types)/sizeof(*content_types);i++) CHECK("grpc/valid-content-type",core_grpc_content_type(content_types[i],strlen(content_types[i])));
    const char *bad_types[]={"application/grpc-web","application/grpc+","application/grpc;","application/grpc +proto","text/plain","application/grpc; key=\"open","application/grpc\0bad"};
    for (size_t i=0;i<sizeof(bad_types)/sizeof(*bad_types)-1;i++) CHECK("grpc/invalid-content-type",!core_grpc_content_type(bad_types[i],strlen(bad_types[i])));
    CHECK("grpc/content-type-nul",!core_grpc_content_type(bad_types[6],20));
    core_hpack_headers_t headers={.status=200,.content_type_seen=1,.grpc_content_type=1}; char metadata_error[160];
    CHECK("grpc/initial-headers",!core_grpc_response_headers(&headers,1,0,metadata_error,sizeof(metadata_error)));
    CHECK("grpc/missing-final-status",core_grpc_response_headers(&headers,1,1,metadata_error,sizeof(metadata_error)) < 0);
    headers.has_grpc_status=1;
    CHECK("grpc/trailers-only-ok",!core_grpc_response_headers(&headers,1,1,metadata_error,sizeof(metadata_error)));
    CHECK("grpc/nonterminal-status",core_grpc_response_headers(&headers,1,0,metadata_error,sizeof(metadata_error)) < 0);
    headers.grpc_status=123;
    CHECK("grpc/unknown-status",core_grpc_response_headers(&headers,1,1,metadata_error,sizeof(metadata_error)) < 0 && strstr(metadata_error,"grpc-status=2"));
    const int http_codes[]={400,401,403,404,429,502,503,504,500},grpc_codes[]={13,16,7,12,14,14,14,14,2};
    for (size_t i=0;i<sizeof(http_codes)/sizeof(*http_codes);i++) {
        headers=(core_hpack_headers_t){.status=http_codes[i]}; char expected[32]; snprintf(expected,sizeof(expected),"grpc-status=%d",grpc_codes[i]);
        CHECK("grpc/http-error-mapping",core_grpc_response_headers(&headers,1,0,metadata_error,sizeof(metadata_error)) < 0 && strstr(metadata_error,expected));
    }
    const uint8_t message[]={0,0,0,0,14,0x10,0xff,0x01,10,3,'a','b','c',10,4,'d','e','f','g',0,0,0,0,0};
    size_t payload;
    CHECK("grpc/gun-last-one-wins",decode(message,sizeof(message),1,&payload) == 0 && payload == 4);
    const uint8_t empty_last[]={0,0,0,0,7,10,3,'a','b','c',10,0},unknown_only[]={0,0,0,0,2,16,1};
    CHECK("grpc/gun-empty-last-replaces-data",decode(empty_last,sizeof(empty_last),1,&payload) == 0 && payload == 0);
    CHECK("grpc/unknown-only-is-empty-message",decode(unknown_only,sizeof(unknown_only),1,&payload) == 0 && payload == 0);
    const uint8_t groups[]={0,0,0,0,9,19,10,1,'x',20,10,2,'o','k'},wrong_wire[]={0,0,0,0,5,10,1,'x',8,1};
    CHECK("grpc/unknown-group-is-skipped",decode(groups,sizeof(groups),1,&payload) == 0 && payload == 2);
    CHECK("grpc/wrong-wire-does-not-replace-data",decode(wrong_wire,sizeof(wrong_wire),1,&payload) == 0 && payload == 1);
    const uint8_t invalid_groups[]={0,0,0,0,2,19,28};
    CHECK("grpc/mismatched-unknown-group",decode(invalid_groups,sizeof(invalid_groups),1,&payload) < 0 && !grpc_reserved);
    const uint8_t invalid_tail[]={0,0,0,0,6,10,3,'a','b','c',0};
    CHECK("grpc/invalid-tail-does-not-emit-gun-data",decode(invalid_tail,sizeof(invalid_tail),1,&payload) < 0 && !payload && !grpc_reserved);
    uint8_t nested[135]={0,0,0,0,128}; memset(nested+5,19,64); memset(nested+69,20,64);
    CHECK("grpc/unknown-groups-bounded-depth",decode(nested,133,1,&payload) == 0 && !payload);
    nested[4]=130; memset(nested+5,19,65); memset(nested+70,20,65);
    CHECK("grpc/unknown-groups-depth-overflow",decode(nested,sizeof(nested),1,&payload) < 0 && !grpc_reserved);
    for (size_t step=1;step<sizeof(message);step++) CHECK("grpc/streaming-repeated-fields",decode_mode(message,sizeof(message),step,&payload,1) == 0 && payload == 7);
    for (size_t cut=1;cut<19;cut++) CHECK("grpc/truncated-message",decode(message,cut,1,&payload) != 0);
    const uint8_t invalid[][12]={{1,0,0,0,0},{0,1,0,0,1},{0,0,0,0,1,0},{0,0,0,0,2,10,100},{0,0,0,0,1,15},{0,0,0,0,1,128}};
    const size_t sizes[]={5,5,6,7,6,6};
    for (size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++) CHECK("grpc/malformed-message",decode(invalid[i],sizes[i],1,&payload) < 0);
    core_grpc_decoder_t decoder={.multi=1}; size_t consumed=0,length=0; const uint8_t *data;
    const uint8_t large[]={0,1,0,0,0,10,0xfb,0xff,0xff,7,'x'};
    CHECK("grpc/large-message-streamed",core_grpc_decode(&decoder,large,sizeof(large),&consumed,&data,&length) == 1 && length == 1 && data[0] == 'x' && consumed == sizeof(large));
    CHECK("grpc/bounded-decoder-memory",sizeof(decoder) < 512);
    core_grpc_clear(&decoder);
    vless_config_t config; char error[160],uri[1024];
    const char *prefix="vless://00000000-0000-0000-0000-000000000001@127.0.0.1:1?type=grpc&";
    const char *valid[]={"initialWindowsSize=1","initialWindowsSize=262144","idleTimeout=1&healthCheckTimeout=2&permitWithoutStream=true","userAgent=vless-core%2Fgrpc"};
    for (size_t i=0;i<sizeof(valid)/sizeof(*valid);i++) {
        snprintf(uri,sizeof(uri),"%s%s",prefix,valid[i]); CHECK("grpc/uri-settings",parse_core_uri(uri,&config,error,sizeof(error)) == 0);
    }
    snprintf(uri,sizeof(uri),"%sinitialWindowsSize=262144",prefix);
    CHECK("grpc/window-not-clamped",parse_core_uri(uri,&config,error,sizeof(error)) == 0 && config.grpc_initial_window == 262144);
    const char *bad[]={"initialWindowsSize=0","initialWindowsSize=262145","initialWindowsSize=-1","idleTimeout=-1","healthCheckTimeout=20s","permitWithoutStream=maybe","userAgent=x%0D%0AEvil%3Atrue"};
    for (size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        snprintf(uri,sizeof(uri),"%s%s",prefix,bad[i]); CHECK("grpc/invalid-uri-settings",parse_core_uri(uri,&config,error,sizeof(error)) < 0);
    }
    return test_result();
}
