#include "check.h"
#include "http2.h"

static core_http2_validation_t started(void) {
    core_http2_validation_t state={0};
    REQUIRE("h2/initial-server-settings",core_http2_validate_frame(&state,4,0,0,NULL,0) == 0 && state.settings_received);
    return state;
}

int main(void) {
    core_http2_validation_t state={0}; const uint8_t payload[16]={0};
    CHECK("h2/ack-cannot-be-server-preface",core_http2_validate_frame(&state,4,1,0,NULL,0) == -1);
    CHECK("h2/data-cannot-be-server-preface",core_http2_validate_frame(&state,0,0,1,payload,1) == -1);
    CHECK("h2/extension-cannot-be-server-preface",core_http2_validate_frame(&state,99,0,0,NULL,0) == -1);
    state=started();
    CHECK("h2/settings-ack",core_http2_validate_frame(&state,4,1,0,NULL,0) == 0);
    CHECK("h2/unexpected-settings-ack",core_http2_validate_frame(&state,4,1,0,NULL,0) == -1);
    struct { uint8_t type,flags; uint32_t stream; size_t length; } bad[]={
        {4,0,1,0},{4,1,0,6},{4,0,0,1},{6,0,1,8},{6,0,0,7},{7,0,1,8},{7,0,0,7},
        {3,0,0,4},{3,0,1,3},{0,0,0,1},{0,8,1,0},{1,0,0,1},{1,32,1,4},{9,4,1,0},
        {8,0,0,3},{5,4,1,4},
    };
    for (size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        state=started();
        CHECK("h2/invalid-known-frame-shape",core_http2_validate_frame(&state,bad[i].type,bad[i].flags,bad[i].stream,payload,bad[i].length) == -1);
    }
    const uint8_t settings[][6]={{0,2,0,0,0,1},{0,2,0,0,0,2},{0,4,0x80,0,0,0},{0,5,0,0,0,1},{0,5,1,0,0,0}};
    for (size_t i=0;i<sizeof(settings)/sizeof(*settings);i++) {
        state=started(); CHECK("h2/invalid-settings-value",core_http2_validate_frame(&state,4,0,0,settings[i],6) == -1);
    }
    state=started();
    CHECK("h2/server-enable-push-zero",core_http2_validate_frame(&state,4,0,0,(const uint8_t[]){0,2,0,0,0,0},6) == 0);
    CHECK("h2/unknown-setting-ignored",core_http2_validate_frame(&state,4,0,0,(const uint8_t[]){255,255,255,255,255,255},6) == 0);
    CHECK("h2/unknown-frame-and-flags-ignored",core_http2_validate_frame(&state,99,255,0x7fffffff,payload,16) == 0);
    CHECK("h2/priority-on-idle-stream",core_http2_validate_frame(&state,2,255,100,payload,5) == 0);
    CHECK("h2/priority-size-is-stream-error",core_http2_validate_frame(&state,2,0,1,payload,4) == -2);
    CHECK("h2/priority-self-dependency",core_http2_validate_frame(&state,2,0,1,(const uint8_t[]){0,0,0,1,0},5) == -2);
    CHECK("h2/stream-zero-window-increment",core_http2_validate_frame(&state,8,0,1,payload,4) == -2);
    CHECK("h2/connection-zero-window-increment",core_http2_validate_frame(&state,8,0,0,payload,4) == -1);
    uint8_t *maximum=calloc(1,16385); REQUIRE("h2/frame-size-fixture",maximum != NULL);
    CHECK("h2/default-frame-limit",core_http2_validate_frame(&state,99,0,0,maximum,16384) == 0);
    CHECK("h2/frame-limit-before-payload-processing",core_http2_validate_frame(&state,99,0,0,maximum,16385) == -1); free(maximum);
    CHECK("h2/headers-open-continuation",core_http2_validate_frame(&state,1,0,1,payload,1) == 0 && state.continuation == 1);
    core_http2_validation_t interrupted=state;
    CHECK("h2/extension-cannot-interleave-headers",core_http2_validate_frame(&interrupted,99,0,0,NULL,0) == -1);
    interrupted=state; CHECK("h2/continuation-other-stream",core_http2_validate_frame(&interrupted,9,4,3,payload,1) == -1);
    CHECK("h2/continuation-completes-block",core_http2_validate_frame(&state,9,4,1,payload,1) == 0 && !state.continuation);
    core_http2_response_t response={0};
    core_hpack_headers_t headers={.status=103,.status_seen=1};
    CHECK("h2/interim-response",core_http2_response_headers(&response,&headers,0) == 0 && !response.headers);
    headers.status=200; headers.has_content_length=1; headers.content_length=4;
    CHECK("h2/initial-response-with-length",core_http2_response_headers(&response,&headers,0) == 0 && response.headers);
    CHECK("h2/fragmented-response-data",core_http2_response_data(&response,2,0) == 0 && response.received == 2);
    core_http2_response_t truncated=response; core_hpack_headers_t trailers={0};
    CHECK("h2/trailers-cannot-truncate-length",core_http2_response_headers(&truncated,&trailers,1) < 0);
    CHECK("h2/remaining-response-data",core_http2_response_data(&response,2,0) == 0);
    CHECK("h2/complete-trailers",core_http2_response_headers(&response,&trailers,1) == 0 && response.ended);
    CHECK("h2/data-after-end",core_http2_response_data(&response,1,0) < 0);
    response=(core_http2_response_t){0};
    CHECK("h2/data-before-response-headers",core_http2_response_data(&response,1,0) < 0);
    headers.other_pseudo=1;
    CHECK("h2/request-pseudo-in-response",core_http2_response_headers(&response,&headers,0) < 0);
    headers.other_pseudo=0; headers.has_te=1;
    CHECK("h2/te-forbidden-in-response",core_http2_response_headers(&response,&headers,0) < 0);
    headers.has_te=0; headers.content_length=UINT64_MAX;
    CHECK("h2/maximum-content-length-is-not-unknown",core_http2_response_headers(&response,&headers,0) == 0 && core_http2_response_data(&response,1,1) < 0);
    response=(core_http2_response_t){0}; headers=(core_hpack_headers_t){.status=304,.status_seen=1,.has_content_length=1,.content_length=10};
    CHECK("h2/304-length-describes-representation",core_http2_response_headers(&response,&headers,1) == 0 && response.ended);
    response=(core_http2_response_t){.no_body=1}; headers=(core_hpack_headers_t){.status=200,.status_seen=1,.has_content_length=1,.content_length=123};
    CHECK("h2/head-length-describes-representation",core_http2_response_headers(&response,&headers,1) == 0 && response.ended && response.no_body);
    response=(core_http2_response_t){.no_body=1};
    CHECK("h2/head-rejects-body",core_http2_response_headers(&response,&headers,0) == 0 && core_http2_response_data(&response,1,0) < 0);
    CHECK("h2/state-memory-bounded",sizeof(response)+sizeof(state) < 128);
    return test_result();
}
