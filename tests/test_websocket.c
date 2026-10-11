#include "check.h"
#include "websocket.h"
#include "uri.h"

static int decode(const uint8_t *input, size_t length, size_t split, unsigned *events, size_t *payload) {
    core_ws_decoder_t decoder={0};
    size_t position=0;
    *events=0; *payload=0;
    while (position < length) {
        size_t piece=length-position < split ? length-position : split,used=0;
        core_ws_event_t event;
        int result=core_ws_decode(&decoder,input+position,piece,&used,&event);
        if (result < 0) return result;
        if (result) { (*events)++; if (event.opcode < 8) *payload+=event.length; }
        if (!used) return -2;
        position+=used;
    }
    return decoder.active || decoder.header_used || decoder.fragmented ? 2 : 0;
}

int main(void) {
    const uint8_t text[]={0x01,2,0xf0,0x9f,0x89,1,'x',0x80,2,0x98,0x80,0x8a,0,0x88,2,3,0xe8};
    unsigned events; size_t payload;
    for (size_t split=1;split<=sizeof(text);split++) CHECK("ws/fragmented-utf8-and-control",decode(text,sizeof(text),split,&events,&payload) == 0 && payload == 4 && events >= 4);
    const uint8_t invalid[][12]={
        {0x82,0x80},{0xc2,0},{0x80,0},{0x83,0},{0x09,0},{0x8a,126,0,126},
        {0x82,126,0,1,'x'},{0x82,127,0,0,0,0,0,0,0,126},
        {0x82,127,0x80,0,0,0,0,0,0,0},{0x01,0,0x82,0},
        {0x81,1,0xc0},{0x81,1,0xc2},{0x81,3,0xed,0xa0,0x80},
        {0x88,1,0},{0x88,2,3,0xed},{0x88,3,3,0xe8,0xff}
    };
    const size_t sizes[]={2,2,2,2,2,4,5,10,10,4,3,3,5,3,4,5};
    for (size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++) for (size_t split=1;split<=sizes[i];split++)
        CHECK("ws/invalid-frame-matrix",decode(invalid[i],sizes[i],split,&events,&payload) < 0);
    core_ws_decoder_t decoder={0}; core_ws_event_t event; size_t used;
    const uint8_t maximum[]={0x02,127,0,0,0,0,1,0,0,0,'x'};
    CHECK("ws/maximum-message-streamed",core_ws_decode(&decoder,maximum,sizeof(maximum),&used,&event) == 1 && used == sizeof(maximum) && event.length == 1 && decoder.remaining == CORE_WS_MESSAGE_LIMIT-1);
    CHECK("ws/bounded-decoder-memory",sizeof(decoder) < 512);
    decoder=(core_ws_decoder_t){0};
    const uint8_t excessive[]={0x82,127,0,0,0,0,1,0,0,1};
    CHECK("ws/message-limit",core_ws_decode(&decoder,excessive,sizeof(excessive),&used,&event) < 0);
    const uint8_t close_frame[]={0x88,0}; decoder=(core_ws_decoder_t){0};
    CHECK("ws/close-event",core_ws_decode(&decoder,close_frame,2,&used,&event) == 1 && event.opcode == 8 && decoder.closed);
    CHECK("ws/data-after-close-rejected",core_ws_decode(&decoder,close_frame,2,&used,&event) < 0);
    vless_config_t config; char error[160];
    const char *prefix="vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?type=ws&";
    const char *valid[]={"ed=0","ed=16384","maxEarlyData=123","heartbeatPeriod=1","path=%2Fvless-core%3Fed%3D100%26other%3D1","headers=%7B%22X-vless-core%22%3A%22custom%22%7D"};
    char uri[2048];
    for (size_t i=0;i<sizeof(valid)/sizeof(*valid);i++) {
        snprintf(uri,sizeof(uri),"%s%s",prefix,valid[i]);
        CHECK("ws/uri-settings",parse_core_uri(uri,&config,error,sizeof(error)) == 0);
        if (i == 4) CHECK("ws/path-early-data-removed",config.ws_early_data == 100 && !strcmp(config.xhttp_path,"/vless-core?other=1"));
        if (i == 5) CHECK("ws/header-configuration",!strcmp(config.ws_headers,"x-vless-core: custom\r\n"));
    }
    const char *bad[]={"ed=16385","ed=-1","ed=true","heartbeatPeriod=1s","headers=%7B%22Sec-WebSocket-Key%22%3A%22evil%22%7D","headers=%7B%22Host%22%3A%22evil%22%7D","headers=%7B%22X-vless-core%22%3A%22x%5Cr%5CnEvil%3Ax%22%7D","path=%2F%3Fed%3D1%26ed%3D2","ed=1&maxEarlyData=1"};
    for (size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        snprintf(uri,sizeof(uri),"%s%s",prefix,bad[i]);
        CHECK("ws/invalid-uri-settings",parse_core_uri(uri,&config,error,sizeof(error)) < 0);
    }
    snprintf(uri,sizeof(uri),"%spath=%%2Fvless-core%%3Fed%%3D100&ed=20",prefix);
    CHECK("ws/explicit-early-data-priority",parse_core_uri(uri,&config,error,sizeof(error)) == 0 && config.ws_early_data == 20 && !strcmp(config.xhttp_path,"/vless-core"));
    return test_result();
}
