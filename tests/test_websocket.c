#include "check.h"
#include "websocket.h"
#include "uri.h"

static void upgrade_vectors(void) {
    const char *accept="s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
    const char *valid="HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: keep-alive, UpGrAdE\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
    char reply[1024]; size_t base=strlen(valid);
    snprintf(reply,sizeof(reply),"%s\r\n",valid);
    CHECK("ws/upgrade-standard-tokens",core_ws_validate_upgrade((const uint8_t *)reply,strlen(reply),accept,NULL) == 0);
    for (size_t cut=0;cut<strlen(reply);cut++) CHECK("ws/upgrade-truncated",core_ws_validate_upgrade((const uint8_t *)reply,cut,accept,NULL) < 0);
    const char *bad[]={"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n","Sec-WebSocket-Extensions: permessage-deflate\r\n","Sec-WebSocket-Protocol: other\r\n","Bad Header: value\r\n"," Folded: value\r\n","NoColon\r\n","Connection: \r\n","Connection: upgrade,\r\n","Upgrade: web socket\r\n"};
    for (size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        snprintf(reply,sizeof(reply),"%s%s\r\n",valid,bad[i]);
        CHECK("ws/upgrade-malformed-or-unrequested",core_ws_validate_upgrade((const uint8_t *)reply,strlen(reply),accept,"vless-core") < 0);
    }
    snprintf(reply,sizeof(reply),"%sSec-WebSocket-Protocol: vless-core\r\n\r\n",valid);
    CHECK("ws/upgrade-subprotocol-exact",core_ws_validate_upgrade((const uint8_t *)reply,strlen(reply),accept,"vless-core") == 0);
    CHECK("ws/upgrade-subprotocol-not-offered",core_ws_validate_upgrade((const uint8_t *)reply,strlen(reply),accept,NULL) < 0);
    CHECK("ws/upgrade-subprotocol-case-sensitive",core_ws_validate_upgrade((const uint8_t *)reply,strlen(reply),accept,"Vless-core") < 0);
    snprintf(reply,sizeof(reply),"%sX-Other: value\r\n\r\n",valid); reply[base+12]=0;
    CHECK("ws/upgrade-nul-rejected",core_ws_validate_upgrade((const uint8_t *)reply,base+18,accept,NULL) < 0);
    uint8_t *maximum=malloc(32769); REQUIRE("ws/upgrade-boundary-fixture",maximum != NULL);
    memcpy(maximum,valid,base); memcpy(maximum+base,"X-Pad: ",7);
    memset(maximum+base+7,'x',32768-base-11); memcpy(maximum+32764,"\r\n\r\n",4);
    CHECK("ws/upgrade-header-limit",core_ws_validate_upgrade(maximum,32768,accept,NULL) == 0);
    CHECK("ws/upgrade-excessive-headers",core_ws_validate_upgrade(maximum,32769,accept,NULL) < 0);
    free(maximum);
}

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
    upgrade_vectors();
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
