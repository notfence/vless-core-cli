#include "xhttp_payload.h"
#include "xhttp_config.h"
#include "utils.h"
#include "check.h"
#include <stdlib.h>
#include <stdint.h>

int __real_RAND_bytes(unsigned char *, int);
static int controlled_random;
static uint32_t next_random;
int __wrap_RAND_bytes(unsigned char *output, int length) {
    if (!controlled_random) return __real_RAND_bytes(output,length);
    if (controlled_random < 0 || length != (int)sizeof(next_random)) return 0;
    uint32_t value=controlled_random == 2 ? next_random : controlled_random == 3 ? next_random++ : 130+next_random++; memcpy(output,&value,sizeof(value)); return 1;
}

static size_t payload_values(const char *headers, const char *key, int cookie, char *output, size_t capacity) {
    size_t used=0;
    for (size_t index=0;;index++) {
        char name[128]; snprintf(name,sizeof(name),cookie ? "%s_%zu=" : "%s-%zu: ",key,index);
        const char *value=strstr(headers,name);
        if (!value) break;
        value+=strlen(name); size_t length=strcspn(value,cookie ? ";\r\n" : "\r\n");
        if (length >= capacity-used) return 0;
        memcpy(output+used,value,length); used+=length;
    }
    output[used]=0; return used;
}

int main(void) {
    uint64_t due;
    controlled_random=2; next_random=101;
    CHECK("xhttp/interval-zero-endpoint",core_xhttp_post_due((core_range_t){0,100},1000,1001,&due) == 0 && due == 1001);
    next_random=201;
    CHECK("xhttp/interval-upper-endpoint",core_xhttp_post_due((core_range_t){0,100},1000,1001,&due) == 0 && due == 1100);
    CHECK("xhttp/interval-does-not-restart-elapsed-time",core_xhttp_post_due((core_range_t){0,100},1000,2000,&due) == 0 && due == 2000);
    CHECK("xhttp/interval-upper-endpoint-overflow",core_xhttp_post_due((core_range_t){0,100},UINT64_MAX-50,UINT64_MAX-49,&due) < 0);
    next_random=UINT32_MAX;
    CHECK("xhttp/interval-maximum-range",core_xhttp_post_due((core_range_t){0,INT32_MAX},1000,1001,&due) == 0 && due == UINT64_C(2147484647));
    controlled_random=-1;
    CHECK("xhttp/interval-rng-failure",core_xhttp_post_due((core_range_t){0,100},1000,1001,&due) < 0);
    CHECK("xhttp/interval-first-post-needs-no-randomness",core_xhttp_post_due((core_range_t){0,100},0,1001,&due) == 0 && due == 1001);
    controlled_random=3; next_random=0;
    CHECK("xhttp/interval-rejects-biased-random-values",core_xhttp_post_due((core_range_t){0,100},1000,1001,&due) == 0 && due == 1068 && next_random == 69);
    CHECK("xhttp/interval-invalid-input",core_xhttp_post_due((core_range_t){-1,100},1000,1001,&due) < 0 && core_xhttp_post_due((core_range_t){100,0},1000,1001,&due) < 0 && core_xhttp_post_due((core_range_t){0,100},1000,1001,NULL) < 0);
    controlled_random=0;
    uint8_t bytes[65535]; for (size_t i=0;i<sizeof(bytes);i++) bytes[i]=(uint8_t)i;
    char error[160]; core_xhttp_payload_t packet;
    core_xhttp_payload_options_t options={.placement="header",.key="vless-core",.chunks={64,64}};
    CHECK("xhttp/payload-base64url-no-padding", core_xhttp_payload_build(&options,(uint8_t[]){255,255},2,"",4096,&packet,error,sizeof(error)) == 0 && !strcmp(packet.headers,"vless-core-0: __8\r\n") && packet.consumed == 2 && !packet.body_size);
    free(packet.headers);
    options.placement="cookie";
    CHECK("xhttp/payload-cookie-vector", core_xhttp_payload_build(&options,(uint8_t[]){255},1,"Cookie: x_session=vless-core\r\n",4096,&packet,error,sizeof(error)) == 0 && !strcmp(packet.headers,"Cookie: x_session=vless-core\r\nCookie: vless-core_0=_w\r\n"));
    free(packet.headers);
    const size_t lengths[]={1,2,3,63,64,65,1023,1024,1025,4093,sizeof(bytes)};
    for (int cookie=0;cookie<2;cookie++) {
        options.placement=cookie ? "cookie" : "header";
        for (size_t i=0;i<sizeof(lengths)/sizeof(*lengths);i++) {
            size_t offset=0;
            while (offset < lengths[i]) {
                REQUIRE("xhttp/payload-build-fragments", core_xhttp_payload_build(&options,bytes+offset,lengths[i]-offset,"X-Session: vless-core\r\n",8192,&packet,error,sizeof(error)) == 0);
                CHECK("xhttp/payload-header-budget-and-progress", packet.consumed > 0 && packet.consumed <= lengths[i]-offset && strlen(packet.headers) < 8192 && !packet.body_size && !strncmp(packet.headers,"X-Session: vless-core\r\n",23));
                char encoded[8192]; uint8_t decoded[8192]; size_t decoded_length;
                REQUIRE("xhttp/payload-ordered-chunks", payload_values(packet.headers,options.key,cookie,encoded,sizeof(encoded)) > 0 && !strchr(encoded,'='));
                CHECK("xhttp/payload-roundtrip-without-loss", base64url_decode(encoded,decoded,sizeof(decoded),&decoded_length) == 0 && decoded_length == packet.consumed && !memcmp(decoded,bytes+offset,decoded_length));
                offset+=packet.consumed; free(packet.headers);
            }
        }
    }
    options.placement="body";
    CHECK("xhttp/payload-body-unchanged", core_xhttp_payload_build(&options,bytes,sizeof(bytes),"X-Session: vless-core\r\n",4096,&packet,error,sizeof(error)) == 0 && packet.consumed == sizeof(bytes) && packet.body_size == sizeof(bytes) && !strcmp(packet.headers,"X-Session: vless-core\r\n")); free(packet.headers);
    options.placement="auto";
    CHECK("xhttp/payload-auto-is-body", core_xhttp_payload_build(&options,bytes,1,"",4096,&packet,error,sizeof(error)) == 0 && packet.body_size == 1); free(packet.headers);
    options.placement="header"; options.key="bad\r\nkey";
    CHECK("xhttp/payload-injection-rejected", core_xhttp_payload_build(&options,bytes,1,"",4096,&packet,error,sizeof(error)) != 0 && !packet.headers);
    options.key="vless-core";
    CHECK("xhttp/payload-insufficient-header-budget", core_xhttp_payload_build(&options,bytes,1,"X: vless-core\r\n",32,&packet,error,sizeof(error)) != 0 && !packet.headers);
    CHECK("xhttp/payload-invalid-prefix", core_xhttp_payload_build(&options,bytes,1,"bad\n",4096,&packet,error,sizeof(error)) != 0);
    options.chunks=(core_range_t){1,1};
    CHECK("xhttp/payload-minimum-chunk-normalized", core_xhttp_payload_build(&options,bytes,100,"",4096,&packet,error,sizeof(error)) == 0 && strstr(packet.headers,"vless-core-2:")); free(packet.headers);
    options.chunks=(core_range_t){64,128};
    controlled_random=1; next_random=0;
    REQUIRE("xhttp/payload-random-chunks-built",core_xhttp_payload_build(&options,bytes,8000,"",65536,&packet,error,sizeof(error)) == 0);
    size_t first=0; int varied=0;
    for (size_t index=0;;index++) {
        char name[80]; snprintf(name,sizeof(name),"vless-core-%zu: ",index);
        const char *chunk=strstr(packet.headers,name); if (!chunk) break;
        chunk+=strlen(name); size_t size=strcspn(chunk,"\r\n");
        if (!strstr(chunk+size+2,"vless-core-")) break;
        CHECK("xhttp/payload-each-chunk-in-range",size >= 64 && size <= 128);
        if (!index) first=size; else if (size != first) varied=1;
    }
    CHECK("xhttp/payload-resamples-each-chunk",varied); free(packet.headers);
    controlled_random=-1;
    CHECK("xhttp/payload-random-failure-propagated",core_xhttp_payload_build(&options,bytes,1,"",65536,&packet,error,sizeof(error)) != 0 && !packet.headers);
    controlled_random=0;
    return test_result();
}
