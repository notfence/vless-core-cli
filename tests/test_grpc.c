#include "check.h"
#include "grpc.h"
#include "uri.h"

static int decode(const uint8_t *input, size_t size, size_t step, size_t *total) {
    core_grpc_decoder_t decoder={0}; *total=0;
    for (size_t offset=0;offset<size;) {
        size_t consumed=0,length=0,take=size-offset < step ? size-offset : step;
        const uint8_t *payload;
        int result=core_grpc_decode(&decoder,input+offset,take,&consumed,&payload,&length);
        if (result < 0) return -1;
        if (!consumed || consumed > take) return -2;
        *total+=length; offset+=consumed;
    }
    return core_grpc_complete(&decoder) ? 0 : 1;
}

int main(void) {
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
    for (size_t step=1;step<sizeof(message);step++) CHECK("grpc/streaming-repeated-fields",decode(message,sizeof(message),step,&payload) == 0 && payload == 7);
    for (size_t cut=1;cut<19;cut++) CHECK("grpc/truncated-message",decode(message,cut,1,&payload) != 0);
    const uint8_t invalid[][12]={{1,0,0,0,0},{0,1,0,0,1},{0,0,0,0,1,0},{0,0,0,0,2,10,100},{0,0,0,0,1,15},{0,0,0,0,1,128}};
    const size_t sizes[]={5,5,6,7,6,6};
    for (size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++) CHECK("grpc/malformed-message",decode(invalid[i],sizes[i],1,&payload) < 0);
    core_grpc_decoder_t decoder={0}; size_t consumed=0,length=0; const uint8_t *data;
    const uint8_t large[]={0,1,0,0,0,10,0xfb,0xff,0xff,7,'x'};
    CHECK("grpc/large-message-streamed",core_grpc_decode(&decoder,large,sizeof(large),&consumed,&data,&length) == 1 && length == 1 && data[0] == 'x' && consumed == sizeof(large));
    CHECK("grpc/bounded-decoder-memory",sizeof(decoder) < 128);
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
