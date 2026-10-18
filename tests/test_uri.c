#include "check.h"
#include "uri.h"
#include "utils.h"
#include "server_ips.h"
#include "xhttp_config.h"
#include <openssl/evp.h>
#include <arpa/inet.h>

#define PREFIX "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?"
#define PBK "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
static vless_config_t config;
static char error[256];
static int parse(const char *uri) { return parse_core_uri(uri, &config, error, sizeof(error)); }

static void check_xmux_empty_ranges(void) {
    const char *names[]={"maxConcurrency","maxConnections","cMaxReuseTimes","hMaxRequestTimes","hMaxReusableSecs"};
    const char *example="{\"xmux\":{\"maxConcurrency\":\"\",\"maxConnections\":3,\"cMaxReuseTimes\":0,\"hMaxRequestTimes\":\"600-900\",\"hMaxReusableSecs\":\"1800-3000\",\"hKeepAlivePeriod\":0}}";
    vless_config_t settings; core_config_defaults(&settings);
    CHECK("xmux/3x-ui-empty-range",!core_xhttp_extra(&settings,example,error,sizeof(error)) && settings.xmux.present && !settings.xmux.max_concurrency.max && settings.xmux.max_connections.min == 3 && settings.xmux.max_connections.max == 3 && !settings.xmux.reuse_times.max && settings.xmux.request_times.min == 600 && settings.xmux.request_times.max == 900 && settings.xmux.reusable_secs.min == 1800 && settings.xmux.reusable_secs.max == 3000 && !settings.xmux.keep_alive_period);
    for (size_t i=0;i<5;i++) {
        char json[512]; vless_config_t blank,zero;
        core_config_defaults(&blank); core_config_defaults(&zero);
        snprintf(json,sizeof(json),"{\"xmux\":{\"hKeepAlivePeriod\":-1,\"%s\":\"\"}}",names[i]);
        int result=core_xhttp_extra(&blank,json,error,sizeof(error));
        snprintf(json,sizeof(json),"{\"xmux\":{\"hKeepAlivePeriod\":-1,\"%s\":0}}",names[i]);
        CHECK("xmux/empty-range-equivalent-to-zero",!result && !core_xhttp_extra(&zero,json,error,sizeof(error)) && !memcmp(&blank.xmux,&zero.xmux,sizeof(blank.xmux)) && blank.xmux.present);
    }
    core_config_defaults(&settings);
    CHECK("xmux/all-empty-ranges-preserve-defaults",!core_xhttp_extra(&settings,"{\"xmux\":{\"maxConcurrency\":\"\",\"maxConnections\":\"\",\"cMaxReuseTimes\":\"\",\"hMaxRequestTimes\":\"\",\"hMaxReusableSecs\":\"\",\"hKeepAlivePeriod\":0}}",error,sizeof(error)) && settings.xmux.present && settings.xmux.max_connections.min == 6 && settings.xmux.request_times.min == 600 && settings.xmux.reusable_secs.min == 1800);
    for (unsigned connections=1;connections<=4;connections++) {
        char json[160]; core_config_defaults(&settings);
        snprintf(json,sizeof(json),"{\"xmux\":{\"maxConcurrency\":\"\",\"maxConnections\":%u}}",connections);
        CHECK("xmux/explicit-connection-limit-not-hardcoded",!core_xhttp_extra(&settings,json,error,sizeof(error)) && settings.xmux.max_connections.min == (int)connections && settings.xmux.max_connections.max == (int)connections);
    }
    core_config_defaults(&settings);
    CHECK("xmux/normalized-alias-duplicates",!core_xhttp_extra(&settings,"{\"xmux\":{\"maxConcurrency\":\"\",\"MaxConcurrency\":0,\"maxConnections\":2}}",error,sizeof(error)));
    const char *invalid[]={"{\"xmux\":{\"hKeepAlivePeriod\":\"\"}}","{\"xmux\":{\"maxConcurrency\":\" \"}}","{\"xmux\":{\"maxConnections\":null}}","{\"xmux\":{\"cMaxReuseTimes\":false}}","{\"xmux\":{\"hMaxRequestTimes\":\"-\"}}","{\"xmux\":{\"hMaxReusableSecs\":\"18446744073709551616\"}}","{\"xmux\":{\"maxConcurrency\":\"\",\"MaxConcurrency\":1}}","{\"xmux\":{\"maxConcurrency\":\"\",\"maxConcurrency\":0}}","{\"xmux\":{\"maxConcurrency\":1,\"maxConnections\":3}}","{\"xPaddingBytes\":\"\"}","{\"scMinPostsIntervalMs\":\"\"}"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        core_config_defaults(&settings);
        CHECK("xmux/empty-range-does-not-weaken-validation",core_xhttp_extra(&settings,invalid[i],error,sizeof(error)) < 0 && error[0]);
    }
    CHECK("uri/xmux-empty-range-startup",!parse(PREFIX "type=xhttp&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%22%22%2C%22maxConnections%22%3A3%7D%7D") && config.xmux.present && config.xmux.max_connections.max == 3);
}

static void check_session_identifier_space(void) {
    vless_config_t settings={0}; char identifier[256],failure[128];
    strcpy(settings.xhttp_mode,"packet-up"); strcpy(settings.xhttp_session_placement,"header");
    strcpy(settings.xhttp_session_id_table,"AAAAAAAA"); settings.xhttp_session_id_length_min=settings.xhttp_session_id_length_max=16;
    CHECK("xhttp/session-identical-symbols-do-not-inflate-space",core_xhttp_validate(&settings,failure,sizeof(failure)) < 0 && strstr(failure,"space"));
    CHECK("xhttp/session-degenerate-alphabet-is-not-generated",core_xhttp_session(&settings,identifier,sizeof(identifier)) < 0 && !identifier[0]);
    settings.xhttp_session_id_length_min=1; settings.xhttp_session_id_length_max=255;
    CHECK("xhttp/session-single-symbol-variable-length-is-too-small",core_xhttp_validate(&settings,failure,sizeof(failure)) < 0);
    strcpy(settings.xhttp_session_id_table,"AAAB"); settings.xhttp_session_id_length_min=settings.xhttp_session_id_length_max=30;
    CHECK("xhttp/session-distinct-symbols-below-boundary",core_xhttp_validate(&settings,failure,sizeof(failure)) < 0);
    settings.xhttp_session_id_length_min=settings.xhttp_session_id_length_max=31;
    CHECK("xhttp/session-distinct-symbols-exact-boundary",core_xhttp_validate(&settings,failure,sizeof(failure)) == 0);
    CHECK("xhttp/session-repeated-symbols-remain-usable",core_xhttp_session(&settings,identifier,sizeof(identifier)) == 0 && strlen(identifier) == 31 && strspn(identifier,"AB") == 31 && !strcmp(settings.xhttp_session_id_table,"AAAB"));
    settings.xhttp_session_id_length_min=1; settings.xhttp_session_id_length_max=30;
    CHECK("xhttp/session-length-range-below-boundary",core_xhttp_validate(&settings,failure,sizeof(failure)) < 0);
    settings.xhttp_session_id_length_max=31;
    CHECK("xhttp/session-length-range-reaches-boundary",core_xhttp_validate(&settings,failure,sizeof(failure)) == 0);
    memset(settings.xhttp_session_id_table,'A',255); settings.xhttp_session_id_table[254]='B'; settings.xhttp_session_id_table[255]=0;
    settings.xhttp_session_id_length_min=settings.xhttp_session_id_length_max=30;
    CHECK("xhttp/session-long-repeated-table-still-has-two-symbols",core_xhttp_validate(&settings,failure,sizeof(failure)) < 0);
    settings.xhttp_session_id_length_min=settings.xhttp_session_id_length_max=255;
    CHECK("xhttp/session-space-saturates-without-overflow",core_xhttp_validate(&settings,failure,sizeof(failure)) == 0);
    CHECK("uri/session-degenerate-table-rejected",parse(PREFIX "type=xhttp&extra=%7B%22sessionIDTable%22%3A%22AAAAAAAA%22%2C%22sessionIDLength%22%3A16%7D") < 0 && strstr(error,"space"));
}

static void check_session_identifiers(void) {
    check_session_identifier_space();
    vless_config_t settings={0}; char identifier[256];
    strcpy(settings.xhttp_mode,"packet-up"); strcpy(settings.xhttp_session_placement,"header");
    CHECK("xhttp/default-session-uuid", core_xhttp_session(&settings,identifier,sizeof(identifier)) == 0 && strlen(identifier) == 36 && identifier[14] == '4' && strchr("89ab",identifier[19]));
    CHECK("xhttp/session-capacity-no-truncation", core_xhttp_session(&settings,identifier,36) != 0);
    const char *names[]={"ALPHABET","Alphabet","BASE36","Base62","HEX","alphabet","base36","hex","number"};
    const char *alphabets[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZ","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz","0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ","0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz","0123456789ABCDEF","abcdefghijklmnopqrstuvwxyz","0123456789abcdefghijklmnopqrstuvwxyz","0123456789abcdef","0123456789"};
    settings.xhttp_session_id_length_min=16; settings.xhttp_session_id_length_max=32;
    for (size_t i=0;i<sizeof(names)/sizeof(*names);i++) {
        strcpy(settings.xhttp_session_id_table,names[i]);
        for (int attempt=0;attempt<8;attempt++) {
            REQUIRE("xhttp/session-table-generation", core_xhttp_session(&settings,identifier,sizeof(identifier)) == 0);
            CHECK("xhttp/session-range-and-characters", strlen(identifier) >= 16 && strlen(identifier) <= 32 && strspn(identifier,alphabets[i]) == strlen(identifier));
        }
    }
    settings.xhttp_session_id_length_min=settings.xhttp_session_id_length_max=255;
    CHECK("xhttp/session-maximum-size", core_xhttp_session(&settings,identifier,sizeof(identifier)) == 0 && strlen(identifier) == 255);
    CHECK("xhttp/session-too-small-buffer", core_xhttp_session(&settings,identifier,255) != 0);
    strcpy(settings.xhttp_mode,"stream-one");
    CHECK("xhttp/stream-one-no-session", core_xhttp_session(&settings,identifier,sizeof(identifier)) == 0 && !identifier[0]);
}

static void check_base64(void) {
    const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint8_t bytes[8], expected[8];
    size_t length;
    const char *malformed[]={"A","A=","A===","AA=","AA===","AAA==","AAAA=","=","====","Zg===","Zh","Zh==","Zm9","Zm9="};
    for (size_t i=0;i<sizeof(malformed)/sizeof(*malformed);i++) CHECK("utils/base64-canonical-padding-and-bits",base64url_decode(malformed[i],bytes,sizeof(bytes),&length) != 0);
    for (unsigned final=0;final<64;final++) {
        char encoded2[]={ 'A',alphabet[final],0 },encoded3[]={ 'A','A',alphabet[final],0 };
        CHECK("utils/base64-unused-four-bits",(base64url_decode(encoded2,bytes,sizeof(bytes),&length) == 0) == !(final&15));
        CHECK("utils/base64-unused-two-bits",(base64url_decode(encoded3,bytes,sizeof(bytes),&length) == 0) == !(final&3));
    }
    char target[32];
    CHECK("utils/request-target-components",core_request_target("/a b?x=%2f#tag",target,sizeof(target)) == 0 && !strcmp(target,"/a%20b?x=%2f%23tag"));
    CHECK("utils/request-target-exact-capacity",core_request_target("/a b",target,7) == 0 && !strcmp(target,"/a%20b"));
    memset(target,'x',sizeof(target));
    CHECK("utils/request-target-overflow-does-not-write",core_request_target("/a b",target,6) < 0 && target[0] == 'x' && target[6] == 'x');
    CHECK("utils/request-path-query-only",core_http_path("?x=a b",target,sizeof(target),1) == 0 && !strcmp(target,"/?x=a%20b"));
    CHECK("utils/request-target-controls",core_request_target("/a\rb",target,sizeof(target)) < 0 && core_request_target("/a\nb",target,sizeof(target)) < 0);
    for (unsigned value = 1; value <= 255; value++) {
        if (strchr(alphabet, (int)value) || value == '=') continue;
        for (size_t position = 0; position < 4; position++) {
            char input[] = "AAAA";
            input[position] = (char)value;
            length = sizeof(bytes);
            CHECK("utils/base64-reject-every-nonalphabet-byte", base64url_decode(input, bytes, sizeof(bytes), &length) != 0 && length == sizeof(bytes));
        }
    }
    for (unsigned value = 1; value <= 255; value++) {
        if (value == '=') continue;
        char input[] = "AA==x";
        input[4] = (char)value;
        CHECK("utils/base64-reject-data-after-padding", base64url_decode(input, bytes, sizeof(bytes), &length) != 0);
    }
    for (size_t value = 0; value < 64; value++) {
        for (size_t position = 0; position < 4; position++) {
            char input[] = "AAAA", standard[] = "AAAA";
            input[position] = alphabet[value];
            standard[position] = value == 62 ? '+' : value == 63 ? '/' : alphabet[value];
            int expected_length = EVP_DecodeBlock(expected, (unsigned char *)standard, 4);
            CHECK("utils/base64-preserve-every-alphabet-value", expected_length == 3 && base64url_decode(input, bytes, sizeof(bytes), &length) == 0 && length == 3 && memcmp(bytes, expected, length) == 0);
        }
    }
    const char *encoded[] = {"", "Zg", "Zg==", "Zm8", "Zm8=", "Zm9v"};
    const char *plain[] = {"", "f", "f", "fo", "fo", "foo"};
    for (size_t i = 0; i < sizeof(encoded) / sizeof(*encoded); i++) {
        CHECK("utils/base64-preserve-padded-and-unpadded", base64url_decode(encoded[i], bytes, sizeof(bytes), &length) == 0 && length == strlen(plain[i]) && memcmp(bytes, plain[i], length) == 0);
    }
    CHECK("utils/base64-exact-capacity", base64url_decode("Zm9v", bytes, 3, &length) == 0 && length == 3 && memcmp(bytes, "foo", 3) == 0);
    CHECK("utils/base64-capacity-rejected", base64url_decode("Zm9v", bytes, 2, &length) != 0);
    CHECK("utils/base64-null", base64url_decode(NULL, bytes, sizeof(bytes), &length) != 0 && base64url_decode("AA", NULL, sizeof(bytes), &length) != 0 && base64url_decode("AA", bytes, sizeof(bytes), NULL) != 0);

    const size_t lengths[] = {4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1182, 1183, 1184, 4096};
    uint8_t source[4096], decoded[4096];
    char long_encoded[4 * ((sizeof(source) + 2) / 3) + 1];
    for (unsigned pattern = 0; pattern < 4; pattern++) {
        for (size_t i = 0; i < sizeof(source); i++) {
            source[i] = pattern == 0 ? 0 : pattern == 1 ? 255 : pattern == 2 ? (i % 2 ? 0x55 : 0xaa) : (uint8_t)i;
        }
        for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); i++) {
            int encoded_length = EVP_EncodeBlock((unsigned char *)long_encoded, source, (int)lengths[i]);
            REQUIRE("utils/base64-reference-encoding", encoded_length == (int)(4 * ((lengths[i] + 2) / 3)));
            for (int j = 0; j < encoded_length; j++) {
                if (long_encoded[j] == '+') long_encoded[j] = '-';
                if (long_encoded[j] == '/') long_encoded[j] = '_';
            }
            CHECK("utils/base64-long-padded-roundtrip", base64url_decode(long_encoded, decoded, lengths[i], &length) == 0 && length == lengths[i] && memcmp(decoded, source, length) == 0);
            while (encoded_length > 0 && long_encoded[encoded_length - 1] == '=') long_encoded[--encoded_length] = '\0';
            CHECK("utils/base64-long-unpadded-roundtrip", base64url_decode(long_encoded, decoded, lengths[i], &length) == 0 && length == lengths[i] && memcmp(decoded, source, length) == 0);
            CHECK("utils/base64-long-capacity-rejected", base64url_decode(long_encoded, decoded, lengths[i] - 1, &length) != 0);
        }
    }
}

int main(void) {
    check_xmux_empty_ranges();
    const char *invalid_options[]={
        "{\"sessionIDPlacement\":\"invalid\"}","{\"seqPlacement\":\"invalid\"}","{\"xPaddingPlacement\":\"invalid\"}","{\"xPaddingMethod\":\"invalid\"}",
        "{\"sessionIDPlacement\":\"header\",\"sessionIDKey\":\"Host\"}","{\"seqPlacement\":\"header\",\"seqKey\":\"Content-Length\"}","{\"xPaddingHeader\":\"Transfer-Encoding\"}",
        "{\"sessionIDPlacement\":\"cookie\",\"sessionIDKey\":\"bad key\"}","{\"seqPlacement\":\"cookie\",\"seqKey\":\"bad;key\"}",
        "{\"sessionIDPlacement\":\"header\",\"sessionIDKey\":\"X-Same\",\"seqPlacement\":\"header\",\"seqKey\":\"x-same\"}",
        "{\"sessionIDPlacement\":\"query\",\"sessionIDKey\":\"same\",\"seqPlacement\":\"query\",\"seqKey\":\"same\"}",
        "{\"sessionIDPlacement\":\"header\",\"sessionIDKey\":\"Cookie\",\"seqPlacement\":\"cookie\"}",
        "{\"uplinkDataPlacement\":\"header\",\"headers\":{\"X-Data-0\":\"vless-core\"}}",
        "{\"uplinkHTTPMethod\":\"OPTIONS\"}","{\"noGRPCHeader\":1}","{\"noSSEHeader\":1}","{\"scMaxBufferedPosts\":true}","{\"scStreamUpServerSecs\":\"20-junk\"}","{\"serverMaxHeaderBytes\":-1}",
        "{\"xmux\":{\"maxConnections\":1,\"MaxConnections\":2}}",
        "{\"sessionIDPlacement\":\"cookie\",\"headers\":{\"Cookie\":\"x_session=old\"}}",
        "{\"seqPlacement\":\"cookie\",\"headers\":{\"Cookie\":\"x_seq=old\"}}",
        "{\"uplinkDataPlacement\":\"cookie\",\"headers\":{\"Cookie\":\"x_data_0=old\"}}",
        "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"header\",\"xPaddingHeader\":\"X-Session\",\"sessionIDPlacement\":\"header\"}",
        "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"query\",\"xPaddingKey\":\"x_session\",\"sessionIDPlacement\":\"query\"}",
        "{\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"cookie\",\"xPaddingKey\":\"x_session\",\"sessionIDPlacement\":\"cookie\"}",
        "{\"uplinkDataPlacement\":\"header\",\"sessionIDPlacement\":\"header\",\"sessionIDKey\":\"X-Data-0\"}",
        "{\"uplinkDataPlacement\":\"header\",\"seqPlacement\":\"header\",\"seqKey\":\"X-Data-1\"}",
        "{\"uplinkDataPlacement\":\"cookie\",\"sessionIDPlacement\":\"cookie\",\"sessionIDKey\":\"x_data_0\"}",
        "{\"uplinkDataPlacement\":\"cookie\",\"seqPlacement\":\"cookie\",\"seqKey\":\"x_data_1\"}",
        "{\"uplinkDataPlacement\":\"header\",\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"header\",\"xPaddingHeader\":\"X-Data-0\"}",
        "{\"uplinkDataPlacement\":\"cookie\",\"xPaddingObfsMode\":true,\"xPaddingPlacement\":\"cookie\",\"xPaddingKey\":\"x_data_0\"}",
    };
    for (size_t i=0;i<sizeof(invalid_options)/sizeof(*invalid_options);i++) {
        char encoded[2048],uri[4096]; size_t used=0; const char *hex="0123456789ABCDEF";
        for (const unsigned char *p=(const unsigned char *)invalid_options[i];*p;p++) { encoded[used++]='%'; encoded[used++]=hex[*p>>4]; encoded[used++]=hex[*p&15]; } encoded[used]=0;
        snprintf(uri,sizeof(uri),PREFIX "type=xhttp&mode=packet-up&extra=%s",encoded);
        CHECK("uri/invalid-xhttp-options-fail-before-connect",parse(uri) != 0 && error[0]);
    }
    CHECK("uri/xhttp-nonindexed-header-metadata-allowed",parse(PREFIX "type=xhttp&mode=packet-up&uplinkDataPlacement=header&sessionIDPlacement=header&sessionIDKey=X-Data-Index") == 0);
    CHECK("uri/xhttp-cookie-key-case-preserved",parse(PREFIX "type=xhttp&mode=packet-up&uplinkDataPlacement=cookie&sessionIDPlacement=cookie&sessionIDKey=x_DATA_0") == 0);
    CHECK("uri/xhttp-custom-payload-key-independent",parse(PREFIX "type=xhttp&mode=packet-up&uplinkDataPlacement=header&uplinkDataKey=X-Segment&sessionIDPlacement=header&sessionIDKey=X-Data-0") == 0);
    CHECK("uri/xhttp-body-does-not-reserve-payload-headers",parse(PREFIX "type=xhttp&mode=packet-up&uplinkDataPlacement=body&sessionIDPlacement=header&sessionIDKey=X-Data-0") == 0);
    CHECK("uri/server-only-fields-recognized",parse(PREFIX "type=xhttp&extra=%7B%22noSSEHeader%22%3Atrue%2C%22scMaxBufferedPosts%22%3A30%2C%22scStreamUpServerSecs%22%3A%2220-80%22%2C%22serverMaxHeaderBytes%22%3A16384%7D") == 0);
    uint64_t due;
    CHECK("xhttp/first-packet-not-delayed",core_xhttp_post_due((core_range_t){100,100},0,1000,&due) == 0 && due == 1000);
    CHECK("xhttp/default-packet-interval",core_xhttp_post_due((core_range_t){0,0},1000,1001,&due) == 0 && due == 1030);
    CHECK("xhttp/explicit-packet-interval",core_xhttp_post_due((core_range_t){120,120},1000,1001,&due) == 0 && due == 1120);
    CHECK("xhttp/zero-minimum-interval-in-range",core_xhttp_post_due((core_range_t){0,100},1000,1001,&due) == 0 && due >= 1001 && due <= 1100);
    CHECK("xhttp/elapsed-interval-not-restarted",core_xhttp_post_due((core_range_t){120,120},1000,2000,&due) == 0 && due == 2000);
    CHECK("xhttp/interval-overflow-rejected",core_xhttp_post_due((core_range_t){120,120},UINT64_MAX-1,UINT64_MAX,&due) != 0);
    vless_config_t sized={0}; sized.xhttp_max_each_post_min=64; sized.xhttp_max_each_post_max=256;
    for (int attempt=0;attempt<100;attempt++) { int size=core_xhttp_post_limit(&sized); CHECK("xhttp/packet-limit-sampled-in-range",size >= 64 && size <= 256); }
    check_session_identifiers();
    check_base64();
    CHECK("uri/tcp-defaults", parse(PREFIX "type=tcp") == 0 && strcmp(config.security, "none") == 0 && config.flow[0] == 0 && config.fp_mode == FP_CHROME);
    const char *unsupported[]={"type=http","type=quic","type=not-a-transport","fp=safari","fp=not-a-fingerprint","allowInsecure=maybe","sid=zz","type=ws&flow=invalid","type=xhttp&flow=invalid"};
    for (size_t i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++) {
        char value[512]; snprintf(value,sizeof(value),PREFIX "%s",unsupported[i]); CHECK("uri/unsupported-value-rejected",parse(value) != 0);
    }
    CHECK("uri/raw-alias",parse(PREFIX "type=raw") == 0 && config.transport_mode == TRANSPORT_VISION);
    const char *bounded[]={"sni","flow","security","alpn","servicename","authority","spx"};
    const size_t capacities[]={sizeof(config.sni),sizeof(config.flow),sizeof(config.security),sizeof(config.alpn),sizeof(config.grpc_service_name),sizeof(config.grpc_authority),sizeof(config.spider_x)};
    for (size_t i=0;i<sizeof(bounded)/sizeof(*bounded);i++) {
        char value[1024]; int prefix=snprintf(value,sizeof(value),PREFIX "%s=",bounded[i]);
        memset(value+prefix,'a',capacities[i]); value[prefix+capacities[i]]=0;
        CHECK("uri/field-overflow-rejected",parse(value) != 0 && strstr(error,bounded[i]));
    }
    const char *types[] = {"tcp", "ws", "xhttp", "grpc"};
    const char *securities[] = {"none", "tls", "reality"};
    const char *flows[] = {"", "xtls-rprx-vision", "invalid"};
    for (size_t t = 0; t < 4; t++) for (size_t s = 0; s < 3; s++) for (size_t f = 0; f < 3; f++) {
        char uri[1024], name[160];
        snprintf(uri, sizeof(uri), PREFIX "type=%s&security=%s&flow=%s&pbk=" PBK "&sid=01", types[t], securities[s], flows[f]);
        snprintf(name, sizeof(name), "uri/matrix/%s/%s/flow%zu", types[t], securities[s], f);
        int accepted = f != 2 && !(t == 1 && s == 2) && !(t == 0 && s == 0 && f != 0);
        CHECK(name, (parse(uri) == 0) == accepted);
        if (accepted && t > 0) CHECK("uri/non-tcp-flow-cleared", config.flow[0] == 0);
    }
    const char *invalid[] = {
        "", "http://127.0.0.1", "vless://bad@host:443", "vless://00000000-0000-0000-0000-000000000001@host:0",
        PREFIX "security=reality", PREFIX "security=unknown", PREFIX "flow=xtls-rprx-vision",
        PREFIX "type=tcp&network=ws", PREFIX "allowInsecure=1&insecure=0", PREFIX "TYPE=tcp&%74ype=ws",
        PREFIX "sni=%00", PREFIX "sni=%0a", PREFIX "sni=%ff", PREFIX "sni=%ed%a0%80", PREFIX "sni=%",
        PREFIX "=x", PREFIX "sni=a&", PREFIX "a", PREFIX "type=ws&security=reality",
        PREFIX "type=xhttp&mode=bad", PREFIX "type=grpc&mode=bad", PREFIX "encryption=bad",
        PREFIX "type=xhttp&mode=stream-up&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%7D",
        PREFIX "type=xhttp&mode=stream-one&extra=%7B%22uplinkDataPlacement%22%3A%22header%22%7D", "socks5://host:0", "socks5://[::1"
    };
    for (size_t t=0;t<4;t++) for (size_t s=0;s<3;s++) {
        char value[1024];
        snprintf(value,sizeof(value),"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?encryption=mlkem768x25519plus.native.0rtt." PBK "&type=%s&security=%s&flow=xtls-rprx-vision&pbk=" PBK "&sid=01",types[t],securities[s]);
        int result=parse(value);
        CHECK("uri/encryption-vision-supported-transports",t == 1 && s == 2 ? result < 0 : result == 0 && !strcmp(config.flow,"xtls-rprx-vision") && config.encryption_enabled);
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        char name[80]; snprintf(name, sizeof(name), "uri/reject/%zu", i); CHECK(name, parse(invalid[i]) != 0);
    }
    CHECK("uri/empty-security", parse(PREFIX "security=") == 0 && strcmp(config.security, "none") == 0);
    CHECK("uri/xhttp-auto-plain", parse(PREFIX "type=xhttp") == 0 && strcmp(config.xhttp_mode, "packet-up") == 0);
    CHECK("uri/xhttp-auto-tls", parse(PREFIX "type=xhttp&security=tls") == 0 && strcmp(config.xhttp_mode, "packet-up") == 0);
    CHECK("uri/xhttp-auto-reality", parse(PREFIX "type=xhttp&security=reality&pbk=" PBK) == 0 && strcmp(config.xhttp_mode, "stream-one") == 0);
    const char *fps[] = {"chrome", "random", "qq", "randomized", "firefox", "edge"};
    for (int i = 0; i < 6; i++) { char uri[512]; snprintf(uri, sizeof(uri), PREFIX "fp=%s", fps[i]); CHECK("uri/fingerprint", parse(uri) == 0 && config.fp_mode == (fingerprint_mode_t)i); }
    CHECK("uri/ipv6", parse("vless://00000000-0000-0000-0000-000000000001@[::1]:443") == 0 && strcmp(config.server_host, "::1") == 0);
    CHECK("uri/socks-default", parse("socks5://127.0.0.1#vless-core") == 0 && config.protocol == CORE_PROTOCOL_SOCKS5 && config.server_port == 1080);
    CHECK("uri/socks-auth", parse("socks5://vless%2Dcore:p%40ss@[::1]:1081#vless-core") == 0 && strcmp(config.socks5_user, "vless-core") == 0 && strcmp(config.socks5_pass, "p@ss") == 0);
    CHECK("uri/socks-tls-not-supported",parse("socks5://127.0.0.1:1080?security=tls") < 0 && strstr(error,"security"));
    CHECK("uri/socks-reality-not-supported",parse("socks5://127.0.0.1:1080?security=reality") < 0 && strstr(error,"security"));
    CHECK("uri/socks-security-unknown",parse("socks5://127.0.0.1:1080?security=unknown") < 0 && strstr(error,"security"));
    CHECK("uri/socks-duplicate-query",parse("socks5://127.0.0.1:1080?security=none&security=none") < 0 && strstr(error,"duplicate"));
    CHECK("uri/socks-does-not-apply-transport-settings",parse("socks5://127.0.0.1:1080?security=NONE&network=xhttp&flow=invalid&allowInsecure=true&extra=not-json") == 0 && config.protocol == CORE_PROTOCOL_SOCKS5 && config.transport_mode == TRANSPORT_VISION && !config.flow[0] && !config.allow_insecure && !strcmp(config.security,"none"));
    CHECK("uri/socks-fragment-does-not-contain-settings",parse("socks5://127.0.0.1:1080#vless-core?security=tls") == 0);
    CHECK("uri/extra", parse(PREFIX "type=xhttp&extra=%7B%22sessionPlacement%22%3A%22header%22%2C%22seqKey%22%3A%22X-vless-core%22%2C%22xPaddingBytes%22%3A%2210-20%22%2C%22scMaxEachPostBytes%22%3A%222000%22%7D") == 0 && strcmp(config.xhttp_session_placement, "header") == 0 && strcmp(config.xhttp_seq_key, "X-vless-core") == 0 && config.xhttp_padding_min == 10 && config.xhttp_padding_max == 20 && config.xhttp_max_each_post_min == 2000);
    CHECK("uri/ws-escaped-request-target",parse(PREFIX "type=ws&path=%2Fvless%20core%2F%D1%82%D0%B5%D1%81%D1%82%3Fx%3D%252F") == 0 && !strcmp(config.xhttp_path,"/vless%20core/%D1%82%D0%B5%D1%81%D1%82?x=%2F"));
    CHECK("uri/xhttp-escaped-request-target",parse(PREFIX "type=xhttp&path=%2Fvless%20core%3Fx%3Da%20b") == 0 && !strcmp(config.xhttp_path,"/vless%20core?x=a%20b"));
    char boundary_uri[2048],boundary_path[256]; memset(boundary_path,'x',sizeof(boundary_path)-1); boundary_path[sizeof(boundary_path)-1]=0;
    snprintf(boundary_uri,sizeof(boundary_uri),PREFIX "type=xhttp&path=%s",boundary_path);
    CHECK("uri/plain-path-capacity-preserved",parse(boundary_uri) == 0 && strlen(config.xhttp_path) == 255);
    memset(boundary_path,' ',85); boundary_path[85]=0;
    snprintf(boundary_uri,sizeof(boundary_uri),PREFIX "type=ws&path=%s",boundary_path);
    CHECK("uri/escaped-path-exact-capacity",parse(boundary_uri) == 0 && strlen(config.xhttp_path) == 255);
    boundary_path[85]=' '; boundary_path[86]=0;
    snprintf(boundary_uri,sizeof(boundary_uri),PREFIX "type=ws&path=%s",boundary_path);
    CHECK("uri/escaped-path-capacity-error",parse(boundary_uri) < 0 && strstr(error,"path"));
    const char *bad_path[]={"%2Fbad%25","%2Fbad%252","%2Fbad%25xx","%2Fbad%2500","%2Fbad%250D","%2Fbad%250a"};
    for (size_t i=0;i<sizeof(bad_path)/sizeof(*bad_path);i++) {
        char input[1024]; snprintf(input,sizeof(input),PREFIX "type=ws&path=%s",bad_path[i]);
        CHECK("uri/ws-invalid-request-target",parse(input) != 0 && strstr(error,"path"));
        snprintf(input,sizeof(input),PREFIX "type=xhttp&path=%s",bad_path[i]);
        CHECK("uri/xhttp-invalid-request-target",parse(input) != 0 && strstr(error,"path"));
    }
    CHECK("uri/extra-invalid-json", parse(PREFIX "type=xhttp&extra=%7B%22sessionPlacement%22%3A%22header%22") != 0);
    CHECK("uri/extra-nested-field-is-not-root", parse(PREFIX "type=xhttp&extra=%7B%22unknown%22%3A%7B%22sessionPlacement%22%3A%22header%22%7D%7D") == 0 && !strcmp(config.xhttp_session_placement,"path"));
    CHECK("uri/extra-explicit-priority-before", parse(PREFIX "type=xhttp&x_padding_bytes=10-20&extra=%7B%22xPaddingBytes%22%3A%2230-40%22%7D") == 0 && config.xhttp_padding_min == 10 && config.xhttp_padding_max == 20);
    CHECK("uri/extra-explicit-priority-after", parse(PREFIX "type=xhttp&extra=%7B%22xPaddingBytes%22%3A%2230-40%22%7D&x_padding_bytes=10-20") == 0 && config.xhttp_padding_min == 10 && config.xhttp_padding_max == 20);
    CHECK("uri/extra-escaped-name", parse(PREFIX "type=xhttp&extra=%7B%22session%5Cu0050lacement%22%3A%22header%22%7D") == 0 && !strcmp(config.xhttp_session_placement,"header"));
    CHECK("uri/extra-known-invalid-range", parse(PREFIX "type=xhttp&extra=%7B%22xPaddingBytes%22%3A%2210junk%22%7D") != 0);
    CHECK("uri/extra-conflicting-aliases", parse(PREFIX "type=xhttp&extra=%7B%22sessionPlacement%22%3A%22header%22%2C%22sessionIDPlacement%22%3A%22cookie%22%7D") != 0);
    CHECK("uri/extra-equal-aliases", parse(PREFIX "type=xhttp&extra=%7B%22sessionPlacement%22%3A%22header%22%2C%22sessionIDPlacement%22%3A%22header%22%7D") == 0);
    CHECK("uri/extra-xmux-defaults", parse(PREFIX "type=xhttp&extra=%7B%22xmux%22%3A%7B%7D%7D") == 0 && config.xmux.present && config.xmux.max_connections.min == 6 && config.xmux.request_times.min == 600);
    CHECK("uri/extra-xmux-absent", parse(PREFIX "type=xhttp") == 0 && !config.xmux.present);
    CHECK("uri/custom-header-query-priority-before", parse(PREFIX "type=xhttp&headers=%7B%22X-vless-core%22%3A%22query%22%7D&noGRPCHeader=1&extra=%7B%22headers%22%3A%7B%22X-vless-core%22%3A%22extra%22%7D%2C%22noGRPCHeader%22%3Afalse%7D") == 0 && !strcmp(config.xhttp_headers,"x-vless-core: query\r\n") && config.xhttp_no_grpc_header);
    CHECK("uri/custom-header-query-priority-after", parse(PREFIX "type=xhttp&extra=%7B%22headers%22%3A%7B%22X-vless-core%22%3A%22extra%22%7D%2C%22noGRPCHeader%22%3Afalse%7D&headers=%7B%22X-vless-core%22%3A%22query%22%7D&noGRPCHeader=1") == 0 && !strcmp(config.xhttp_headers,"x-vless-core: query\r\n") && config.xhttp_no_grpc_header);
    CHECK("uri/custom-header-framing-rejected", parse(PREFIX "type=xhttp&extra=%7B%22headers%22%3A%7B%22Content-Length%22%3A%227%22%7D%7D") != 0);
    CHECK("uri/custom-header-pseudo-rejected", parse(PREFIX "type=xhttp&extra=%7B%22headers%22%3A%7B%22%3Aauthority%22%3A%22vless-core%22%7D%7D") != 0);
    CHECK("uri/custom-header-value-type", parse(PREFIX "type=xhttp&extra=%7B%22headers%22%3A%7B%22X-vless-core%22%3A7%7D%7D") != 0);
    CHECK("uri/custom-header-case-conflict", parse(PREFIX "type=xhttp&extra=%7B%22headers%22%3A%7B%22X-vless-core%22%3A%22a%22%2C%22x-vless-core%22%3A%22b%22%7D%7D") != 0);
    CHECK("uri/session-table-requires-positive-length", parse(PREFIX "type=xhttp&extra=%7B%22sessionIDTable%22%3A%22Base62%22%2C%22sessionIDLength%22%3A%220-16%22%7D") != 0);
    CHECK("uri/session-table-too-little-room", parse(PREFIX "type=xhttp&extra=%7B%22sessionIDTable%22%3A%22number%22%2C%22sessionIDLength%22%3A2%7D") != 0);
    CHECK("uri/session-table-known-type", parse(PREFIX "type=xhttp&extra=%7B%22sessionIDTable%22%3A7%2C%22sessionIDLength%22%3A16%7D") != 0);
    CHECK("uri/extra-xmux-conflict", parse(PREFIX "type=xhttp&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A2%2C%22maxConnections%22%3A2%7D%7D") != 0);
    CHECK("uri/extra-xmux-types", parse(PREFIX "type=xhttp&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%222-5%22%2C%22cMaxReuseTimes%22%3A7%2C%22hKeepAlivePeriod%22%3A-1%7D%7D") == 0 && config.xmux.max_concurrency.min == 2 && config.xmux.max_concurrency.max == 5 && config.xmux.reuse_times.min == 7 && config.xmux.keep_alive_period == -1);
    const char *modes[] = {"native", "xorpub", "random"};
    const char *rtts[] = {"0rtt", "1rtt"};
    for (int m = 0; m < 3; m++) for (int r = 0; r < 2; r++) {
        char uri[1024]; snprintf(uri, sizeof(uri), PREFIX "encryption=mlkem768x25519plus.%s.%s." PBK, modes[m], rtts[r]);
        CHECK("uri/encryption-mode", parse(uri) == 0 && config.encryption_enabled && config.encryption_xor_mode == m && config.encryption_relay_count == 1 && config.encryption_relays[0].key_len == 32);
    }
    uint8_t key[1184] = {1}; char encoded[1600]; EVP_EncodeBlock((unsigned char *)encoded, key, sizeof(key));
    for (size_t i = 0; encoded[i]; i++) { if (encoded[i] == '+') encoded[i] = '-'; if (encoded[i] == '/') encoded[i] = '_'; if (encoded[i] == '=') { encoded[i] = 0; break; } }
    char long_uri[5000]; snprintf(long_uri, sizeof(long_uri), PREFIX "encryption=mlkem768x25519plus.native.1rtt.%s", encoded);
    CHECK("uri/mlkem-relay", parse(long_uri) == 0 && config.encryption_relays[0].key_len == 1184);
    snprintf(long_uri, sizeof(long_uri), PREFIX "encryption=mlkem768x25519plus.native.1rtt." PBK "." PBK "." PBK "." PBK);
    CHECK("uri/four-relays", parse(long_uri) == 0 && config.encryption_relay_count == 4);
    strcat(long_uri, "." PBK); CHECK("uri/too-many-relays", parse(long_uri) != 0);
    memset(long_uri, 'a', CORE_URI_MAX_LENGTH + 1); long_uri[CORE_URI_MAX_LENGTH + 1] = 0;
    CHECK("uri/length-limit", parse(long_uri) != 0);
    CHECK("uri/null", parse_core_uri(NULL, &config, error, sizeof(error)) != 0);
    CHECK("uri/invalid-base64-reality-key", parse(PREFIX "security=reality&pbk=!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") != 0);
    CHECK("uri/invalid-base64-encryption-key", parse(PREFIX "encryption=mlkem768x25519plus.native.1rtt.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") != 0);
    CHECK("server-ips/order-deduplicate", core_set_server_ips(" 127.0.0.2 ,127.0.0.1,127.0.0.2\t") == 0 && core_server_ip_count() == 2);
    struct in_addr ip; inet_pton(AF_INET, "127.0.0.2", &ip);
    CHECK("server-ips/first", core_server_ip_at(0)->s_addr == ip.s_addr && core_server_ip_at(2) == NULL);
    const char *bad_ips[] = {"", "127.0.0.1,", ",127.0.0.1", "127.0.0.1,,127.0.0.2", "host", "[::1]", "999.0.0.1", "127.0.0.1\n"};
    for (size_t i = 0; i < sizeof(bad_ips) / sizeof(*bad_ips); i++) CHECK("server-ips/reject-atomic", core_set_server_ips(bad_ips[i]) != 0 && core_server_ip_count() == 2);
    char maximum_ips[1024] = "";
    for (int i = 0; i < 64; i++) { char value[32]; snprintf(value, sizeof(value), "%s127.0.0.%d", i ? "," : "", i+1); strcat(maximum_ips,value); }
    CHECK("server-ips/maximum", core_set_server_ips(maximum_ips) == 0 && core_server_ip_count() == 64);
    strcat(maximum_ips, ",127.0.0.65"); CHECK("server-ips/overflow-atomic", core_set_server_ips(maximum_ips) != 0 && core_server_ip_count() == 64);
    CHECK("server-ips/ipv6-mixed-deduplicate", core_set_server_ips("::1,127.0.0.1,0:0:0:0:0:0:0:1") == 0 && core_server_ip_count() == 2);
    uint8_t bytes[32]; size_t length = 0; char decoded[64];
    CHECK("utils/uuid", parse_uuid("00000000-0000-0000-0000-000000000001", bytes) == 0 && bytes[15] == 1);
    CHECK("utils/hex", hex_to_bytes("00ff10", bytes, sizeof(bytes), &length) == 0 && length == 3 && bytes[1] == 255);
    CHECK("utils/hex-invalid", hex_to_bytes("0", bytes, sizeof(bytes), &length) != 0 && hex_to_bytes("zz", bytes, sizeof(bytes), &length) != 0);
    CHECK("utils/percent", percent_decode("vless%2Dcore+test", decoded, sizeof(decoded)) == 0 && strcmp(decoded, "vless-core test") == 0);
    CHECK("utils/percent-overflow", percent_decode("1234", decoded, 4) != 0);
    CHECK("utils/base64-invalid", base64url_decode("!!!!", bytes, sizeof(bytes), &length) != 0);
    return test_result();
}
