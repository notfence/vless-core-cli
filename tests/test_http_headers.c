#include "http_headers.h"
#include "check.h"

static int parse(const char *json, char *output, size_t capacity) {
    char error[256]; core_json_t *object=core_json_parse(json,error,sizeof(error));
    if (!object) return -1;
    int result=core_http_headers_parse(object,output,capacity,error,sizeof(error));
    core_json_free(object); return result;
}

int main(void) {
    char headers[256],previous[256]; size_t length=0;
    CHECK("headers/canonical-order", parse("{\"X-Z\":\"last\",\"X-A\":\"first\"}",headers,sizeof(headers)) == 0 && !strcmp(headers,"x-a: first\r\nx-z: last\r\n"));
    CHECK("headers/equal-case-aliases", parse("{\"X-A\":\"same\",\"x-a\":\"same\"}",headers,sizeof(headers)) == 0 && !strcmp(headers,"x-a: same\r\n"));
    CHECK("headers/conflicting-case-aliases", parse("{\"X-A\":\"first\",\"x-a\":\"second\"}",headers,sizeof(headers)) != 0);
    const char *invalid[]={"[]","{\"x\":1}","{\":authority\":\"x\"}","{\"x a\":\"x\"}","{\"x\":\"a\\r\\nb\"}","{\"x\":\"a\\u007fb\"}","{\"Host\":\"x\"}","{\"Content-Length\":\"7\"}","{\"Transfer-Encoding\":\"chunked\"}","{\"Connection\":\"close\"}","{\"TE\":\"trailers\"}"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) CHECK("headers/invalid-fields-rejected",parse(invalid[i],headers,sizeof(headers)) != 0);
    CHECK("headers/capacity-error-not-truncation",parse("{\"x\":\"vless-core\"}",headers,8) != 0);
    strcpy(headers,"X-A: first\r\nx-a: second\r\nOther: value\r\n");
    CHECK("headers/replace-all-case-aliases",core_http_header_set(headers,sizeof(headers),"x-A","vless-core") == 0 && !strcmp(headers,"Other: value\r\nx-A: vless-core\r\n"));
    strcpy(previous,headers);
    CHECK("headers/insufficient-capacity-preserves-input",core_http_header_set(headers,strlen(headers)+1,"new","value") != 0 && !strcmp(headers,previous));
    CHECK("headers/injection-preserves-input",core_http_header_set(headers,sizeof(headers),"new","value\r\ninjected: yes") != 0 && !strcmp(headers,previous));
    CHECK("headers/invalid-name-preserves-input",core_http_header_set(headers,sizeof(headers),":path","value") != 0 && !strcmp(headers,previous));
    strcpy(headers,"X-A: \t vless-core \t\r\n");
    const char *value=core_http_header_get(headers,"x-a",&length);
    CHECK("headers/get-trims-whitespace",value && length == 10 && !memcmp(value,"vless-core",length));
    CHECK("headers/get-missing",!core_http_header_get(headers,"missing",&length));
    strcpy(headers,"Cookie: custom=enabled\r\n");
    CHECK("headers/append-generated-cookie",core_http_header_append_cookie(headers,sizeof(headers),"session=vless-core") == 0 && !strcmp(headers,"Cookie: custom=enabled; session=vless-core\r\n"));
    CHECK("headers/append-second-generated-cookie",core_http_header_append_cookie(headers,sizeof(headers),"seq=0") == 0 && !strcmp(headers,"Cookie: custom=enabled; session=vless-core; seq=0\r\n"));
    strcpy(previous,headers);
    CHECK("headers/cookie-capacity-preserves-input",core_http_header_append_cookie(headers,strlen(headers)+1,"seq=1") != 0 && !strcmp(headers,previous));
    return test_result();
}
