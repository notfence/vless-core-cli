#include "http1.h"
#include "check.h"
#include <string.h>

static int transfer(const char *response, size_t fragment, int eof) {
    core_http1_response_t parser={0}; core_http1_event_t event;
    uint8_t cache[512],body[64]; size_t used=0,sent=0,received=0,total=strlen(response); int status=0,finished=0;
    for (size_t iteration=0;iteration<1024;iteration++) {
        if (sent < total) {
            size_t take=total-sent; if (take > fragment) take=fragment;
            memcpy(cache+used,response+sent,take); used+=take; sent+=take;
        }
        int result=core_http1_next(&parser,cache,used,eof && sent == total,3,&event);
        if (result < 0) return -1;
        if (!result && event.kind == 1 && event.status >= 200) status=event.status;
        if (!result && event.kind == 2) {
            if (received+event.length > sizeof(body)) return -1;
            memcpy(body+received,cache+event.offset,event.length); received+=event.length;
        }
        if (!result && event.kind == 3) { finished=1; break; }
        memmove(cache,cache+event.consumed,used-event.consumed); used-=event.consumed;
        if (sent == total && result == 1 && !event.consumed) return -1;
    }
    return finished && status == 200 && received == 10 && !memcmp(body,"vless-core",10) ? 0 : -1;
}

int main(void) {
    const char *cases[]={
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvless-core",
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=v\r\nvles\r\n6\r\ns-core\r\n0\r\nx-trailer: value\r\n\r\n",
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na ; extension = \"vless core\" ; flag\r\nvless-core\r\n0\r\n\r\n",
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(*cases);i++)
        for (size_t fragment=1;fragment<=strlen(cases[i]);fragment++) CHECK("http1/fragmented-complete-response", transfer(cases[i],fragment,1) == 0);
    const char *invalid[]={
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 11\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\nvless-core",
        "HTTP/1.1 101 Switching Protocols\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nContent-Length: 10x\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nx\r\nvless-core\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nvless-core\r\n0\r\nBad trailer\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nvless-core",
        "HTTP/1.1 200 bad\x01reason\r\nContent-Length: 10\r\n\r\nvless-core",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na;bad name\r\nvless-core\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na;key=\"unterminated\r\nvless-core\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nvless-core\r\n0\r\nContent-Length: 10\r\n\r\n",
    };
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) CHECK("http1/reject-malformed-or-truncated-response", transfer(invalid[i],1,1) != 0);
    core_http1_response_t parser={0}; core_http1_event_t event;
    const char *response="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    CHECK("http1/zero-response-headers", core_http1_next(&parser,(const uint8_t *)response,strlen(response),0,0,&event) == 0 && event.kind == 1);
    CHECK("http1/zero-response-fully-drained", core_http1_next(&parser,NULL,0,0,0,&event) == 0 && event.kind == 3 && !event.close_connection);
    const char *heads[]={"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"};
    for (size_t i=0;i<sizeof(heads)/sizeof(*heads);i++) {
        parser=(core_http1_response_t){.head_response=1}; size_t length=strlen(heads[i]);
        for (size_t part=0;part<length;part++) CHECK("http1/head-fragmented-headers",core_http1_next(&parser,(const uint8_t *)heads[i],part,0,8192,&event) == 1 && !event.consumed);
        REQUIRE("http1/head-headers",core_http1_next(&parser,(const uint8_t *)heads[i],length,0,8192,&event) == 0 && event.kind == 1 && event.consumed == length);
        CHECK("http1/head-no-body-with-persistent-connection",core_http1_next(&parser,(const uint8_t *)response,strlen(response),0,8192,&event) == 0 && event.kind == 3 && !event.consumed && !event.close_connection);
        CHECK("http1/head-does-not-consume-next-response",core_http1_next(&parser,(const uint8_t *)response,strlen(response),0,8192,&event) < 0 && !event.consumed);
    }
    parser=(core_http1_response_t){.head_response=1}; const char *interim="HTTP/1.1 103 Early Hints\r\n\r\n";
    REQUIRE("http1/head-interim-headers",core_http1_next(&parser,(const uint8_t *)interim,strlen(interim),0,0,&event) == 0 && event.status == 103 && !parser.state && parser.head_response);
    REQUIRE("http1/head-final-after-interim",core_http1_next(&parser,(const uint8_t *)heads[0],strlen(heads[0]),0,0,&event) == 0);
    CHECK("http1/head-completes-after-interim",core_http1_next(&parser,NULL,0,0,0,&event) == 0 && event.kind == 3);
    return test_result();
}
