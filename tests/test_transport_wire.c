#include "check.h"
#include "tls_fixture.h"

int __wrap_RAND_bytes(unsigned char *data,int length) {
    for (int i=0;i<length;i++) data[i]=(unsigned char)i;
    return 1;
}

static void vector(const char *name,const uint8_t *data,size_t length,const char *expected) {
    uint8_t hash[32]; unsigned size=0;
    REQUIRE("wire/sha256",EVP_Digest(data,length,hash,&size,EVP_sha256(),NULL) == 1 && size == 32);
    char encoded[65],scenario[128];
    for (size_t i=0;i<sizeof(hash);i++) snprintf(encoded+2*i,3,"%02x",hash[i]);
    snprintf(scenario,sizeof(scenario),"wire/%s-byte-vector",name);
    CHECK(scenario,!strcmp(encoded,expected));
    printf("WIRE %s %zu ",name,length);
    for (size_t i=0;i<sizeof(hash);i++) printf("%02x",hash[i]);
    putchar('\n');
}

static void head_response_backend(void) {
    vless_config_t config={.transport_mode=TRANSPORT_XHTTP,.server_port=80,.xmux.present=1};
    strcpy(config.server_host,"vless-core.test"); strcpy(config.xhttp_mode,"packet-up");
    strcpy(config.xhttp_uplink_method,"HEAD"); strcpy(config.xhttp_path,"/vless-core");
    tls13_conn_t physical={.mode=CONN_MODE_XHTTP_PLAIN,.fd=-1,.xmux_async=1,.h2_next_stream_id=1};
    uint32_t id; size_t consumed,body; core_xmux_frame_t frame;
    const char *responses[]={"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"};
    for (int role=2;role<=3;role++) for (size_t i=0;i<sizeof(responses)/sizeof(*responses);i++) {
        strcpy(config.xhttp_mode,role == 2 ? "stream-up" : "packet-up");
        REQUIRE("wire/head-request",xmux_transport_request(&physical,&config,"vless-core",i,role,role == 2 ? NULL : (const uint8_t *)"vless-core",role == 2 ? 0 : 10,&id,8192,&consumed,&body) == 0);
        CHECK("wire/head-method-is-sent",physical.xmux_plain_output.len >= 5 && !memcmp(physical.xmux_plain_output.data,"HEAD ",5));
        REQUIRE("wire/head-response-input",db_append(&physical.h2_net_cache,responses[i],strlen(responses[i])) == 0);
        CHECK("wire/head-response-headers",xmux_transport_read_frame(&physical,&frame,8192) == 0 && frame.event == 1 && frame.status == 200);
        int result=xmux_transport_read_frame(&physical,&frame,8192);
        CHECK("wire/head-completes-without-body-or-eof",result == 0 && frame.event == 3 && !physical.xmux_http1_id && !frame.close_connection && !physical.h2_net_cache.len);
        physical.xmux_http1_id=0; db_free(&physical.h2_net_cache); db_free(&physical.xmux_plain_output);
    }
}

static void priority_reset_wire(void) {
    for (int self=0;self<2;self++) {
        int pair[2]; REQUIRE("wire/priority-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t connection={.mode=CONN_MODE_GRPC_PLAIN,.fd=pair[0],.h2_stream_id=1,.h2_next_stream_id=7,.h2_receive_window=65535};
        connection.h2_validation.settings_received=1;
        uint8_t input[]={0,0,4,2,0,0,0,0,3,0,0,0,3,0};
        if (self) input[2]=5;
        REQUIRE("wire/priority-input",db_append(&connection.h2_net_cache,input,self ? sizeof(input) : sizeof(input)-1) == 0);
        uint8_t type,flags,*payload=NULL; uint32_t id; size_t length;
        CHECK("wire/priority-stream-error-does-not-close-connection",h2_read_frame(&connection,&type,&flags,&id,&payload,&length) == 0);
        free(payload);
        uint8_t reset[13]={0}; ssize_t count=recv(pair[1],reset,sizeof(reset),MSG_DONTWAIT);
        CHECK("wire/priority-reset-code",count == 13 && reset[3] == 3 && reset[8] == 3 && reset[12] == (self ? 1 : 6));
        const uint8_t sibling[]={0,0,1,1,4,0,0,0,1,0x88,0,0,10,0,1,0,0,0,1,'v','l','e','s','s','-','c','o','r','e'};
        REQUIRE("wire/priority-sibling-input",db_append(&connection.h2_net_cache,sibling,sizeof(sibling)) == 0);
        CHECK("wire/priority-sibling-response-survives",h2_pump_one_frame(&connection) == 0 && h2_pump_one_frame(&connection) == 0 && connection.app_cache.len == 10 && !memcmp(connection.app_cache.data,"vless-core",10));
        db_free(&connection.h2_net_cache); db_free(&connection.app_cache); db_free(&connection.h2_send_buf); h2_response_clear(&connection); core_hpack_clear(&connection.hpack);
        close(pair[0]); close(pair[1]);
    }
}

static void priority_headers_keep_hpack(void) {
    int pair[2]; REQUIRE("wire/priority-header-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    tls13_conn_t connection={.mode=CONN_MODE_GRPC_PLAIN,.fd=pair[0],.h2_stream_id=3,.h2_next_stream_id=7};
    connection.h2_validation.settings_received=1;
    REQUIRE("wire/priority-header-request",h2_response_get(&connection,1,1) != NULL);
    const uint8_t input[]={0,0,7,1,32,0,0,0,1,0,0,0,1,0,0x88,0x40,0,0,4,9,4,0,0,0,1,1,'x',1,'v',0,0,2,1,4,0,0,0,3,0x88,0xbe};
    REQUIRE("wire/priority-header-input",db_append(&connection.h2_net_cache,input,sizeof(input)) == 0);
    CHECK("wire/priority-header-keeps-continuation",h2_pump_one_frame(&connection) == 0 && connection.h2_validation.continuation == 1);
    uint8_t reset[13]={0}; ssize_t received=recv(pair[1],reset,sizeof(reset),MSG_DONTWAIT);
    CHECK("wire/priority-header-reset-code",received == 13 && reset[3] == 3 && reset[8] == 1 && reset[12] == 1);
    CHECK("wire/priority-header-decodes-closed-stream",h2_pump_one_frame(&connection) == 0 && connection.hpack.count == 1 && !connection.h2_validation.continuation);
    CHECK("wire/priority-header-neighbor-dynamic-index",h2_pump_one_frame(&connection) == 0 && connection.h2_headers_received && !connection.grpc_read_failed);
    char error[128]; CHECK("wire/reset-stream-cannot-send-final-data",h2_send_xhttp_body(&connection,1,NULL,0,error,sizeof(error)) < 0);
    db_free(&connection.h2_net_cache); db_free(&connection.h2_header_block); db_free(&connection.h2_send_buf); h2_response_clear(&connection); core_hpack_clear(&connection.hpack);
    close(pair[0]); close(pair[1]);
}

int main(void) {
    char authority[256];
    const char *invalid_hosts[]={"vless-core.test\r\nX-Audit: injected","bad host","bad\thost","bad\\host","[bad]","[::1]extra","vless-core.test:+80","vless-core.test:"};
    for (size_t i=0;i<sizeof(invalid_hosts)/sizeof(*invalid_hosts);i++)
        CHECK("wire/invalid-authority-rejected",http_host(invalid_hosts[i],authority,sizeof(authority)) < 0);
    CHECK("wire/ipv6-authority-brackets",!http_host("::1",authority,sizeof(authority)) && !strcmp(authority,"[::1]"));
    CHECK("wire/ipv6-authority-port",!http_host("[::1]:65535",authority,sizeof(authority)) && !strcmp(authority,"[::1]:65535"));
    CHECK("wire/dns-authority-port",!http_host("vless_core.test.:00080",authority,sizeof(authority)) && !strcmp(authority,"vless_core.test.:00080"));
    CHECK("wire/authority-capacity",http_host("::1",authority,5) < 0);
    int injected_pair[2]; REQUIRE("wire/host-injection-pair",socketpair(AF_UNIX,SOCK_STREAM,0,injected_pair) == 0);
    tls13_conn_t injected_websocket={.fd=injected_pair[0],.mode=CONN_MODE_WS}; char failure[128];
    strcpy(injected_websocket.ws_path,"/vless-core"); strcpy(injected_websocket.ws_host,"vless-core.test\r\nX-Audit: injected");
    CHECK("wire/upgrade-rejects-host-before-write",ws_upgrade(&injected_websocket,NULL,0,failure,sizeof(failure)) < 0 && !strstr(failure,"injected"));
    uint8_t byte; CHECK("wire/invalid-host-emits-no-request",recv(injected_pair[1],&byte,1,MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    close(injected_pair[0]); close(injected_pair[1]);
    priority_headers_keep_hpack();
    priority_reset_wire();
    head_response_backend();
    tls13_conn_t connection={.mode=CONN_MODE_GRPC_PLAIN,.fd=-1,.xmux_async=1,.h2_stream_id=1};
    strcpy(connection.grpc_service_name,"vless-core"); strcpy(connection.grpc_authority,"vless-core.test");
    strcpy(connection.grpc_user_agent,"vless-core-wire"); strcpy(connection.xhttp_host,"vless-core.test");
    char error[160];
    REQUIRE("wire/grpc-headers",h2_send_grpc_request_headers(&connection,error,sizeof(error)) == 0);
    vector("grpc-gun",connection.xmux_plain_output.data,connection.xmux_plain_output.len,"627b8e416853d59aee4c14fb70153fdff7112d241a37e245a6bac26979d0acf9"); db_free(&connection.xmux_plain_output);
    connection.grpc_multi_mode=1;
    REQUIRE("wire/grpc-multi-headers",h2_send_grpc_request_headers(&connection,error,sizeof(error)) == 0);
    vector("grpc-multi",connection.xmux_plain_output.data,connection.xmux_plain_output.len,"6b127aea39b41faa79d96845aea06c1adec1f088d324cb5d2356fa23a61fdcd8"); db_free(&connection.xmux_plain_output);
    REQUIRE("wire/xhttp-h2-headers",h2_send_xhttp_request_headers(&connection,3,"POST","/vless-core/session","X-vless-core: value\r\nUser-Agent: vless-core-wire\r\n",10,1,0,error,sizeof(error)) == 0);
    vector("xhttp-h2",connection.xmux_plain_output.data,connection.xmux_plain_output.len,"f5bd2274f8312c313c6cb737ddf1e366c456aa2dbd3a94eb54bdc73ce10bd381"); db_free(&connection.xmux_plain_output);
    dynbuf_t request={0};
    REQUIRE("wire/xhttp-h1-headers",xhttp_http1_headers(&connection,"POST","/vless-core/session","X-vless-core: value\r\nUser-Agent: vless-core-wire\r\n",1,10,"keep-alive",&request) == 0);
    vector("xhttp-h1",request.data,request.len,"334deb9518df3f8be14983202a426c102816e7d9bb32e700189662992cca01d9"); db_free(&request);
    int pair[2]; REQUIRE("wire/ws-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    tls13_conn_t websocket={.fd=pair[0],.mode=CONN_MODE_WS};
    REQUIRE("wire/ws-masked-data",ws_write_frame(&websocket,2,(const uint8_t *)"vless-core",10) == 0);
    uint8_t frame[16]; REQUIRE("wire/ws-read",read_exact(pair[1],frame,sizeof(frame)) == 0);
    vector("websocket",frame,sizeof(frame),"4d34156f6b739a282e8d69dc7dcc5ebfe365350c29b29bec9b67541c1b528583"); close(pair[0]); close(pair[1]);
    REQUIRE("wire/backend-send-data",xmux_transport_send_frame(&connection,0,1,3,(const uint8_t *)"vless-core",10) == 0);
    vector("pool-data",connection.xmux_plain_output.data,connection.xmux_plain_output.len,"48e4703359ca9bb4bdd124581188ec4380fae7b2fb65336dbc18b75fc02a18fe"); db_free(&connection.xmux_plain_output);
    db_free(&connection.h2_send_buf);
    return test_result();
}
