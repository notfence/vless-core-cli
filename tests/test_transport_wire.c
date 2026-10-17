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

int main(void) {
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
