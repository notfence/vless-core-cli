#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "../src/tls13_reality.c"
#include "uri.h"
#include <sys/wait.h>
static int io_failure;
ssize_t __real_write(int fd, const void *data, size_t size);
int __real_fsync(int fd);
int __real_rename(const char *source, const char *destination);
ssize_t __wrap_write(int fd, const void *data, size_t size) { if (io_failure == 1) { io_failure = 0; errno = EIO; return -1; } return __real_write(fd, data, size); }
int __wrap_fsync(int fd) { if (io_failure == 2) { io_failure = 0; errno = EIO; return -1; } return __real_fsync(fd); }
int __wrap_rename(const char *source, const char *destination) { if (io_failure == 3) { io_failure = 0; errno = EIO; return -1; } return __real_rename(source, destination); }
static void clear_conn(tls13_conn_t *c) {
    h2_response_clear(c);
    db_free(&c->tls_post_handshake); db_free(&c->tls_client_hello); db_free(&c->tls_certificate_message);
    X509_free(c->tls_peer_certificate); c->tls_peer_certificate=NULL; EVP_PKEY_free(c->tls_retry_key); c->tls_retry_key=NULL;
    db_free(&c->h2_net_cache); db_free(&c->h2_send_buf); db_free(&c->app_cache); db_free(&c->transcript);
    db_free(&c->ws_net_cache); db_free(&c->xhttp_net_cache);
    db_free(&c->xmux_raw_input); db_free(&c->xmux_wire_output); db_free(&c->xmux_plain_output);
    db_free(&c->h2_header_block);
    core_hpack_clear(&c->hpack);
}

static int request_header_value(const uint8_t *block, size_t length, const char *key, const char *expected) {
    size_t offset=0; int found=0;
    while (offset < length) {
        uint32_t index; uint8_t first=block[offset];
        if (first & 128) { if (core_hpack_decode_int(block,length,&offset,7,&index) != 0) return -1; continue; }
        if (first != 0) return -1;
        offset++; char name[128],value[1024]; size_t size;
        if (core_hpack_read_string(block,length,&offset,name,sizeof(name),&size) != 0 || core_hpack_read_string(block,length,&offset,value,sizeof(value),&size) != 0) return -1;
        if (!strcmp(name,key)) { if (strcmp(value,expected)) return -1; found++; }
    }
    return found;
}

static void custom_request_headers(void) {
    char padding[2048];
    CHECK("xhttp/tokenish-padding-is-not-repeat-x",random_xpadding_value(100,100,"tokenish",padding,sizeof(padding)) == 0 && strspn(padding,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == strlen(padding) && strspn(padding,"X") != strlen(padding));
    CHECK("xhttp/padding-zero-minimum-preserved",random_xpadding_value(0,1,"repeat-x",padding,sizeof(padding)) == 0 && strlen(padding) <= 1);
    core_deadline_t deadline; REQUIRE("xhttp/interval-deadline-attachment",core_deadline_attach(&deadline) == 0);
    core_deadline_begin(5); tls13_conn_t delayed={.xhttp_post_intervals={100,100},.xhttp_last_post_ms=core_now_ms()}; char wait_error[160];
    CHECK("xhttp/interval-shares-connection-budget",xhttp_wait_post(&delayed,wait_error,sizeof(wait_error)) != 0 && errno == ETIMEDOUT);
    core_deadline_end(); core_deadline_detach();
    for (int no_grpc=0;no_grpc<2;no_grpc++) {
        tls13_conn_t connection={.mode=CONN_MODE_XHTTP_TLS_H2,.xmux_async=1,.xhttp_no_grpc_header=no_grpc};
        strcpy(connection.xhttp_host,"vless-core.test"); char error[160];
        REQUIRE("xhttp/custom-http2-request",h2_send_xhttp_request_headers(&connection,3,"PUT","/vless-core/","X-vless-core: enabled\r\nUser-Agent: custom\r\nContent-Type: application/vless-core\r\n",0,1,1,error,sizeof(error)) == 0);
        const uint8_t *block=connection.xmux_plain_output.data+9; size_t length=connection.xmux_plain_output.len-9;
        CHECK("xhttp/custom-http2-header-delivered",request_header_value(block,length,"x-vless-core","enabled") == 1);
        CHECK("xhttp/custom-user-agent-not-duplicated",request_header_value(block,length,"user-agent","custom") == 1);
        CHECK("xhttp/http2-method-delivered",request_header_value(block,length,":method","PUT") == 1);
        CHECK("xhttp/http2-grpc-header-policy",request_header_value(block,length,"content-type",no_grpc ? "application/vless-core" : "application/grpc") == 1);
        db_free(&connection.xmux_plain_output); db_free(&connection.h2_send_buf);
    }
}
static void hpack_status_vectors(void) {
    static const struct { uint8_t data[5]; size_t size; int status; } cases[] = {
        {{0x48,0x82,0x10,0x01},4,200},
        {{0x48,0x82,0x64,0x02},4,302},
        {{0x48,0x83,0x68,0x0c,0xff},5,403},
        {{0x48,0x83,0x68,0x4f,0xff},5,429},
        {{0x48,0x83,0x6c,0x0c,0xff},5,503},
    };
    tls13_conn_t connection = {.h2_stream_id=1};
    char error[160];
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        CHECK("h2/huffman-status", core_hpack_status(cases[i].data,cases[i].size) == cases[i].status);
        for (int grpc = 0; grpc <= 1; grpc++) {
            h2_response_clear(&connection); connection.h2_headers_received=connection.h2_stream_eof=0;
            connection.grpc_transport = grpc;
            error[0] = 0;
            dynbuf_t header={0};
            REQUIRE("h2/status-fixture",db_append(&header,cases[i].data,cases[i].size) == 0);
            if (grpc) REQUIRE("h2/grpc-status-content-type",hpack_append_literal_new_name(&header,"content-type","application/grpc") == 0);
            int result = h2_process_headers(&connection,H2_FLAG_END_HEADERS,1,header.data,header.len,error,sizeof(error));
            db_free(&header);
            CHECK("h2/huffman-status-result", cases[i].status == 200 ? result == 0 : result < 0);
            if (cases[i].status != 200) {
                char expected[32]; snprintf(expected,sizeof(expected),"non-200: %d",cases[i].status);
                CHECK("h2/huffman-status-diagnostic", strstr(error,expected) != NULL && strstr(error,grpc ? "grpc" : "xhttp") != NULL);
            }
        }
    }
    const uint8_t named[] = {0,0x85,0xb8,0x84,0x8d,0x36,0xa3,0x83,0x68,0x0c,0xff};
    CHECK("h2/huffman-status-name", core_hpack_status(named,sizeof(named)) == 403);
    uint8_t literal[] = {0x48,0x82,0x10,0x01};
    for (unsigned prefix = 0; prefix < 3; prefix++) {
        literal[0] = (const uint8_t[]){0x48,0x08,0x18}[prefix];
        CHECK("h2/huffman-literal-representations", core_hpack_status(literal,sizeof(literal)) == 200);
    }
    for (unsigned index = 8; index <= 14; index++) {
        literal[0] = 0x40 | index;
        CHECK("h2/literal-static-status-names", core_hpack_status(literal,sizeof(literal)) == 200);
    }
    const uint8_t new_name[] = {0x40,0x85,0xb8,0x84,0x8d,0x36,0xa3,3,'2','0','0'};
    CHECK("h2/huffman-indexed-new-name", core_hpack_status(new_name,sizeof(new_name)) == 200);
    const uint8_t rfc[] = {
        0x48,0x82,0x64,0x02,0x58,0x85,0xae,0xc3,0x77,0x1a,0x4b,0x61,0x96,0xd0,0x7a,0xbe,
        0x94,0x10,0x54,0xd4,0x44,0xa8,0x20,0x05,0x95,0x04,0x0b,0x81,0x66,0xe0,0x82,0xa6,
        0x2d,0x1b,0xff,0x6e,0x91,0x9d,0x29,0xad,0x17,0x18,0x63,0xc7,0x8f,0x0b,0x97,0xc8,
        0xe9,0xae,0x82,0xae,0x43,0xd3,
    };
    CHECK("h2/rfc7541-response", core_hpack_status(rfc,sizeof(rfc)) == 302);
    for (size_t cut = 1; cut < sizeof(cases[2].data); cut++) {
        CHECK("h2/huffman-truncated-status", core_hpack_status(cases[2].data,cut) < 0);
    }
    static const struct { uint8_t data[10]; size_t size; } malformed[] = {
        {{0x48,0x81,0xff},3},
        {{0x48,0x84,0xff,0xff,0xff,0xff},6},
        {{0x48,0x82,0x10,0x00},4},
        {{0x48,4,'2','0','0','0'},6},
        {{0x48,3,'2',0,'0'},5},
        {{0x48,3,'2','x','0'},5},
        {{0x48,3,'0','9','9'},5},
        {{0x48,0},2},
        {{0x88,0x88},2},
        {{0x88,0x80},2},
        {{0x88,0x40,0x81,0xff,0},5},
        {{0xff,0xff,0xff,0xff,0xff,0x10},6},
    };
    for (size_t i = 0; i < sizeof(malformed)/sizeof(malformed[0]); i++) {
        CHECK("h2/malformed-status-block", core_hpack_status(malformed[i].data,malformed[i].size) < 0);
        error[0] = 0;
        CHECK("h2/malformed-header-diagnostic", h2_process_headers(&connection,H2_FLAG_END_HEADERS,1,malformed[i].data,malformed[i].size,error,sizeof(error)) < 0 && strstr(error,"invalid h2") != NULL);
        clear_conn(&connection); connection.h2_headers_received=connection.h2_stream_eof=0;
    }
    const uint8_t trailer[] = {0,11,'g','r','p','c','-','s','t','a','t','u','s',1,'0'};
    const uint8_t grpc_headers[]="\x88\x00\x0c" "content-type\x10" "application/grpc";
    REQUIRE("h2/trailer-initial-response",h2_process_headers(&connection,H2_FLAG_END_HEADERS,1,grpc_headers,sizeof(grpc_headers)-1,error,sizeof(error)) == 0);
    CHECK("h2/statusless-trailers", core_hpack_status(trailer,sizeof(trailer)) == 0 && h2_process_headers(&connection,H2_FLAG_END_HEADERS|H2_FLAG_END_STREAM,1,trailer,sizeof(trailer),error,sizeof(error)) == 0);
    const uint8_t long_name[] = {0,8,':','s','t','a','t','u','s','x',4,'2','0','0','0'};
    CHECK("h2/status-name-not-truncated", core_hpack_status(long_name,sizeof(long_name)) < 0);
    clear_conn(&connection); connection.h2_headers_received=connection.h2_stream_eof=0;
    uint8_t wrapped[16] = {2,0,0,0,0,0};
    memcpy(wrapped+6,cases[2].data,cases[2].size);
    CHECK("h2/padded-priority-huffman-status", h2_process_headers(&connection,H2_FLAG_END_HEADERS|H2_FLAG_PADDED|H2_FLAG_PRIORITY,1,wrapped,6+cases[2].size+2,error,sizeof(error)) < 0 && strstr(error,"non-200: 403") != NULL);
    const uint8_t maximum[] = {0xff,0x80,0xff,0xff,0xff,0x0f}; size_t off = 0; uint32_t value = 0;
    CHECK("h2/integer-uint32-maximum", core_hpack_decode_int(maximum,sizeof(maximum),&off,7,&value) == 0 && value == UINT32_MAX && off == sizeof(maximum));
    clear_conn(&connection);
}
static void hpack_huffman_vectors(void) {
    const uint8_t missing_dynamic[] = {0xbe};
    CHECK("h2/missing-dynamic-index", core_hpack_status(missing_dynamic, sizeof(missing_dynamic)) < 0);
    const uint8_t oversized_table[] = {0x3f,0xe2,0x1f};
    CHECK("h2/oversized-dynamic-table", core_hpack_status(oversized_table, sizeof(oversized_table)) < 0);
    const uint8_t alphabet[] = {
        0xff,0xc7,0xff,0xfd,0x8f,0xff,0xff,0xe2,0xff,0xff,0xfe,0x3f,0xff,0xff,0xe4,0xff,
        0xff,0xfe,0x5f,0xff,0xff,0xe6,0xff,0xff,0xfe,0x7f,0xff,0xff,0xe8,0xff,0xff,0xea,
        0xff,0xff,0xff,0xf3,0xff,0xff,0xfa,0x7f,0xff,0xff,0xab,0xff,0xff,0xff,0xdf,0xff,
        0xff,0xeb,0xff,0xff,0xfe,0xcf,0xff,0xff,0xed,0xff,0xff,0xfe,0xef,0xff,0xff,0xef,
        0xff,0xff,0xff,0x0f,0xff,0xff,0xf1,0xff,0xff,0xff,0x2f,0xff,0xff,0xff,0xbf,0xff,
        0xff,0xcf,0xff,0xff,0xfd,0x3f,0xff,0xff,0xd7,0xff,0xff,0xfd,0xbf,0xff,0xff,0xdf,
        0xff,0xff,0xfe,0x3f,0xff,0xff,0xe7,0xff,0xff,0xfe,0xbf,0xff,0xff,0xed,0x4f,0xe3,
        0xf9,0xff,0xaf,0xfc,0xab,0xf1,0xfe,0xbf,0xaf,0xef,0xe7,0xfd,0xfd,0x2c,0xbb,0x00,
        0x08,0x99,0x69,0xb7,0x1d,0x79,0xfb,0x9f,0x7f,0xff,0x20,0xff,0xbf,0xf3,0xff,0x50,
        0xdd,0xbd,0x7f,0x06,0x1c,0x58,0xf2,0x65,0xcd,0x9f,0x46,0x9d,0x5a,0xf6,0x6d,0xdd,
        0xbf,0x87,0x1e,0x5f,0x9c,0xff,0x7f,0xf7,0xff,0xfc,0x3f,0xf9,0xff,0xe4,0x5f,0xff,
        0x47,0x19,0x24,0x2c,0xb3,0x4e,0x6e,0x9d,0x68,0xa6,0xa3,0xd7,0xda,0xc4,0x26,0xde,
        0xfe,0x3c,0xfa,0xf7,0xff,0xfb,0xfe,0x7f,0xfb,0xff,0xdf,0xff,0xff,0xfc,0xff,0xfe,
        0x6f,0xff,0xf4,0xbf,0xff,0x9f,0xff,0xfa,0x3f,0xff,0xd3,0xff,0xff,0x53,0xff,0xfd,
        0x5f,0xff,0xfb,0x3f,0xff,0xeb,0x7f,0xff,0xda,0xff,0xff,0xb7,0xff,0xff,0x73,0xff,
        0xfe,0xef,0xff,0xfd,0xef,0xff,0xfe,0xbf,0xff,0xfb,0xff,0xff,0xfd,0x9f,0xff,0xfd,
        0xbf,0xff,0xeb,0xff,0xff,0xe0,0xff,0xff,0xee,0xff,0xff,0xc3,0xff,0xff,0x8b,0xff,
        0xff,0x1f,0xff,0xfe,0x4f,0xff,0xee,0x7f,0xff,0xb1,0xff,0xff,0x97,0xff,0xfd,0x9f,
        0xff,0xfc,0xdf,0xff,0xf9,0xff,0xff,0xfb,0xff,0xff,0xda,0xff,0xfe,0xef,0xff,0xf4,
        0xff,0xff,0xb7,0xff,0xfe,0xe7,0xff,0xfe,0x8f,0xff,0xfd,0x3f,0xff,0xde,0xff,0xff,
        0xd5,0xff,0xfe,0xef,0xff,0xfb,0xdf,0xff,0xfe,0x1f,0xff,0xdf,0xff,0xff,0x7f,0xff,
        0xff,0x5f,0xff,0xfe,0xcf,0xff,0xf0,0x7f,0xff,0x87,0xff,0xfe,0x0f,0xff,0xf1,0x7f,
        0xff,0xed,0xff,0xff,0x87,0xff,0xff,0x77,0xff,0xfe,0xff,0xff,0xea,0xff,0xff,0x8b,
        0xff,0xfe,0x3f,0xff,0xf9,0x3f,0xff,0xf8,0x7f,0xff,0xcb,0xff,0xff,0x37,0xff,0xff,
        0x1f,0xff,0xff,0x83,0xff,0xff,0xe1,0xff,0xfe,0xbf,0xff,0xe3,0xff,0xff,0x3f,0xff,
        0xff,0x2f,0xff,0xfa,0x3f,0xff,0xfd,0x9f,0xff,0xff,0x17,0xff,0xff,0xc7,0xff,0xff,
        0xf2,0x7f,0xff,0xfd,0xef,0xff,0xff,0xbf,0xff,0xff,0xf2,0xff,0xff,0xf8,0xff,0xff,
        0xfb,0x7f,0xff,0x97,0xff,0xf8,0xff,0xff,0xfe,0x6f,0xff,0xff,0xc1,0xff,0xff,0xf8,
        0x7f,0xff,0xfe,0x7f,0xff,0xff,0xc5,0xff,0xff,0xe5,0xff,0xfe,0x4f,0xff,0xf2,0xff,
        0xff,0xfd,0x1f,0xff,0xff,0x4f,0xff,0xff,0xfe,0xff,0xff,0xfe,0x3f,0xff,0xff,0xc9,
        0xff,0xff,0xf9,0x7f,0xff,0xb3,0xff,0xff,0xcf,0xff,0xfb,0x7f,0xff,0xcd,0xff,0xff,
        0x4f,0xff,0xf9,0xff,0xff,0xd1,0xff,0xff,0xcf,0xff,0xfe,0xaf,0xff,0xfa,0xff,0xff,
        0xfd,0xdf,0xff,0xfe,0xff,0xff,0xff,0x4f,0xff,0xff,0x5f,0xff,0xff,0xab,0xff,0xff,
        0xa7,0xff,0xff,0xd7,0xff,0xff,0xf9,0xbf,0xff,0xfe,0xcf,0xff,0xff,0xb7,0xff,0xff,
        0xf3,0xff,0xff,0xfe,0x8f,0xff,0xff,0xd3,0xff,0xff,0xfa,0xbf,0xff,0xff,0x5f,0xff,
        0xff,0xff,0x7f,0xff,0xfe,0xcf,0xff,0xff,0xdb,0xff,0xff,0xfb,0xbf,0xff,0xff,0x7f,
        0xff,0xff,0xf0,0xff,0xff,0xfb,0xbf,
    };
    char output[258]; size_t length = 0;
    CHECK("h2/huffman-full-alphabet", core_hpack_decode_huffman(alphabet,sizeof(alphabet),output,257,&length) == 0 && length == 256 && output[256] == 0);
    for (unsigned i = 0; i < 256; i++) CHECK("h2/huffman-symbol-integrity", (uint8_t)output[i] == i);
    for (size_t cap = 0; cap <= 257; cap++) {
        memset(output,0x55,sizeof(output));
        CHECK("h2/huffman-bounded-output", core_hpack_decode_huffman(alphabet,sizeof(alphabet),output,cap,&length) == 0 && length == 256 && output[cap] == 0x55 && (cap == 0 || output[cap-1] == 0));
    }
    CHECK("h2/huffman-skip-output", core_hpack_decode_huffman(alphabet,sizeof(alphabet),NULL,0,&length) == 0 && length == 256);
    uint8_t repeated[320] = {0};
    CHECK("h2/huffman-expands", core_hpack_decode_huffman(repeated,sizeof(repeated),output,33,&length) == 0 && length == 512 && output[32] == 0);
    for (unsigned i = 0; i < 32; i++) CHECK("h2/huffman-expanded-prefix", output[i] == '0');
}
static void hpack_continuation_vectors(void) {
    const uint8_t success[] = {0x48,0x82,0x10,0x01}, failure[] = {0x48,0x83,0x68,0x0c,0xff};
    char error[160];
    for (int failed = 0; failed < 2; failed++) {
        const uint8_t *block = failed ? failure : success;
        size_t length = failed ? sizeof(failure) : sizeof(success);
        for (size_t cut = 0; cut < length; cut++) {
            tls13_conn_t c = {.h2_stream_id=1};
            CHECK("h2/partial-headers-buffered", h2_process_control_frame(&c,H2_FRAME_HEADERS,H2_FLAG_END_STREAM,1,block,cut,error,sizeof(error)) == 0 && c.h2_header_stream_id == 1 && !c.h2_stream_eof);
            int result = h2_process_control_frame(&c,H2_FRAME_CONTINUATION,H2_FLAG_END_HEADERS,1,block+cut,length-cut,error,sizeof(error));
            CHECK("h2/continued-status-result", failed ? result < 0 && strstr(error,"non-200: 403") != NULL : result == 0 && c.h2_stream_eof);
            CHECK("h2/continuation-state-cleared", c.h2_header_stream_id == 0 && c.h2_header_block.len == 0);
            clear_conn(&c);
        }
    }
    tls13_conn_t c = {.h2_stream_id=1};
    CHECK("h2/orphan-continuation-rejected", h2_process_control_frame(&c,H2_FRAME_CONTINUATION,H2_FLAG_END_HEADERS,1,success,sizeof(success),error,sizeof(error)) < 0);
    CHECK("h2/zero-headers-stream-rejected", h2_process_headers(&c,H2_FLAG_END_HEADERS,0,success,sizeof(success),error,sizeof(error)) < 0);
    REQUIRE("h2/multipart-header-start", h2_process_headers(&c,H2_FLAG_END_STREAM,1,success,1,error,sizeof(error)) == 0);
    CHECK("h2/wrong-continuation-stream", h2_process_control_frame(&c,H2_FRAME_CONTINUATION,H2_FLAG_END_HEADERS,3,success+1,3,error,sizeof(error)) < 0);
    CHECK("h2/interleaved-header-rejected", h2_process_control_frame(&c,H2_FRAME_SETTINGS,H2_FLAG_ACK,0,NULL,0,error,sizeof(error)) < 0);
    CHECK("h2/multipart-middle", h2_process_control_frame(&c,H2_FRAME_CONTINUATION,0,1,success+1,1,error,sizeof(error)) == 0 && !c.h2_stream_eof);
    CHECK("h2/multipart-end", h2_process_control_frame(&c,H2_FRAME_CONTINUATION,H2_FLAG_END_HEADERS,1,success+2,2,error,sizeof(error)) == 0 && c.h2_stream_eof);
    c.h2_stream_eof = 0;
    c.h2_next_stream_id=5; REQUIRE("h2/next-request-state",h2_response_get(&c,3,1) != NULL);
    CHECK("h2/next-header-block", h2_process_headers(&c,H2_FLAG_END_HEADERS,3,success,sizeof(success),error,sizeof(error)) == 0);
    REQUIRE("h2/oversized-header-start", h2_process_headers(&c,0,1,success,1,error,sizeof(error)) == 0);
    c.h2_header_block.len = H2_MAX_INBOUND_FRAME;
    CHECK("h2/oversized-continuation-rejected", h2_process_control_frame(&c,H2_FRAME_CONTINUATION,H2_FLAG_END_HEADERS,1,success,1,error,sizeof(error)) < 0 && strstr(error,"too large") != NULL);
    clear_conn(&c);
}
static void hpack_response_phases(void) {
    tls13_conn_t c = {.h2_stream_id=1,.grpc_transport=1}; char error[160];
    const uint8_t interim[] = {0x48,3,'1','0','3'}, success[] = "\x88\x00\x0c" "content-type\x10" "application/grpc";
    const uint8_t upgrade[] = {0x48,3,'1','0','1'};
    CHECK("h2/protocol-upgrade-status-rejected",h2_process_headers(&c,H2_FLAG_END_HEADERS,1,upgrade,sizeof(upgrade),error,sizeof(error)) != 0);
    core_hpack_clear(&c.hpack);
    const uint8_t trailer[] = {0x40,11,'g','r','p','c','-','s','t','a','t','u','s',1,'0'};
    CHECK("h2/informational-response", h2_process_headers(&c,H2_FLAG_END_HEADERS,1,interim,sizeof(interim),error,sizeof(error)) == 0 && !c.h2_headers_received && !c.h2_stream_eof);
    CHECK("h2/informational-end-rejected", h2_process_headers(&c,H2_FLAG_END_HEADERS|H2_FLAG_END_STREAM,1,interim,sizeof(interim),error,sizeof(error)) != 0);
    CHECK("h2/initial-response", h2_process_headers(&c,H2_FLAG_END_HEADERS,1,success,sizeof(success)-1,error,sizeof(error)) == 0 && c.h2_headers_received);
    CHECK("h2/repeated-initial-rejected", h2_process_headers(&c,H2_FLAG_END_HEADERS,1,success,sizeof(success)-1,error,sizeof(error)) != 0);
    CHECK("h2/late-informational-rejected", h2_process_headers(&c,H2_FLAG_END_HEADERS,1,interim,sizeof(interim),error,sizeof(error)) != 0);
    CHECK("h2/nonfinal-trailer-rejected", h2_process_headers(&c,H2_FLAG_END_HEADERS,1,trailer,sizeof(trailer),error,sizeof(error)) != 0);
    CHECK("h2/grpc-trailer-completes", h2_process_headers(&c,H2_FLAG_END_HEADERS|H2_FLAG_END_STREAM,1,trailer,sizeof(trailer),error,sizeof(error)) == 0 && c.h2_stream_eof);
    clear_conn(&c); c.h2_headers_received=0; c.h2_stream_eof=0;
    CHECK("h2/trailer-before-response-rejected", h2_process_headers(&c,H2_FLAG_END_HEADERS|H2_FLAG_END_STREAM,1,trailer,sizeof(trailer),error,sizeof(error)) != 0);
    CHECK("h2/new-stream-response", h2_process_headers(&c,H2_FLAG_END_HEADERS,1,success,sizeof(success)-1,error,sizeof(error)) == 0);
    const uint8_t failed[] = {0x7e,2,'1','3'};
    CHECK("h2/grpc-error-trailer", h2_process_headers(&c,H2_FLAG_END_HEADERS|H2_FLAG_END_STREAM,1,failed,sizeof(failed),error,sizeof(error)) != 0 && strstr(error,"grpc-status=13"));
    clear_conn(&c);
}
static void wait_tls_fixture(tls13_conn_t *c) {
    if (SSL_pending(c->ssl) > 0) return;
    fd_set rfds; FD_ZERO(&rfds); FD_SET(c->fd, &rfds);
    struct timeval timeout = {2,0};
    REQUIRE("xhttp/tls-fixture-input", select(c->fd + 1, &rfds, NULL, NULL, &timeout) > 0);
}
static int xhttp_fixture_read(tls13_conn_t *c, uint8_t *data, size_t capacity, size_t *length) {
    uint64_t until=core_now_ms()+2000;
    for (;;) {
        int result=tls13_read_app(c,data,capacity,length);
        if (result != 1) return result;
        uint64_t now=core_now_ms();
        if (now >= until || core_wait_socket(c->fd,POLLIN,(int)(until-now)) <= 0) return -1;
    }
}
static int live_xhttp_chunks(const char *uri) {
    vless_config_t cfg; char error[256]; tls13_conn_t *c = NULL;
    REQUIRE("xhttp/tls-fixture-config", parse_core_uri(uri, &cfg, error, sizeof(error)) == 0);
    REQUIRE("xhttp/tls-fixture-connect", tls13_reality_connect(&cfg, &c, error, sizeof(error)) == 0);
    REQUIRE("xhttp/tls-fixture-h1", c->mode == CONN_MODE_XHTTP_TLS);
    core_set_socket_io_timeout(c->fd, 500);
    int flags = fcntl(c->fd, F_GETFL, 0);
    uint8_t data[64]; size_t length = 0;
    wait_tls_fixture(c);
    CHECK("xhttp/tls-first-chunk", xhttp_fixture_read(c, data, sizeof(data), &length) == 0 && length == 3 && memcmp(data, "abc", 3) == 0);
    for (int stage = 0; stage < 4; stage++) {
        if (stage) wait_tls_fixture(c);
        CHECK("xhttp/tls-incomplete-chunk-yields", tls13_read_app(c, data, sizeof(data), &length) == 1 && length == 0);
        CHECK("xhttp/tls-incomplete-chunk-not-pending", !tls13_has_pending_app(c));
        CHECK("xhttp/tls-socket-flags-restored", fcntl(c->fd, F_GETFL, 0) == flags);
        REQUIRE("xhttp/tls-fixture-ack", ssl_write_all(c->ssl, "ack", 3) == 0);
    }
    wait_tls_fixture(c);
    CHECK("xhttp/tls-fragmented-chunk-body", xhttp_fixture_read(c, data, sizeof(data), &length) == 0 && length == 1 && data[0] == 'v');
    REQUIRE("xhttp/tls-body-ack", ssl_write_all(c->ssl, "ack", 3) == 0);
    wait_tls_fixture(c);
    CHECK("xhttp/tls-fragmented-chunk-tail", xhttp_fixture_read(c, data, sizeof(data), &length) == 0 && length == 3 && memcmp(data, "pn!", 3) == 0);
    CHECK("xhttp/tls-chunk-ending-yields", tls13_read_app(c, data, sizeof(data), &length) == 1 && length == 0);
    CHECK("xhttp/tls-chunk-ending-not-pending", !tls13_has_pending_app(c));
    REQUIRE("xhttp/tls-end-ack", ssl_write_all(c->ssl, "ack", 3) == 0);
    wait_tls_fixture(c);
    CHECK("xhttp/tls-chunked-eof", xhttp_fixture_read(c, data, sizeof(data), &length) == 0 && !length && c->xhttp_eof);
    CHECK("xhttp/tls-final-flags-restored", fcntl(c->fd, F_GETFL, 0) == flags);
    tls13_reality_close(c);
    return test_result();
}
typedef struct { int fd, failed; size_t received; } flow_peer_t;
static void hybrid_vectors(void) {
    uint8_t public_key[1184], point[32];
    for (size_t i = 0; i < sizeof(public_key); i++) public_key[i] = (uint8_t)i;
    memset(point, 0x42, sizeof(point));
    dynbuf_t extension = {0};
    REQUIRE("tls/hybrid-share-build", ext_key_share_firefox(&extension, point, public_key,NULL) == 0);
    CHECK("tls/hybrid-share-size", extension.len == 4 + 2 + 4 + 1216 + 4 + 32 + 4 + 65);
    CHECK("tls/hybrid-share-group", extension.data[6] == 0x11 && extension.data[7] == 0xec && extension.data[8] == 4 && extension.data[9] == 0xc0);
    CHECK("tls/hybrid-share-public-key", memcmp(extension.data + 10, public_key, sizeof(public_key)) == 0);
    CHECK("tls/hybrid-share-x25519", memcmp(extension.data + 1194, point, sizeof(point)) == 0 && memcmp(extension.data + 1230, point, sizeof(point)) == 0);
    db_free(&extension);
    REQUIRE("tls/hybrid-groups-build", ext_supported_groups_firefox(&extension, 1) == 0);
    CHECK("tls/hybrid-groups-first", extension.data[6] == 0x11 && extension.data[7] == 0xec);
    db_free(&extension);
    const size_t lengths[] = {32, 1120};
    for (size_t sample = 0; sample < sizeof(lengths) / sizeof(lengths[0]); sample++) {
        size_t length = lengths[sample], message_length = 52 + length, body_length = message_length - 4;
        uint8_t message[1172] = {2, (uint8_t)(body_length >> 16), (uint8_t)(body_length >> 8), (uint8_t)body_length, 3, 3};
        message[39] = 0x13; message[40] = 3;
        message[42] = (uint8_t)((length + 8) >> 8); message[43] = (uint8_t)(length + 8);
        message[44] = 0; message[45] = 0x33;
        message[46] = (uint8_t)((length + 4) >> 8); message[47] = (uint8_t)(length + 4);
        message[48] = length == 32 ? 0 : 0x11; message[49] = length == 32 ? 0x1d : 0xec;
        message[50] = (uint8_t)(length >> 8); message[51] = (uint8_t)length;
        for (size_t i = 0; i < length; i++) message[52 + i] = (uint8_t)i;
        uint8_t share[1120]; size_t share_length = 0; uint16_t cipher = 0;
        CHECK("tls/server-share-parsed", parse_server_hello_for_keyshare(message, message_length, &cipher, share, &share_length) == 0 && cipher == 0x1303 && share_length == length && memcmp(share, message + 52, length) == 0);
        for (size_t cut = 0; cut < message_length; cut++) CHECK("tls/truncated-server-share", parse_server_hello_for_keyshare(message, cut, &cipher, share, &share_length) != 0);
        message[51]--;
        CHECK("tls/server-share-length-rejected", parse_server_hello_for_keyshare(message, message_length, &cipher, share, &share_length) != 0);
        message[51]++; message[49] = 0;
        CHECK("tls/server-share-group-rejected", parse_server_hello_for_keyshare(message, message_length, &cipher, share, &share_length) != 0);
    }
}
static void send_window(int fd, uint32_t stream, uint32_t amount) {
    uint8_t frame[] = {0,0,4,8,0,0,0,0,(uint8_t)stream,(uint8_t)(amount>>24),(uint8_t)(amount>>16),(uint8_t)(amount>>8),(uint8_t)amount};
    if (write_exact(fd, frame, sizeof(frame)) != 0) abort();
}
static void *flow_peer(void *opaque) {
    flow_peer_t *peer = opaque;
    send_window(peer->fd, 0, 64); send_window(peer->fd, 1, 64);
    while (peer->received < 16385) {
        uint8_t header[9], payload[64];
        if (read_exact(peer->fd, header, sizeof(header)) != 0) { peer->failed = 1; break; }
        size_t length = ((size_t)header[0]<<16)|((size_t)header[1]<<8)|header[2];
        if (header[3] != H2_FRAME_DATA || length > sizeof(payload) || read_exact(peer->fd, payload, length) != 0) { peer->failed = 1; break; }
        for (size_t i = 0; i < length; i++) if (payload[i] != (uint8_t)((peer->received+i)%251)) peer->failed = 1;
        peer->received += length;
        send_window(peer->fd, 0, (uint32_t)length); send_window(peer->fd, 1, (uint32_t)length);
    }
    return NULL;
}
static void directional_finish(void) {
    int pair[2]; uint8_t buffer[128]; size_t length;
    for (int raw=0;raw<2;raw++) {
        REQUIRE("tls/finish-socket-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t c={.fd=pair[0],.mode=CONN_MODE_TLS};
        REQUIRE("tls/finish-cipher",configure_tls_cipher(&c,0x1303) == 0);
        REQUIRE("tls/finish-write",tls13_finish_write(&c,raw) == 0);
        CHECK("tls/finish-idempotent",tls13_finish_write(&c,raw) == 0 && c.send_closed && c.c_app_seq == (raw ? 0 : 1));
        CHECK("tls/finish-rejects-new-payload",tls13_write_app(&c,(const uint8_t *)"x",1) < 0);
        if (raw) CHECK("tls/finish-raw-direction-only",recv(pair[1],buffer,sizeof(buffer),0) == 0);
        else {
            uint8_t type=0,*encoded=NULL,*plain=NULL,inner=0; size_t encoded_length=0,plain_length=0; uint64_t sequence=0;
            REQUIRE("tls/finish-close-notify-record",read_record(pair[1],&type,&encoded,&encoded_length) == 0);
            CHECK("tls/finish-authenticated-close-notify",decrypt_record(&c,c.c_app_key,c.c_app_iv,&sequence,type,encoded,encoded_length,&plain,&plain_length,&inner) == 0 && inner == 21 && plain_length == 2 && plain[0] == 1 && !plain[1]);
            free(encoded); free(plain);
            CHECK("tls/finish-close-notify-sent-once",recv(pair[1],buffer,sizeof(buffer),MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        }
        uint64_t sequence=0; uint8_t *record=NULL; size_t record_length=0;
        REQUIRE("tls/finish-peer-can-respond",encrypt_record(&c,c.s_app_key,c.s_app_iv,&sequence,23,(const uint8_t *)"vless-core",10,&record,&record_length) == 0 && write_exact(pair[1],record,record_length) == 0); free(record);
        CHECK("tls/finish-retains-incoming-payload",tls13_read_app(&c,buffer,sizeof(buffer),&length) == 0 && length == 10 && !memcmp(buffer,"vless-core",10));
        const uint8_t alert[]={1,0};
        REQUIRE("tls/finish-peer-close-notify",encrypt_record(&c,c.s_app_key,c.s_app_iv,&sequence,21,alert,sizeof(alert),&record,&record_length) == 0 && write_exact(pair[1],record,record_length) == 0); free(record);
        CHECK("tls/finish-clean-peer-eof",tls13_read_app(&c,buffer,sizeof(buffer),&length) == 0 && !length);
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    for (int upload=0;upload<2;upload++) {
        REQUIRE("http1/finish-socket-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t c={.fd=pair[0],.xhttp_upload_fd=pair[0],.mode=CONN_MODE_XHTTP_PLAIN};
        strcpy(c.xhttp_transport_mode,upload ? "stream-up" : "stream-one");
        REQUIRE("http1/finish-payload",tls13_write_app(&c,(const uint8_t *)"last",4) == 0 && tls13_finish_write(&c,0) == 0);
        CHECK("http1/finish-final-chunk-order",read_exact(pair[1],buffer,14) == 0 && !memcmp(buffer,"4\r\nlast\r\n0\r\n\r\n",14));
        CHECK("http1/finish-idempotent",tls13_finish_write(&c,0) == 0 && recv(pair[1],buffer,sizeof(buffer),MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    tls13_conn_t c={.mode=CONN_MODE_XHTTP_PLAIN,.fd=-1}; strcpy(c.xhttp_transport_mode,"packet-up");
    CHECK("http1/packet-up-does-not-invent-fin",tls13_finish_write(&c,0) == 0 && c.send_closed);
}

static void relay_backpressure(void) {
    int pair[2]; uint8_t payload[65536],output[65536]; memset(payload,0x39,sizeof(payload));
    REQUIRE("relay/backpressure-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    int small=1024; REQUIRE("relay/backpressure-buffer",setsockopt(pair[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)) == 0);
    tls13_conn_t c={.fd=pair[0],.mode=CONN_MODE_PLAIN};
    REQUIRE("relay/backpressure-enable",tls13_start_relay(&c) == 0);
    CHECK("relay/backpressure-queues-payload",tls13_write_app(&c,payload,sizeof(payload)) == 0 && c.xmux_wire_output.len == sizeof(payload));
    CHECK("relay/backpressure-does-not-block",tls13_flush(&c) == 0 && c.xmux_wire_output.len && c.xmux_wire_output.len < sizeof(payload));
    CHECK("relay/backpressure-defers-fin",tls13_finish_write(&c,0) == 0 && tls13_finish_write(&c,0) == 0 && tls13_finish_pending(&c) == 1);
    size_t total=0;
    while (total < sizeof(payload)) {
        ssize_t received=recv(pair[1],output+total,sizeof(output)-total,MSG_DONTWAIT);
        if (received > 0) total+=(size_t)received;
        REQUIRE("relay/backpressure-flush-progress",tls13_flush(&c) == 0);
    }
    CHECK("relay/backpressure-preserves-all-bytes",!memcmp(payload,output,sizeof(payload)));
    CHECK("relay/backpressure-fin-after-last-byte",recv(pair[1],output,1,0) == 0 && !tls13_finish_pending(&c));
    REQUIRE("relay/backpressure-response-after-fin",write_exact(pair[1],"reply",5) == 0);
    size_t received=0; CHECK("relay/backpressure-retains-opposite-direction",tls13_read_app(&c,output,sizeof(output),&received) == 0 && received == 5 && !memcmp(output,"reply",5));
    clear_conn(&c); close(pair[0]); close(pair[1]);
    for (size_t cut=0;cut<32;cut++) {
        REQUIRE("tls/fragment-relay-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        c=(tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_TLS};
        REQUIRE("tls/fragment-relay-cipher",configure_tls_cipher(&c,0x1303) == 0 && tls13_start_relay(&c) == 0);
        uint8_t *record=NULL; size_t length=0; uint64_t sequence=0;
        REQUIRE("tls/fragment-relay-record",encrypt_record(&c,c.s_app_key,c.s_app_iv,&sequence,23,(const uint8_t *)"vless-core",10,&record,&length) == 0);
        size_t prefix=cut < length ? cut : length-1;
        REQUIRE("tls/fragment-relay-prefix",write_exact(pair[1],record,prefix) == 0);
        received=0;
        CHECK("tls/fragment-relay-yields",tls13_read_app(&c,output,sizeof(output),&received) == 1 && !received && !tls13_has_pending_input(&c));
        CHECK("tls/fragment-relay-allows-upload",tls13_write_app(&c,(const uint8_t *)"upload",6) == 0 && tls13_flush(&c) == 0);
        REQUIRE("tls/fragment-relay-tail",write_exact(pair[1],record+prefix,length-prefix) == 0); free(record);
        CHECK("tls/fragment-relay-preserves-record",tls13_read_app(&c,output,sizeof(output),&received) == 0 && received == 10 && !memcmp(output,"vless-core",10));
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    REQUIRE("vision/raw-tail-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    c=(tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_REALITY};
    REQUIRE("vision/raw-tail-cipher",configure_tls_cipher(&c,0x1303) == 0 && tls13_start_relay(&c) == 0);
    uint8_t command[21]={0}; command[16]=2; uint8_t *record=NULL; size_t length=0; uint64_t sequence=0;
    REQUIRE("vision/raw-tail-record",encrypt_record(&c,c.s_app_key,c.s_app_iv,&sequence,23,command,sizeof(command),&record,&length) == 0);
    memcpy(payload,record,length); memcpy(payload+length,"raw tail",8); free(record);
    REQUIRE("vision/raw-tail-combined-wire",write_exact(pair[1],payload,length+8) == 0);
    received=0;
    REQUIRE("vision/raw-tail-command",tls13_read_app(&c,output,sizeof(output),&received) == 0 && received == sizeof(command));
    tls13_mark_raw_direct(&c);
    CHECK("vision/raw-tail-readiness",tls13_has_pending_raw(&c));
    CHECK("vision/raw-tail-delivered-before-socket",tls13_read_raw(&c,output,sizeof(output),&received) == 0 && received == 8 && !memcmp(output,"raw tail",8) && !tls13_has_pending_raw(&c));
    clear_conn(&c); close(pair[0]); close(pair[1]);
}

static void protocol_edges(void) {
    hybrid_vectors();
    int pair[2]; tls13_conn_t c;
    for (int mode = 0; mode < 3; mode++) {
        c = (tls13_conn_t){.fd=-1,.h2_stream_id=1,.mode=mode == 0 ? CONN_MODE_XHTTP_TLS_H2 : mode == 1 ? CONN_MODE_XHTTP_REALITY : CONN_MODE_GRPC_PLAIN};
        const uint8_t control[] = {0,0,4,H2_FRAME_WINDOW_UPDATE,0,0,0,0,0,0,0,0,1};
        REQUIRE("h2/control-readiness-fixture", db_append(&c.h2_net_cache,control,sizeof(control)) == 0);
        CHECK("h2/control-is-input-not-app", tls13_has_pending_input(&c) && !tls13_has_pending_app(&c));
        REQUIRE("h2/app-readiness-fixture", db_append(&c.app_cache,"vless-core",10) == 0);
        CHECK("h2/data-is-app", tls13_has_pending_input(&c) && tls13_has_pending_app(&c));
        c.app_cache.len = 0; c.h2_net_cache.len = 0; c.h2_stream_eof = 1;
        CHECK("h2/eof-is-readable", tls13_has_pending_input(&c) && tls13_has_pending_app(&c));
        clear_conn(&c);
    }
    CHECK("h2/null-readiness", !tls13_has_pending_input(NULL) && !tls13_has_pending_app(NULL));
    SSL_CTX *want_ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE("xhttp/want-write-context", want_ctx != NULL);
    SSL *want_ssl = SSL_new(want_ctx); BIO *want_bio = NULL, *want_peer = NULL;
    REQUIRE("xhttp/want-write-fixture", want_ssl != NULL && BIO_new_bio_pair(&want_bio, 1, &want_peer, 1) == 1);
    SSL_set_bio(want_ssl, want_bio, want_bio); SSL_set_connect_state(want_ssl);
    ERR_clear_error();
    int handshake = SSL_do_handshake(want_ssl);
    REQUIRE("xhttp/want-write-produced", handshake < 0 && SSL_get_error(want_ssl, handshake) == SSL_ERROR_WANT_WRITE);
    c = (tls13_conn_t){.ssl=want_ssl,.mode=CONN_MODE_XHTTP_TLS};
    CHECK("xhttp/tls-want-write-readiness", tls13_needs_write(&c));
    c.mode = CONN_MODE_XHTTP_TLS_H2;
    CHECK("xhttp/want-write-only-h1", !tls13_needs_write(&c));
    c.mode = CONN_MODE_XHTTP_TLS; c.ssl = NULL;
    CHECK("xhttp/want-write-null", !tls13_needs_write(&c) && !tls13_needs_write(NULL));
    SSL_free(want_ssl); BIO_free(want_peer); SSL_CTX_free(want_ctx);
    const uint8_t record[] = {22,3,3,0,10,'v','l','e','s','s','-','c','o','r','e'};
    for (size_t cut = 0; cut <= sizeof(record); cut++) {
        REQUIRE("tls/record-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        REQUIRE("tls/record-fixture", write_exact(pair[1], record, cut) == 0 && shutdown(pair[1], SHUT_WR) == 0);
        uint8_t type = 0, *payload = NULL; size_t length = 0;
        int result = read_record(pair[0], &type, &payload, &length);
        if (cut == 0) CHECK("tls/record-eof-distinguished", result == 1 && payload == NULL);
        else if (cut < sizeof(record)) CHECK("tls/truncated-record-rejected", result < 0 && payload == NULL);
        else CHECK("tls/complete-record-before-eof", result == 0 && type == 22 && length == 10 && memcmp(payload, "vless-core", 10) == 0);
        free(payload); close(pair[0]); close(pair[1]);
    }
    REQUIRE("tls/app-eof-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    REQUIRE("tls/app-eof-fixture", shutdown(pair[1], SHUT_WR) == 0);
    c = (tls13_conn_t){.fd=pair[0]};
    uint8_t eof_buffer[32]; size_t eof_length = 99;
    CHECK("tls/eof-without-close-notify-rejected", tls13_read_app(&c, eof_buffer, sizeof(eof_buffer), &eof_length) < 0 && eof_length == 0);
    clear_conn(&c); close(pair[0]); close(pair[1]);
    for (int fatal = 0; fatal < 2; fatal++) {
        REQUIRE("tls/alert-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        c = (tls13_conn_t){.fd=pair[0]};
        REQUIRE("tls/alert-cipher", configure_tls_cipher(&c, 0x1303) == 0);
        uint8_t alert[2] = {fatal ? 2 : 1, fatal ? 80 : 0}, *encoded = NULL;
        size_t encoded_length = 0; uint64_t sequence = 0;
        REQUIRE("tls/alert-record", encrypt_record(&c, c.s_app_key, c.s_app_iv, &sequence, 0x15, alert, sizeof(alert), &encoded, &encoded_length) == 0);
        REQUIRE("tls/alert-send", write_exact(pair[1], encoded, encoded_length) == 0);
        free(encoded);
        int result = tls13_read_app(&c, eof_buffer, sizeof(eof_buffer), &eof_length);
        CHECK(fatal ? "tls/fatal-alert-rejected" : "tls/close-notify-eof", fatal ? result < 0 : result == 0 && eof_length == 0);
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    uint8_t ws_frame[130] = {0x82,126,0,126};
    for (size_t i = 4; i < sizeof(ws_frame); i++) ws_frame[i] = (uint8_t)(i-4);
    for (size_t cut = 0; cut <= sizeof(ws_frame); cut++) {
        REQUIRE("ws/truncation-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        REQUIRE("ws/truncation-fixture", write_exact(pair[1], ws_frame, cut) == 0 && shutdown(pair[1], SHUT_WR) == 0);
        c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_WS};
        int result = ws_fill_app_cache(&c);
        if (cut < sizeof(ws_frame)) {
            size_t available=cut > 4 ? cut-4 : 0;
            CHECK("ws/partial-frame-streamed",c.app_cache.len == available && (!available || memcmp(c.app_cache.data,ws_frame+4,available) == 0));
            if (result == 0) { c.app_cache.len=0; result=ws_fill_app_cache(&c); }
            CHECK("ws/truncated-frame-rejected",result < 0);
        }
        else CHECK("ws/complete-frame-before-eof", result == 0 && c.app_cache.len == 126 && memcmp(c.app_cache.data, ws_frame+4, 126) == 0);
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    uint8_t data[16385]; for (size_t i = 0; i < sizeof(data); i++) data[i] = i%251;
    for (int grpc = 0; grpc < 2; grpc++) {
        REQUIRE("h2/flow-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        core_set_socket_io_timeout(pair[0], 2000); core_set_socket_io_timeout(pair[1], 2000);
        c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_GRPC_PLAIN,.grpc_transport=grpc,.h2_stream_id=1,.h2_peer_max_frame_size=64};
        c.h2_validation.settings_received=1; c.h2_validation.settings_pending=1;
        strcpy(c.xhttp_transport_mode,"stream-one");
        flow_peer_t peer = {.fd=pair[1]}; pthread_t thread; REQUIRE("h2/flow-thread", pthread_create(&thread,NULL,flow_peer,&peer) == 0);
        CHECK(grpc ? "h2/grpc-zero-window-resume" : "h2/xhttp-zero-window-resume", h2_write_data(&c,data,sizeof(data)) == 0);
        REQUIRE("h2/flow-join", pthread_join(thread,NULL) == 0);
        CHECK("h2/flow-integrity", !peer.failed && peer.received == sizeof(data)); clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    for (int stream_up = 0; stream_up < 2; stream_up++) {
        for (int low_connection = 0; low_connection < 2; low_connection++) {
            REQUIRE("h2/remaining-credit-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
            core_set_socket_io_timeout(pair[0], 100); core_set_socket_io_timeout(pair[1], 100);
            c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_GRPC_PLAIN,.h2_stream_id=1,.h2_upload_stream_id=3,.h2_peer_max_frame_size=64,.h2_peer_conn_window=low_connection ? 16 : 64,.h2_peer_stream_window=low_connection ? 64 : 16,.h2_upload_stream_window=low_connection ? 64 : 16};
            strcpy(c.xhttp_transport_mode,stream_up ? "stream-up" : "stream-one");
            int written = h2_write_data(&c,(const uint8_t *)"vless-core",10);
            CHECK("h2/remaining-credit-no-premature-wait", written == 0);
            if (written == 0) {
                uint8_t frame[19];
                CHECK("h2/remaining-credit-frame", read_exact(pair[1],frame,sizeof(frame)) == 0 && frame[2] == 10 && frame[3] == H2_FRAME_DATA && frame[8] == (stream_up ? 3 : 1) && memcmp(frame+9,"vless-core",10) == 0);
                CHECK("h2/remaining-credit-accounting", c.h2_peer_conn_window == (low_connection ? 6 : 54) && (stream_up ? c.h2_upload_stream_window : c.h2_peer_stream_window) == (low_connection ? 54 : 6));
            }
            clear_conn(&c); close(pair[0]); close(pair[1]);
        }
    }
    REQUIRE("h2/cancelled-upload-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    core_set_socket_io_timeout(pair[0], 200);
    c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_GRPC_PLAIN,.h2_stream_id=1};
    c.h2_validation.settings_received=1; c.h2_validation.settings_pending=1;
    c.h2_headers_received=1; c.h2_receive_window=H2_CLIENT_INITIAL_WINDOW+H2_DEFAULT_WINDOW;
    strcpy(c.xhttp_transport_mode, "stream-one");
    uint8_t completed_response[] = {0,0,10,0,1,0,0,0,1,'v','l','e','s','s','-','c','o','r','e',0,0,4,3,0,0,0,0,1,0,0,0,0};
    REQUIRE("h2/cancelled-upload-response", write_exact(pair[1], completed_response, sizeof(completed_response)) == 0);
    CHECK("h2/cancelled-upload-no-window-wait", h2_write_data(&c, (const uint8_t *)"request", 7) == 0 && c.h2_request_cancelled);
    uint8_t completed_payload[16]; size_t completed_length = 0;
    CHECK("h2/cancelled-upload-response-preserved", tls13_read_app(&c, completed_payload, sizeof(completed_payload), &completed_length) == 0 && completed_length == 10 && memcmp(completed_payload, "vless-core", 10) == 0);
    clear_conn(&c); close(pair[0]); close(pair[1]);
    REQUIRE("h2/separate-upload-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_GRPC_PLAIN,.h2_stream_id=1,.h2_upload_stream_id=3,.h2_request_cancelled=1,.h2_peer_conn_window=64,.h2_upload_stream_window=64,.h2_peer_max_frame_size=64};
    strcpy(c.xhttp_transport_mode, "stream-up");
    uint8_t separate_frame[19];
    CHECK("h2/separate-upload-not-cancelled", h2_write_data(&c, (const uint8_t *)"vless-core", 10) == 0 && read_exact(pair[1], separate_frame, sizeof(separate_frame)) == 0 && separate_frame[8] == 3 && memcmp(separate_frame + 9, "vless-core", 10) == 0);
    clear_conn(&c); close(pair[0]); close(pair[1]);
    REQUIRE("ws/pair", socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0); c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_WS};
    char accept[29]; CHECK("ws/rfc-accept-golden", ws_make_accept("dGhlIHNhbXBsZSBub25jZQ==",accept) == 0 && strcmp(accept,"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
    const uint8_t frames[] = {0x89,1,'p',0x02,2,'a','b',0x80,1,'c'};
    REQUIRE("ws/cache-fixture", db_append(&c.ws_net_cache,frames,sizeof(frames)) == 0);
    CHECK("ws/ping-and-fragment", ws_fill_app_cache(&c) == 0 && c.app_cache.len == 2 && memcmp(c.app_cache.data,"ab",2) == 0);
    uint8_t pong[7]; REQUIRE("ws/pong-read", read_exact(pair[1],pong,sizeof(pong)) == 0);
    CHECK("ws/pong-masked", pong[0] == 0x8a && pong[1] == 0x81 && (pong[6]^pong[2]) == 'p');
    CHECK("ws/continuation", ws_fill_app_cache(&c) == 0 && c.app_cache.len == 3 && c.app_cache.data[2] == 'c');
    c.ws_net_cache.len = 0; c.app_cache.len = 0;
    const uint8_t bad_control[] = {0x09,0}; db_append(&c.ws_net_cache,bad_control,sizeof(bad_control)); CHECK("ws/fragmented-ping-rejected", ws_fill_app_cache(&c) != 0);
    c.ws_net_cache.len = 0; const uint8_t huge[] = {0x82,127,0x80,0,0,0,0,0,0,0}; db_append(&c.ws_net_cache,huge,sizeof(huge)); CHECK("ws/length-overflow-rejected", ws_fill_app_cache(&c) != 0);
    uint8_t ws_data[300], wire[308]; memset(ws_data,42,sizeof(ws_data));
    REQUIRE("ws/write-frame", ws_write_frame(&c,2,ws_data,sizeof(ws_data)) == 0 && read_exact(pair[1],wire,sizeof(wire)) == 0);
    CHECK("ws/extended-length", wire[0] == 0x82 && wire[1] == 0xfe && wire[2] == 1 && wire[3] == 44);
    for (size_t i = 0; i < sizeof(ws_data); i++) CHECK("ws/masked-payload", (wire[i+8]^wire[4+i%4]) == 42);
    clear_conn(&c); close(pair[0]); close(pair[1]);
    const uint8_t invalid_ws[][7] = {{0x82,0x81,0,0,0,0,'x'},{0xc2,1,'x'},{0x80,1,'x'}};
    const size_t invalid_ws_sizes[] = {7,3,3};
    const char *invalid_ws_names[] = {"ws/server-mask-rejected","ws/reserved-bits-rejected","ws/orphan-continuation-rejected"};
    for (size_t i=0;i<3;i++) {
        REQUIRE("ws/invalid-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        c=(tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_WS};
        REQUIRE("ws/invalid-fixture",db_append(&c.ws_net_cache,invalid_ws[i],invalid_ws_sizes[i]) == 0);
        CHECK(invalid_ws_names[i],ws_fill_app_cache(&c) < 0 && c.app_cache.len == 0);
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    REQUIRE("xhttp/chunk-pair", socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_XHTTP_PLAIN};
    const char *chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;vless-core=yes\r\nabc\r\n0\r\n\r\n";
    db_append(&c.xhttp_net_cache,chunked,strlen(chunked));
    CHECK("xhttp/chunked-extensions", xhttp_fill_app_cache(&c) == 0 && c.app_cache.len == 3 && memcmp(c.app_cache.data,"abc",3) == 0);
    CHECK("xhttp/chunked-eof", xhttp_fill_app_cache(&c) < 0 && c.xhttp_eof); clear_conn(&c); close(pair[0]); close(pair[1]);
    char headers[128] = "", cookies[128] = "", path[128] = "/vless-core";
    CHECK("xhttp/header-injection-rejected", xhttp_append_header_line(headers,sizeof(headers),"X-Session","a\r\nb") != 0);
    CHECK("xhttp/cookie-injection-rejected", xhttp_append_cookie_pair(cookies,sizeof(cookies),"x_session","a\nb") != 0);
    CHECK("xhttp/unknown-placement-rejected", xhttp_apply_meta_one(path,sizeof(path),headers,sizeof(headers),cookies,sizeof(cookies),"invalid","x_session","vless-core") != 0);
    strcpy(path,"/vless-core/?fixed=1");
    CHECK("xhttp/path-metadata-escaped-before-query", xhttp_append_path_segment(path,sizeof(path),"a?b#c%") == 0 && !strcmp(path,"/vless-core/a%3Fb%23c%25?fixed=1"));
    strcpy(path,"/vless-core/");
    CHECK("xhttp/query-metadata-encoded", xhttp_append_query_param(path,sizeof(path),"vless core&x","a+b%/#") == 0 && !strcmp(path,"/vless-core/?vless%20core%26x=a%2Bb%25%2F%23"));
    strcpy(path,"/vless-core/?x_session=old&fixed=1&%78_session=second");
    CHECK("xhttp/query-metadata-replaces-existing-key",xhttp_append_query_param(path,sizeof(path),"x_session","vless-core") == 0 && !strcmp(path,"/vless-core/?fixed=1&x_session=vless-core"));
    strcpy(path,"/vless-core/?fixed=1"); char previous[128]; strcpy(previous,path);
    CHECK("xhttp/query-capacity-error-preserves-input",xhttp_append_query_param(path,strlen(path)+4,"key","value") != 0 && !strcmp(path,previous));
    CHECK("xhttp/path-trailing-slash-before-query", normalize_xhttp_path("/vless-core?fixed=1",path,sizeof(path)) == 0 && !strcmp(path,"/vless-core/?fixed=1"));
}
static void xhttp_http1_vectors(void) {
    const char *invalid[]={
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3junk\r\nabc\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcZZ0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nBad trailer\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
    };
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        int pair[2]; REQUIRE("xhttp/http1-malformed-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t connection={.fd=pair[0],.mode=CONN_MODE_XHTTP_PLAIN};
        REQUIRE("xhttp/http1-malformed-fixture",db_append(&connection.xhttp_net_cache,invalid[i],strlen(invalid[i])) == 0 && shutdown(pair[1],SHUT_WR) == 0);
        int result=0;
        for (unsigned step=0;step<32 && result >= 0;step++) {
            result=xhttp_fill_app_cache(&connection); connection.app_cache.len=0;
        }
        CHECK("xhttp/http1-invalid-framing-is-not-clean-eof",result < 0 && !connection.xhttp_eof);
        clear_conn(&connection); close(pair[0]); close(pair[1]);
    }
    const char *valid[]={
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc",
    };
    for (size_t i=0;i<sizeof(valid)/sizeof(*valid);i++) {
        int pair[2]; REQUIRE("xhttp/http1-complete-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t connection={.fd=pair[0],.mode=CONN_MODE_XHTTP_PLAIN};
        REQUIRE("xhttp/http1-complete-fixture",db_append(&connection.xhttp_net_cache,valid[i],strlen(valid[i])) == 0 && shutdown(pair[1],SHUT_WR) == 0);
        CHECK("xhttp/http1-interim-or-close-body",xhttp_fill_app_cache(&connection) == 0 && connection.app_cache.len == 3 && !memcmp(connection.app_cache.data,"abc",3));
        connection.app_cache.len=0;
        CHECK("xhttp/http1-complete-eof",xhttp_fill_app_cache(&connection) < 0 && connection.xhttp_eof);
        clear_conn(&connection); close(pair[0]); close(pair[1]);
    }
}

static void http2_single_wire_vectors(void) {
    const uint8_t invalid[][10]={{0,0,1,0,0,0,0,0,1,'x'},{0,0,0,4,1,0,0,0,0},{0,0,0,99,0,0,0,0,0},{0,0x40,1,0,0,0,0,0,1}};
    const size_t sizes[]={10,9,9,9};
    for (size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++) {
        tls13_conn_t connection={.fd=-1,.mode=CONN_MODE_GRPC_PLAIN};
        REQUIRE("h2/single-wire-invalid-fixture",db_append(&connection.h2_net_cache,invalid[i],sizes[i]) == 0);
        if (i == 3) CHECK("h2/oversize-header-is-ready-for-rejection",h2_cached_frame_ready(&connection));
        uint8_t type,flags,*body=NULL; uint32_t stream; size_t length;
        CHECK("h2/single-wire-initial-sequence-or-size",h2_read_frame(&connection,&type,&flags,&stream,&body,&length) < 0 && !body);
        free(body); clear_conn(&connection);
    }
    tls13_conn_t connection={.fd=-1,.mode=CONN_MODE_GRPC_PLAIN};
    const uint8_t frames[]={0,0,0,4,0,0,0,0,0,0,0,1,99,255,0,0,0,7,'x'};
    REQUIRE("h2/single-wire-extension-fixture",db_append(&connection.h2_net_cache,frames,sizeof(frames)) == 0);
    uint8_t type,flags,*body=NULL; uint32_t stream; size_t length;
    CHECK("h2/single-wire-settings",h2_read_frame(&connection,&type,&flags,&stream,&body,&length) == 0 && type == 4);
    free(body);
    CHECK("h2/single-wire-unknown-extension",h2_read_frame(&connection,&type,&flags,&stream,&body,&length) == 0 && type == 99 && length == 1 && body[0] == 'x');
    free(body); clear_conn(&connection);
    connection=(tls13_conn_t){.h2_stream_id=1};
    for (unsigned id=1;id<=256;id++) REQUIRE("h2/response-state-gradual-reservation",h2_response_get(&connection,id*2-1,1) != NULL);
    CHECK("h2/response-state-count-bound",!h2_response_get(&connection,513,1) && connection.h2_response_count == 256);
    h2_response_remove(&connection,3);
    CHECK("h2/response-state-budget-recovers",h2_response_get(&connection,513,1) != NULL && connection.h2_response_count == 256);
    clear_conn(&connection); CHECK("h2/response-state-cleanup",!connection.h2_responses && !connection.h2_response_count);
    connection=(tls13_conn_t){.fd=-1,.h2_stream_id=1,.h2_upload_stream_id=3,.xmux_async=1};
    h2_response_entry_t *main=h2_response_get(&connection,1,1),*upload=h2_response_get(&connection,3,1);
    REQUIRE("h2/active-response-fixture",main && upload);
    CHECK("h2/active-streams-counted",h2_response_active(&connection) == 2);
    main->response.ended=upload->response.ended=1;
    CHECK("h2/half-closed-streams-still-active",h2_response_active(&connection) == 2);
    connection.send_closed=1;
    main->request_ended=upload->request_ended=1;
    CHECK("h2/fully-closed-streams-not-active",!h2_response_active(&connection));
    char error[160]; const uint8_t limit[]={0,3,0,0,0,1};
    CHECK("h2/single-server-concurrency-applied",h2_process_control_frame(&connection,H2_FRAME_SETTINGS,0,0,limit,sizeof(limit),error,sizeof(error)) == 0 && connection.h2_peer_concurrency == 1);
    const uint8_t accepted[]={0,0,0,3,0,0,0,0};
    CHECK("h2/single-goaway-preserves-accepted-stream",h2_process_control_frame(&connection,H2_FRAME_GOAWAY,0,0,accepted,sizeof(accepted),error,sizeof(error)) == 0 && connection.h2_goaway);
    size_t pending=1;
    CHECK("h2/single-goaway-blocks-new-request",xhttp_h2_post_packet(&connection,(const uint8_t *)"x",&pending,error,sizeof(error)) < 0 && strstr(error,"prevents new requests"));
    clear_conn(&connection);
    connection=(tls13_conn_t){.fd=-1,.mode=CONN_MODE_GRPC_PLAIN,.h2_stream_id=1,.h2_next_stream_id=3,.h2_peer_concurrency=UINT32_MAX};
    connection.h2_validation.settings_received=1;
    const uint8_t queued_goaway[]={0,0,8,7,0,0,0,0,0,0,0,0,1,0,0,0,0};
    REQUIRE("h2/queued-goaway-fixture",db_append(&connection.h2_net_cache,queued_goaway,sizeof(queued_goaway)) == 0);
    CHECK("h2/goaway-during-admission-prevents-new-request",h2_request_capacity(&connection,error,sizeof(error)) < 0 && strstr(error,"prevents new requests"));
    clear_conn(&connection);
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1],"--xhttp-post")) {
        vless_config_t config; tls13_conn_t *connection=NULL; char error[256]={0};
        if (parse_core_uri(argv[2],&config,error,sizeof(error)) || tls13_reality_connect(&config,&connection,error,sizeof(error))) { fprintf(stderr,"%s\n",error); return 2; }
        int result=tls13_write_app(connection,(const uint8_t *)"vless-core",10);
        tls13_reality_close(connection); return result ? 1 : 0;
    }
    if (argc == 3 && strcmp(argv[1], "--xhttp-chunks") == 0) return live_xhttp_chunks(argv[2]);
    if (argc == 2) {
        vless_config_t cfg; char error[256]; REQUIRE("tls/live-config", parse_core_uri(argv[1], &cfg, error, sizeof(error)) == 0);
        for (int i = 0; i < 3; i++) {
            tls13_conn_t *connection = NULL;
            int result = tls13_reality_connect(&cfg, &connection, error, sizeof(error));
            if (result) fprintf(stderr, "live handshake error: %s\n", error);
            REQUIRE("tls/live-aes-fallback", result == 0);
            CHECK("tls/live-aes-cached", connection->tls_use_aes_fallback && tls_aes_fallback_cached(cfg.server_host, cfg.server_port, cfg.sni));
            tls13_reality_close(connection);
        }
        return test_result();
    }
    http2_single_wire_vectors();
    xhttp_http1_vectors();
    hpack_status_vectors();
    custom_request_headers();
    tls13_conn_t oversized_h2={.mode=CONN_MODE_GRPC_PLAIN}; core_http2_frame_t invalid_frame;
    const uint8_t oversized_header[]={1,0,0,0,0,0,0,0,1};
    REQUIRE("h2/oversized-frame-header-fixture",db_append(&oversized_h2.h2_net_cache,oversized_header,sizeof(oversized_header)) == 0);
    CHECK("h2/oversized-frame-is-not-backpressure",xmux_transport_read_frame(&oversized_h2,&invalid_frame,0) < 0);
    clear_conn(&oversized_h2);
    tls13_conn_t completed_http1={.mode=CONN_MODE_XHTTP_PLAIN,.xmux_http1_eof=1}; core_xmux_frame_t closed_http1;
    CHECK("xmux/http1-clean-idle-eof-notification",xmux_transport_read_frame(&completed_http1,&closed_http1,65535) == 0 && closed_http1.event == 4 && !closed_http1.id);
    CHECK("xmux/http1-clean-eof-reported-once",xmux_transport_read_frame(&completed_http1,&closed_http1,65535) == 1);
    hpack_huffman_vectors();
    hpack_continuation_vectors();
    hpack_response_phases();
    protocol_edges();
    directional_finish();
    relay_backpressure();
    tls13_conn_t multiplexed={.mode=CONN_MODE_XHTTP_REALITY,.xmux_async=1};
    uint8_t settings_ack[9]={0,0,0,4,1,0,0,0,0};
    REQUIRE("xmux/h2-response-fixture", db_append(&multiplexed.h2_net_cache,settings_ack,sizeof(settings_ack)) == 0);
    core_xmux_frame_t response;
    memset(&response,0xff,sizeof(response));
    CHECK("xmux/h2-events-reset-on-reused-thread", xmux_transport_read_frame(&multiplexed,&response,65535) == 0 && !response.event && response.type == 4 && response.flags == 1 && !response.id && !response.length);
    free(response.data); db_free(&multiplexed.h2_net_cache);
    tls13_conn_t outbound={.mode=CONN_MODE_XHTTP_TLS_H2,.xmux_async=1};
    strcpy(outbound.xhttp_host,"vless-core.test");
    char *large_headers=malloc(32032);
    REQUIRE("xhttp/large-header-fixture", large_headers != NULL);
    strcpy(large_headers,"X-vless-core: "); size_t prefix_size=strlen(large_headers);
    memset(large_headers+prefix_size,'A',32000); memcpy(large_headers+prefix_size+32000,"\r\n",3);
    char header_error[160];
    REQUIRE("xhttp/large-header-encoding", h2_send_xhttp_request_headers(&outbound,3,"POST","/vless-core/",large_headers,0,0,0,header_error,sizeof(header_error)) == 0);
    size_t frame_offset=0,frame_count=0;
    while (frame_offset < outbound.xmux_plain_output.len) {
        const uint8_t *frame=outbound.xmux_plain_output.data+frame_offset;
        size_t size=((size_t)frame[0]<<16)|((size_t)frame[1]<<8)|frame[2];
        CHECK("xhttp/request-header-fragments-bounded", size <= 16384 && frame_offset+9+size <= outbound.xmux_plain_output.len && frame[3] == (frame_count ? H2_FRAME_CONTINUATION : H2_FRAME_HEADERS));
        CHECK("xhttp/request-header-flags", (!!(frame[4]&H2_FLAG_END_HEADERS) == (frame_offset+9+size == outbound.xmux_plain_output.len)) && (!!(frame[4]&H2_FLAG_END_STREAM) == !frame_count));
        frame_offset+=9+size; frame_count++;
    }
    CHECK("xhttp/request-header-continuation-used", frame_count > 1);
    free(large_headers); db_free(&outbound.xmux_plain_output); db_free(&outbound.h2_send_buf);
    SSL_CTX *asynchronous_context=SSL_CTX_new(TLS_client_method());
    REQUIRE("xmux/tls-context", asynchronous_context != NULL);
    SSL *asynchronous_ssl=SSL_new(asynchronous_context);
    BIO *input_bio=BIO_new(BIO_s_mem()),*output_bio=BIO_new(BIO_s_mem());
    REQUIRE("xmux/tls-memory-channel", asynchronous_ssl && input_bio && output_bio);
    BIO_set_mem_eof_return(input_bio,-1); SSL_set_bio(asynchronous_ssl,input_bio,output_bio); SSL_set_connect_state(asynchronous_ssl);
    tls13_conn_t asynchronous={.mode=CONN_MODE_XHTTP_TLS,.ssl=asynchronous_ssl};
    ERR_put_error(ERR_LIB_SYS,0,EAGAIN,__FILE__,__LINE__);
    CHECK("xmux/tls-receive-clears-earlier-errors", xmux_transport_collect(&asynchronous) == 0 && !asynchronous.xmux_http1_eof);
    SSL_free(asynchronous_ssl); SSL_CTX_free(asynchronous_context); db_free(&asynchronous.h2_net_cache);
    unsetenv("VLESS_TLS_MODE"); unsetenv("VLESS_XHTTP_TLS_MODE"); CHECK("tls/default-strict", get_tls_verify_mode() == TLS_VERIFY_MODE_STRICT);
    setenv("VLESS_XHTTP_TLS_MODE", "tofu", 1); CHECK("tls/legacy-tofu", get_tls_verify_mode() == TLS_VERIFY_MODE_TOFU);
    setenv("VLESS_TLS_MODE", "auto", 1); CHECK("tls/auto-no-downgrade", get_tls_verify_mode() == TLS_VERIFY_MODE_STRICT);
    setenv("VLESS_TLS_MODE", "unknown", 1); CHECK("tls/unknown-strict", get_tls_verify_mode() == TLS_VERIFY_MODE_STRICT);
    setenv("VLESS_TLS_MODE", "insecure", 1); CHECK("tls/explicit-insecure", get_tls_verify_mode() == TLS_VERIFY_MODE_INSECURE);
    vless_config_t cfg = {.server_port=443}; strcpy(cfg.server_host, "vless-core.test"); strcpy(cfg.sni, "vless-core.test"); cfg.allow_insecure = 1;
    setenv("VLESS_TLS_MODE", "strict", 1); CHECK("tls/uri-insecure-priority", tls_verify_mode_for_config(&cfg) == TLS_VERIFY_MODE_INSECURE); cfg.allow_insecure = 0;
    unsigned char alpn[32]; unsigned int alpn_length;
    CHECK("tls/alpn-default", build_xhttp_tls_alpn(NULL, alpn, sizeof(alpn), &alpn_length) == 0 && alpn_length == 12 && alpn[0] == 2 && memcmp(alpn+1, "h2", 2) == 0);
    CHECK("tls/alpn-h1", build_xhttp_tls_alpn("http/1.1", alpn, sizeof(alpn), &alpn_length) == 0 && alpn_length == 9);
    CHECK("tls/alpn-capacity", build_xhttp_tls_alpn(NULL, alpn, 2, &alpn_length) != 0);
    CHECK("tls/xray-version", tls13_reality_set_xray_version("26.6.27") == 0 && g_xray_version[1] == 6 && tls13_reality_set_xray_version("256.0.0") != 0 && tls13_reality_set_xray_version("1.2.3x") != 0); tls13_reality_set_xray_version("26.3.27");
    cache_tls_aes_fallback(cfg.server_host, 443, cfg.sni);
    CHECK("tls/aes-cache-isolation", tls_aes_fallback_cached(cfg.server_host, 443, cfg.sni) && !tls_aes_fallback_cached(cfg.server_host, 444, cfg.sni) && !tls_aes_fallback_cached(cfg.server_host, 443, "other.test"));
    struct sockaddr_in address = {.sin_family=AF_INET,.sin_port=htons(443),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)}; struct sockaddr_storage found; socklen_t found_size;
    cache_tls_endpoint(&cfg, cfg.sni, (void *)&address, sizeof(address));
    CHECK("tls/endpoint-cache", get_cached_tls_endpoint(&cfg, cfg.sni, &found, &found_size));
    cfg.pbk[0] = 1; CHECK("tls/key-cache-isolation", !get_cached_tls_endpoint(&cfg, cfg.sni, &found, &found_size)); cfg.pbk[0] = 0;
    invalidate_cached_tls_endpoint(&cfg, cfg.sni, (void *)&address, sizeof(address)); CHECK("tls/endpoint-invalidate", !get_cached_tls_endpoint(&cfg, cfg.sni, &found, &found_size));
    for (int fp = 0; fp < 6; fp++) for (int offer = 0; offer < 2; offer++) {
        cfg.fp_mode = fp; uint8_t priv[32], pub[32], random[32], auth[32], *hello = NULL; size_t length, sid;
        REQUIRE("tls/clienthello-build", build_client_hello(&cfg, 0, offer, priv, pub, random, auth, &hello, &length, &sid, NULL,NULL) == 0);
        CHECK("tls/clienthello-length", hello[0] == 1 && (((size_t)hello[1]<<16)|((size_t)hello[2]<<8)|hello[3]) == length-4 && sid+32 <= length);
        free(hello);
    }
    int pair[2]; REQUIRE("h2/socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    tls13_conn_t c = {.fd=pair[0],.mode=CONN_MODE_GRPC_PLAIN,.h2_stream_id=1,.h2_upload_stream_id=3,.h2_peer_initial_window=65535,.h2_peer_conn_window=65535,.h2_peer_stream_window=65535,.h2_upload_stream_window=65535}; char error[160];
    uint8_t settings[] = {0,4,0,0,0,32};
    CHECK("h2/settings", h2_process_control_frame(&c, H2_FRAME_SETTINGS, 0, 0, settings, sizeof(settings), error, sizeof(error)) == 0 && c.h2_peer_stream_window == 32 && c.h2_upload_stream_window == 32);
    uint8_t ack[9]; REQUIRE("h2/settings-ack-read", read(pair[1], ack, sizeof(ack)) == (ssize_t)sizeof(ack)); CHECK("h2/settings-ack", ack[3] == H2_FRAME_SETTINGS && ack[4] == H2_FLAG_ACK);
    CHECK("h2/settings-malformed", h2_process_control_frame(&c, H2_FRAME_SETTINGS, 0, 0, settings, 5, error, sizeof(error)) != 0);
    uint8_t update[] = {0,0,0,8};
    CHECK("h2/upload-window", h2_process_control_frame(&c, H2_FRAME_WINDOW_UPDATE, 0, 3, update, 4, error, sizeof(error)) == 0 && c.h2_upload_stream_window == 40 && c.h2_peer_stream_window == 32);
    CHECK("h2/download-window", h2_process_control_frame(&c, H2_FRAME_WINDOW_UPDATE, 0, 1, update, 4, error, sizeof(error)) == 0 && c.h2_peer_stream_window == 40);
    uint8_t zero[4] = {0}; CHECK("h2/zero-window-reject", h2_process_control_frame(&c, H2_FRAME_WINDOW_UPDATE, 0, 0, zero, 4, error, sizeof(error)) != 0);
    const uint8_t literal_status[] = {0x48,3,'2','0','0'};
    const uint8_t plain_status[] = {0x08,3,'2','0','0'};
    const uint8_t named_status[] = {0,7,':','s','t','a','t','u','s',3,'2','0','4'};
    const uint8_t extra_header[] = {0x88,0x40,3,'f','o','o',3,'b','a','r'};
    CHECK("h2/literal-indexed-status", core_hpack_status(literal_status,sizeof(literal_status)) == 200);
    CHECK("h2/literal-plain-status", core_hpack_status(plain_status,sizeof(plain_status)) == 200);
    CHECK("h2/literal-named-status", core_hpack_status(named_status,sizeof(named_status)) == 204);
    CHECK("h2/unknown-header-skipped", core_hpack_status(extra_header,sizeof(extra_header)) == 200);
    for (size_t cut = 0; cut < sizeof(literal_status); cut++) CHECK("h2/truncated-literal-status", cut == 0 ? core_hpack_status(literal_status,cut) == 0 : core_hpack_status(literal_status,cut) < 0);
    for (size_t cut = 0; cut < sizeof(extra_header); cut++) CHECK("h2/truncated-unknown-header", cut == 0 ? core_hpack_status(extra_header,cut) == 0 : cut == 1 ? core_hpack_status(extra_header,cut) == 200 : core_hpack_status(extra_header,cut) < 0);
    const uint8_t huffman_status[] = {0x48,0x81,0xff};
    CHECK("h2/invalid-huffman-padding", core_hpack_status(huffman_status,sizeof(huffman_status)) < 0);
    errno = 0; set_connect_err(error,sizeof(error),"vless-core"); CHECK("tls/connect-error-without-errno", strcmp(error,"vless-core") == 0);
    errno = ECONNREFUSED; set_connect_err(error,sizeof(error),"vless-core"); CHECK("tls/connect-error-with-errno", strstr(error,strerror(ECONNREFUSED)) != NULL);
    set_connect_err(NULL,0,"vless-core");
    c.h2_peer_conn_window = 0x7fffffff; CHECK("h2/window-overflow", h2_process_control_frame(&c, H2_FRAME_WINDOW_UPDATE, 0, 0, update, 4, error, sizeof(error)) != 0);
    CHECK("h2/reset", h2_process_control_frame(&c, H2_FRAME_RST_STREAM, 0, 1, zero, 4, error, sizeof(error)) != 0);
    c.h2_stream_eof = 1;
    REQUIRE("h2/completed-response-fixture", db_append(&c.app_cache, "vless-core", 10) == 0);
    CHECK("h2/completed-response-reset", h2_process_control_frame(&c, H2_FRAME_RST_STREAM, 0, 1, zero, 4, error, sizeof(error)) == 0 && c.app_cache.len == 10);
    uint8_t cancel[4] = {0,0,0,8};
    CHECK("h2/reset-code-reported", h2_process_control_frame(&c, H2_FRAME_RST_STREAM, 0, 1, cancel, 4, error, sizeof(error)) != 0 && strstr(error, "code=8") != NULL);
    CHECK("h2/reset-zero-stream-rejected", h2_process_control_frame(&c, H2_FRAME_RST_STREAM, 0, 0, zero, 4, error, sizeof(error)) != 0);
    c.h2_stream_eof = 0; c.h2_request_cancelled = 0; c.app_cache.len = 0;
    CHECK("h2/malformed-reset", h2_process_control_frame(&c, H2_FRAME_RST_STREAM, 0, 1, zero, 3, error, sizeof(error)) != 0);
    CHECK("h2/goaway", h2_process_control_frame(&c, H2_FRAME_GOAWAY, 0, 0, zero, 4, error, sizeof(error)) != 0);
    uint8_t status[] = {0x88}, bad_status[] = {0x8d};
    CHECK("h2/status-200", h2_process_headers(&c, H2_FLAG_END_HEADERS, 1, status, 1, error, sizeof(error)) == 0);
    CHECK("h2/status-error", h2_process_headers(&c, H2_FLAG_END_HEADERS, 1, bad_status, 1, error, sizeof(error)) != 0);
    c.grpc_transport = 1; uint8_t grpc[] = {0,0,0,0,5,10,3,'a','b','c'};
    for (size_t i = 0; i < sizeof(grpc); i++) REQUIRE("grpc/fragmented-frame", grpc_feed_data(&c, grpc+i, 1) == 0);
    CHECK("grpc/decoded-hunk", c.app_cache.len == 3 && memcmp(c.app_cache.data, "abc", 3) == 0);
    uint8_t compressed[] = {1,0,0,0,0}; CHECK("grpc/compressed-reject", grpc_feed_data(&c, compressed, 5) != 0); c.grpc_decoder=(core_grpc_decoder_t){0};
    CHECK("batch/grpc", tls13_write_batch_size(&c) == 65536); c.grpc_transport = 0;
    strcpy(c.xhttp_transport_mode, "packet-up"); c.mode = CONN_MODE_XHTTP_PLAIN; c.xhttp_max_each_post_bytes = 2000000;
    CHECK("batch/xhttp-cap", tls13_write_batch_size(&c) == 1048576); c.xhttp_max_each_post_bytes = 1000; CHECK("batch/xhttp-small", tls13_write_batch_size(&c) == 1000);
    c.mode = CONN_MODE_PLAIN; CHECK("batch/tcp", tls13_write_batch_size(&c) == 8192);
    clear_conn(&c); close(pair[0]); close(pair[1]);
    const char *root = getenv("TEST_PRIVATE_ROOT"); REQUIRE("tofu/private-root", root != NULL);
    char path[PATH_MAX], lock[PATH_MAX], parent[PATH_MAX], pin[65]; snprintf(path, sizeof(path), "%s/pins", root); snprintf(lock, sizeof(lock), "%s/pins.lock", root); memset(pin, 'a', 64); pin[64] = 0; setenv("VLESS_XHTTP_PIN_FILE", path, 1);
    int stored = -1; CHECK("tofu/first-pin", secure_tofu_verify_or_store("vless-core.test:443", pin, &stored, error, sizeof(error)) == 0 && stored == 1);
    CHECK("tofu/repeated-pin", secure_tofu_verify_or_store("vless-core.test:443", pin, &stored, error, sizeof(error)) == 0 && stored == 0);
    pin[0] = 'b'; CHECK("tofu/mismatch", secure_tofu_verify_or_store("vless-core.test:443", pin, &stored, error, sizeof(error)) != 0); pin[0] = 'a';
    for (int failure = 1; failure <= 3; failure++) {
        io_failure = failure;
        CHECK("tofu/atomic-failure", secure_tofu_verify_or_store("fault.test:443", pin, &stored, error, sizeof(error)) != 0);
        int fd = open(path, O_RDONLY); char existing[65];
        CHECK("tofu/old-pin-preserved", fd >= 0 && find_pin_in_fd(fd, "vless-core.test:443", existing) == 0 && strcmp(existing, pin) == 0 && find_pin_in_fd(fd, "fault.test:443", existing) == 1); close(fd);
    }
    pid_t children[4];
    for (int i = 0; i < 4; i++) {
        children[i] = fork(); REQUIRE("tofu/fork", children[i] >= 0);
        if (children[i] == 0) { char name[64]; snprintf(name, sizeof(name), "parallel-%d.test:443", i); _exit(secure_tofu_verify_or_store(name, pin, &stored, error, sizeof(error)) == 0 ? 0 : 1); }
    }
    for (int i = 0; i < 4; i++) { int status; REQUIRE("tofu/parallel-write", waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) && WEXITSTATUS(status) == 0); }
    int all_fd = open(path, O_RDONLY);
    for (int i = 0; i < 4; i++) { char name[64], existing[65]; snprintf(name, sizeof(name), "parallel-%d.test:443", i); CHECK("tofu/parallel-preserves-all", find_pin_in_fd(all_fd, name, existing) == 0 && strcmp(existing, pin) == 0); } close(all_fd);
    struct stat st; stat(path, &st); CHECK("tofu/permissions", (st.st_mode & 0777) == 0600);
    CHECK("tofu/tmp-unsafe", ensure_private_pin_parent("/tmp/pins", parent, error, sizeof(error)) != 0);
    CHECK("tofu/relative-unsafe", ensure_private_pin_parent("relative/pins", parent, error, sizeof(error)) != 0);
    char bad_path[PATH_MAX]; snprintf(bad_path, sizeof(bad_path), "%s/symlink", root); REQUIRE("tofu/symlink-create", symlink(path, bad_path) == 0); setenv("VLESS_XHTTP_PIN_FILE", bad_path, 1);
    CHECK("tofu/symlink-reject", secure_tofu_verify_or_store("new.test:443", pin, &stored, error, sizeof(error)) != 0); unlink(bad_path); snprintf(bad_path, sizeof(bad_path), "%s/symlink.lock", root); unlink(bad_path);
    snprintf(bad_path, sizeof(bad_path), "%s/hardlink", root); REQUIRE("tofu/hardlink-create", link(path, bad_path) == 0); setenv("VLESS_XHTTP_PIN_FILE", path, 1);
    CHECK("tofu/hardlink-reject", secure_tofu_verify_or_store("new.test:443", pin, &stored, error, sizeof(error)) != 0); unlink(bad_path);
    int pin_fd = open(path, O_WRONLY); REQUIRE("tofu/oversize-create", pin_fd >= 0 && ftruncate(pin_fd, TLS_PIN_FILE_MAX_SIZE+1) == 0); close(pin_fd);
    CHECK("tofu/oversize-reject", secure_tofu_verify_or_store("new.test:443", pin, &stored, error, sizeof(error)) != 0);
    unlink(path); unlink(lock); unsetenv("VLESS_XHTTP_PIN_FILE");
    return test_result();
}
