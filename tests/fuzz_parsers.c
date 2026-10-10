#define _POSIX_C_SOURCE 200809L
#include "../src/tls13_reality.c"
#include "uri.h"
#include "json.h"
#include "utils.h"
#include "vision.h"

static const char *const fuzz_names[] = {"uri", "hpack", "h2", "grpc", "http", "xhttp", "ws", "vision", "tls"};
static size_t fuzz_target;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    const char *name = getenv("VC_FUZZ_PARSER");
    for (size_t i = 0; i < sizeof(fuzz_names) / sizeof(fuzz_names[0]); i++) {
        if (name && strcmp(name, fuzz_names[i]) == 0) {
            fuzz_target = i;
            return 0;
        }
    }
    fprintf(stderr, "VC_FUZZ_PARSER must name a supported parser\n");
    exit(2);
}

static void fuzz_clear(tls13_conn_t *c) {
    db_free(&c->h2_net_cache);
    db_free(&c->h2_header_block);
    core_hpack_clear(&c->hpack);
    db_free(&c->h2_send_buf);
    db_free(&c->app_cache);
    db_free(&c->grpc_recv_cache);
    db_free(&c->ws_net_cache);
    db_free(&c->xhttp_net_cache);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;
    char error[160] = {0};
    tls13_conn_t c = {.fd = -1, .mode = CONN_MODE_GRPC_PLAIN, .h2_stream_id = 1,
                     .h2_peer_initial_window = H2_DEFAULT_WINDOW, .h2_peer_stream_window = H2_DEFAULT_WINDOW,
                     .h2_peer_conn_window = H2_DEFAULT_WINDOW};
    switch (fuzz_target) {
    case 0: {
        char *text = malloc(size + 1);
        if (!text) abort();
        memcpy(text, data, size);
        text[size] = '\0';
        vless_config_t config;
        (void)parse_core_uri(text, &config, error, sizeof(error));
        core_json_t *json = core_json_parse(text, error, sizeof(error));
        core_json_free(json);
        uint8_t decoded[256];
        size_t length = 0, capacity = size ? data[0] : 0;
        (void)base64url_decode(text, decoded, capacity, &length);
        char escaped[256];
        (void)percent_decode(text, escaped, capacity);
        (void)parse_uuid(text, decoded);
        free(text);
        break;
    }
    case 1: {
        (void)core_hpack_status(data, size);
        core_hpack_decoder_t decoder = {0}; core_hpack_headers_t headers;
        size_t split=size ? data[0] % size : 0;
        (void)core_hpack_decode(&decoder,data,split,&headers);
        (void)core_hpack_decode(&decoder,data+split,size-split,&headers);
        core_hpack_clear(&decoder);
        char decoded[256];
        size_t length = 0, capacity = size ? data[0] : 0;
        (void)core_hpack_decode_huffman(data, size, decoded, capacity, &length);
        (void)core_hpack_decode_huffman(data, size, NULL, 0, &length);
        break;
    }
    case 2: {
        if (db_append(&c.h2_net_cache, data, size) != 0) abort();
        while (c.h2_net_cache.len > 0) {
            uint8_t type, flags, *payload = NULL;
            uint32_t stream;
            size_t length = 0;
            if (h2_read_frame(&c, &type, &flags, &stream, &payload, &length) != 0) break;
            int result = type == H2_FRAME_DATA ? grpc_feed_data(&c, payload, length)
                : h2_process_control_frame(&c, type, flags, stream, payload, length, error, sizeof(error));
            free(payload);
            if (result != 0) break;
        }
        break;
    }
    case 3: {
        (void)grpc_append_hunk_payload(&c, data, size);
        c.app_cache.len = 0;
        size_t step = size ? 1 + data[0] % 64 : 1;
        for (size_t off = 0; off < size; off += step) {
            size_t length = size - off < step ? size - off : step;
            if (grpc_feed_data(&c, data + off, length) != 0) break;
        }
        break;
    }
    case 4: {
        core_http1_response_t response={0}; core_http1_event_t event; size_t offset=0;
        for (size_t iteration=0;iteration<size+8;iteration++) {
            int result=core_http1_next(&response,data+offset,size-offset,1,4096,&event);
            offset+=event.consumed;
            if (result || event.kind == 3) break;
        }
        if (db_append(&c.xhttp_net_cache, data, size) != 0) abort();
        int status, chunked, upgrade, connection_upgrade;
        int64_t length;
        (void)parse_http_response_headers(NULL, -1, &c.xhttp_net_cache, &status, &chunked, &length, error, sizeof(error));
        c.xhttp_net_cache.len = 0;
        if (db_append(&c.xhttp_net_cache, data, size) != 0) abort();
        c.mode = CONN_MODE_WS;
        char accept[64];
        (void)parse_ws_upgrade_response(&c, &c.xhttp_net_cache, &status, accept, sizeof(accept), &upgrade,
                                        &connection_upgrade, error, sizeof(error));
        break;
    }
    case 5: {
        core_xhttp_payload_options_t options={.placement=size && (data[0]&1) ? "header" : "cookie",.key="vless-core",.chunks={64,256}};
        core_xhttp_payload_t packet;
        if (core_xhttp_payload_build(&options,data,size,"X-Session: vless-core\r\n",size && (data[0]&2) ? 8192 : 65536,&packet,error,sizeof(error)) == 0) free(packet.headers);
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 || shutdown(pair[1], SHUT_WR) != 0) abort();
        c.fd = pair[0];
        c.mode = CONN_MODE_XHTTP_PLAIN;
        c.xhttp_headers_read = 1;
        c.xhttp_chunked = 1;
        c.xhttp_chunk_rem = -1;
        if (db_append(&c.xhttp_net_cache, data, size) != 0) abort();
        while (c.xhttp_net_cache.len > 0) {
            size_t before = c.xhttp_net_cache.len;
            int result = xhttp_fill_app_cache(&c);
            c.app_cache.len = 0;
            if (result != 0 || c.xhttp_net_cache.len == before) break;
        }
        close(pair[0]);
        close(pair[1]);
        break;
    }
    case 6:
        c.mode = CONN_MODE_WS;
        if (db_append(&c.ws_net_cache, data, size) != 0) abort();
        while (c.ws_net_cache.len > 0) {
            size_t before = c.ws_net_cache.len;
            int result = ws_fill_app_cache(&c);
            c.app_cache.len = 0;
            if (result != 0 || c.ws_net_cache.len == before) break;
        }
        break;
    case 7: {
        uint8_t uuid[16] = {0};
        vision_unpad_t unpad;
        vision_unpad_init(&unpad, uuid);
        size_t step = size ? 1 + data[size - 1] % 64 : 1;
        for (size_t off = 0; off < size; off += step) {
            uint8_t *plain = NULL;
            size_t length = 0, count = size - off < step ? size - off : step;
            int direct = 0;
            int result = vision_unpad_feed(&unpad, data + off, count, &plain, &length, &direct);
            free(plain);
            if (result != 0) break;
        }
        vision_unpad_free(&unpad);
        break;
    }
    case 8: {
        uint8_t share[TLS_HYBRID_SERVER_SHARE_SIZE];
        uint16_t cipher;
        size_t share_length = 0;
        (void)parse_server_hello_for_keyshare(data, size, &cipher, share, &share_length);
        const uint8_t *certificate = NULL;
        size_t certificate_length = 0;
        (void)parse_first_cert_der(data, size, &certificate, &certificate_length);
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) abort();
        if (write_exact(pair[1], data, size) != 0 || shutdown(pair[1], SHUT_WR) != 0) abort();
        uint8_t type, *payload = NULL;
        size_t length = 0;
        (void)read_record(pair[0], &type, &payload, &length);
        free(payload);
        close(pair[0]);
        close(pair[1]);
        break;
    }
    }
    fuzz_clear(&c);
    return 0;
}
