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
    db_free(&c->h2_net_cache); db_free(&c->h2_send_buf); db_free(&c->app_cache); db_free(&c->grpc_recv_cache); db_free(&c->transcript);
    db_free(&c->ws_net_cache); db_free(&c->xhttp_net_cache);
}
static void wait_tls_fixture(tls13_conn_t *c) {
    if (SSL_pending(c->ssl) > 0) return;
    fd_set rfds; FD_ZERO(&rfds); FD_SET(c->fd, &rfds);
    struct timeval timeout = {2,0};
    REQUIRE("xhttp/tls-fixture-input", select(c->fd + 1, &rfds, NULL, NULL, &timeout) > 0);
}
static int live_xhttp_chunks(const char *uri) {
    vless_config_t cfg; char error[256]; tls13_conn_t *c = NULL;
    REQUIRE("xhttp/tls-fixture-config", parse_core_uri(uri, &cfg, error, sizeof(error)) == 0);
    REQUIRE("xhttp/tls-fixture-connect", tls13_reality_connect(&cfg, &c, error, sizeof(error)) == 0);
    REQUIRE("xhttp/tls-fixture-h1", c->mode == CONN_MODE_XHTTP_TLS);
    core_set_socket_io_timeout(c->fd, 500);
    int flags = fcntl(c->fd, F_GETFL, 0);
    uint8_t data[64]; size_t length = 0;
    CHECK("xhttp/tls-first-chunk", tls13_read_app(c, data, sizeof(data), &length) == 0 && length == 3 && memcmp(data, "abc", 3) == 0);
    for (int stage = 0; stage < 4; stage++) {
        if (stage) wait_tls_fixture(c);
        CHECK("xhttp/tls-incomplete-chunk-yields", tls13_read_app(c, data, sizeof(data), &length) == 1 && length == 0);
        CHECK("xhttp/tls-incomplete-chunk-not-pending", !tls13_has_pending_app(c));
        CHECK("xhttp/tls-socket-flags-restored", fcntl(c->fd, F_GETFL, 0) == flags);
        REQUIRE("xhttp/tls-fixture-ack", ssl_write_all(c->ssl, "ack", 3) == 0);
    }
    wait_tls_fixture(c);
    CHECK("xhttp/tls-fragmented-chunk-body", tls13_read_app(c, data, sizeof(data), &length) == 0 && length == 1 && data[0] == 'v');
    REQUIRE("xhttp/tls-body-ack", ssl_write_all(c->ssl, "ack", 3) == 0);
    wait_tls_fixture(c);
    CHECK("xhttp/tls-fragmented-chunk-tail", tls13_read_app(c, data, sizeof(data), &length) == 0 && length == 3 && memcmp(data, "pn!", 3) == 0);
    CHECK("xhttp/tls-chunk-ending-yields", tls13_read_app(c, data, sizeof(data), &length) == 1 && length == 0);
    CHECK("xhttp/tls-chunk-ending-not-pending", !tls13_has_pending_app(c));
    REQUIRE("xhttp/tls-end-ack", ssl_write_all(c->ssl, "ack", 3) == 0);
    wait_tls_fixture(c);
    CHECK("xhttp/tls-chunked-eof", tls13_read_app(c, data, sizeof(data), &length) < 0 && c->xhttp_eof);
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
    REQUIRE("tls/hybrid-share-build", ext_key_share_firefox(&extension, point, public_key) == 0);
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
    CHECK("tls/app-eof", tls13_read_app(&c, eof_buffer, sizeof(eof_buffer), &eof_length) == 0 && eof_length == 0);
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
        if (cut < sizeof(ws_frame)) CHECK("ws/truncated-frame-rejected", result != 0 && c.app_cache.len == 0);
        else CHECK("ws/complete-frame-before-eof", result == 0 && c.app_cache.len == 126 && memcmp(c.app_cache.data, ws_frame+4, 126) == 0);
        clear_conn(&c); close(pair[0]); close(pair[1]);
    }
    uint8_t data[16385]; for (size_t i = 0; i < sizeof(data); i++) data[i] = i%251;
    for (int grpc = 0; grpc < 2; grpc++) {
        REQUIRE("h2/flow-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        core_set_socket_io_timeout(pair[0], 2000); core_set_socket_io_timeout(pair[1], 2000);
        c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_GRPC_PLAIN,.grpc_transport=grpc,.h2_stream_id=1,.h2_peer_max_frame_size=64};
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
    REQUIRE("xhttp/chunk-pair", socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    c = (tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_XHTTP_PLAIN,.xhttp_chunk_rem=-1,.xhttp_content_rem=-1};
    const char *chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;vless-core=yes\r\nabc\r\n0\r\n\r\n";
    db_append(&c.xhttp_net_cache,chunked,strlen(chunked));
    CHECK("xhttp/chunked-extensions", xhttp_fill_app_cache(&c) == 0 && c.app_cache.len == 3 && memcmp(c.app_cache.data,"abc",3) == 0);
    CHECK("xhttp/chunked-eof", xhttp_fill_app_cache(&c) < 0 && c.xhttp_eof); clear_conn(&c); close(pair[0]); close(pair[1]);
    char headers[128] = "", cookies[128] = "", path[128] = "/vless-core";
    CHECK("xhttp/header-injection-rejected", xhttp_append_header_line(headers,sizeof(headers),"X-Session","a\r\nb") != 0);
    CHECK("xhttp/cookie-injection-rejected", xhttp_append_cookie_pair(cookies,sizeof(cookies),"x_session","a\nb") != 0);
    CHECK("xhttp/unknown-placement-rejected", xhttp_apply_meta_one(path,sizeof(path),headers,sizeof(headers),cookies,sizeof(cookies),"invalid","x_session","vless-core") != 0);
}
int main(int argc, char **argv) {
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
    protocol_edges();
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
        REQUIRE("tls/clienthello-build", build_client_hello(&cfg, 0, offer, priv, pub, random, auth, &hello, &length, &sid, NULL) == 0);
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
    const uint8_t extra_header[] = {0x40,3,'f','o','o',3,'b','a','r',0x88};
    CHECK("h2/literal-indexed-status", h2_decode_status_header(literal_status,sizeof(literal_status)) == 200);
    CHECK("h2/literal-plain-status", h2_decode_status_header(plain_status,sizeof(plain_status)) == 200);
    CHECK("h2/literal-named-status", h2_decode_status_header(named_status,sizeof(named_status)) == 204);
    CHECK("h2/unknown-header-skipped", h2_decode_status_header(extra_header,sizeof(extra_header)) == 200);
    for (size_t cut = 0; cut < sizeof(literal_status); cut++) CHECK("h2/truncated-literal-status", h2_decode_status_header(literal_status,cut) == 0);
    for (size_t cut = 0; cut < sizeof(extra_header); cut++) CHECK("h2/truncated-unknown-header", h2_decode_status_header(extra_header,cut) == 0);
    const uint8_t huffman_status[] = {0x48,0x81,0xff};
    CHECK("h2/unsupported-huffman-status", h2_decode_status_header(huffman_status,sizeof(huffman_status)) == 0);
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
    CHECK("h2/status-200", h2_process_headers(&c, 0, 1, status, 1, error, sizeof(error)) == 0);
    CHECK("h2/status-error", h2_process_headers(&c, 0, 1, bad_status, 1, error, sizeof(error)) != 0);
    c.grpc_transport = 1; uint8_t grpc[] = {0,0,0,0,5,10,3,'a','b','c'};
    for (size_t i = 0; i < sizeof(grpc); i++) REQUIRE("grpc/fragmented-frame", grpc_feed_data(&c, grpc+i, 1) == 0);
    CHECK("grpc/decoded-hunk", c.app_cache.len == 3 && memcmp(c.app_cache.data, "abc", 3) == 0);
    uint8_t compressed[] = {1,0,0,0,0}; CHECK("grpc/compressed-reject", grpc_feed_data(&c, compressed, 5) != 0); c.grpc_recv_cache.len = 0;
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
