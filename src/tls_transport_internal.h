#ifndef CORE_TLS_TRANSPORT_INTERNAL_H
#define CORE_TLS_TRANSPORT_INTERNAL_H
#include "tls_internal.h"

enum {
    H2_FRAME_DATA = 0x0,
    H2_FRAME_HEADERS = 0x1,
    H2_FRAME_RST_STREAM = 0x3,
    H2_FRAME_SETTINGS = 0x4,
    H2_FRAME_PING = 0x6,
    H2_FRAME_GOAWAY = 0x7,
    H2_FRAME_WINDOW_UPDATE = 0x8,
    H2_FRAME_CONTINUATION = 0x9,
};

enum {
    H2_FLAG_END_STREAM = 0x1,
    H2_FLAG_END_HEADERS = 0x4,
    H2_FLAG_PADDED = 0x8,
    H2_FLAG_PRIORITY = 0x20,
    H2_FLAG_ACK = 0x1,
};

#define H2_DEFAULT_WINDOW 65535
#define H2_CONNECTION_WINDOW_INC (16U * 1024U * 1024U)
#define H2_CLIENT_INITIAL_WINDOW (16U * 1024U * 1024U)
#define H2_WINDOW_UPDATE_THRESHOLD (1024U * 1024U)
#define H2_DEFAULT_MAX_FRAME 16384U
#define H2_MAX_INBOUND_FRAME (1024U * 1024U)
#define H2_INPUT_DRAIN_LIMIT 4
#define H2_GRPC_INPUT_DRAIN_LIMIT 64
#define H2_WRITE_BATCH_SIZE (64U * 1024U)

int tcp_connect_host(const char *host, uint16_t port, int use_server_ips);
int ssl_write_all(SSL *ssl, const void *buf, size_t len);
int ssl_read_some(SSL *ssl, uint8_t *buf, size_t cap, size_t *out_len);
int fd_read_some(int fd, uint8_t *buf, size_t cap, size_t *out_len);
int open_tls_socket(int use_server_ips, const char *connect_host, uint16_t connect_port, const char *sni, int verify_peer,
                           const unsigned char *alpn_protos, unsigned int alpn_protos_len, SSL_CTX **out_ctx, SSL **out_ssl, int *out_fd,
                           int *use_aes_fallback, char *err, size_t err_cap);
size_t find_double_crlf(const uint8_t *buf, size_t len);
void trim_ascii(char *s);
int http_host(const char *input, char *output, size_t capacity);
int ws_conn_read_some(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len);
int ws_conn_write_all(tls13_conn_t *c, const void *buf, size_t len);
int ws_write_frame(tls13_conn_t *c, uint8_t opcode, const uint8_t *buf, size_t len);
int ws_fill_app_cache(tls13_conn_t *c);
int xhttp_fill_app_cache(tls13_conn_t *c);
int h2_send_frame(tls13_conn_t *c, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t len);
void h2_response_clear(tls13_conn_t *c);
int h2_collect_tls_available(tls13_conn_t *c, int *want_write);
int h2_read_frame(tls13_conn_t *c, uint8_t *type, uint8_t *flags, uint32_t *stream_id, uint8_t **payload, size_t *payload_len);
int h2_write_data(tls13_conn_t *c, const uint8_t *buf, size_t len);
int grpc_fill_app_cache(tls13_conn_t *c);
int grpc_pool_read(tls13_conn_t *c, uint8_t *buffer, size_t capacity, size_t *length);
int grpc_write_hunk(tls13_conn_t *c, const uint8_t *buf, size_t len);
int h2_pump_one_frame(tls13_conn_t *c);
int h2_fill_app_cache(tls13_conn_t *c);
int xhttp_prepare_request(tls13_conn_t *c, const char *seq_str, char *path, size_t path_cap, char *headers, size_t headers_cap);
int xhttp_packet_headers(tls13_conn_t *connection, const char *sequence, const uint8_t *data, size_t length, uint32_t header_limit,
                                char path[2048], core_xhttp_payload_t *packet, char *error, size_t capacity);
int h2_send_xhttp_request_headers(tls13_conn_t *c, uint32_t stream_id, const char *method, const char *path,
                                         const char *extra_headers, size_t content_len, int has_body, int streaming_body, char *err,
                                         size_t err_cap);
int xhttp_wait_post(tls13_conn_t *connection, char *error, size_t capacity);
int xhttp_h2_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap);
int xhttp_h2_start_mode(tls13_conn_t *c, char *err, size_t err_cap);
int h2_send_grpc_request_headers(tls13_conn_t *c, char *err, size_t err_cap);
int xhttp_http1_headers(tls13_conn_t *connection, const char *method, const char *path, const char *source, int body_mode, size_t body_size,
                               const char *keep_alive, dynbuf_t *request);
int xhttp_write_plain_stream(tls13_conn_t *c, const uint8_t *buf, size_t len);
int xhttp_http1_packet_request(tls13_conn_t *connection, const char *path, const char *headers, size_t body_size, const char *keep_alive, dynbuf_t *request);
int xhttp_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap);
int h2_cached_frame_ready(const tls13_conn_t *c);
int h2_input_ready(const tls13_conn_t *c);
int connect_manual_tls(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);
int ws_upgrade(tls13_conn_t *c, const uint8_t *early, size_t early_length, char *err, size_t err_cap);
int ws_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);
int xhttp_configure(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);
int xhttp_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);
int grpc_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);
int tls13_connect_budgeted(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap,
                                  core_buffer_budget_t *output_memory, core_buffer_budget_t *input_memory);
extern const core_xmux_backend_t xmux_backend;
extern const char xhttp_user_agent[];
#endif
