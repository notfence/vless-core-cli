#ifndef CORE_TLS_INTERNAL_H
#define CORE_TLS_INTERNAL_H
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "core_log.h"
#include "server_ips.h"
#include "dialer.h"
#include "xmux.h"
#include "xhttp_config.h"
#include "xhttp_payload.h"
#include "http_headers.h"
#include "xhttp_padding.h"
#include "xhttp_download.h"
#include "utils.h"
#include "socket_util.h"
#include "deadline.h"
#include "hpack.h"
#include "http1.h"
#include "http2.h"
#include "connection_trace.h"
#include "tls13_reality.h"
#include "tls_hello.h"
#include "tls12.h"
#include "websocket.h"
#include "grpc.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TLS_HANDSHAKE_LIMIT (1024U*1024U)
#define TLS_HANDSHAKE_TOTAL_LIMIT (8U*1024U*1024U)
#define TLS_POST_HANDSHAKE_LIMIT (256U*1024U)
#define TLS_RECORD_REKEY_LIMIT (UINT64_C(1)<<20)
#define TLS_RECORD_HARD_LIMIT (UINT64_C(1)<<24)

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    size_t limit;
    size_t *handshake_bytes;
    int tls_budget;
    core_buffer_budget_t *memory;
} dynbuf_t;


typedef enum {
    CONN_MODE_REALITY = 0,
    CONN_MODE_XHTTP_TLS = 1,
    CONN_MODE_XHTTP_REALITY = 2,
    CONN_MODE_TLS = 3,
    CONN_MODE_WS = 4,
    CONN_MODE_XHTTP_TLS_H2 = 5,
    CONN_MODE_PLAIN = 6,
    CONN_MODE_XHTTP_PLAIN = 7,
    CONN_MODE_GRPC_PLAIN = 8
} conn_mode_t;

typedef enum {
    TLS_VERIFY_MODE_STRICT = 0,
    TLS_VERIFY_MODE_INSECURE = 1,
    TLS_VERIFY_MODE_TOFU = 2
} tls_verify_mode_t;

typedef enum {
    TLS_CIPHER_OFFER_CHACHA = 0,
    TLS_CIPHER_OFFER_AES = 1
} tls_cipher_offer_t;

#define CORE_CONNECT_TIMEOUT_MS 12000
#define CORE_TLS_HANDSHAKE_TIMEOUT_MS 12000
#define CORE_OPENSSL_GROUPS "X25519:P-256:P-384"
#define TLS_GROUP_X25519MLKEM768 0x11ec
#define TLS_MLKEM768_PUBLIC_KEY_SIZE 1184
#define TLS_MLKEM768_CIPHERTEXT_SIZE 1088
#define TLS_HYBRID_CLIENT_SHARE_SIZE (TLS_MLKEM768_PUBLIC_KEY_SIZE + 32)
#define TLS_HYBRID_SERVER_SHARE_SIZE (TLS_MLKEM768_CIPHERTEXT_SIZE + 32)
#define TLS_AES_FALLBACK_CACHE_SIZE 16
#define TLS_ENDPOINT_CACHE_SIZE 16
#define XRAY_DEFAULT_VERSION_X 26
#define XRAY_DEFAULT_VERSION_Y 3
#define XRAY_DEFAULT_VERSION_Z 27

typedef struct {
    char host[256];
    uint16_t port;
    char sni[256];
    struct sockaddr_storage address;
    socklen_t address_len;
} tls_aes_fallback_entry_t;

typedef struct {
    int valid;
    char host[256];
    uint16_t port;
    char sni[256];
    uint8_t pbk[32];
    uint8_t short_id[16];
    size_t short_id_len;
    struct sockaddr_storage address;
    socklen_t address_len;
} tls_endpoint_entry_t;

typedef struct h2_response_entry {
    struct h2_response_entry *next;
    uint32_t id;
    core_http2_response_t response;
    int64_t receive_window;
    int request_ended;
} h2_response_entry_t;


struct tls13_conn {
    core_xmux_stream_t *xmux_stream;
    struct tls13_conn *xmux_owner;
    int xmux_physical, xmux_async;
    core_buffer_budget_t *input_memory, *output_memory;
    int relay_async,relay_raw_finish;
    dynbuf_t xmux_raw_input, xmux_plain_output, xmux_wire_output;
    size_t xmux_ssl_write_length;
    uint64_t xmux_enqueued, xmux_flushed;
    size_t xmux_wire_plain_length;
    int xmux_read_wants_write, xmux_write_wants_read;
    core_http1_response_t xmux_http1_response;
    uint32_t xmux_http1_id;
    int xmux_http1_role, xmux_http1_eof, xmux_http1_eof_notified;
    core_hpack_decoder_t hpack;
    core_http2_validation_t h2_validation;
    h2_response_entry_t *h2_responses;
    unsigned h2_response_count;
    int64_t h2_receive_window;
    int fd;
    int ignore_server_ips, ip_source;
    conn_mode_t mode;
    int xhttp_upload_fd;
    pthread_t xhttp_upload_reader;
    int xhttp_upload_reader_started, xhttp_upload_failed, xhttp_upload_stopping;

    uint8_t auth_key[32];

    uint16_t tls_cipher_suite;
    const core_tls12_suite_t *tls12_suite;
    int tls12_etm,tls12_ems,tls12_ticket,tls12_status;
    uint8_t tls12_c_mac[48],tls12_s_mac[48];
    const EVP_MD *tls_md;
    size_t tls_hash_len;
    size_t tls_key_len;
    X509 *tls_peer_certificate;
    dynbuf_t tls_certificate_message;
    unsigned tls_auth_state;
    int tls_client_certificate_requested;
    size_t tls_handshake_bytes;
    unsigned tls_receive_record_limit,tls_send_record_limit;
    int tls_receive_update_requested;
    dynbuf_t tls_post_handshake;
    dynbuf_t tls_stream_input;
    char tls_offered_alpn[128], tls_selected_alpn[128];
    int tls_h2_required, tls_is_reality;
    int tls_alps_received;
    core_http2_settings_t tls_alps_settings;
    dynbuf_t tls_client_hello;
    EVP_PKEY *tls_retry_key;
    unsigned tls_retry_group,tls_exchange_group;
    int tls_retry_seen;

    uint8_t hs_secret[64];
    uint8_t c_hs_traffic[64];
    uint8_t s_hs_traffic[64];

    uint8_t c_app_traffic[64];
    uint8_t s_app_traffic[64];

    uint8_t c_hs_key[32], c_hs_iv[12];
    uint8_t s_hs_key[32], s_hs_iv[12];

    uint8_t c_app_key[32], c_app_iv[12];
    uint8_t s_app_key[32], s_app_iv[12];

    uint64_t c_hs_seq;
    uint64_t s_hs_seq;
    uint64_t c_app_seq;
    uint64_t s_app_seq;
    uint64_t c_app_record_bytes;

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    char remote_host[256];
    uint16_t remote_port;
    char remote_sni[256];

    char xhttp_base_path[512];
    char xhttp_host[256];
    char xhttp_transport_mode[32];
    char xhttp_session_id[256];
    char xhttp_session_placement[16];
    char xhttp_session_key[64];
    char xhttp_seq_placement[16];
    char xhttp_seq_key[64];
    char xhttp_uplink_method[32], xhttp_headers[4096];
    int xhttp_no_grpc_header;
    char xhttp_uplink_data_placement[16], xhttp_uplink_data_key[64];
    core_range_t xhttp_uplink_chunks;
    char xhttp_padding_placement[16];
    char xhttp_padding_key[64];
    char xhttp_padding_header[64];
    char xhttp_padding_method[16];
    int xhttp_padding_obfs;
    int xhttp_padding_min;
    int xhttp_padding_max;
    int xhttp_max_each_post_bytes;
    core_range_t xhttp_post_intervals;
    uint64_t xhttp_last_post_ms;
    uint64_t xhttp_seq;
    core_http1_response_t xhttp_http1_response;
    int xhttp_eof, xhttp_wire_eof;
    int xhttp_tls_insecure;
    char xhttp_pin_key[320];
    tls_verify_mode_t tls_verify_policy;
    char tls_verify_mode[16];
    int tls_use_aes_fallback;
    char ws_path[512];
    char ws_host[320];
    char ws_headers[4096];
    core_ws_decoder_t ws_decoder;
    int ws_upgraded, ws_early_data, ws_want_write, ws_close_sent;
    uint64_t ws_heartbeat_ms, ws_next_heartbeat;
    char grpc_service_name[256];
    char grpc_authority[320];
    char grpc_user_agent[256];
    core_grpc_decoder_t grpc_decoder;
    dynbuf_t grpc_net_cache;
    int grpc_read_failed;
    int grpc_physical_only;
    unsigned grpc_initial_window;
    int grpc_transport;
    int grpc_multi_mode;

    dynbuf_t xhttp_net_cache;
    dynbuf_t ws_net_cache;
    dynbuf_t h2_net_cache;
    dynbuf_t h2_send_buf;
    dynbuf_t h2_header_block;
    dynbuf_t transcript;
    dynbuf_t app_cache;
    int reality_raw_direct;
    int send_closed, receive_closed;

    uint32_t h2_stream_id;
    uint32_t h2_header_stream_id;
    uint8_t h2_header_flags;
    uint32_t h2_next_stream_id;
    int h2_goaway;
    uint32_t h2_peer_initial_window;
    uint32_t h2_peer_max_frame_size;
    uint32_t h2_peer_header_list_size;
    uint32_t h2_peer_concurrency;
    int64_t h2_peer_conn_window;
    int64_t h2_peer_stream_window;
    uint32_t h2_upload_stream_id;
    int64_t h2_upload_stream_window;
    uint32_t h2_recv_conn_pending;
    uint32_t h2_recv_stream_pending;
    int h2_stream_eof;
    int h2_headers_received;
    int h2_request_cancelled;
};


#pragma GCC visibility push(hidden)
extern pthread_mutex_t g_tls_state_lock;
int x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]);
int build_client_hello(const vless_config_t *cfg, int use_reality, tls_cipher_offer_t cipher_offer, uint8_t client_priv[32],
                              uint8_t client_pub[32], uint8_t client_random[32], uint8_t auth_key[32], uint8_t **out, size_t *out_len,
                              size_t *sid_pos, const uint8_t *hybrid_pub, EVP_PKEY **retained);
tls_verify_mode_t tls_verify_mode_for_config(const vless_config_t *cfg);
const char *tls_verify_mode_name(tls_verify_mode_t mode);
int tls_verify_peer(tls_verify_mode_t mode);
int xhttp_make_pin_key(const char *host, uint16_t port, char *out, size_t out_cap);
int xhttp_tofu_verify_or_store(SSL *ssl, const char *pin_key, int log_ok, char *err, size_t err_cap);
int tls_identity_is_ip(const char *identity);
int tls_identity_parameters(X509_VERIFY_PARAM *parameters, const char *identity);
int parse_first_cert_der(const uint8_t *message, size_t length, const uint8_t **der, size_t *der_length);
int tcp_tls_tofu_verify_or_store(const vless_config_t *cfg, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap);
int verify_reality_cert(const uint8_t auth_key[32], const uint8_t *cert_der, size_t cert_der_len);
int tls_certificate_key_usage(X509 *certificate, int signing);
int verify_tls_cert_message(const char *servername, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap);
void set_err(char *err, size_t cap, const char *msg);
int db_reserve(dynbuf_t *b, size_t n);
int db_append(dynbuf_t *b, const void *src, size_t n);
int relay_write_wire(tls13_conn_t *c, const void *data, size_t length);
void db_consume(dynbuf_t *b, size_t n);
void db_free(dynbuf_t *b);
int tls_buffer_init(dynbuf_t *buffer, size_t limit, size_t *owner);
void tls_handshake_material_clear(tls13_conn_t *connection);
int write_exact(int fd, const void *buf, size_t len);
int read_exact(int fd, void *buf, size_t len);
int hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len, uint8_t out[64]);
int hkdf_extract_md(const EVP_MD *md, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk,
                           size_t prk_len);
int hkdf_expand_md(const EVP_MD *md, const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *out,
                          size_t out_len);
int read_record_bounded(int fd, uint8_t *rtype, uint8_t **payload, size_t *payload_len, int tls12_encrypted);
int read_record(int fd, uint8_t *rtype, uint8_t **payload, size_t *payload_len);
int configure_tls_cipher(tls13_conn_t *c, uint16_t suite);
int parse_server_hello_for_keyshare(const uint8_t *msg, size_t msg_len, uint16_t *cipher_out,
                                         uint8_t server_share[TLS_HYBRID_SERVER_SHARE_SIZE], size_t *share_len);
int transcript_hash(const tls13_conn_t *c, uint8_t *out);
int calc_finished_verify(const tls13_conn_t *c, const uint8_t *traffic_secret, const uint8_t *transcript_hash_val, uint8_t *out);
int derive_handshake_keys(tls13_conn_t *c, const uint8_t *shared, size_t shared_len);
int derive_app_keys(tls13_conn_t *c);
int encrypt_record(const tls13_conn_t *c, const uint8_t *key, const uint8_t iv[12], uint64_t *seq, uint8_t inner_type, const uint8_t *plain,
                          size_t plain_len, uint8_t **out, size_t *out_len);
int decrypt_record(const tls13_conn_t *c, const uint8_t *key, const uint8_t iv[12], uint64_t *seq, uint8_t rtype, const uint8_t *payload,
                          size_t payload_len, uint8_t **plain, size_t *plain_len, uint8_t *inner_type);
int append_transcript(tls13_conn_t *c, const uint8_t *msg, size_t msg_len);
int tls_prepare_app_record(tls13_conn_t *c);
int tls_application_plain(tls13_conn_t *c, unsigned type, const uint8_t *data, size_t length, dynbuf_t *cache);
int reality_write_app_records(tls13_conn_t *c, const uint8_t *buf, size_t len);
int fill_reality_plain_cache(tls13_conn_t *c, dynbuf_t *cache);
int fill_reality_app_cache(tls13_conn_t *c);
int manual_stream_read(tls13_conn_t *c,uint8_t *data,size_t capacity,size_t *length);
int run_tls_handshake(const vless_config_t *cfg, tls13_conn_t *c, tls_cipher_offer_t cipher_offer, char *err, size_t err_cap);
int alpn_csv_has_token(const char *csv, const char *token);
int build_xhttp_tls_alpn(const char *cfg_alpn, unsigned char *out, unsigned int cap, unsigned int *out_len);
#pragma GCC visibility pop
#endif
