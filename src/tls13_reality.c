#define _POSIX_C_SOURCE 200809L
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
#include "websocket.h"
#include "grpc.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/ec.h>
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

static pthread_mutex_t tls_buffer_lock=PTHREAD_MUTEX_INITIALIZER;
static size_t tls_buffer_bytes;

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

static uint8_t g_xray_version[3] = {
    XRAY_DEFAULT_VERSION_X,
    XRAY_DEFAULT_VERSION_Y,
    XRAY_DEFAULT_VERSION_Z,
};

int tls13_reality_set_xray_version(const char *value) {
    unsigned int x = 0, y = 0, z = 0;
    char trailing = '\0';
    if (value == NULL ||
        sscanf(value, "%u.%u.%u%c", &x, &y, &z, &trailing) != 3 ||
        x > 255 || y > 255 || z > 255) {
        return -1;
    }
    g_xray_version[0] = (uint8_t)x;
    g_xray_version[1] = (uint8_t)y;
    g_xray_version[2] = (uint8_t)z;
    return 0;
}

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

static tls_aes_fallback_entry_t g_tls_aes_fallback_cache[TLS_AES_FALLBACK_CACHE_SIZE];
static size_t g_tls_aes_fallback_count = 0;
static tls_endpoint_entry_t g_tls_endpoint_cache[TLS_ENDPOINT_CACHE_SIZE];
static size_t g_tls_endpoint_replace_index = 0;
static pthread_mutex_t g_tls_state_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_tls_cipher_logged = 0;

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
    int ignore_server_ips;
    conn_mode_t mode;
    int xhttp_upload_fd;
    pthread_t xhttp_upload_reader;
    int xhttp_upload_reader_started, xhttp_upload_failed, xhttp_upload_stopping;

    uint8_t auth_key[32];

    uint16_t tls_cipher_suite;
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
    char tls_offered_alpn[128], tls_selected_alpn[128];
    int tls_h2_required, tls_is_reality;
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

static int reality_write_app_records(tls13_conn_t *c, const uint8_t *buf, size_t len);
static int fill_reality_plain_cache(tls13_conn_t *c, dynbuf_t *cache);
static int write_exact(int fd, const void *buf, size_t len);
static int h2_pump_one_frame(tls13_conn_t *c);
static int h2_cached_frame_ready(const tls13_conn_t *c);
static const core_xmux_backend_t xmux_backend;

static void set_err(char *err, size_t cap, const char *msg) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
}

static int tls_aes_fallback_entry_matches(const tls_aes_fallback_entry_t *entry, const char *host, uint16_t port, const char *sni) {
    return entry->port == port && strcmp(entry->host, host) == 0 && strcmp(entry->sni, sni != NULL ? sni : "") == 0;
}

static int tls_aes_fallback_cached(const char *host, uint16_t port, const char *sni) {
    int found = 0;
    pthread_mutex_lock(&g_tls_state_lock);
    for (size_t i = 0; i < g_tls_aes_fallback_count; i++) {
        if (!g_tls_aes_fallback_cache[i].address_len && tls_aes_fallback_entry_matches(&g_tls_aes_fallback_cache[i], host, port, sni)) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_tls_state_lock);
    return found;
}

static void cache_tls_aes_fallback(const char *host, uint16_t port, const char *sni) {
    pthread_mutex_lock(&g_tls_state_lock);
    for (size_t i = 0; i < g_tls_aes_fallback_count; i++) {
        if (!g_tls_aes_fallback_cache[i].address_len && tls_aes_fallback_entry_matches(&g_tls_aes_fallback_cache[i], host, port, sni)) {
            pthread_mutex_unlock(&g_tls_state_lock);
            return;
        }
    }
    if (g_tls_aes_fallback_count < TLS_AES_FALLBACK_CACHE_SIZE) {
        tls_aes_fallback_entry_t *entry = &g_tls_aes_fallback_cache[g_tls_aes_fallback_count++];
        snprintf(entry->host, sizeof(entry->host), "%s", host);
        entry->port = port;
        snprintf(entry->sni, sizeof(entry->sni), "%s", sni != NULL ? sni : "");
    }
    pthread_mutex_unlock(&g_tls_state_lock);
}

static void log_tls_cipher_once(const char *cipher) {
    pthread_mutex_lock(&g_tls_state_lock);
    if (!g_tls_cipher_logged) {
        vc_log_debug("tls", "selected cipher=%s", cipher != NULL ? cipher : "unknown");
        g_tls_cipher_logged = 1;
    }
    pthread_mutex_unlock(&g_tls_state_lock);
}

static int tls_endpoint_entry_matches(const tls_endpoint_entry_t *entry, const vless_config_t *cfg, const char *sni) {
    return entry->valid && entry->port == cfg->server_port && entry->short_id_len == cfg->short_id_len &&
           strcmp(entry->host, cfg->server_host) == 0 && strcmp(entry->sni, sni) == 0 &&
           memcmp(entry->pbk, cfg->pbk, sizeof(entry->pbk)) == 0 &&
           memcmp(entry->short_id, cfg->short_id, cfg->short_id_len) == 0;
}

static int sockaddr_equal(const struct sockaddr *a, socklen_t a_len, const struct sockaddr *b, socklen_t b_len) {
    if (a == NULL || b == NULL || a->sa_family != b->sa_family) {
        return 0;
    }
    if (a->sa_family == AF_INET && a_len >= (socklen_t)sizeof(struct sockaddr_in) &&
        b_len >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        return a4->sin_port == b4->sin_port && a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6 && a_len >= (socklen_t)sizeof(struct sockaddr_in6) &&
        b_len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        return a6->sin6_port == b6->sin6_port && a6->sin6_scope_id == b6->sin6_scope_id &&
               memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
    }
    return 0;
}

static int tls_address_aes_cached(const char *host, uint16_t port, const char *sni, const struct sockaddr *address, socklen_t length) {
    int found=0; pthread_mutex_lock(&g_tls_state_lock);
    for (size_t i=0;i<g_tls_aes_fallback_count;i++) {
        const tls_aes_fallback_entry_t *entry=g_tls_aes_fallback_cache+i;
        if (tls_aes_fallback_entry_matches(entry,host,port,sni) && sockaddr_equal((const struct sockaddr *)&entry->address,entry->address_len,address,length)) { found=1; break; }
    }
    pthread_mutex_unlock(&g_tls_state_lock); return found;
}

static void cache_tls_address_aes(const char *host, uint16_t port, const char *sni, const struct sockaddr *address, socklen_t length) {
    if (!address || length > sizeof(struct sockaddr_storage)) return;
    pthread_mutex_lock(&g_tls_state_lock);
    for (size_t i=0;i<g_tls_aes_fallback_count;i++) {
        const tls_aes_fallback_entry_t *entry=g_tls_aes_fallback_cache+i;
        if (tls_aes_fallback_entry_matches(entry,host,port,sni) && sockaddr_equal((const struct sockaddr *)&entry->address,entry->address_len,address,length)) {
            pthread_mutex_unlock(&g_tls_state_lock); return;
        }
    }
    if (g_tls_aes_fallback_count < TLS_AES_FALLBACK_CACHE_SIZE) {
        tls_aes_fallback_entry_t *entry=g_tls_aes_fallback_cache+g_tls_aes_fallback_count++;
        snprintf(entry->host,sizeof(entry->host),"%s",host); entry->port=port;
        snprintf(entry->sni,sizeof(entry->sni),"%s",sni ? sni : "");
        memcpy(&entry->address,address,length); entry->address_len=length;
    }
    pthread_mutex_unlock(&g_tls_state_lock);
}

static int get_cached_tls_endpoint(const vless_config_t *cfg, const char *sni, struct sockaddr_storage *address,
                                   socklen_t *address_len) {
    int found = 0;
    pthread_mutex_lock(&g_tls_state_lock);
    for (size_t i = 0; i < TLS_ENDPOINT_CACHE_SIZE; i++) {
        if (tls_endpoint_entry_matches(&g_tls_endpoint_cache[i], cfg, sni)) {
            *address = g_tls_endpoint_cache[i].address;
            *address_len = g_tls_endpoint_cache[i].address_len;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_tls_state_lock);
    return found;
}

static void cache_tls_endpoint(const vless_config_t *cfg, const char *sni, const struct sockaddr *address, socklen_t address_len) {
    if (address == NULL || address_len > (socklen_t)sizeof(struct sockaddr_storage)) {
        return;
    }

    pthread_mutex_lock(&g_tls_state_lock);
    tls_endpoint_entry_t *entry = NULL;
    for (size_t i = 0; i < TLS_ENDPOINT_CACHE_SIZE; i++) {
        if (tls_endpoint_entry_matches(&g_tls_endpoint_cache[i], cfg, sni)) {
            entry = &g_tls_endpoint_cache[i];
            break;
        }
        if (entry == NULL && !g_tls_endpoint_cache[i].valid) {
            entry = &g_tls_endpoint_cache[i];
        }
    }
    if (entry == NULL) {
        entry = &g_tls_endpoint_cache[g_tls_endpoint_replace_index++ % TLS_ENDPOINT_CACHE_SIZE];
    }

    memset(entry, 0, sizeof(*entry));
    entry->valid = 1;
    snprintf(entry->host, sizeof(entry->host), "%s", cfg->server_host);
    entry->port = cfg->server_port;
    snprintf(entry->sni, sizeof(entry->sni), "%s", sni);
    memcpy(entry->pbk, cfg->pbk, sizeof(entry->pbk));
    memcpy(entry->short_id, cfg->short_id, cfg->short_id_len);
    entry->short_id_len = cfg->short_id_len;
    memcpy(&entry->address, address, address_len);
    entry->address_len = address_len;
    pthread_mutex_unlock(&g_tls_state_lock);
}

static void invalidate_cached_tls_endpoint(const vless_config_t *cfg, const char *sni, const struct sockaddr *address,
                                           socklen_t address_len) {
    pthread_mutex_lock(&g_tls_state_lock);
    for (size_t i = 0; i < TLS_ENDPOINT_CACHE_SIZE; i++) {
        tls_endpoint_entry_t *entry = &g_tls_endpoint_cache[i];
        if (tls_endpoint_entry_matches(entry, cfg, sni) &&
            sockaddr_equal((const struct sockaddr *)&entry->address, entry->address_len, address, address_len)) {
            entry->valid = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_tls_state_lock);
}

static int db_reserve(dynbuf_t *b, size_t n) {
    if (n > SIZE_MAX-b->len) { errno=EOVERFLOW; return -1; }
    if (b->limit && b->len+n > b->limit) { errno=EMSGSIZE; return -1; }
    if (b->len + n <= b->cap) {
        return 0;
    }
    size_t nc = (b->cap == 0) ? 1024 : b->cap;
    while (nc < b->len + n) {
        if (nc > SIZE_MAX/2) { nc=b->len+n; break; }
        nc *= 2;
    }
    if (b->limit && nc > b->limit) nc=b->limit;
    size_t retained=nc-b->cap,increase=b->tls_budget ? nc : retained;
    if (b->tls_budget) {
        pthread_mutex_lock(&tls_buffer_lock);
        if (increase > TLS_HANDSHAKE_TOTAL_LIMIT-tls_buffer_bytes ||
            (b->handshake_bytes && retained > TLS_HANDSHAKE_LIMIT-*b->handshake_bytes)) {
            pthread_mutex_unlock(&tls_buffer_lock); errno=ENOBUFS; return -1;
        }
        tls_buffer_bytes+=increase;
        if (b->handshake_bytes) *b->handshake_bytes+=retained;
        pthread_mutex_unlock(&tls_buffer_lock);
    }
    uint8_t *tmp = b->tls_budget ? malloc(nc) : b->memory ? core_buffer_realloc(b->memory,b->data,b->cap,nc) : realloc(b->data,nc);
    if (tmp == NULL) {
        if (b->tls_budget) {
            pthread_mutex_lock(&tls_buffer_lock); tls_buffer_bytes-=increase;
            if (b->handshake_bytes) *b->handshake_bytes-=retained;
            pthread_mutex_unlock(&tls_buffer_lock);
        }
        return -1;
    }
    if (b->tls_budget) {
        if (b->len) memcpy(tmp,b->data,b->len);
        if (b->data) { OPENSSL_cleanse(b->data,b->cap); free(b->data); }
        pthread_mutex_lock(&tls_buffer_lock); tls_buffer_bytes-=b->cap;
        pthread_mutex_unlock(&tls_buffer_lock);
    }
    b->data = tmp;
    b->cap = nc;
    return 0;
}

static int db_append(dynbuf_t *b, const void *src, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (db_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static int relay_write_wire(tls13_conn_t *c, const void *data, size_t length) {
    if (!c->relay_async) return write_exact(c->fd,data,length);
    if (length > 256U*1024U-c->xmux_wire_output.len) { errno=EAGAIN; return -1; }
    return db_append(&c->xmux_wire_output,data,length);
}

static void db_consume(dynbuf_t *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
        if (b->memory && b->cap > 65536) {
            core_buffer_free(b->memory,b->data,b->cap); b->data=NULL; b->cap=0;
        }
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

static void db_free(dynbuf_t *b) {
    if (b->tls_budget) {
        pthread_mutex_lock(&tls_buffer_lock); tls_buffer_bytes-=b->cap;
        if (b->handshake_bytes) *b->handshake_bytes-=b->cap;
        pthread_mutex_unlock(&tls_buffer_lock);
        if (b->data) OPENSSL_cleanse(b->data,b->cap);
    }
    if (b->data != NULL) {
        if (b->memory) core_buffer_free(b->memory,b->data,b->cap);
        else free(b->data);
    }
    memset(b, 0, sizeof(*b));
}

static int tls_buffer_init(dynbuf_t *buffer, size_t limit, size_t *owner) {
    if (buffer->tls_budget) return buffer->limit == limit && buffer->handshake_bytes == owner ? 0 : -1;
    if (buffer->cap > limit) { errno=EMSGSIZE; return -1; }
    pthread_mutex_lock(&tls_buffer_lock);
    if (buffer->cap > TLS_HANDSHAKE_TOTAL_LIMIT-tls_buffer_bytes || (owner && buffer->cap > TLS_HANDSHAKE_LIMIT-*owner)) {
        pthread_mutex_unlock(&tls_buffer_lock); errno=ENOBUFS; return -1;
    }
    tls_buffer_bytes+=buffer->cap; if (owner) *owner+=buffer->cap;
    pthread_mutex_unlock(&tls_buffer_lock);
    buffer->limit=limit; buffer->handshake_bytes=owner; buffer->tls_budget=1; return 0;
}

static void tls_handshake_material_clear(tls13_conn_t *connection) {
    OPENSSL_cleanse(connection->auth_key,sizeof(connection->auth_key));
    OPENSSL_cleanse(connection->hs_secret,sizeof(connection->hs_secret));
    OPENSSL_cleanse(connection->c_hs_traffic,sizeof(connection->c_hs_traffic));
    OPENSSL_cleanse(connection->s_hs_traffic,sizeof(connection->s_hs_traffic));
    OPENSSL_cleanse(connection->c_hs_key,sizeof(connection->c_hs_key));
    OPENSSL_cleanse(connection->s_hs_key,sizeof(connection->s_hs_key));
    OPENSSL_cleanse(connection->c_hs_iv,sizeof(connection->c_hs_iv));
    OPENSSL_cleanse(connection->s_hs_iv,sizeof(connection->s_hs_iv));
    db_free(&connection->transcript); db_free(&connection->tls_client_hello); db_free(&connection->tls_certificate_message);
    X509_free(connection->tls_peer_certificate); connection->tls_peer_certificate=NULL;
    EVP_PKEY_free(connection->tls_retry_key); connection->tls_retry_key=NULL;
}

static int write_exact(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = core_send(fd, p + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_exact(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = core_recv(fd, p + off, len - off, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            if (n == 0) errno = EPROTO;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int tcp_connect_host(const char *host, uint16_t port, int use_server_ips) {
    return core_dial_host(host, port, use_server_ips, CORE_CONNECT_TIMEOUT_MS);
}

static int tcp_connect_address(int family, int socktype, int protocol, const struct sockaddr *address, socklen_t address_len) {
    int fd = socket(family, socktype, protocol);
    if (fd < 0) {
        return -1;
    }
    core_tune_tcp_socket(fd);
    if (core_connect_with_timeout(fd, address, address_len, CORE_CONNECT_TIMEOUT_MS) == 0) {
        return fd;
    }
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

static void set_connect_err(char *err, size_t err_cap, const char *prefix) {
    if (err == NULL || err_cap == 0) return;
    int code = errno;
    if (code == 0) {
        snprintf(err, err_cap, "%s", prefix);
    } else {
        snprintf(err, err_cap, "%s: %s (%d)", prefix, strerror(code), code);
    }
}

static int ssl_budget_call(SSL *ssl, void *buffer, int length, int operation) {
    if (!core_deadline_active()) {
        return operation == 0 ? SSL_connect(ssl) : operation == 1 ? SSL_read(ssl, buffer, length) : SSL_write(ssl, buffer, length);
    }
    int fd = SSL_get_fd(ssl), flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    int result = -1;
    for (;;) {
        if (core_deadline_remaining() == 0) break;
        result = operation == 0 ? SSL_connect(ssl) : operation == 1 ? SSL_read(ssl, buffer, length) : SSL_write(ssl, buffer, length);
        if (result > 0) break;
        int error = SSL_get_error(ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) break;
        int ready = core_wait_socket(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, -1);
        if (ready <= 0) { if (ready == 0) errno = ETIMEDOUT; result = -1; break; }
    }
    int saved_errno = errno;
    if (fcntl(fd, F_SETFL, flags) != 0) result = -1;
    errno = saved_errno;
    return result;
}

static int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        int n = ssl_budget_call(ssl, (void *)(p + off), (int)(len - off), 2);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int ssl_read_some(SSL *ssl, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    int n = ssl_budget_call(ssl, buf, (int)cap, 1);
    if (n <= 0) {
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

static int fd_read_some(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    ssize_t n = core_recv(fd, buf, cap, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

static int normalize_xhttp_path(const char *in, char *out, size_t out_cap) {
    return core_http_path(in,out,out_cap,1);
}

static int random_xpadding_value(int min_len, int max_len, const char *method, char *buf, size_t cap) {
    return core_xhttp_padding((core_range_t){min_len,max_len},method,buf,cap);
}

static tls_verify_mode_t get_tls_verify_mode(void) {
    const char *v = getenv("VLESS_TLS_MODE");
    if (v == NULL || v[0] == '\0') v = getenv("VLESS_XHTTP_TLS_MODE");
    if (v == NULL || v[0] == '\0') return TLS_VERIFY_MODE_STRICT;
    if (strcmp(v, "insecure") == 0) {
        return TLS_VERIFY_MODE_INSECURE;
    }
    if (strcmp(v, "tofu") == 0) {
        return TLS_VERIFY_MODE_TOFU;
    }
    return TLS_VERIFY_MODE_STRICT;
}

static tls_verify_mode_t tls_verify_mode_for_config(const vless_config_t *cfg) {
    return cfg != NULL && cfg->allow_insecure ? TLS_VERIFY_MODE_INSECURE : get_tls_verify_mode();
}

static const char *tls_verify_mode_name(tls_verify_mode_t mode) {
    switch (mode) {
    case TLS_VERIFY_MODE_INSECURE:
        return "insecure";
    case TLS_VERIFY_MODE_TOFU:
        return "tofu";
    case TLS_VERIFY_MODE_STRICT:
    default:
        return "strict";
    }
}

static int tls_verify_peer(tls_verify_mode_t mode) {
    return mode == TLS_VERIFY_MODE_STRICT;
}

static void ascii_lower(char *s) {
    if (s == NULL) {
        return;
    }
    for (size_t i = 0; s[i] != '\0'; i++) {
        s[i] = (char)tolower((unsigned char)s[i]);
    }
}

static int xhttp_make_pin_key(const char *host, uint16_t port, char *out, size_t out_cap) {
    if (host == NULL || host[0] == '\0' || out == NULL || out_cap < 8) {
        return -1;
    }
    int n = snprintf(out, out_cap, "%s:%u", host, (unsigned int)port);
    if (n <= 0 || (size_t)n >= out_cap) {
        return -1;
    }
    ascii_lower(out);
    return 0;
}

#define TLS_PIN_FILE_MAX_SIZE (1024U * 1024U)

static int tls_pin_file_path(char out[PATH_MAX], char *err, size_t err_cap) {
    const char *override = getenv("VLESS_XHTTP_PIN_FILE");
    if (override != NULL && override[0] != '\0') {
        if (override[0] != '/' || strlen(override) >= PATH_MAX) {
            set_err(err, err_cap, "TOFU pin path must be absolute");
            return -1;
        }
        snprintf(out, PATH_MAX, "%s", override);
        return 0;
    }

#ifdef __APPLE__
    snprintf(out, PATH_MAX, "%s", "/private/var/mobile/Library/Preferences/vless-core/xhttp-pins.txt");
#else
    struct passwd pw;
    struct passwd *result = NULL;
    char pw_buffer[4096];
    if (getpwuid_r(geteuid(), &pw, pw_buffer, sizeof(pw_buffer), &result) != 0 || result == NULL || pw.pw_dir == NULL ||
        pw.pw_dir[0] != '/') {
        set_err(err, err_cap, "failed to resolve a private TOFU pin path");
        return -1;
    }
    int n = snprintf(out, PATH_MAX, "%s/.local/state/vless-core/tls-pins.txt", pw.pw_dir);
    if (n <= 0 || n >= PATH_MAX) {
        set_err(err, err_cap, "TOFU pin path is too long");
        return -1;
    }
#endif
    return 0;
}

static int ensure_private_pin_parent(const char *path, char parent[PATH_MAX], char *err, size_t err_cap) {
    if (path == NULL || path[0] != '/' || strstr(path, "/../") != NULL) {
        set_err(err, err_cap, "unsafe TOFU pin path");
        return -1;
    }

    size_t length = strlen(path);
    if (length == 0 || length >= PATH_MAX) {
        set_err(err, err_cap, "TOFU pin path is too long");
        return -1;
    }
    memcpy(parent, path, length + 1);
    char *slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        set_err(err, err_cap, "TOFU pin path needs a private parent directory");
        return -1;
    }
    *slash = '\0';

    size_t parent_length = strlen(parent);
    for (size_t i = 1; i <= parent_length; i++) {
        if (i != parent_length && parent[i] != '/') continue;

        char saved = parent[i];
        parent[i] = '\0';
        struct stat st;
        if (lstat(parent, &st) != 0) {
            if (errno != ENOENT || mkdir(parent, 0700) != 0 || lstat(parent, &st) != 0) {
                parent[i] = saved;
                set_err(err, err_cap, "failed to create private TOFU pin directory");
                return -1;
            }
        }
        if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) || (st.st_mode & 0022) != 0) {
            parent[i] = saved;
            set_err(err, err_cap, "unsafe TOFU pin directory");
            return -1;
        }
        if (i == parent_length && st.st_uid != geteuid()) {
            parent[i] = saved;
            set_err(err, err_cap, "TOFU pin directory has the wrong owner");
            return -1;
        }
        parent[i] = saved;
    }
    return 0;
}

static int open_private_pin_file(const char *path, int flags, char *err, size_t err_cap) {
    int fd = open(path, flags | O_NOFOLLOW, 0600);
    if (fd < 0) {
        set_err(err, err_cap, errno == ELOOP ? "refusing symlink TOFU pin file" : "failed to open TOFU pin file");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1) {
        close(fd);
        set_err(err, err_cap, "unsafe TOFU pin file");
        return -1;
    }
    if ((st.st_mode & 0077) != 0 && fchmod(fd, 0600) != 0) {
        close(fd);
        set_err(err, err_cap, "failed to protect TOFU pin file");
        return -1;
    }
    return fd;
}

static int find_pin_in_fd(int fd, const char *key, char pin_hex[65]) {
    int copy = dup(fd);
    if (copy < 0 || lseek(copy, 0, SEEK_SET) < 0) {
        if (copy >= 0) close(copy);
        return -1;
    }
    FILE *f = fdopen(copy, "r");
    if (f == NULL) {
        close(copy);
        return -1;
    }

    int result = 1;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        char file_key[512];
        char file_pin[130];
        if (line[0] == '#' || sscanf(line, "%511s %129s", file_key, file_pin) != 2 || strcmp(file_key, key) != 0 ||
            strlen(file_pin) != 64) {
            continue;
        }
        size_t i = 0;
        while (i < 64 && isxdigit((unsigned char)file_pin[i])) i++;
        if (i != 64) continue;
        memcpy(pin_hex, file_pin, 64);
        pin_hex[64] = '\0';
        ascii_lower(pin_hex);
        result = 0;
        break;
    }
    if (ferror(f)) result = -1;
    fclose(f);
    return result;
}

static int write_fd_all(int fd, const void *data, size_t length) {
    const uint8_t *p = (const uint8_t *)data;
    while (length > 0) {
        ssize_t written = write(fd, p, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        p += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int atomic_add_pin(const char *path, const char *parent, int source_fd, const char *key, const char *pin_hex, char *err,
                          size_t err_cap) {
    struct stat st;
    if (fstat(source_fd, &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size > TLS_PIN_FILE_MAX_SIZE) {
        set_err(err, err_cap, "TOFU pin file is too large");
        return -1;
    }

    char temp_path[PATH_MAX];
    int n = snprintf(temp_path, sizeof(temp_path), "%s.tmp.XXXXXX", path);
    if (n <= 0 || (size_t)n >= sizeof(temp_path)) {
        set_err(err, err_cap, "TOFU temporary path is too long");
        return -1;
    }
    int temp_fd = mkstemp(temp_path);
    if (temp_fd < 0 || fchmod(temp_fd, 0600) != 0) {
        if (temp_fd >= 0) close(temp_fd);
        if (temp_fd >= 0) unlink(temp_path);
        set_err(err, err_cap, "failed to create TOFU pin file");
        return -1;
    }

    int result = -1;
    char buffer[4096];
    if (lseek(source_fd, 0, SEEK_SET) < 0) goto done;
    for (;;) {
        ssize_t count = read(source_fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (count > 0 && write_fd_all(temp_fd, buffer, (size_t)count) != 0)) goto done;
        if (count == 0) break;
    }

    if (st.st_size > 0) {
        char last = '\0';
        if (pread(source_fd, &last, 1, st.st_size - 1) != 1) goto done;
        if (last != '\n' && write_fd_all(temp_fd, "\n", 1) != 0) goto done;
    }
    char entry[1024];
    n = snprintf(entry, sizeof(entry), "%s %s\n", key, pin_hex);
    if (n <= 0 || (size_t)n >= sizeof(entry) || write_fd_all(temp_fd, entry, (size_t)n) != 0 || fsync(temp_fd) != 0) goto done;
    if (close(temp_fd) != 0) {
        temp_fd = -1;
        goto done;
    }
    temp_fd = -1;
    if (rename(temp_path, path) != 0) goto done;

    int parent_fd = open(parent, O_RDONLY | O_NOFOLLOW);
    if (parent_fd >= 0) {
        (void)fsync(parent_fd);
        close(parent_fd);
    }
    result = 0;

done:
    if (temp_fd >= 0) close(temp_fd);
    if (result != 0) {
        unlink(temp_path);
        set_err(err, err_cap, "failed to persist TOFU pin");
    }
    return result;
}

static int secure_tofu_verify_or_store(const char *key, const char *pin_hex, int *stored, char *err, size_t err_cap) {
    char path[PATH_MAX];
    char parent[PATH_MAX];
    if (tls_pin_file_path(path, err, err_cap) != 0 || ensure_private_pin_parent(path, parent, err, err_cap) != 0) return -1;

    char lock_path[PATH_MAX];
    int n = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (n <= 0 || (size_t)n >= sizeof(lock_path)) {
        set_err(err, err_cap, "TOFU lock path is too long");
        return -1;
    }
    int lock_fd = open_private_pin_file(lock_path, O_RDWR | O_CREAT, err, err_cap);
    if (lock_fd < 0) return -1;
    if (flock(lock_fd, LOCK_EX) != 0) {
        close(lock_fd);
        set_err(err, err_cap, "failed to lock TOFU pin file");
        return -1;
    }

    int result = -1;
    int pin_fd = open_private_pin_file(path, O_RDWR | O_CREAT, err, err_cap);
    if (pin_fd >= 0) {
        struct stat st;
        if (fstat(pin_fd, &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size > TLS_PIN_FILE_MAX_SIZE) {
            close(pin_fd);
            (void)flock(lock_fd, LOCK_UN);
            close(lock_fd);
            set_err(err, err_cap, "TOFU pin file is too large");
            return -1;
        }
        char existing[65];
        int found = find_pin_in_fd(pin_fd, key, existing);
        if (found == 0) {
            if (strcmp(existing, pin_hex) == 0) {
                *stored = 0;
                result = 0;
            } else {
                set_err(err, err_cap, "TOFU pin mismatch");
            }
        } else if (found > 0 && atomic_add_pin(path, parent, pin_fd, key, pin_hex, err, err_cap) == 0) {
            *stored = 1;
            result = 0;
        } else if (found < 0) {
            set_err(err, err_cap, "failed to read TOFU pin file");
        }
        close(pin_fd);
    }

    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return result;
}

static int sha256_hex(const uint8_t *data, size_t len, char out_hex[65]) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    if (SHA256(data, len, digest) == NULL) {
        return -1;
    }
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
    }
    out_hex[64] = '\0';
    return 0;
}

static int tofu_verify_or_store_pin(const char *log_component, const char *pin_key, const char *peer_pin, int log_ok, char *err, size_t err_cap) {
    int stored = 0;
    if (secure_tofu_verify_or_store(pin_key, peer_pin, &stored, err, err_cap) != 0) {
        if (err != NULL && err_cap > 0 && strcmp(err, "TOFU pin mismatch") == 0) {
            snprintf(err, err_cap, "TOFU pin mismatch for %s", pin_key);
        }
        return -1;
    }
    if (log_ok) {
        vc_log_info(log_component, "TOFU pin %s for %s", stored ? "learned" : "verified", pin_key);
    }
    return 0;
}

static int tls_peer_leaf_pin_hex(SSL *ssl, char pin_hex[65], char *err, size_t err_cap) {
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer == NULL) {
        set_err(err, err_cap, "TLS peer certificate is missing");
        return -1;
    }

    unsigned char *der = NULL;
    int der_len = i2d_X509(peer, &der);
    if (der_len <= 0 || der == NULL) {
        X509_free(peer);
        set_err(err, err_cap, "failed to serialize peer certificate");
        return -1;
    }

    if (sha256_hex(der, (size_t)der_len, pin_hex) != 0) {
        OPENSSL_free(der);
        X509_free(peer);
        set_err(err, err_cap, "failed to hash peer certificate");
        return -1;
    }

    OPENSSL_free(der);
    X509_free(peer);
    return 0;
}

static int xhttp_tofu_verify_or_store(SSL *ssl, const char *pin_key, int log_ok, char *err, size_t err_cap) {
    char peer_pin[65];
    int saved=errno; errno=0;
    int result=tls_peer_leaf_pin_hex(ssl,peer_pin,err,err_cap);
    if (!result) result=tofu_verify_or_store_pin("xhttp",pin_key,peer_pin,log_ok,err,err_cap);
    if (result) {
        int cause=errno ? errno : EPROTO;
        core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,cause)); errno=cause;
    } else errno=saved;
    return result;
}

static int alpn_csv_has_token(const char *csv, const char *token) {
    if (csv == NULL || token == NULL || token[0] == '\0') {
        return 0;
    }
    size_t token_len = strlen(token);
    const char *p = csv;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        const char *start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        if ((size_t)(end - start) == token_len && strncmp(start, token, token_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int append_alpn_token(unsigned char *out, unsigned int cap, unsigned int *len, const char *token) {
    size_t n = strlen(token);
    if (n == 0 || n > 255 || *len + 1U + (unsigned int)n > cap) {
        return -1;
    }
    out[(*len)++] = (unsigned char)n;
    memcpy(out + *len, token, n);
    *len += (unsigned int)n;
    return 0;
}

static int build_xhttp_tls_alpn(const char *cfg_alpn, unsigned char *out, unsigned int cap, unsigned int *out_len) {
    *out_len = 0;
    if (!cfg_alpn || !*cfg_alpn) cfg_alpn="h2,http/1.1";
    while (*cfg_alpn) {
        const char *end=strchr(cfg_alpn,','); if (!end) end=cfg_alpn+strlen(cfg_alpn);
        while (cfg_alpn < end && (*cfg_alpn == ' ' || *cfg_alpn == '\t')) cfg_alpn++;
        const char *last=end; while (last > cfg_alpn && (last[-1] == ' ' || last[-1] == '\t')) last--;
        size_t length=(size_t)(last-cfg_alpn); char token[256];
        if (!length || length > 255) return -1;
        for (size_t i=0;i<length;i++) if ((unsigned char)cfg_alpn[i] <= 0x20 || (unsigned char)cfg_alpn[i] >= 0x7f) return -1;
        memcpy(token,cfg_alpn,length); token[length]=0;
        if (append_alpn_token(out,cap,out_len,token)) return -1;
        if (!*end) break;
        cfg_alpn=end+1; if (!*cfg_alpn) return -1;
    }
    return *out_len > 0 ? 0 : -1;
}

static int ssl_selected_alpn_is_h2(SSL *ssl) {
    const unsigned char *selected = NULL;
    unsigned int selected_len = 0;
    SSL_get0_alpn_selected(ssl, &selected, &selected_len);
    return selected != NULL && selected_len == 2 && memcmp(selected, "h2", 2) == 0;
}

static int tls_identity_is_ip(const char *identity) {
    unsigned char address[16];
    return identity && (inet_pton(AF_INET,identity,address) == 1 || inet_pton(AF_INET6,identity,address) == 1);
}

static int tls_identity_parameters(X509_VERIFY_PARAM *parameters, const char *identity) {
    if (!parameters || !identity || !*identity) return -1;
    return (tls_identity_is_ip(identity) ? X509_VERIFY_PARAM_set1_ip_asc(parameters,identity) :
            X509_VERIFY_PARAM_set1_host(parameters,identity,0)) == 1 ? 0 : -1;
}

static int open_tls_socket_once(int fd, const char *connect_host, const char *sni, int verify_peer,
                                const unsigned char *alpn_protos, unsigned int alpn_protos_len, tls_cipher_offer_t cipher_offer,
                                SSL_CTX **out_ctx, SSL **out_ssl, int *out_fd, int *retry_with_aes, char *err, size_t err_cap) {
    *out_ctx = NULL;
    *out_ssl = NULL;
    *out_fd = -1;
    *retry_with_aes = 0;

    if (fd < 0) {
        set_connect_err(err, err_cap, "tcp connect failed");
        return -1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        close(fd);
        set_err(err, err_cap, "SSL_CTX_new failed");
        return -1;
    }
    if (SSL_CTX_set1_groups_list(ctx, CORE_OPENSSL_GROUPS) != 1) {
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to set TLS groups");
        return -1;
    }
    const char *cipher_suites = cipher_offer == TLS_CIPHER_OFFER_CHACHA
                                    ? "TLS_CHACHA20_POLY1305_SHA256"
                                    : "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    if (SSL_CTX_set_ciphersuites(ctx, cipher_suites) != 1 ||
        (cipher_offer == TLS_CIPHER_OFFER_CHACHA && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)) {
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to set TLS cipher suites");
        return -1;
    }

    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        int default_paths_ready = (SSL_CTX_set_default_verify_paths(ctx) == 1) ? 1 : 0;
        int custom_ca_loaded = 0;

        const char *ca_paths[] = {
            getenv("VLESS_CA_BUNDLE"),
            "/usr/share/vless-core/cacert.pem",
            "/Applications/vless-core.app/cacert.pem",
            "third_party/cacert.pem",
        };
        for (size_t i = 0; i < sizeof(ca_paths) / sizeof(ca_paths[0]); i++) {
            if (ca_paths[i] == NULL || ca_paths[i][0] == '\0') {
                continue;
            }
            if (SSL_CTX_load_verify_locations(ctx, ca_paths[i], NULL) == 1) {
                custom_ca_loaded = 1;
                break;
            }
        }
        if (!custom_ca_loaded && !default_paths_ready) {
            SSL_CTX_free(ctx);
            close(fd);
            set_err(err, err_cap, "no trusted CA bundle found (set VLESS_CA_BUNDLE or install /usr/share/vless-core/cacert.pem)");
            return -1;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "SSL_new failed");
        return -1;
    }

    const char *servername = (sni != NULL && sni[0] != '\0') ? sni : connect_host;
    if (!tls_identity_is_ip(servername) && SSL_set_tlsext_host_name(ssl, servername) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to set SNI");
        return -1;
    }
    if (verify_peer) {
        if (tls_identity_parameters(SSL_get0_param(ssl),servername) != 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            set_err(err, err_cap, "failed to set TLS hostname verify");
            return -1;
        }
    }
    if (SSL_set_fd(ssl, fd) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "SSL_set_fd failed");
        return -1;
    }
    if (alpn_protos != NULL && alpn_protos_len > 0 && SSL_set_alpn_protos(ssl, alpn_protos, alpn_protos_len) != 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to set TLS ALPN");
        return -1;
    }
    core_set_socket_io_timeout(fd, CORE_TLS_HANDSHAKE_TIMEOUT_MS);
    errno=0;
    if (ssl_budget_call(ssl, NULL, 0, 0) != 1) {
        int failure=errno ? errno : EPROTO;
        unsigned long e = ERR_get_error();
        *retry_with_aes = SSL_get_current_cipher(ssl) == NULL;
        long verify_rc = X509_V_OK;
        if (verify_peer) {
            verify_rc = SSL_get_verify_result(ssl);
        }
        char ebuf[192];
        if (e != 0) {
            ERR_error_string_n(e, ebuf, sizeof(ebuf));
        } else {
            snprintf(ebuf, sizeof(ebuf), "unknown SSL error");
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        errno=failure;
        if (err != NULL && err_cap > 0) {
            if (verify_peer) {
                if (verify_rc != X509_V_OK) {
                    snprintf(err, err_cap, "TLS handshake failed: %s (%s)", ebuf, X509_verify_cert_error_string(verify_rc));
                } else {
                    snprintf(err, err_cap, "TLS handshake failed: %s", ebuf);
                }
            } else {
                snprintf(err, err_cap, "TLS handshake failed (insecure mode): %s", ebuf);
            }
        }
        return -1;
    }
    core_set_socket_io_timeout(fd, 0);

    if (verify_peer) {
        long verify_rc = SSL_get_verify_result(ssl);
        if (verify_rc != X509_V_OK) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "TLS certificate verify failed: %s", X509_verify_cert_error_string(verify_rc));
            }
            return -1;
        }
    }

    *out_ctx = ctx;
    *out_ssl = ssl;
    *out_fd = fd;
    return 0;
}

static int open_tls_socket(int use_server_ips, const char *connect_host, uint16_t connect_port, const char *sni, int verify_peer,
                           const unsigned char *alpn_protos, unsigned int alpn_protos_len, SSL_CTX **out_ctx, SSL **out_ssl, int *out_fd,
                           int *use_aes_fallback, char *err, size_t err_cap) {
    *out_ctx=NULL; *out_ssl=NULL; *out_fd=-1;
    core_dialer_t *dialer=core_dialer_start(connect_host,connect_port,use_server_ips,CORE_CONNECT_TIMEOUT_MS,NULL,0);
    if (!dialer) { set_connect_err(err,err_cap,"tcp address resolution failed"); return -1; }
    struct sockaddr_storage address; socklen_t length=0;
    int fd,first=1,failed_handshake=0;
    core_connection_error_t failure={0};
    while ((fd=core_dialer_next(dialer,&address,&length)) >= 0) {
        int aes=(first && *use_aes_fallback) || tls_address_aes_cached(connect_host,connect_port,sni,(const struct sockaddr *)&address,length);
        first=0;
        tls_cipher_offer_t offer=aes ? TLS_CIPHER_OFFER_AES : TLS_CIPHER_OFFER_CHACHA;
        for (unsigned attempt=0;attempt<2;attempt++) {
            int retry=0;
            if (open_tls_socket_once(fd,connect_host,sni,verify_peer,alpn_protos,alpn_protos_len,offer,out_ctx,out_ssl,out_fd,&retry,err,err_cap) == 0) {
                *use_aes_fallback=offer == TLS_CIPHER_OFFER_AES;
                if (*use_aes_fallback) cache_tls_address_aes(connect_host,connect_port,sni,(const struct sockaddr *)&address,length);
                if (err && err_cap) *err=0;
                core_dialer_free(dialer); core_trace_error_clear(); log_tls_cipher_once(SSL_get_cipher_name(*out_ssl)); return 0;
            }
            failed_handshake=1;
            failure=core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,errno ? errno : EPROTO);
            if (attempt || !retry || (core_deadline_active() && !core_deadline_remaining())) break;
            offer=offer == TLS_CIPHER_OFFER_CHACHA ? TLS_CIPHER_OFFER_AES : TLS_CIPHER_OFFER_CHACHA;
            fd=tcp_connect_address(address.ss_family,SOCK_STREAM,IPPROTO_TCP,(const struct sockaddr *)&address,length);
            if (fd < 0) break;
        }
    }
    int saved=errno; core_dialer_free(dialer);
    if (failure.kind && saved != ETIMEDOUT) saved=failure.system_error;
    if (failed_handshake) core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,failure.kind,saved));
    errno=saved;
    if (!failed_handshake || saved == ETIMEDOUT) set_connect_err(err,err_cap,saved == ETIMEDOUT ? "TLS connection budget exhausted" : "tcp connect failed");
    return -1;
}

static size_t find_double_crlf(const uint8_t *buf, size_t len) {
    if (len < 4) {
        return 0;
    }
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return 0;
}

static void trim_ascii(char *s) {
    if (s == NULL) {
        return;
    }
    size_t n = strlen(s);
    size_t start = 0;
    while (start < n && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        start++;
    }
    size_t end = n;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }
    if (start > 0) {
        memmove(s, s + start, end - start);
    }
    s[end - start] = '\0';
}

static int xhttp_read_http1_response(SSL *ssl, int fd, char *err, size_t err_cap) {
    core_http1_response_t parser={0}; dynbuf_t cache={.limit=73728}; int eof=0,result=-1;
    for (;;) {
        core_http1_event_t event;
        int parsed=core_http1_next(&parser,cache.data,cache.len,eof,8192,&event);
        if (parsed < 0) break;
        if (!parsed && event.kind == 1 && event.status >= 200 && event.status != 200) {
            if (err && err_cap) snprintf(err,err_cap,"XHTTP HTTP/1.1 response returned non-200: %d",event.status);
            db_free(&cache); return -1;
        }
        db_consume(&cache,event.consumed);
        if (!parsed && event.kind == 3) { if (!cache.len) result=0; break; }
        if (!parsed) continue;
        uint8_t input[4096]; size_t received=0;
        int read_result=ssl ? ssl_read_some(ssl,input,sizeof(input),&received) : fd_read_some(fd,input,sizeof(input),&received);
        if (read_result < 0 && (!ssl || !(SSL_get_shutdown(ssl)&SSL_RECEIVED_SHUTDOWN))) break;
        if (read_result > 0) {
            if (core_wait_socket(fd,POLLIN,-1) <= 0) break;
            continue;
        }
        if (!received) eof=1;
        else if (db_append(&cache,input,received)) break;
    }
    db_free(&cache);
    if (result) set_err(err,err_cap,"invalid or truncated XHTTP HTTP/1.1 response");
    return result;
}

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t need = 4 * ((in_len + 2) / 3);
    if (need + 1 > out_cap || in_len > (size_t)INT_MAX) {
        return -1;
    }
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (n < 0 || (size_t)n != need) {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

static int normalize_ws_path(const char *in, char *out, size_t out_cap) {
    return core_http_path(in,out,out_cap,0);
}

static int http_host(const char *input, char *output, size_t capacity) {
    uint8_t address[16];
    int size=snprintf(output,capacity,inet_pton(AF_INET6,input,address) == 1 ? "[%s]" : "%s",input);
    return size < 0 || (size_t)size >= capacity ? -1 : 0;
}

static int ws_make_key(char out[25]) {
    uint8_t r[16];
    if (RAND_bytes(r, sizeof(r)) != 1) {
        return -1;
    }
    return base64_encode(r, sizeof(r), out, 25);
}

static int ws_make_accept(const char *key, char out[29]) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t digest[SHA_DIGEST_LENGTH];
    char material[128];
    int n = snprintf(material, sizeof(material), "%s%s", key, guid);
    if (n <= 0 || (size_t)n >= sizeof(material)) {
        return -1;
    }
    if (SHA1((const uint8_t *)material, (size_t)n, digest) == NULL) {
        return -1;
    }
    return base64_encode(digest, sizeof(digest), out, 29);
}

static int ws_conn_read_some(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    if (c->ssl != NULL) {
        if (c->ws_upgraded) {
            int result=SSL_read(c->ssl,buf,(int)cap);
            c->ws_want_write=0;
            if (result > 0) { *out_len=(size_t)result; return 0; }
            int error=SSL_get_error(c->ssl,result);
            if (error == SSL_ERROR_SYSCALL && errno == EINTR) return 1;
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                c->ws_want_write=error == SSL_ERROR_WANT_WRITE; return 1;
            }
            return -1;
        }
        return ssl_read_some(c->ssl, buf, cap, out_len);
    }
    if (c->ws_upgraded) {
        ssize_t result;
        do { result=recv(c->fd,buf,cap,MSG_DONTWAIT); } while (result < 0 && errno == EINTR);
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 1;
        if (result <= 0) return -1;
        *out_len=(size_t)result; return 0;
    }
    ssize_t n = core_recv(c->fd, buf, cap, 0);
    if (n <= 0) {
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

static int ws_conn_write_all(tls13_conn_t *c, const void *buf, size_t len) {
    if (c->relay_async) return relay_write_wire(c,buf,len);
    const uint8_t *bytes=buf;
    for (size_t offset=0;offset<len;) {
        int result;
        if (c->ssl) {
            result=SSL_write(c->ssl,bytes+offset,(int)(len-offset));
            if (result <= 0) {
                int error=SSL_get_error(c->ssl,result);
                if (error == SSL_ERROR_SYSCALL && errno == EINTR) continue;
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return -1;
                if (core_wait_socket(c->fd,error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,-1) <= 0) return -1;
                continue;
            }
        } else {
            ssize_t sent=core_send(c->fd,bytes+offset,len-offset,0);
            if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (core_wait_socket(c->fd,POLLOUT,-1) <= 0) return -1;
                continue;
            }
            if (sent <= 0) return -1;
            result=(int)sent;
        }
        offset+=(size_t)result;
    }
    return 0;
}

static int parse_ws_upgrade_response(tls13_conn_t *c, dynbuf_t *cache, const char *accept, const char *protocol, char *err, size_t err_cap) {
    for (;;) {
        size_t headers=find_double_crlf(cache->data,cache->len);
        if (headers) {
            if (core_ws_validate_upgrade(cache->data,headers,accept,protocol)) {
                set_err(err,err_cap,"invalid WebSocket upgrade response"); return -1;
            }
            db_consume(cache,headers); return 0;
        }
        if (cache->len >= 32768) { set_err(err,err_cap,"WebSocket response headers too large"); return -1; }
        uint8_t input[4096]; size_t received=0;
        if (ws_conn_read_some(c,input,sizeof(input),&received) || !received) {
            set_err(err,err_cap,"failed to read WebSocket upgrade response"); return -1;
        }
        if (db_append(cache,input,received)) { set_err(err,err_cap,"oom"); return -1; }
    }
}

static int ws_write_frame(tls13_conn_t *c, uint8_t opcode, const uint8_t *buf, size_t len) {
    if (len > CORE_WS_MESSAGE_LIMIT || (opcode >= 8 && len > 125)) return -1;
    uint8_t header[14],mask[4],chunk[8192];
    size_t size=0;
    header[size++]=(uint8_t)(0x80|opcode);
    if (len <= 125) header[size++]=(uint8_t)(0x80|len);
    else if (len <= 65535) {
        header[size++]=0xfe; header[size++]=(uint8_t)(len>>8); header[size++]=(uint8_t)len;
    } else {
        header[size++]=0xff;
        for (int i=7;i>=0;i--) header[size++]=(uint8_t)((uint64_t)len>>(i*8));
    }
    if (RAND_bytes(mask,sizeof(mask)) != 1) return -1;
    memcpy(header+size,mask,4); size+=4;
    if (ws_conn_write_all(c,header,size)) return -1;
    for (size_t offset=0;offset<len;) {
        size_t take=len-offset < sizeof(chunk) ? len-offset : sizeof(chunk);
        for (size_t i=0;i<take;i++) chunk[i]=buf[offset+i]^mask[(offset+i)%4];
        if (ws_conn_write_all(c,chunk,take)) return -1;
        offset+=take;
    }
    return 0;
}

static int ws_fill_app_cache(tls13_conn_t *c) {
    for (;;) {
        if (c->ws_decoder.closed) return 0;
        if (c->ws_net_cache.len) {
            core_ws_event_t event; size_t consumed=0;
            int result=core_ws_decode(&c->ws_decoder,c->ws_net_cache.data,c->ws_net_cache.len,&consumed,&event);
            if (result < 0) return -1;
            if (result && event.opcode < 8 && db_append(&c->app_cache,event.data,event.length)) return -1;
            if (result && event.opcode == 9 && ws_write_frame(c,10,event.data,event.length)) return -1;
            if (result && event.opcode == 8 && !c->ws_close_sent) {
                if (ws_write_frame(c,8,event.data,event.length)) return -1;
                c->ws_close_sent=1;
            }
            db_consume(&c->ws_net_cache,consumed);
            if (c->app_cache.len || c->ws_decoder.closed) return 0;
            if (c->ws_net_cache.len) continue;
        }
        uint8_t input[8192]; size_t received=0;
        int result=ws_conn_read_some(c,input,sizeof(input),&received);
        if (result) return result;
        if (!received) return -1;
        if (db_append(&c->ws_net_cache,input,received)) return -1;
    }
}

static int xhttp_buffer_available(tls13_conn_t *c) {
    c->xhttp_net_cache.limit=73728;
    if (c->xhttp_wire_eof) return 0;
    uint8_t input[4096];
    if (c->ssl) {
        int flags=fcntl(c->fd,F_GETFL,0);
        if (flags < 0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return -1;
        ERR_clear_error();
        int received=SSL_read(c->ssl,input,sizeof(input));
        int error=received > 0 ? SSL_ERROR_NONE : SSL_get_error(c->ssl,received),saved=errno;
        if (fcntl(c->fd,F_SETFL,flags)) return -1;
        errno=saved;
        if (received > 0) return db_append(&c->xhttp_net_cache,input,(size_t)received);
        if (error == SSL_ERROR_ZERO_RETURN) { c->xhttp_wire_eof=1; return 0; }
        return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE || (error == SSL_ERROR_SYSCALL && saved == EINTR) ? 0 : -1;
    }
    int ready=core_wait_socket(c->fd,POLLIN,0);
    if (ready <= 0) return ready < 0 && errno != EINTR ? -1 : 0;
    ssize_t received=recv(c->fd,input,sizeof(input),MSG_DONTWAIT);
    if (received > 0) return db_append(&c->xhttp_net_cache,input,(size_t)received);
    if (!received) { c->xhttp_wire_eof=1; return 0; }
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
}

static int xhttp_fill_app_cache(tls13_conn_t *c) {
    if (c->xhttp_eof) return -1;
    for (;;) {
        core_http1_event_t event;
        int result=core_http1_next(&c->xhttp_http1_response,c->xhttp_net_cache.data,c->xhttp_net_cache.len,c->xhttp_wire_eof,8192,&event);
        if (result < 0) { vc_log_error("xhttp","invalid or truncated XHTTP HTTP/1.1 response"); return -1; }
        if (!result && event.kind == 1 && event.status >= 200 && event.status != 200) {
            vc_log_error("xhttp","GET returned non-200: %d",event.status); return -1;
        }
        if (!result && event.kind == 2 && db_append(&c->app_cache,c->xhttp_net_cache.data+event.offset,event.length)) return -1;
        db_consume(&c->xhttp_net_cache,event.consumed);
        if (!result && event.kind == 3) {
            if (c->xhttp_net_cache.len) return -1;
            c->xhttp_eof=1; return -1;
        }
        if (c->app_cache.len) return 0;
        if (!result) continue;
        size_t before=c->xhttp_net_cache.len;
        int previous_eof=c->xhttp_wire_eof;
        if (xhttp_buffer_available(c)) return -1;
        if (before == c->xhttp_net_cache.len && previous_eof == c->xhttp_wire_eof) return 1;
    }
}

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

static int h2_send_frame(tls13_conn_t *c, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t len) {
    if (len > 0xFFFFFFU) {
        return -1;
    }
    c->h2_send_buf.len = 0;
    if (db_reserve(&c->h2_send_buf, 9 + len) != 0) {
        return -1;
    }
    uint8_t *hdr = c->h2_send_buf.data;
    hdr[0] = (uint8_t)(len >> 16);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)len;
    hdr[3] = type;
    hdr[4] = flags;
    stream_id &= 0x7FFFFFFFU;
    hdr[5] = (uint8_t)(stream_id >> 24);
    hdr[6] = (uint8_t)(stream_id >> 16);
    hdr[7] = (uint8_t)(stream_id >> 8);
    hdr[8] = (uint8_t)stream_id;
    if (len > 0) {
        memcpy(hdr + 9, payload, len);
    }
    c->h2_send_buf.len = 9 + len;

    if (c->xmux_async) {
        tls13_conn_t *owner = c->xmux_owner ? c->xmux_owner : c;
        if (c->h2_send_buf.len > 256U*1024U - owner->xmux_plain_output.len) return -1;
        int result=db_append(&owner->xmux_plain_output, c->h2_send_buf.data, c->h2_send_buf.len);
        if (!result) owner->xmux_enqueued+=c->h2_send_buf.len;
        return result;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
        if (ssl_write_all(c->ssl, c->h2_send_buf.data, c->h2_send_buf.len) != 0) {
            return -1;
        }
    } else if (c->mode == CONN_MODE_GRPC_PLAIN) {
        if (write_exact(c->fd, c->h2_send_buf.data, c->h2_send_buf.len) != 0) {
            return -1;
        }
    } else {
        if (reality_write_app_records(c, c->h2_send_buf.data, c->h2_send_buf.len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int h2_send_window_update(tls13_conn_t *c, uint32_t stream_id, uint32_t increment) {
    if (increment == 0 || increment > 0x7FFFFFFFU) {
        return -1;
    }
    uint8_t payload[4] = {
        (uint8_t)(increment >> 24),
        (uint8_t)(increment >> 16),
        (uint8_t)(increment >> 8),
        (uint8_t)increment,
    };
    return h2_send_frame(c, H2_FRAME_WINDOW_UPDATE, 0, stream_id, payload, sizeof(payload));
}

static h2_response_entry_t *h2_response_get(tls13_conn_t *c, uint32_t id, int create) {
    for (h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next) if (entry->id == id) return entry;
    if (!create) return NULL;
    if (c->h2_response_count >= 256) { errno=EAGAIN; return NULL; }
    h2_response_entry_t *entry=calloc(1,sizeof(*entry));
    if (!entry) return NULL;
    entry->id=id; entry->receive_window=H2_CLIENT_INITIAL_WINDOW;
    if (id == c->h2_stream_id) entry->response.headers=c->h2_headers_received;
    entry->next=c->h2_responses; c->h2_responses=entry; c->h2_response_count++;
    return entry;
}

static void h2_response_remove(tls13_conn_t *c, uint32_t id) {
    h2_response_entry_t **cursor=&c->h2_responses;
    while (*cursor) {
        if ((*cursor)->id == id) { h2_response_entry_t *entry=*cursor; *cursor=entry->next; c->h2_response_count--; free(entry); return; }
        cursor=&(*cursor)->next;
    }
}

static void h2_response_clear(tls13_conn_t *c) {
    while (c->h2_responses) h2_response_remove(c,c->h2_responses->id);
}

static unsigned h2_response_active(const tls13_conn_t *c) {
    unsigned count=0;
    for (const h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next)
        if (!entry->response.ended || !entry->request_ended) count++;
    return count;
}

static int h2_note_recv_data(tls13_conn_t *c, h2_response_entry_t *entry, size_t payload_len, int delivered) {
    if (payload_len == 0) {
        return 0;
    }
    if ((int64_t)payload_len > c->h2_receive_window || (entry && (int64_t)payload_len > entry->receive_window)) return -1;
    if (!delivered) {
        if (h2_send_window_update(c,0,(uint32_t)payload_len) || (entry && !entry->response.ended && h2_send_window_update(c,entry->id,(uint32_t)payload_len))) return -1;
        return 0;
    }
    c->h2_receive_window-=(int64_t)payload_len;
    if (entry) entry->receive_window-=(int64_t)payload_len;
    if (payload_len > 0x7FFFFFFFU || c->h2_recv_conn_pending > 0x7FFFFFFFU - payload_len ||
        c->h2_recv_stream_pending > 0x7FFFFFFFU - payload_len) {
        return -1;
    }

    c->h2_recv_conn_pending += (uint32_t)payload_len;
    c->h2_recv_stream_pending += (uint32_t)payload_len;
    if (c->h2_recv_conn_pending < H2_WINDOW_UPDATE_THRESHOLD && c->h2_recv_stream_pending < H2_WINDOW_UPDATE_THRESHOLD) {
        return 0;
    }

    uint32_t conn_inc = c->h2_recv_conn_pending;
    uint32_t stream_inc = c->h2_recv_stream_pending;
    c->h2_recv_conn_pending = 0;
    c->h2_recv_stream_pending = 0;
    c->h2_receive_window+=conn_inc;
    if (entry) entry->receive_window+=stream_inc;
    if (h2_send_window_update(c, 0, conn_inc) != 0 || h2_send_window_update(c, c->h2_stream_id, stream_inc) != 0) {
        return -1;
    }
    return 0;
}

static int h2_collect_tls_available(tls13_conn_t *c, int *want_write) {
    if (c == NULL || c->ssl == NULL) {
        return -1;
    }
    if (want_write != NULL) {
        *want_write = 0;
    }

    int fd = SSL_get_fd(c->ssl);
    if (fd < 0) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }

    int result = 0;
    uint8_t buf[16384];
    for (int reads = 0; reads < 64; reads++) {
        ERR_clear_error();
        int n = SSL_read(c->ssl, buf, sizeof(buf));
        if (n > 0) {
            if (db_append(&c->h2_net_cache, buf, (size_t)n) != 0) {
                result = -1;
                break;
            }
            result = 1;
            if (h2_cached_frame_ready(c)) {
                break;
            }
            continue;
        }

        int ssl_error = SSL_get_error(c->ssl, n);
        if (ssl_error == SSL_ERROR_WANT_READ) {
            break;
        }
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            if (want_write != NULL) {
                *want_write = 1;
            }
            break;
        }
        if (result > 0 &&
            (ssl_error == SSL_ERROR_ZERO_RETURN ||
             (ssl_error == SSL_ERROR_SYSCALL && n == 0))) {
            break;
        }
        result = -1;
        break;
    }

    int saved_errno = errno;
    if (fcntl(fd, F_SETFL, flags) != 0) {
        result = -1;
    }
    errno = saved_errno;
    return result;
}

static int h2_wait_tls_input(tls13_conn_t *c, int want_write) {
    int rc = core_wait_socket(c->fd, want_write ? POLLOUT : POLLIN, -1);
    return rc > 0 ? 0 : -1;
}

static int h2_read_exact(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (c->h2_net_cache.len > 0) {
            size_t take = c->h2_net_cache.len;
            if (take > len - off) {
                take = len - off;
            }
            memcpy(buf + off, c->h2_net_cache.data, take);
            db_consume(&c->h2_net_cache, take);
            off += take;
            continue;
        }

        if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
            int want_write = 0;
            int collected = h2_collect_tls_available(c, &want_write);
            if (collected < 0) {
                return -1;
            }
            if (c->h2_net_cache.len == 0 &&
                h2_wait_tls_input(c, want_write) != 0) {
                return -1;
            }
        } else if (c->mode == CONN_MODE_GRPC_PLAIN) {
            if (read_exact(c->fd, buf + off, len - off) != 0) {
                return -1;
            }
            off = len;
        } else {
            if (fill_reality_plain_cache(c, &c->h2_net_cache) != 0) {
                return -1;
            }
            if (c->h2_net_cache.len == 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int h2_read_frame(tls13_conn_t *c, uint8_t *type, uint8_t *flags, uint32_t *stream_id, uint8_t **payload, size_t *payload_len) {
    *payload=NULL; *payload_len=0;
    uint8_t hdr[9];
    if (h2_read_exact(c, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    size_t len = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | (size_t)hdr[2];
    if (len > H2_DEFAULT_MAX_FRAME) {
        return -1;
    }

    uint8_t *body = NULL;
    if (len > 0) {
        body = (uint8_t *)malloc(len);
        if (body == NULL) {
            return -1;
        }
        if (h2_read_exact(c, body, len) != 0) {
            free(body);
            return -1;
        }
    }

    *type = hdr[3];
    *flags = hdr[4];
    *stream_id = (((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8]) & 0x7FFFFFFFU;
    if (!c->xmux_async && core_http2_validate_frame(&c->h2_validation,*type,*flags,*stream_id,body,len)) {
        free(body); vc_log_error("h2","invalid h2 frame sequence"); return -1;
    }
    if (!c->xmux_async && (*type == 0 || *type == 1 || *type == 3 || *type == 8) && *stream_id &&
        (!(*stream_id&1) || (*stream_id != c->h2_stream_id && *stream_id != c->h2_upload_stream_id && *stream_id >= c->h2_next_stream_id))) {
        free(body); vc_log_error("h2","h2 frame on idle stream"); return -1;
    }
    *payload = body;
    *payload_len = len;
    return 0;
}

static int hpack_append_int(dynbuf_t *b, uint32_t value, uint8_t prefix_bits, uint8_t first) {
    uint8_t max_first = (uint8_t)((1U << prefix_bits) - 1U);
    if (value < max_first) {
        uint8_t ch = first | (uint8_t)value;
        return db_append(b, &ch, 1);
    }

    uint8_t ch = first | max_first;
    if (db_append(b, &ch, 1) != 0) {
        return -1;
    }
    value -= max_first;
    while (value >= 128) {
        ch = (uint8_t)((value & 0x7F) | 0x80);
        if (db_append(b, &ch, 1) != 0) {
            return -1;
        }
        value >>= 7;
    }
    ch = (uint8_t)value;
    return db_append(b, &ch, 1);
}

static int hpack_append_string(dynbuf_t *b, const char *s) {
    size_t len = strlen(s);
    if (len > 0x7FFFFFFFU) {
        return -1;
    }
    if (hpack_append_int(b, (uint32_t)len, 7, 0x00) != 0) {
        return -1;
    }
    return db_append(b, s, len);
}

static int hpack_append_indexed(dynbuf_t *b, uint32_t index) {
    return hpack_append_int(b, index, 7, 0x80);
}

static int hpack_append_literal_new_name(dynbuf_t *b, const char *name, const char *value) {
    uint8_t literal = 0x00;
    if (db_append(b, &literal, 1) != 0) {
        return -1;
    }
    if (hpack_append_string(b, name) != 0 || hpack_append_string(b, value) != 0) {
        return -1;
    }
    return 0;
}


static int h2_finish_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *block, size_t len, char *err, size_t err_cap) {
    core_hpack_headers_t headers;
    int decoded=core_hpack_decode(&c->hpack,block,len,&headers);
    if (decoded == -1) { core_trace_failure(CORE_TRACE_TRANSPORT); set_err(err,err_cap,"invalid h2 header block"); return -1; }
    h2_response_entry_t *entry=h2_response_get(c,stream_id,stream_id == c->h2_stream_id);
    if (!entry) {
        if (!(stream_id&1) || (stream_id != c->h2_stream_id && stream_id >= c->h2_next_stream_id)) {
            set_err(err,err_cap,"h2 response on idle stream"); return -1;
        }
        return 0;
    }
    int initial=!entry->response.headers;
    if (decoded || core_http2_response_headers(&entry->response,&headers,flags&H2_FLAG_END_STREAM)) {
        core_trace_failure(CORE_TRACE_TRANSPORT); set_err(err,err_cap,"invalid h2 response headers"); return -1;
    }
    int status=headers.status;
    if (status >= 100 && status < 200) return 0;
    if (c->grpc_transport && core_grpc_response_headers(&headers,initial,flags&H2_FLAG_END_STREAM,err,err_cap)) {
        core_trace_failure(CORE_TRACE_TRANSPORT); return -1;
    }
    if (status && status != 200) {
        core_trace_failure(CORE_TRACE_TRANSPORT);
        if (err && err_cap) snprintf(err,err_cap,"%s h2 stream %u returned non-200: %d",c->grpc_transport ? "grpc" : "xhttp",stream_id,status);
        return -1;
    }
    if (stream_id == c->h2_stream_id) c->h2_headers_received=entry->response.headers;
    if (entry->response.ended) {
        if (stream_id == c->h2_stream_id) c->h2_stream_eof=1;
        else if (entry->request_ended) h2_response_remove(c,stream_id);
    }
    return 0;
}

static int h2_append_header_block(tls13_conn_t *c, const uint8_t *data, size_t len, char *err, size_t err_cap) {
    if (c->h2_header_block.len > H2_MAX_INBOUND_FRAME || len > H2_MAX_INBOUND_FRAME - c->h2_header_block.len) {
        set_err(err, err_cap, "h2 header block too large");
        return -1;
    }
    if (db_append(&c->h2_header_block, data, len) != 0) {
        set_err(err, err_cap, "failed to buffer h2 headers");
        return -1;
    }
    return 0;
}

static int h2_process_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t payload_len, char *err,
                              size_t err_cap) {
    if (stream_id == 0 || c->h2_header_stream_id != 0) {
        set_err(err, err_cap, "invalid h2 headers stream");
        return -1;
    }
    size_t off = 0;
    if ((flags & H2_FLAG_PADDED) != 0) {
        if (payload_len == 0) {
            set_err(err, err_cap, "invalid h2 padded headers");
            return -1;
        }
        uint8_t pad = payload[off++];
        if ((size_t)pad > payload_len - off) {
            set_err(err, err_cap, "invalid h2 headers padding");
            return -1;
        }
        payload_len -= (size_t)pad;
    }
    if ((flags & H2_FLAG_PRIORITY) != 0) {
        if (payload_len - off < 5) {
            set_err(err, err_cap, "invalid h2 priority headers");
            return -1;
        }
        off += 5;
    }
    if (off > payload_len) {
        set_err(err, err_cap, "invalid h2 headers");
        return -1;
    }

    const uint8_t *block = off != 0 ? payload + off : payload;
    if ((flags & H2_FLAG_END_HEADERS) != 0) {
        return h2_finish_headers(c, flags, stream_id, block, payload_len - off, err, err_cap);
    }
    if (h2_append_header_block(c, block, payload_len - off, err, err_cap) != 0) {
        return -1;
    }
    c->h2_header_stream_id = stream_id;
    c->h2_header_flags = flags & H2_FLAG_END_STREAM;
    return 0;
}

static int h2_add_send_window(int64_t *window, uint32_t increment) {
    if (window == NULL || increment == 0 || *window > 0x7FFFFFFFLL - (int64_t)increment) {
        return -1;
    }
    *window += (int64_t)increment;
    return 0;
}

static int h2_process_control_frame(tls13_conn_t *c, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload,
                                    size_t payload_len, char *err, size_t err_cap) {
    if (c->h2_header_stream_id != 0 && type != H2_FRAME_CONTINUATION) {
        set_err(err, err_cap, "interleaved h2 header block");
        return -1;
    }
    switch (type) {
    case H2_FRAME_SETTINGS:
        if ((flags & H2_FLAG_ACK) != 0) {
            return 0;
        }
        if (payload_len % 6 != 0) {
            set_err(err, err_cap, "invalid h2 settings");
            return -1;
        }
        for (size_t off = 0; off + 6 <= payload_len; off += 6) {
            uint16_t id = ((uint16_t)payload[off] << 8) | (uint16_t)payload[off + 1];
            uint32_t val = ((uint32_t)payload[off + 2] << 24) | ((uint32_t)payload[off + 3] << 16) | ((uint32_t)payload[off + 4] << 8) |
                           (uint32_t)payload[off + 5];
            if (id == 3) c->h2_peer_concurrency=val;
            else if (id == 4) {
                if (val > 0x7FFFFFFFU) {
                    set_err(err, err_cap, "invalid h2 initial window");
                    return -1;
                }
                int64_t delta = (int64_t)val - (int64_t)c->h2_peer_initial_window;
                if (c->h2_peer_stream_window+delta > INT_MAX || (c->h2_upload_stream_id && c->h2_upload_stream_window+delta > INT_MAX)) return -1;
                c->h2_peer_initial_window = val;
                c->h2_peer_stream_window += delta;
                if (c->h2_upload_stream_id != 0) {
                    c->h2_upload_stream_window += delta;
                }
            } else if (id == 6) c->h2_peer_header_list_size=val;
            else if (id == 5 && val >= 16384 && val <= 16777215) {
                c->h2_peer_max_frame_size = val;
            }
        }
        return h2_send_frame(c, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
    case H2_FRAME_WINDOW_UPDATE:
        if (payload_len != 4) {
            set_err(err, err_cap, "invalid h2 window update");
            return -1;
        }
        {
            uint32_t inc = (((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) | ((uint32_t)payload[2] << 8) | (uint32_t)payload[3]) &
                           0x7FFFFFFFU;
            if (inc == 0) {
                set_err(err, err_cap, "invalid h2 window increment");
                return -1;
            }
            if (stream_id == 0) {
                if (h2_add_send_window(&c->h2_peer_conn_window, inc) != 0) {
                    set_err(err, err_cap, "h2 connection window overflow");
                    return -1;
                }
            } else if (stream_id == c->h2_stream_id) {
                if (h2_add_send_window(&c->h2_peer_stream_window, inc) != 0) {
                    set_err(err, err_cap, "h2 stream window overflow");
                    return -1;
                }
            } else if (stream_id == c->h2_upload_stream_id) {
                if (h2_add_send_window(&c->h2_upload_stream_window, inc) != 0) {
                    set_err(err, err_cap, "h2 upload window overflow");
                    return -1;
                }
            }
        }
        return 0;
    case H2_FRAME_PING:
        if ((flags & H2_FLAG_ACK) == 0 && payload_len == 8) {
            return h2_send_frame(c, H2_FRAME_PING, H2_FLAG_ACK, 0, payload, payload_len);
        }
        return 0;
    case H2_FRAME_HEADERS:
        return h2_process_headers(c, flags, stream_id, payload, payload_len, err, err_cap);
    case H2_FRAME_CONTINUATION:
        if (c->h2_header_stream_id == 0 || stream_id != c->h2_header_stream_id) {
            set_err(err, err_cap, "invalid h2 continuation stream");
            return -1;
        }
        if (h2_append_header_block(c, payload, payload_len, err, err_cap) != 0) {
            return -1;
        }
        if ((flags & H2_FLAG_END_HEADERS) != 0) {
            int rc = h2_finish_headers(c, c->h2_header_flags, stream_id, c->h2_header_block.data, c->h2_header_block.len, err, err_cap);
            c->h2_header_stream_id = 0;
            c->h2_header_flags = 0;
            c->h2_header_block.len = 0;
            return rc;
        }
        return 0;
    case H2_FRAME_RST_STREAM:
        if (stream_id == 0 || payload_len != 4) {
            set_err(err, err_cap, "invalid h2 stream reset");
            return -1;
        }
        {
            if (stream_id != c->h2_stream_id && !h2_response_get(c,stream_id,0)) return 0;
            uint32_t code = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                            ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];
            if (code == 0 && stream_id == c->h2_stream_id && c->h2_stream_eof) {
                c->h2_request_cancelled = 1;
                vc_log_debug(c->grpc_transport ? "grpc" : "xhttp", "h2 request closed after response fd=%d stream=%u", c->fd, (unsigned)stream_id);
                return 0;
            }
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "h2 stream reset fd=%d stream=%u code=%u response_complete=%d",
                         c->fd, (unsigned)stream_id, (unsigned)code, c->h2_stream_eof);
            }
        }
        return -1;
    case H2_FRAME_GOAWAY:
        if (stream_id || payload_len < 8) { set_err(err,err_cap,"invalid h2 goaway"); return -1; }
        {
            uint32_t last=(((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)|((uint32_t)payload[2]<<8)|payload[3])&0x7fffffffU;
            uint32_t code=((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|((uint32_t)payload[6]<<8)|payload[7];
            c->h2_goaway=1;
            if (code || c->h2_stream_id > last) { set_err(err,err_cap,"h2 goaway rejected stream"); return -1; }
            for (h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next)
                if (!entry->response.ended && entry->id > last) { set_err(err,err_cap,"h2 goaway rejected stream"); return -1; }
            return 0;
        }
    default:
        return 0;
    }
}

static int h2_send_client_preface(tls13_conn_t *c, char *err, size_t err_cap) {
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    int preface_rc = 0;
    if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
        preface_rc = ssl_write_all(c->ssl, preface, sizeof(preface) - 1);
    } else if (c->mode == CONN_MODE_GRPC_PLAIN) {
        preface_rc = write_exact(c->fd, preface, sizeof(preface) - 1);
    } else {
        preface_rc = reality_write_app_records(c, (const uint8_t *)preface, sizeof(preface) - 1);
    }
    if (preface_rc != 0) {
        set_err(err, err_cap, "failed to send h2 preface");
        return -1;
    }

    uint32_t initial_window = c->grpc_physical_only ? c->grpc_initial_window : c->xmux_physical ? CORE_HTTP2_STREAM_LIMIT : H2_CLIENT_INITIAL_WINDOW;
    uint8_t settings[24] = {
        0x00,
        0x04,
        (uint8_t)(initial_window >> 24),
        (uint8_t)(initial_window >> 16),
        (uint8_t)(initial_window >> 8),
        (uint8_t)initial_window,
        0,1,0,0,0x10,0,
        0,6,0,1,0,0,
        0,2,0,0,0,0,
    };
    if (h2_send_frame(c, H2_FRAME_SETTINGS, 0, 0, settings, sizeof(settings)) != 0 ||
        (!c->xmux_physical && !c->grpc_physical_only && h2_send_window_update(c, 0, H2_CONNECTION_WINDOW_INC) != 0)) {
        set_err(err, err_cap, "failed to send h2 settings");
        return -1;
    }
    return 0;
}

static int h2_write_data(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    int stream_up = strcmp(c->xhttp_transport_mode, "stream-up") == 0;
    uint32_t stream_id = stream_up ? c->h2_upload_stream_id : c->h2_stream_id;
    int64_t *stream_window = stream_up ? &c->h2_upload_stream_window : &c->h2_peer_stream_window;
    if (stream_id == 0) {
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        if (!stream_up && c->h2_request_cancelled) return 0;
        if (c->grpc_transport && tls13_drain_h2_input(c) < 0) {
            return -1;
        }
        while (c->h2_peer_conn_window <= 0 || *stream_window <= 0) {
            if (!stream_up && c->h2_request_cancelled) return 0;
            if (h2_pump_one_frame(c) != 0) {
                vc_log_error(c->grpc_transport ? "grpc" : "xhttp", "failed while waiting for h2 upload window");
                return -1;
            }
        }
        if (!stream_up && c->h2_request_cancelled) return 0;
        size_t chunk = len - off;
        if (chunk > c->h2_peer_max_frame_size) {
            chunk = c->h2_peer_max_frame_size;
        }
        if ((int64_t)chunk > c->h2_peer_conn_window) {
            chunk = (size_t)c->h2_peer_conn_window;
        }
        if ((int64_t)chunk > *stream_window) {
            chunk = (size_t)*stream_window;
        }
        if (chunk == 0 || h2_send_frame(c, H2_FRAME_DATA, 0, stream_id, buf + off, chunk) != 0) {
            return -1;
        }
        c->h2_peer_conn_window -= (int64_t)chunk;
        *stream_window -= (int64_t)chunk;
        off += chunk;
    }
    return 0;
}

static size_t protobuf_varint_size(size_t value) {
    size_t n = 1;
    while (value >= 0x80) {
        value >>= 7;
        n++;
    }
    return n;
}

static size_t protobuf_write_varint(uint8_t *out, size_t value) {
    size_t n = 0;
    do {
        uint8_t ch = (uint8_t)(value & 0x7f);
        value >>= 7;
        if (value != 0) {
            ch |= 0x80;
        }
        out[n++] = ch;
    } while (value != 0);
    return n;
}


static int grpc_fill_app_cache(tls13_conn_t *c) {
    while (!c->app_cache.len) {
        if (core_grpc_pending(&c->grpc_decoder)) {
            uint8_t output[8192]; size_t length=0;
            if (core_grpc_read(&c->grpc_decoder,output,sizeof(output),&length) || (length && db_append(&c->app_cache,output,length))) return -1;
            if (length) return 0;
        }
        if (c->grpc_read_failed) return -1;
        if (!c->grpc_net_cache.len) return 1;
        size_t consumed=0,payload_length=0; const uint8_t *payload=NULL;
        int result=core_grpc_decode(&c->grpc_decoder,c->grpc_net_cache.data,c->grpc_net_cache.len,&consumed,&payload,&payload_length);
        if (result < 0 || (!consumed && !core_grpc_pending(&c->grpc_decoder)) || (payload_length && db_append(&c->app_cache,payload,payload_length))) {
            vc_log_error("grpc",c->grpc_decoder.failed == 2 ? "gRPC message buffering budget exhausted" : c->grpc_decoder.failed == 3 ? "gRPC message buffer allocation failed" : "invalid gRPC protobuf message");
            c->grpc_read_failed=1; return -1;
        }
        db_consume(&c->grpc_net_cache,consumed);
    }
    return 0;
}

static int grpc_feed_data(tls13_conn_t *c, const uint8_t *data, size_t length) {
    c->grpc_net_cache.limit=32768;
    if (db_append(&c->grpc_net_cache,data,length)) return -1;
    return grpc_fill_app_cache(c) < 0 ? -1 : 0;
}

static int grpc_pool_read(tls13_conn_t *c, uint8_t *buffer, size_t capacity, size_t *length) {
    *length=0;
    if (!capacity) return 0;
    if (!c->app_cache.len) {
        int pending=grpc_fill_app_cache(c);
        if (pending < 0) return -1;
        if (pending) {
            uint8_t input[8192]; size_t received=0;
            int result=core_http2_read(c->xmux_stream,input,sizeof(input),&received);
            if (result < 0) return -1;
            if (result > 0) return result;
            if (!received) return core_grpc_complete(&c->grpc_decoder) && !c->grpc_net_cache.len ? 0 : -1;
            if (grpc_feed_data(c,input,received)) { c->grpc_read_failed=1; if (!c->app_cache.len) return -1; }
            if (!c->app_cache.len) return 1;
        }
    }
    size_t take=c->app_cache.len < capacity ? c->app_cache.len : capacity;
    memcpy(buffer,c->app_cache.data,take); db_consume(&c->app_cache,take);
    *length=take; return 0;
}

static int grpc_write_hunk(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    size_t varint_len = protobuf_varint_size(len);
    if (len > UINT32_MAX - 1U - varint_len) {
        return -1;
    }
    size_t msg_len = 1U + varint_len + len;
    size_t frame_len = 5U + msg_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (frame == NULL) {
        return -1;
    }

    frame[0] = 0;
    frame[1] = (uint8_t)(msg_len >> 24);
    frame[2] = (uint8_t)(msg_len >> 16);
    frame[3] = (uint8_t)(msg_len >> 8);
    frame[4] = (uint8_t)msg_len;
    frame[5] = 0x0a;
    size_t written = protobuf_write_varint(frame + 6, len);
    memcpy(frame + 6 + written, buf, len);

    int rc = c->xmux_stream ? core_http2_write(c->xmux_stream,frame,frame_len) : h2_write_data(c, frame, frame_len);
    free(frame);
    return rc;
}

static int h2_pump_one_frame(tls13_conn_t *c) {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    char err[160] = {0};

    if (h2_read_frame(c, &type, &flags, &stream_id, &payload, &payload_len) != 0) {
        free(payload);
        return -1;
    }

    int rc = 0;
    if (type == H2_FRAME_DATA && c->h2_header_stream_id == 0) {
        h2_response_entry_t *entry=h2_response_get(c,stream_id,stream_id == c->h2_stream_id);
        if (!stream_id || !(stream_id&1) || (!entry && stream_id >= c->h2_next_stream_id)) { free(payload); return -1; }
        size_t off = 0;
        size_t data_len = payload_len;
        if ((flags & H2_FLAG_PADDED) != 0) {
            if (payload_len == 0) {
                rc = -1;
            } else {
                uint8_t pad = payload[0];
                off = 1;
                if ((size_t)pad > payload_len - off) {
                    rc = -1;
                } else {
                    data_len = payload_len - off - (size_t)pad;
                }
            }
        }

        if (rc == 0 && entry && core_http2_response_data(&entry->response,data_len,flags&H2_FLAG_END_STREAM)) rc=-1;
        int delivered=stream_id == c->h2_stream_id;
        if (rc == 0 && h2_note_recv_data(c, entry, payload_len, delivered) != 0) {
            rc = -1;
        }
        if (rc == 0 && delivered && data_len > 0) {
            if (c->grpc_transport) {
                rc = grpc_feed_data(c, payload + off, data_len);
            } else if (db_append(&c->app_cache, payload + off, data_len) != 0) {
                rc = -1;
            }
        }
        if (rc == 0 && (flags & H2_FLAG_END_STREAM) != 0) {
            if (c->grpc_transport) { vc_log_error("grpc","gRPC DATA ended without grpc-status"); rc=-1; }
            else if (delivered) c->h2_stream_eof=1;
            else if (entry && entry->request_ended) h2_response_remove(c,stream_id);
        }
    } else {
        rc = h2_process_control_frame(c, type, flags, stream_id, payload, payload_len, err, sizeof(err));
        if (rc != 0) core_trace_failure(CORE_TRACE_TRANSPORT);
        if (rc != 0 && err[0] != '\0') {
            vc_log_error(c->grpc_transport ? "grpc" : "xhttp", "%s", err);
        }
    }

    free(payload);
    if (rc && c->grpc_transport) c->grpc_read_failed=1;
    return rc;
}

static int h2_fill_app_cache(tls13_conn_t *c) {
    if (c->grpc_transport) {
        int result=grpc_fill_app_cache(c);
        if (result <= 0) return result;
    }
    if (c->grpc_read_failed) return -1;
    if (c->h2_stream_eof) {
        return -1;
    }
    if (h2_pump_one_frame(c) != 0) {
        return c->grpc_transport && c->app_cache.len ? 0 : -1;
    }
    if (c->app_cache.len > 0) {
        return 0;
    }
    if (c->h2_stream_eof) {
        return -1;
    }
    return 1;
}

static int xhttp_encode_component(const char *input, char *output, size_t capacity) {
    size_t used=0; const char *hex="0123456789ABCDEF";
    for (const unsigned char *cursor=(const unsigned char *)input;*cursor;cursor++) {
        unsigned char ch=*cursor;
        int plain=(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~';
        size_t need=plain ? 1 : 3;
        if (used+need >= capacity) return -1;
        if (plain) output[used++]=(char)ch;
        else { output[used++]='%'; output[used++]=hex[ch>>4]; output[used++]=hex[ch&15]; }
    }
    if (used >= capacity) return -1;
    output[used]=0; return 0;
}

static int xhttp_append_path_segment(char *path, size_t cap, const char *segment) {
    if (path == NULL || segment == NULL || segment[0] == '\0') {
        return 0;
    }
    size_t len = strlen(path);
    if (len == 0) {
        if (cap < 2) {
            return -1;
        }
        path[0] = '/';
        path[1] = '\0';
        len = 1;
    }
    char encoded[1024];
    if (xhttp_encode_component(segment,encoded,sizeof(encoded)) != 0) return -1;
    const char *query=strchr(path,'?'); size_t path_length=query ? (size_t)(query-path) : len;
    size_t seg_len = strlen(encoded);
    int need_slash = (!path_length || path[path_length - 1] != '/');
    if (len + (need_slash ? 1U : 0U) + seg_len + 1U > cap) {
        return -1;
    }
    memmove(path+path_length+(size_t)need_slash+seg_len,path+path_length,len-path_length+1);
    if (need_slash) path[path_length++]='/';
    memcpy(path+path_length,encoded,seg_len);
    return 0;
}

static int xhttp_append_query_param(char *path, size_t cap, const char *key, const char *value) {
    if (path == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    size_t len=strlen(path);
    if (len >= cap) return -1;
    char encoded_key[256],encoded_value[27001];
    if (xhttp_encode_component(key,encoded_key,sizeof(encoded_key)) != 0 || xhttp_encode_component(value,encoded_value,sizeof(encoded_value)) != 0) return -1;
    char *request=malloc(cap); if (!request) return -1;
    const char *query=strchr(path,'?'); size_t used=query ? (size_t)(query-path) : len;
    memcpy(request,path,used); int has_query=0;
    for (const char *part=query ? query+1 : NULL;part && *part;) {
        const char *end=strchr(part,'&'); if (!end) end=path+len;
        const char *equals=memchr(part,'=',(size_t)(end-part)); size_t name_size=(size_t)((equals ? equals : end)-part);
        char raw[256],decoded[256]; int same=0;
        if (name_size < sizeof(raw)) {
            memcpy(raw,part,name_size); raw[name_size]=0;
            same=percent_decode(raw,decoded,sizeof(decoded)) == 0 && !strcmp(decoded,key);
        }
        if (!same && end > part) { request[used++]=has_query ? '&' : '?'; memcpy(request+used,part,(size_t)(end-part)); used+=(size_t)(end-part); has_query=1; }
        part=*end ? end+1 : NULL;
    }
    int written=snprintf(request+used,cap-used,"%c%s=%s",has_query ? '&' : '?',encoded_key,encoded_value);
    int result=written > 0 && (size_t)written < cap-used ? 0 : -1;
    if (!result) memcpy(path,request,used+(size_t)written+1);
    free(request); return result;
}

static int xhttp_append_header_line(char *headers, size_t cap, const char *key, const char *value) {
    if (headers == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    return core_http_header_set(headers,cap,key,value);
}

static int xhttp_append_cookie_pair(char *cookies, size_t cap, const char *key, const char *value) {
    if (cookies == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL || strchr(value, '\r') != NULL || strchr(value, '\n') != NULL) {
        return -1;
    }
    size_t len = strlen(cookies);
    size_t avail = cap > len ? cap - len : 0;
    if (avail == 0) {
        return -1;
    }
    int n = snprintf(cookies + len, avail, "%s%s=%s", len > 0 ? "; " : "", key, value);
    return (n > 0 && (size_t)n < avail) ? 0 : -1;
}

static const char *xhttp_meta_key(const char *placement, const char *configured, const char *header_default, const char *other_default) {
    if (configured != NULL && configured[0] != '\0') {
        return configured;
    }
    if (placement != NULL && strcmp(placement, "header") == 0) {
        return header_default;
    }
    if (placement != NULL && (strcmp(placement, "query") == 0 || strcmp(placement, "cookie") == 0)) {
        return other_default;
    }
    return "";
}

static int xhttp_apply_meta_one(char *path, size_t path_cap, char *headers, size_t headers_cap, char *cookies, size_t cookies_cap,
                                const char *placement, const char *key, const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    if (placement == NULL || placement[0] == '\0' || strcmp(placement, "path") == 0) {
        return xhttp_append_path_segment(path, path_cap, value);
    }
    if (strcmp(placement, "query") == 0) {
        return xhttp_append_query_param(path, path_cap, key, value);
    }
    if (strcmp(placement, "header") == 0) {
        return xhttp_append_header_line(headers, headers_cap, key, value);
    }
    if (strcmp(placement, "cookie") == 0) {
        return xhttp_append_cookie_pair(cookies, cookies_cap, key, value);
    }
    return -1;
}

static int xhttp_apply_padding(tls13_conn_t *c, char *path, size_t path_cap, char *headers, size_t headers_cap, char *cookies,
                               size_t cookies_cap) {
    char padding[16384];
    if (random_xpadding_value(c->xhttp_padding_min, c->xhttp_padding_max, c->xhttp_padding_method, padding, sizeof(padding)) != 0) {
        return -1;
    }

    const char *placement = c->xhttp_padding_obfs ? c->xhttp_padding_placement : "queryinheader";
    const char *key = c->xhttp_padding_obfs && c->xhttp_padding_key[0] != '\0' ? c->xhttp_padding_key : "x_padding";
    const char *header = c->xhttp_padding_obfs && c->xhttp_padding_header[0] != '\0' ? c->xhttp_padding_header : "Referer";

    if (strcmp(placement, "header") == 0) {
        return xhttp_append_header_line(headers, headers_cap, header, padding);
    }
    if (strcmp(placement, "query") == 0) {
        return xhttp_append_query_param(path, path_cap, key, padding);
    }
    if (strcmp(placement, "cookie") == 0) {
        return xhttp_append_cookie_pair(cookies, cookies_cap, key, padding);
    }

    char bare_path[1024];
    snprintf(bare_path, sizeof(bare_path), "%s", path);
    char *q = strchr(bare_path, '?');
    if (q != NULL) {
        *q = '\0';
    }

    char referer[16384];
    const char *scheme = c->mode == CONN_MODE_XHTTP_PLAIN ? "http" : "https";
    int n = snprintf(referer, sizeof(referer), "%s://%s%s?%s=%s", scheme, c->xhttp_host, bare_path, key, padding);
    if (n <= 0 || (size_t)n >= sizeof(referer)) {
        return -1;
    }
    return xhttp_append_header_line(headers, headers_cap, header, referer);
}

static int xhttp_prepare_request(tls13_conn_t *c, const char *seq_str, char *path, size_t path_cap, char *headers, size_t headers_cap) {
    char cookies[16384];
    cookies[0] = '\0';
    if (strlen(c->xhttp_headers) >= headers_cap) return -1;
    memcpy(headers,c->xhttp_headers,strlen(c->xhttp_headers)+1);
    snprintf(path, path_cap, "%s", c->xhttp_base_path);

    if (xhttp_apply_padding(c, path, path_cap, headers, headers_cap, cookies, sizeof(cookies)) != 0) {
        return -1;
    }

    const char *session_key = xhttp_meta_key(c->xhttp_session_placement, c->xhttp_session_key, "X-Session", "x_session");
    if (xhttp_apply_meta_one(path, path_cap, headers, headers_cap, cookies, sizeof(cookies), c->xhttp_session_placement, session_key,
                             c->xhttp_session_id) != 0) {
        return -1;
    }

    if (seq_str != NULL && seq_str[0] != '\0') {
        const char *seq_key = xhttp_meta_key(c->xhttp_seq_placement, c->xhttp_seq_key, "X-Seq", "x_seq");
        if (xhttp_apply_meta_one(path, path_cap, headers, headers_cap, cookies, sizeof(cookies), c->xhttp_seq_placement, seq_key, seq_str) !=
            0) {
            return -1;
        }
    }

    if (cookies[0] != '\0' && core_http_header_append_cookie(headers,headers_cap,cookies) != 0) {
        return -1;
    }
    return 0;
}

static const char xhttp_user_agent[]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

static int xhttp_packet_headers(tls13_conn_t *connection, const char *sequence, const uint8_t *data, size_t length, uint32_t header_limit,
                                char path[2048], core_xhttp_payload_t *packet, char *error, size_t capacity) {
    char *prefix=connection->output_memory ? core_buffer_alloc(connection->output_memory,65537) : malloc(65537);
    if (!prefix) { set_err(error,capacity,"XHTTP metadata allocation failed"); return -1; }
    if (xhttp_prepare_request(connection,sequence,path,2048,prefix,65537) != 0) {
        if (connection->output_memory) core_buffer_free(connection->output_memory,prefix,65537); else free(prefix);
        set_err(error,capacity,"failed to build XHTTP packet metadata"); return -1;
    }
    size_t reserve=strlen(path)+strlen(connection->xhttp_host)+strlen(connection->xhttp_uplink_method)+5;
    reserve+=strlen(":method:scheme:authority:path")+4*32;
    reserve+=strlen("user-agent")+strlen(xhttp_user_agent)+32;
    reserve+=strlen("accept")+3+32+strlen("cache-control")+8+32+strlen("pragma")+8+32;
    reserve+=strlen("content-length")+20+32;
    size_t budget=header_limit > reserve ? (size_t)header_limit-reserve : 0;
    core_xhttp_payload_options_t options={.placement=connection->xhttp_uplink_data_placement,.key=connection->xhttp_uplink_data_key,.chunks=connection->xhttp_uplink_chunks,.memory=connection->output_memory};
    int result=core_xhttp_payload_build(&options,data,length,prefix,budget,packet,error,capacity);
    if (connection->output_memory) core_buffer_free(connection->output_memory,prefix,65537); else free(prefix);
    return result;
}

static int h2_append_regular_header(dynbuf_t *block, const char *name, size_t name_len, const char *value, size_t value_len) {
    if (name == NULL || value == NULL || name_len == 0) {
        return 0;
    }
    if (name_len >= 128 || value_len > 65536) {
        return -1;
    }

    char lname[128];
    for (size_t i = 0; i < name_len; i++) {
        unsigned char ch = (unsigned char)name[i];
        if (ch == '\r' || ch == '\n' || ch == ':' || ch == '\0') {
            return -1;
        }
        lname[i] = (char)tolower(ch);
    }
    lname[name_len] = '\0';

    while (value_len > 0 && (*value == ' ' || *value == '\t')) {
        value++;
        value_len--;
    }
    while (value_len > 0 && (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
        value_len--;
    }
    if (strcmp(lname, "connection") == 0 || strcmp(lname, "keep-alive") == 0 || strcmp(lname, "proxy-connection") == 0 ||
        strcmp(lname, "transfer-encoding") == 0 || strcmp(lname, "upgrade") == 0) {
        return 0;
    }
    char *text=block->memory ? core_buffer_alloc(block->memory,value_len+1) : malloc(value_len+1);
    if (!text) return -1;
    memcpy(text,value,value_len); text[value_len]=0;
    int result=hpack_append_literal_new_name(block,lname,text);
    if (block->memory) core_buffer_free(block->memory,text,value_len+1); else free(text);
    return result;
}

static int h2_append_http1_header_lines(dynbuf_t *block, const char *headers, int omit_content_type) {
    const char *p = headers;
    while (p != NULL && *p != '\0') {
        const char *line_end = strstr(p, "\r\n");
        size_t line_len = line_end != NULL ? (size_t)(line_end - p) : strlen(p);
        if (line_len > 0) {
            const char *colon = memchr(p, ':', line_len);
            if (colon == NULL) {
                return -1;
            }
            if (!(omit_content_type && colon-p == 12 && !strncasecmp(p,"content-type",12)) && h2_append_regular_header(block, p, (size_t)(colon - p), colon + 1, line_len - (size_t)(colon - p) - 1) != 0) {
                return -1;
            }
        }
        if (line_end == NULL) {
            break;
        }
        p = line_end + 2;
    }
    return 0;
}

static int h2_send_xhttp_request_headers(tls13_conn_t *c, uint32_t stream_id, const char *method, const char *path,
                                         const char *extra_headers, size_t content_len, int has_body, int streaming_body, char *err,
                                         size_t err_cap) {
    dynbuf_t block = {.limit=1024U*1024U,.memory=c->output_memory};
    int rc = 0;

    if (strcmp(method, "GET") == 0) {
        rc = hpack_append_indexed(&block, 2);
    } else if (strcmp(method, "POST") == 0) {
        rc = hpack_append_indexed(&block, 3);
    } else {
        rc = hpack_append_literal_new_name(&block, ":method", method);
    }

    if (rc == 0) {
        rc = hpack_append_indexed(&block, 7);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, ":authority", c->xhttp_host);
    }
    if (rc == 0) {
        rc = (strcmp(path, "/") == 0) ? hpack_append_indexed(&block, 4) : hpack_append_literal_new_name(&block, ":path", path);
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"User-Agent",NULL)) {
        rc = hpack_append_literal_new_name(&block, "user-agent",xhttp_user_agent);
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"Accept",NULL)) {
        rc = hpack_append_literal_new_name(&block, "accept", "*/*");
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"Cache-Control",NULL)) {
        rc = hpack_append_literal_new_name(&block, "cache-control", "no-cache");
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"Pragma",NULL)) {
        rc = hpack_append_literal_new_name(&block, "pragma", "no-cache");
    }
    if (rc == 0 && extra_headers != NULL && extra_headers[0] != '\0') {
        rc = h2_append_http1_header_lines(&block, extra_headers,has_body && streaming_body == 1 && !c->xhttp_no_grpc_header);
    }
    if (rc == 0 && has_body && streaming_body == 1 && !c->xhttp_no_grpc_header) {
        rc = hpack_append_literal_new_name(&block, "content-type", "application/grpc");
    }
    if (rc == 0 && has_body && !streaming_body) {
        char clen[32];
        snprintf(clen, sizeof(clen), "%zu", content_len);
        rc = hpack_append_literal_new_name(&block, "content-length", clen);
    }

    uint8_t flags = H2_FLAG_END_HEADERS;
    if (!has_body) {
        flags |= H2_FLAG_END_STREAM;
    }
    if (rc == 0) {
        size_t offset=0;
        do {
            size_t length=block.len-offset; if (length > 16384) length=16384;
            uint8_t part_flags=offset ? 0 : (uint8_t)(flags&~H2_FLAG_END_HEADERS);
            if (offset+length == block.len) part_flags|=H2_FLAG_END_HEADERS;
            if (h2_send_frame(c,offset ? H2_FRAME_CONTINUATION : H2_FRAME_HEADERS,part_flags,stream_id,block.data+offset,length) != 0) { rc=-1; break; }
            offset+=length;
        } while (offset < block.len);
    }

    db_free(&block);
    if (rc != 0) {
        set_err(err, err_cap, "failed to send xhttp h2 headers");
        return -1;
    }
    return 0;
}

static int h2_send_xhttp_body(tls13_conn_t *c, uint32_t stream_id, const uint8_t *buf, size_t len, char *err, size_t err_cap) {
    size_t off = 0;
    if (len == 0) {
        if (h2_send_frame(c, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id, NULL, 0) != 0) {
            set_err(err, err_cap, "failed to send xhttp h2 body");
            return -1;
        }
        return 0;
    }

    c->h2_upload_stream_id = stream_id;
    c->h2_upload_stream_window = c->h2_peer_initial_window;
    while (off < len) {
        while (c->h2_peer_conn_window <= 0 || c->h2_upload_stream_window <= 0) {
            if (h2_pump_one_frame(c) != 0) {
                c->h2_upload_stream_id = 0;
                c->h2_upload_stream_window = 0;
                set_err(err, err_cap, "failed while waiting for xhttp h2 upload window");
                return -1;
            }
        }

        size_t chunk = len - off;
        if (chunk > c->h2_peer_max_frame_size) {
            chunk = c->h2_peer_max_frame_size;
        }
        if ((int64_t)chunk > c->h2_peer_conn_window) {
            chunk = (size_t)c->h2_peer_conn_window;
        }
        if ((int64_t)chunk > c->h2_upload_stream_window) {
            chunk = (size_t)c->h2_upload_stream_window;
        }
        uint8_t flags = (off + chunk == len) ? H2_FLAG_END_STREAM : 0;
        if (h2_send_frame(c, H2_FRAME_DATA, flags, stream_id, buf + off, chunk) != 0) {
            c->h2_upload_stream_id = 0;
            c->h2_upload_stream_window = 0;
            set_err(err, err_cap, "failed to send xhttp h2 body");
            return -1;
        }
        c->h2_peer_conn_window -= (int64_t)chunk;
        c->h2_upload_stream_window -= (int64_t)chunk;
        off += chunk;
    }
    c->h2_upload_stream_id = 0;
    c->h2_upload_stream_window = 0;
    h2_response_entry_t *entry=h2_response_get(c,stream_id,0);
    if (entry) { entry->request_ended=1; if (entry->response.ended) h2_response_remove(c,stream_id); }
    return 0;
}

static int xhttp_h2_begin(tls13_conn_t *c, char *err, size_t err_cap) {
    c->h2_stream_id = 1;
    c->h2_header_stream_id = 0;
    c->h2_header_flags = 0;
    c->h2_header_block.len = 0;
    c->h2_next_stream_id = 3;
    c->h2_peer_initial_window = H2_DEFAULT_WINDOW;
    c->h2_peer_max_frame_size = H2_DEFAULT_MAX_FRAME;
    c->h2_peer_header_list_size = 8192;
    c->h2_peer_concurrency=UINT32_MAX;
    c->h2_peer_conn_window = H2_DEFAULT_WINDOW;
    c->h2_peer_stream_window = H2_DEFAULT_WINDOW;
    c->h2_upload_stream_id = 0;
    c->h2_upload_stream_window = 0;
    c->h2_recv_conn_pending = 0;
    c->h2_recv_stream_pending = 0;
    c->h2_stream_eof = 0;
    c->h2_request_cancelled = 0;
    c->h2_receive_window=H2_DEFAULT_WINDOW+H2_CONNECTION_WINDOW_INC;
    if (!c->xmux_physical && !c->grpc_physical_only) {
        h2_response_entry_t *entry=h2_response_get(c,c->h2_stream_id,1);
        if (!entry) { set_err(err,err_cap,"failed to allocate h2 response state"); return -1; }
        entry->request_ended=!c->grpc_transport && strcmp(c->xhttp_transport_mode,"stream-one");
    }

    if (h2_send_client_preface(c, err, err_cap) != 0) {
        return -1;
    }
    return 0;
}

static int xhttp_h2_send_download_request(tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 GET");
        return -1;
    }

    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    return h2_send_xhttp_request_headers(c, c->h2_stream_id, "GET", request_path, extra_headers, 0, 0, 0, err, err_cap);
}

static int xhttp_h2_send_stream_one_request(tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 stream-one request");
        return -1;
    }

    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    const char *method = c->xhttp_uplink_method;
    return h2_send_xhttp_request_headers(c, c->h2_stream_id, method, request_path, extra_headers, 0, 1, 1, err, err_cap);
}

static int h2_request_capacity(tls13_conn_t *c, char *err, size_t err_cap) {
    if (c->h2_goaway) { set_err(err,err_cap,"h2 goaway prevents new requests"); return -1; }
    if (!c->h2_next_stream_id || c->h2_next_stream_id > 0x7ffffffdU) { set_err(err,err_cap,"h2 stream identifier exhausted"); return -1; }
    if (tls13_drain_h2_input(c) < 0) { set_err(err,err_cap,"failed to read h2 settings"); return -1; }
    while (!c->h2_goaway && (c->h2_response_count >= 256 || h2_response_active(c) >= c->h2_peer_concurrency))
        if (h2_pump_one_frame(c)) { set_err(err,err_cap,"h2 outstanding response capacity wait failed"); return -1; }
    if (c->h2_goaway) { set_err(err,err_cap,"h2 goaway prevents new requests"); return -1; }
    return 0;
}

static int xhttp_h2_send_stream_up_request(tls13_conn_t *c, char *err, size_t err_cap) {
    if (h2_request_capacity(c,err,err_cap)) return -1;
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 stream-up request");
        return -1;
    }

    uint32_t stream_id = c->h2_next_stream_id;
    c->h2_next_stream_id += 2;
    c->h2_upload_stream_id = stream_id;
    c->h2_upload_stream_window = c->h2_peer_initial_window;
    if (!h2_response_get(c,stream_id,1)) { set_err(err,err_cap,"failed to allocate h2 response state"); return -1; }
    const char *method = c->xhttp_uplink_method;
    return h2_send_xhttp_request_headers(c, stream_id, method, request_path, extra_headers, 0, 1, 1, err, err_cap);
}

static int xhttp_wait_post(tls13_conn_t *connection, char *error, size_t capacity) {
    uint64_t due,now=core_now_ms();
    if (core_xhttp_post_due(connection->xhttp_post_intervals,connection->xhttp_last_post_ms,now,&due) != 0) { set_err(error,capacity,"XHTTP packet interval sampling failed"); return -1; }
    while ((now=core_now_ms()) < due) {
        if ((core_deadline_active() && !core_deadline_remaining()) || core_poll(NULL,0,due-now > INT_MAX ? INT_MAX : (int)(due-now)) < 0) {
            set_err(error,capacity,"XHTTP packet interval wait failed"); return -1;
        }
    }
    connection->xhttp_last_post_ms=now; return 0;
}

static int xhttp_h2_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap) {
    if (h2_request_capacity(c,err,err_cap)) return -1;
    if (xhttp_wait_post(c,err,err_cap) != 0) return -1;
    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    core_xhttp_payload_t packet;
    if (xhttp_packet_headers(c,seq,buf,*length,c->h2_peer_header_list_size,request_path,&packet,err,err_cap) != 0) return -1;
    *length=packet.consumed;

    uint32_t stream_id = c->h2_next_stream_id;
    c->h2_next_stream_id += 2;
    h2_response_entry_t *entry=h2_response_get(c,stream_id,1);
    if (!entry) { core_xhttp_payload_clear(&packet); set_err(err,err_cap,"failed to allocate h2 response state"); return -1; }
    entry->request_ended=!packet.body_size;
    const char *method = c->xhttp_uplink_method;
    int result=h2_send_xhttp_request_headers(c,stream_id,method,request_path,packet.headers,packet.body_size,packet.body_size != 0,0,err,err_cap);
    if (!result && packet.body_size) result=h2_send_xhttp_body(c,stream_id,buf,packet.body_size,err,err_cap);
    core_xhttp_payload_clear(&packet); return result;
}

static int xhttp_h2_start_mode(tls13_conn_t *c, char *err, size_t err_cap) {
    if (c->xmux_physical) return xhttp_h2_begin(c, err, err_cap);
    if (strcmp(c->xhttp_transport_mode, "stream-one") == 0) {
        return xhttp_h2_send_stream_one_request(c, err, err_cap);
    }
    if (xhttp_h2_send_download_request(c, err, err_cap) != 0) {
        return -1;
    }
    if (strcmp(c->xhttp_transport_mode, "stream-up") == 0) {
        return xhttp_h2_send_stream_up_request(c, err, err_cap);
    }
    return 0;
}

static int grpc_path_escape(const char *src, char *dst, size_t cap, int keep_slash) {
    static const char hex[] = "0123456789ABCDEF";
    size_t out = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p != '\0'; p++) {
        unsigned char ch = *p;
        int safe = (ch >= 'a' && ch <= 'z') ||
                   (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') ||
                   ch == '-' || ch == '_' || ch == '.' || ch == '~' ||
                   ch == '$' || ch == '&' || ch == '+' || ch == ':' ||
                   ch == '=' || ch == '@' || (keep_slash && ch == '/');
        if (safe) {
            if (out + 1 >= cap) {
                return -1;
            }
            dst[out++] = (char)ch;
        } else {
            if (out + 3 >= cap) {
                return -1;
            }
            dst[out++] = '%';
            dst[out++] = hex[ch >> 4];
            dst[out++] = hex[ch & 0x0f];
        }
    }
    if (out >= cap) {
        return -1;
    }
    dst[out] = '\0';
    return 0;
}

static int grpc_build_request_path(const char *service_name, int multi_mode, char *path, size_t cap) {
    char service[512];
    char stream[256];

    if (service_name[0] != '/') {
        if (grpc_path_escape(service_name, service, sizeof(service), 0) != 0) {
            return -1;
        }
        snprintf(stream, sizeof(stream), "%s", multi_mode ? "TunMulti" : "Tun");
    } else {
        const char *last = strrchr(service_name, '/');
        if (last == NULL || last == service_name) {
            service[0] = '\0';
        } else {
            char raw_service[512];
            size_t n = (size_t)(last - service_name - 1);
            if (n >= sizeof(raw_service)) {
                return -1;
            }
            memcpy(raw_service, service_name + 1, n);
            raw_service[n] = '\0';
            if (grpc_path_escape(raw_service, service, sizeof(service), 1) != 0) {
                return -1;
            }
        }

        const char *raw_stream = last != NULL ? last + 1 : "";
        char stream_part[256];
        const char *separator = strchr(raw_stream, '|');
        if (multi_mode && separator != NULL) {
            raw_stream = separator + 1;
        }
        size_t n = strcspn(raw_stream, "|");
        if (n >= sizeof(stream_part)) {
            return -1;
        }
        memcpy(stream_part, raw_stream, n);
        stream_part[n] = '\0';
        if (grpc_path_escape(stream_part, stream, sizeof(stream), 0) != 0) {
            return -1;
        }
    }

    int n = snprintf(path, cap, "/%s/%s", service, stream);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

static int h2_send_grpc_request_headers(tls13_conn_t *c, char *err, size_t err_cap) {
    char path[1024];
    if (grpc_build_request_path(c->grpc_service_name, c->grpc_multi_mode, path, sizeof(path)) != 0) {
        set_err(err, err_cap, "invalid grpc serviceName");
        return -1;
    }

    dynbuf_t block = {.limit=1024U*1024U,.memory=c->output_memory};
    int rc = hpack_append_indexed(&block, 3);
    if (rc == 0) {
        rc = hpack_append_indexed(&block, c->mode == CONN_MODE_GRPC_PLAIN ? 6 : 7);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, ":authority", c->grpc_authority);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, ":path", path);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "content-type", "application/grpc");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "user-agent",
                                           c->grpc_user_agent[0] ? c->grpc_user_agent : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                           "Chrome/149.0.0.0 Safari/537.36");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "te", "trailers");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "grpc-accept-encoding", "identity");
    }
    if (rc == 0 && h2_send_frame(c, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, c->h2_stream_id, block.data, block.len) != 0) {
        rc = -1;
    }
    db_free(&block);

    if (rc != 0) {
        set_err(err, err_cap, "failed to send grpc h2 headers");
        return -1;
    }
    return 0;
}

static int grpc_h2_start(tls13_conn_t *c, char *err, size_t err_cap) {
    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    if (c->grpc_physical_only) c->h2_next_stream_id=1;
    return c->grpc_physical_only ? 0 : h2_send_grpc_request_headers(c, err, err_cap);
}

static int xhttp_conn_write_all(tls13_conn_t *c, const void *buf, size_t len) {
    return c->ssl != NULL ? ssl_write_all(c->ssl, buf, len) : write_exact(c->fd, buf, len);
}

static void *xhttp_plain_upload_reader(void *arg) {
    tls13_conn_t *connection=arg; char error[160]={0};
    if (xhttp_read_http1_response(NULL,connection->xhttp_upload_fd,error,sizeof(error))) {
        pthread_mutex_lock(&g_tls_state_lock);
        int failed=!connection->xhttp_upload_stopping;
        if (failed) connection->xhttp_upload_failed=1;
        pthread_mutex_unlock(&g_tls_state_lock);
        if (failed) {
            vc_log_error("xhttp","upload response failed: %s",error);
            shutdown(connection->fd,SHUT_RDWR);
        }
    }
    return NULL;
}

static int xhttp_start_plain_upload_reader(tls13_conn_t *c) {
    if (pthread_create(&c->xhttp_upload_reader, NULL, xhttp_plain_upload_reader, c) != 0) {
        return -1;
    }
    c->xhttp_upload_reader_started = 1;
    return 0;
}

static int xhttp_http1_headers(tls13_conn_t *connection, const char *method, const char *path, const char *source, int body_mode, size_t body_size,
                               const char *keep_alive, dynbuf_t *request) {
    char line[4096]; int size=snprintf(line,sizeof(line),"%s %s HTTP/1.1\r\nHost: %s\r\n",method,path,connection->xhttp_host);
    if (size < 0 || (size_t)size >= sizeof(line) || db_append(request,line,(size_t)size) != 0) return -1;
    size_t capacity=strlen(source)+1024;
    char *headers=request->memory ? core_buffer_alloc(request->memory,capacity) : malloc(capacity);
    if (!headers) return -1;
    memcpy(headers,source,strlen(source)+1); int result=0;
    if (!core_http_header_get(headers,"User-Agent",NULL)) result=core_http_header_set(headers,capacity,"User-Agent","vless-core/1.0");
    if (!result && !core_http_header_get(headers,"Accept",NULL)) result=core_http_header_set(headers,capacity,"Accept","*/*");
    if (!result && body_mode == 2 && !connection->xhttp_no_grpc_header) result=core_http_header_set(headers,capacity,"Content-Type","application/grpc");
    if (!result && (body_mode == 1 || body_mode == 3) && !core_http_header_get(headers,"Content-Type",NULL)) result=core_http_header_set(headers,capacity,"Content-Type","application/octet-stream");
    if (!result && (body_mode == 2 || body_mode == 3)) result=core_http_header_set(headers,capacity,"Transfer-Encoding","chunked");
    if (!result && body_mode == 1) { snprintf(line,sizeof(line),"%zu",body_size); result=core_http_header_set(headers,capacity,"Content-Length",line); }
    if (!result) result=core_http_header_set(headers,capacity,"Connection",keep_alive);
    if (!result) result=db_append(request,headers,strlen(headers));
    if (!result) result=db_append(request,"\r\n",2);
    if (request->memory) core_buffer_free(request->memory,headers,capacity); else free(headers);
    return result;
}

static int xhttp_send_plain_stream_request(tls13_conn_t *c, int fd, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp stream request");
        return -1;
    }

    dynbuf_t request={0};
    if (xhttp_http1_headers(c,c->xhttp_uplink_method,request_path,extra_headers,2,0,"close",&request) != 0) {
        db_free(&request);
        set_err(err, err_cap, "xhttp stream request too large");
        return -1;
    }
    int result=write_exact(fd,request.data,request.len); db_free(&request);
    if (result != 0) {
        set_err(err, err_cap, "failed to send xhttp stream request");
        return -1;
    }

    c->xhttp_http1_response=(core_http1_response_t){0};
    c->xhttp_eof=c->xhttp_wire_eof=0;
    return 0;
}

static int xhttp_write_plain_stream(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    int fd = strcmp(c->xhttp_transport_mode, "stream-one") == 0 ? c->fd : c->xhttp_upload_fd;
    if (fd < 0) {
        return -1;
    }

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 16384) {
            chunk = 16384;
        }
        char header[32];
        int header_len = snprintf(header, sizeof(header), "%zx\r\n", chunk);
        if (header_len <= 0 || (size_t)header_len >= sizeof(header) || write_exact(fd, header, (size_t)header_len) != 0 ||
            write_exact(fd, buf + off, chunk) != 0 || write_exact(fd, "\r\n", 2) != 0) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}

static int xhttp_send_download_request(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp GET");
        return -1;
    }

    dynbuf_t request={0};
    if ((!core_http_header_get(extra_headers,"Cache-Control",NULL) && core_http_header_set(extra_headers,sizeof(extra_headers),"Cache-Control","no-cache") != 0) ||
        xhttp_http1_headers(c,"GET",request_path,extra_headers,0,0,"keep-alive",&request) != 0) {
        db_free(&request);
        set_err(err, err_cap, "xhttp GET request too large");
        return -1;
    }

    int result=xhttp_conn_write_all(c,request.data,request.len); db_free(&request);
    if (result != 0) {
        set_err(err, err_cap, "failed to send xhttp GET");
        return -1;
    }

    c->xhttp_http1_response=(core_http1_response_t){0};
    c->xhttp_eof=c->xhttp_wire_eof=0;
    (void)cfg;
    return 0;
}

static int xhttp_http1_packet_request(tls13_conn_t *connection, const char *path, const char *headers, size_t body_size, const char *keep_alive, dynbuf_t *request) {
    return xhttp_http1_headers(connection,connection->xhttp_uplink_method,path,headers,1,body_size,keep_alive,request);
}

static int xhttp_post_packet_plain(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap) {
    if (xhttp_wait_post(c,err,err_cap) != 0) return -1;
    int fd = tcp_connect_host(c->remote_host, c->remote_port, !c->ignore_server_ips);
    if (fd < 0) {
        set_err(err, err_cap, "tcp connect failed");
        return -1;
    }

    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    core_xhttp_payload_t packet;
    if (xhttp_packet_headers(c,seq,buf,*length,8192,request_path,&packet,err,err_cap) != 0) {
        close(fd);
        return -1;
    }
    *length=packet.consumed;

    dynbuf_t request={0};
    if (xhttp_http1_packet_request(c,request_path,packet.headers,packet.body_size,"close",&request) != 0) {
        core_xhttp_payload_clear(&packet); db_free(&request);
        close(fd);
        set_err(err, err_cap, "xhttp POST request too large");
        return -1;
    }

    int rc = 0;
    if (write_exact(fd,request.data,request.len) != 0 || (packet.body_size && write_exact(fd,buf,packet.body_size) != 0)) {
        rc = -1;
        set_err(err, err_cap, "failed to send xhttp POST");
    } else {
        rc=xhttp_read_http1_response(NULL,fd,err,err_cap);
    }

    core_xhttp_payload_clear(&packet); db_free(&request); close(fd);
    return rc;
}

static int xhttp_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap) {
    if (c->mode == CONN_MODE_XHTTP_PLAIN) {
        return xhttp_post_packet_plain(c, buf, length, err, err_cap);
    }
    if (xhttp_wait_post(c,err,err_cap) != 0) return -1;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    tls_verify_mode_t mode = c->tls_verify_policy;
    if (mode == TLS_VERIFY_MODE_TOFU) {
        if (c->xhttp_pin_key[0] == '\0' &&
            xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                               sizeof(c->xhttp_pin_key)) != 0) {
            set_err(err, err_cap, "failed to build TOFU pin key");
            return -1;
        }
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, 0, NULL, 0, &ctx, &ssl, &fd, &c->tls_use_aes_fallback, err,
                            err_cap) != 0) {
            return -1;
        }
        if (xhttp_tofu_verify_or_store(ssl, c->xhttp_pin_key, 0, err, err_cap) != 0) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = c->xhttp_tls_insecure ? 0 : tls_verify_peer(mode);
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, verify_peer, NULL, 0, &ctx, &ssl, &fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
    }

    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    core_xhttp_payload_t packet;
    if (xhttp_packet_headers(c,seq,buf,*length,8192,request_path,&packet,err,err_cap) != 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }
    *length=packet.consumed;

    dynbuf_t request={0};
    if (xhttp_http1_packet_request(c,request_path,packet.headers,packet.body_size,"close",&request) != 0) {
        core_xhttp_payload_clear(&packet); db_free(&request);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "xhttp POST request too large");
        return -1;
    }

    int rc = 0;
    if (ssl_write_all(ssl,request.data,request.len) != 0 || (packet.body_size && ssl_write_all(ssl,buf,packet.body_size) != 0)) {
        rc = -1;
        set_err(err, err_cap, "failed to send xhttp POST");
    } else {
        rc=xhttp_read_http1_response(ssl,fd,err,err_cap);
    }

    core_xhttp_payload_clear(&packet); db_free(&request);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return rc;
}

static void xor_seq_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (uint8_t)((seq >> (i * 8)) & 0xFF);
    }
}

static int digest_hash(const EVP_MD *md, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    if (md == NULL || out == NULL) {
        return -1;
    }
    size_t want = (size_t)EVP_MD_size(md);
    if (want == 0 || out_len != want) {
        return -1;
    }
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    if (m == NULL) {
        return -1;
    }
    int ok = EVP_DigestInit_ex(m, md, NULL) == 1;
    if (ok && in_len > 0) {
        ok = EVP_DigestUpdate(m, in, in_len) == 1;
    }
    if (ok) {
        ok = EVP_DigestFinal_ex(m, out, NULL) == 1;
    }
    EVP_MD_CTX_free(m);
    return ok ? 0 : -1;
}

static int hmac_digest_segments(const EVP_MD *md, const uint8_t *key, size_t key_len, const uint8_t *seg1, size_t seg1_len,
                                const uint8_t *seg2, size_t seg2_len, const uint8_t *seg3, size_t seg3_len, uint8_t *out,
                                size_t out_len) {
    if (md == NULL || out == NULL) {
        return -1;
    }
    int md_size = EVP_MD_size(md);
    if (md_size <= 0 || out_len != (size_t)md_size) {
        return -1;
    }
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    const char *digest_name = EVP_MD_get0_name(md);
    if (digest_name == NULL) {
        return -1;
    }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return -1;
    }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (ctx == NULL) {
        return -1;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    int ok = EVP_MAC_init(ctx, key, key_len, params) == 1;
    if (ok && seg1_len > 0) ok = EVP_MAC_update(ctx, seg1, seg1_len) == 1;
    if (ok && seg2_len > 0) ok = EVP_MAC_update(ctx, seg2, seg2_len) == 1;
    if (ok && seg3_len > 0) ok = EVP_MAC_update(ctx, seg3, seg3_len) == 1;

    size_t got_len = 0;
    if (ok) {
        ok = EVP_MAC_final(ctx, out, &got_len, out_len) == 1 && got_len == out_len;
    }
    EVP_MAC_CTX_free(ctx);
    return ok ? 0 : -1;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    int ok = HMAC_Init_ex(ctx, key, (int)key_len, md, NULL) == 1;
    if (ok && seg1_len > 0) ok = HMAC_Update(ctx, seg1, seg1_len) == 1;
    if (ok && seg2_len > 0) ok = HMAC_Update(ctx, seg2, seg2_len) == 1;
    if (ok && seg3_len > 0) ok = HMAC_Update(ctx, seg3, seg3_len) == 1;

    unsigned int got_len = 0;
    if (ok) {
        ok = HMAC_Final(ctx, out, &got_len) == 1 && got_len == (unsigned int)out_len;
    }
    HMAC_CTX_free(ctx);
    return ok ? 0 : -1;
#endif
}

static int hmac_digest(const EVP_MD *md, const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    return hmac_digest_segments(md, key, key_len, in, in_len, NULL, 0, NULL, 0, out, out_len);
}

static int hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len, uint8_t out[64]) {
    return hmac_digest(EVP_sha512(), key, key_len, in, in_len, out, 64);
}

static int hkdf_extract_md(const EVP_MD *md, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk,
                           size_t prk_len) {
    return hmac_digest(md, salt, salt_len, ikm, ikm_len, prk, prk_len);
}

static int hkdf_expand_md(const EVP_MD *md, const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *out,
                          size_t out_len) {
    if (md == NULL || prk == NULL || out == NULL) {
        return -1;
    }
    size_t hash_len = (size_t)EVP_MD_size(md);
    if (hash_len == 0 || hash_len > 64 || prk_len != hash_len) {
        return -1;
    }

    uint8_t t[64];
    size_t pos = 0;
    uint8_t counter = 1;
    size_t t_len = 0;

    while (pos < out_len) {
        if (hmac_digest_segments(md, prk, prk_len, t_len > 0 ? t : NULL, t_len, info, info_len, &counter, 1, t, hash_len) != 0) {
            return -1;
        }

        size_t take = out_len - pos;
        if (take > hash_len) {
            take = hash_len;
        }
        memcpy(out + pos, t, take);
        pos += take;
        t_len = hash_len;
        counter++;
    }

    return 0;
}

static int hkdf_expand_label_md(const EVP_MD *md, const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *ctx,
                                size_t ctx_len, uint8_t *out, size_t out_len) {
    uint8_t info[256];
    size_t label_len = strlen(label);
    const char *prefix = "tls13 ";
    size_t full_label_len = strlen(prefix) + label_len;

    if (full_label_len > 255 || ctx_len > 255 || out_len > 65535) {
        return -1;
    }

    size_t off = 0;
    info[off++] = (uint8_t)(out_len >> 8);
    info[off++] = (uint8_t)(out_len & 0xFF);
    info[off++] = (uint8_t)full_label_len;
    memcpy(info + off, prefix, strlen(prefix));
    off += strlen(prefix);
    memcpy(info + off, label, label_len);
    off += label_len;
    info[off++] = (uint8_t)ctx_len;
    if (ctx_len > 0) {
        memcpy(info + off, ctx, ctx_len);
        off += ctx_len;
    }

    return hkdf_expand_md(md, secret, secret_len, info, off, out, out_len);
}

static int derive_secret_md(const EVP_MD *md, const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *transcript_hash,
                            size_t transcript_hash_len, uint8_t *out, size_t out_len) {
    return hkdf_expand_label_md(md, secret, secret_len, label, transcript_hash, transcript_hash_len, out, out_len);
}

static int derive_key_iv_md(const EVP_MD *md, const uint8_t *traffic_secret, size_t secret_len, size_t key_len, uint8_t *key,
                            uint8_t iv[12]) {
    uint8_t zero_ctx[1] = {0};
    if (hkdf_expand_label_md(md, traffic_secret, secret_len, "key", zero_ctx, 0, key, key_len) != 0) {
        return -1;
    }
    if (hkdf_expand_label_md(md, traffic_secret, secret_len, "iv", zero_ctx, 0, iv, 12) != 0) {
        return -1;
    }
    return 0;
}

static int x25519_generate(uint8_t priv[32], uint8_t pub[32]) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (kctx == NULL) {
        return -1;
    }
    EVP_PKEY *pkey = NULL;
    int ok = EVP_PKEY_keygen_init(kctx) == 1 && EVP_PKEY_keygen(kctx, &pkey) == 1;
    EVP_PKEY_CTX_free(kctx);
    if (!ok || pkey == NULL) {
        if (pkey != NULL) {
            EVP_PKEY_free(pkey);
        }
        return -1;
    }

    size_t priv_len = 32;
    size_t pub_len = 32;
    ok = EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) == 1 && priv_len == 32 &&
         EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) == 1 && pub_len == 32;
    EVP_PKEY_free(pkey);
    return ok ? 0 : -1;
}

static int x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]) {
    EVP_PKEY *sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (sk == NULL || pk == NULL) {
        if (sk != NULL) {
            EVP_PKEY_free(sk);
        }
        if (pk != NULL) {
            EVP_PKEY_free(pk);
        }
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(sk);
        EVP_PKEY_free(pk);
        return -1;
    }

    size_t out_len = 32;
    int ok = EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, pk) == 1 &&
             EVP_PKEY_derive(ctx, out, &out_len) == 1 && out_len == 32;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 3
static int p256_generate_public_legacy(uint8_t pub[65], EVP_PKEY **retained) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL) {
        return -1;
    }
    int ok = EC_KEY_generate_key(key) == 1;
    if (ok) {
        const EC_GROUP *group = EC_KEY_get0_group(key);
        const EC_POINT *point = EC_KEY_get0_public_key(key);
        ok = group != NULL && point != NULL &&
             EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pub, 65, NULL) == 65;
    }
    if (ok && retained) {
        *retained=EVP_PKEY_new();
        if (!*retained || EVP_PKEY_assign_EC_KEY(*retained,key) != 1) { EVP_PKEY_free(*retained); *retained=NULL; ok=0; }
        else key=NULL;
    }
    EC_KEY_free(key);
    return ok ? 0 : -1;
}
#endif

static int p256_generate_public(uint8_t pub[65], EVP_PKEY **retained) {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    int ok = 0;

    if (ctx == NULL) {
        return -1;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
        EVP_PKEY_generate(ctx, &key) == 1 &&
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, 65, NULL) == 1) {
        ok = 1;
    }

    if (ok && retained) { *retained=key; key=NULL; }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
#else
    return p256_generate_public_legacy(pub,retained);
#endif
}

static uint16_t random_grease_value(void) {
    static const uint16_t vals[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                                    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
    uint8_t b = 0;
    RAND_bytes(&b, 1);
    return vals[b % (sizeof(vals) / sizeof(vals[0]))];
}

static int add_ext(dynbuf_t *b, uint16_t etype, const uint8_t *edata, size_t elen) {
    uint8_t hdr[4] = {(uint8_t)(etype >> 8), (uint8_t)(etype & 0xFF), (uint8_t)(elen >> 8), (uint8_t)(elen & 0xFF)};
    if (db_append(b, hdr, 4) != 0) {
        return -1;
    }
    return db_append(b, edata, elen);
}

static int ext_server_name(dynbuf_t *exts, const char *sni) {
    if (tls_identity_is_ip(sni)) return 0;
    uint8_t data[512];
    size_t sni_len = strlen(sni);
    if (sni_len == 0 || sni_len > 255) {
        return -1;
    }

    size_t off = 0;
    size_t list_len = 1 + 2 + sni_len;
    data[off++] = (uint8_t)(list_len >> 8);
    data[off++] = (uint8_t)(list_len & 0xFF);
    data[off++] = 0x00;
    data[off++] = (uint8_t)(sni_len >> 8);
    data[off++] = (uint8_t)(sni_len & 0xFF);
    memcpy(data + off, sni, sni_len);
    off += sni_len;
    return add_ext(exts, 0x0000, data, off);
}

static int ext_supported_groups(dynbuf_t *exts, uint16_t grease, int random_mode, int hybrid) {
    uint8_t data[32];
    uint16_t groups[5];
    size_t gcount = 0;
    if (!random_mode) groups[gcount++] = grease;
    if (hybrid) groups[gcount++] = TLS_GROUP_X25519MLKEM768;
    groups[gcount++] = 0x001d;
    groups[gcount++] = 0x0017;
    if (!random_mode) groups[gcount++] = 0x0018;

    size_t off = 0;
    size_t glen = gcount * 2;
    data[off++] = (uint8_t)(glen >> 8);
    data[off++] = (uint8_t)(glen & 0xFF);
    for (size_t i = 0; i < gcount; i++) {
        data[off++] = (uint8_t)(groups[i] >> 8);
        data[off++] = (uint8_t)(groups[i] & 0xFF);
    }

    return add_ext(exts, 0x000a, data, off);
}

static int ext_supported_groups_firefox(dynbuf_t *exts, int hybrid) {
    uint16_t groups[] = {TLS_GROUP_X25519MLKEM768, 0x001d, 0x0017, 0x0018, 0x0019};
    uint8_t data[32];
    size_t off = 0;
    size_t start = hybrid ? 0 : 1;
    size_t glen = sizeof(groups) - start * sizeof(groups[0]);
    data[off++] = (uint8_t)(glen >> 8);
    data[off++] = (uint8_t)(glen & 0xFF);
    for (size_t i = start; i < sizeof(groups) / sizeof(groups[0]); i++) {
        data[off++] = (uint8_t)(groups[i] >> 8);
        data[off++] = (uint8_t)(groups[i] & 0xFF);
    }
    return add_ext(exts, 0x000a, data, off);
}

static int ext_ec_point_formats(dynbuf_t *exts) {
    uint8_t data[] = {0x01, 0x00};
    return add_ext(exts, 0x000b, data, sizeof(data));
}

static int ext_sig_algs(dynbuf_t *exts) {
    uint16_t sigs[] = {0x0403, 0x0804, 0x0503, 0x0805, 0x0806, 0x0807, 0x0601, 0x0501, 0x0401};
    uint8_t data[64];
    size_t off = 0;
    size_t slen = sizeof(sigs);
    data[off++] = (uint8_t)(slen >> 8);
    data[off++] = (uint8_t)(slen & 0xFF);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        data[off++] = (uint8_t)(sigs[i] >> 8);
        data[off++] = (uint8_t)(sigs[i] & 0xFF);
    }
    return add_ext(exts, 0x000d, data, off);
}

static int ext_sig_algs_qq(dynbuf_t *exts) {
    /* Matches uTLS HelloQQ_11_1 signature algorithm ordering. */
    uint16_t sigs[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0807, 0x0601};
    uint8_t data[64];
    size_t off = 0;
    size_t slen = sizeof(sigs);
    data[off++] = (uint8_t)(slen >> 8);
    data[off++] = (uint8_t)(slen & 0xFF);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        data[off++] = (uint8_t)(sigs[i] >> 8);
        data[off++] = (uint8_t)(sigs[i] & 0xFF);
    }
    return add_ext(exts, 0x000d, data, off);
}

static int ext_sig_algs_firefox(dynbuf_t *exts) {
    uint16_t sigs[] = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201};
    uint8_t data[64];
    size_t off = 0;
    size_t slen = sizeof(sigs);
    data[off++] = (uint8_t)(slen >> 8);
    data[off++] = (uint8_t)(slen & 0xFF);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        data[off++] = (uint8_t)(sigs[i] >> 8);
        data[off++] = (uint8_t)(sigs[i] & 0xFF);
    }
    return add_ext(exts, 0x000d, data, off);
}

static int ext_alpn(dynbuf_t *exts, int random_mode) {
    const char *p1 = random_mode ? "http/1.1" : "h2";
    const char *p2 = random_mode ? "h2" : "http/1.1";
    size_t l1 = strlen(p1);
    size_t l2 = strlen(p2);

    uint8_t data[64];
    size_t off = 0;
    size_t list_len = 1 + l1 + 1 + l2;
    data[off++] = (uint8_t)(list_len >> 8);
    data[off++] = (uint8_t)(list_len & 0xFF);
    data[off++] = (uint8_t)l1;
    memcpy(data + off, p1, l1);
    off += l1;
    data[off++] = (uint8_t)l2;
    memcpy(data + off, p2, l2);
    off += l2;

    return add_ext(exts, 0x0010, data, off);
}

static int ext_supported_versions(dynbuf_t *exts, uint16_t grease, int random_mode) {
    uint8_t data[8];
    size_t off = 0;
    if (random_mode) {
        data[off++] = 0x04;
        data[off++] = 0x03;
        data[off++] = 0x04;
        data[off++] = 0x03;
        data[off++] = 0x03;
    } else {
        data[off++] = 0x06;
        data[off++] = (uint8_t)(grease >> 8);
        data[off++] = (uint8_t)(grease & 0xFF);
        data[off++] = 0x03;
        data[off++] = 0x04;
        data[off++] = 0x03;
        data[off++] = 0x03;
    }
    return add_ext(exts, 0x002b, data, off);
}

static int ext_supported_versions_qq(dynbuf_t *exts, uint16_t grease) {
    uint8_t data[] = {0x0a, (uint8_t)(grease >> 8), (uint8_t)(grease & 0xFF), 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01};
    return add_ext(exts, 0x002b, data, sizeof(data));
}

static int ext_supported_versions_firefox(dynbuf_t *exts) {
    uint8_t data[] = {0x04, 0x03, 0x04, 0x03, 0x03};
    return add_ext(exts, 0x002b, data, sizeof(data));
}

static int ext_psk_modes(dynbuf_t *exts) {
    uint8_t data[] = {0x01, 0x01};
    return add_ext(exts, 0x002d, data, sizeof(data));
}

static size_t append_x25519_key_shares(uint8_t *data, size_t off, const uint8_t pubkey[32], const uint8_t *hybrid_pub) {
    if (hybrid_pub != NULL) {
        data[off++] = (uint8_t)(TLS_GROUP_X25519MLKEM768 >> 8);
        data[off++] = (uint8_t)TLS_GROUP_X25519MLKEM768;
        data[off++] = (uint8_t)(TLS_HYBRID_CLIENT_SHARE_SIZE >> 8);
        data[off++] = (uint8_t)TLS_HYBRID_CLIENT_SHARE_SIZE;
        memcpy(data + off, hybrid_pub, TLS_MLKEM768_PUBLIC_KEY_SIZE);
        off += TLS_MLKEM768_PUBLIC_KEY_SIZE;
        memcpy(data + off, pubkey, 32);
        off += 32;
    }

    data[off++] = 0x00;
    data[off++] = 0x1d;
    data[off++] = 0x00;
    data[off++] = 0x20;
    memcpy(data + off, pubkey, 32);
    off += 32;
    return off;
}

static int ext_key_share(dynbuf_t *exts, uint16_t grease, const uint8_t pubkey[32], int random_mode, const uint8_t *hybrid_pub) {
    uint8_t data[2 + 5 + 4 + TLS_HYBRID_CLIENT_SHARE_SIZE + 4 + 32];
    size_t off = 2;

    if (!random_mode) {
        data[off++] = (uint8_t)(grease >> 8);
        data[off++] = (uint8_t)(grease & 0xFF);
        data[off++] = 0x00;
        data[off++] = 0x01;
        data[off++] = 0x00;
    }
    off = append_x25519_key_shares(data, off, pubkey, hybrid_pub);

    size_t list_len = off - 2;
    data[0] = (uint8_t)(list_len >> 8);
    data[1] = (uint8_t)(list_len & 0xFF);

    return add_ext(exts, 0x0033, data, off);
}

static int ext_key_share_firefox(dynbuf_t *exts, const uint8_t x25519_pub[32], const uint8_t *hybrid_pub, EVP_PKEY **retained) {
    uint8_t p256_pub[65];
    if (p256_generate_public(p256_pub,retained) != 0) {
        return -1;
    }

    uint8_t data[2 + 4 + TLS_HYBRID_CLIENT_SHARE_SIZE + 4 + 32 + 4 + 65];
    size_t off = append_x25519_key_shares(data, 2, x25519_pub, hybrid_pub);

    data[off++] = 0x00;
    data[off++] = 0x17;
    data[off++] = 0x00;
    data[off++] = 0x41;
    memcpy(data + off, p256_pub, sizeof(p256_pub));
    off += sizeof(p256_pub);

    size_t list_len = off - 2;
    data[0] = (uint8_t)(list_len >> 8);
    data[1] = (uint8_t)(list_len & 0xFF);
    return add_ext(exts, 0x0033, data, off);
}

static int ext_padding(dynbuf_t *exts, size_t pad_len) {
    uint8_t *z = (uint8_t *)calloc(1, pad_len);
    if (z == NULL) {
        return -1;
    }
    int rc = add_ext(exts, 0x0015, z, pad_len);
    free(z);
    return rc;
}

static int ext_grease(dynbuf_t *exts, uint16_t grease) {
    return add_ext(exts, grease, NULL, 0);
}

static int ext_grease_1byte_zero(dynbuf_t *exts, uint16_t grease) {
    uint8_t zero = 0;
    return add_ext(exts, grease, &zero, 1);
}

static int ext_extended_master_secret(dynbuf_t *exts) {
    return add_ext(exts, 0x0017, NULL, 0);
}

static int ext_renegotiation_info(dynbuf_t *exts) {
    uint8_t data[] = {0x00};
    return add_ext(exts, 0xff01, data, sizeof(data));
}

static int ext_session_ticket(dynbuf_t *exts) {
    return add_ext(exts, 0x0023, NULL, 0);
}

static int ext_status_request(dynbuf_t *exts) {
    /* status_type=ocsp, empty responder_id_list and request_extensions */
    uint8_t data[] = {0x01, 0x00, 0x00, 0x00, 0x00};
    return add_ext(exts, 0x0005, data, sizeof(data));
}

static int ext_sct(dynbuf_t *exts) {
    return add_ext(exts, 0x0012, NULL, 0);
}

static int ext_record_size_limit_firefox(dynbuf_t *exts) {
    uint8_t data[] = {0x40, 0x01};
    return add_ext(exts, 0x001c, data, sizeof(data));
}

static int ext_ech_grease_firefox(dynbuf_t *exts) {
    enum { ECH_PAYLOAD_LEN = 239 };
    uint8_t data[1 + 2 + 2 + 1 + 2 + 32 + 2 + ECH_PAYLOAD_LEN];
    size_t off = 0;

    data[off++] = 0x00;
    data[off++] = 0x00;
    data[off++] = 0x01;
    data[off++] = 0x00;
    data[off++] = 0x01;
    if (RAND_bytes(data + off, 1) != 1) {
        return -1;
    }
    off += 1;
    data[off++] = 0x00;
    data[off++] = 0x20;
    if (RAND_bytes(data + off, 32) != 1) {
        return -1;
    }
    off += 32;
    data[off++] = (uint8_t)(ECH_PAYLOAD_LEN >> 8);
    data[off++] = (uint8_t)(ECH_PAYLOAD_LEN & 0xFF);
    if (RAND_bytes(data + off, ECH_PAYLOAD_LEN) != 1) {
        return -1;
    }
    off += ECH_PAYLOAD_LEN;

    return add_ext(exts, 0xfe0d, data, off);
}

static int ext_application_settings_h2(dynbuf_t *exts) {
    /* ALPS (0x4469): protocol_name_list with single entry "h2". */
    uint8_t data[] = {0x00, 0x03, 0x02, 'h', '2'};
    return add_ext(exts, 0x4469, data, sizeof(data));
}

static size_t boring_padding_len(size_t unpadded_client_hello_len) {
    if (unpadded_client_hello_len > 0xff && unpadded_client_hello_len < 0x200) {
        size_t pad_len = 0x200 - unpadded_client_hello_len;
        if (pad_len >= 5) {
            pad_len -= 4;
        } else {
            pad_len = 1;
        }
        return pad_len;
    }
    return 0;
}

static int shuffle_indices(size_t *idx, size_t n) {
    for (size_t i = 0; i < n; i++) {
        idx[i] = i;
    }
    for (size_t i = n; i > 1; i--) {
        uint8_t r = 0;
        RAND_bytes(&r, 1);
        size_t j = r % i;
        size_t tmp = idx[i - 1];
        idx[i - 1] = idx[j];
        idx[j] = tmp;
    }
    return 0;
}

static int build_client_hello(const vless_config_t *cfg, int use_reality, tls_cipher_offer_t cipher_offer, uint8_t client_priv[32],
                              uint8_t client_pub[32], uint8_t client_random[32], uint8_t auth_key[32], uint8_t **out, size_t *out_len,
                              size_t *sid_pos, const uint8_t *hybrid_pub, EVP_PKEY **retained) {
    dynbuf_t hs = {0};

    if (x25519_generate(client_priv, client_pub) != 0) {
        return -1;
    }
    if (RAND_bytes(client_random, 32) != 1) {
        return -1;
    }

    uint8_t head4[4] = {0x01, 0x00, 0x00, 0x00};
    if (db_append(&hs, head4, 4) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t legacy_ver[] = {0x03, 0x03};
    if (db_append(&hs, legacy_ver, sizeof(legacy_ver)) != 0 || db_append(&hs, client_random, 32) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t sid_len = 32;
    if (db_append(&hs, &sid_len, 1) != 0) {
        db_free(&hs);
        return -1;
    }

    *sid_pos = hs.len;
    uint8_t session_id[32] = {0};
    if (!use_reality && RAND_bytes(session_id, sizeof(session_id)) != 1) {
        db_free(&hs);
        return -1;
    }
    if (db_append(&hs, session_id, sizeof(session_id)) != 0) {
        db_free(&hs);
        return -1;
    }

    uint16_t grease = random_grease_value();
    uint16_t boring_grease_cipher = random_grease_value();
    uint16_t boring_grease_group = random_grease_value();
    while (boring_grease_group == boring_grease_cipher) {
        boring_grease_group = random_grease_value();
    }
    uint16_t boring_grease_vers = random_grease_value();
    while (boring_grease_vers == boring_grease_cipher || boring_grease_vers == boring_grease_group) {
        boring_grease_vers = random_grease_value();
    }
    uint16_t boring_grease_ext1 = boring_grease_cipher;
    uint16_t boring_grease_ext2 = boring_grease_vers;
    uint8_t suites[64];
    size_t soff = 0;
    if (cfg->fp_mode == FP_QQ || cfg->fp_mode == FP_CHROME || cfg->fp_mode == FP_EDGE) {
        suites[soff++] = (uint8_t)(boring_grease_cipher >> 8);
        suites[soff++] = (uint8_t)(boring_grease_cipher & 0xFF);
    }
    if (cipher_offer == TLS_CIPHER_OFFER_CHACHA) {
        suites[soff++] = 0x13;
        suites[soff++] = 0x03;
    } else {
        suites[soff++] = 0x13;
        suites[soff++] = 0x01;
        suites[soff++] = 0x13;
        suites[soff++] = 0x02;
    }

    uint8_t slen[2] = {(uint8_t)(soff >> 8), (uint8_t)(soff & 0xFF)};
    if (db_append(&hs, slen, 2) != 0 || db_append(&hs, suites, soff) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t comp[] = {0x01, 0x00};
    if (db_append(&hs, comp, sizeof(comp)) != 0) {
        db_free(&hs);
        return -1;
    }

    dynbuf_t exts = {0};

    if (cfg->fp_mode == FP_QQ) {
        size_t header_len = hs.len - 4;
        if (ext_grease(&exts, boring_grease_ext1) != 0 || ext_server_name(&exts, cfg->sni) != 0 ||
            ext_extended_master_secret(&exts) != 0 || ext_renegotiation_info(&exts) != 0 ||
            ext_supported_groups(&exts, boring_grease_group, 0, hybrid_pub != NULL) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_status_request(&exts) != 0 ||
            ext_sig_algs_qq(&exts) != 0 || ext_sct(&exts) != 0 || ext_key_share(&exts, boring_grease_group, client_pub, 0, hybrid_pub) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_supported_versions_qq(&exts, boring_grease_vers) != 0 ||
            ext_application_settings_h2(&exts) != 0 ||
            ext_grease_1byte_zero(&exts, boring_grease_ext2) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
        size_t unpadded_len = header_len + 4 + exts.len + 2;
        size_t pad_len = boring_padding_len(unpadded_len);
        if (pad_len > 0 && ext_padding(&exts, pad_len) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
    } else if (cfg->fp_mode == FP_CHROME || cfg->fp_mode == FP_EDGE) {
        size_t header_len = hs.len - 4;
        if (ext_grease(&exts, boring_grease_ext1) != 0 || ext_server_name(&exts, cfg->sni) != 0 ||
            ext_extended_master_secret(&exts) != 0 || ext_renegotiation_info(&exts) != 0 ||
            ext_supported_groups(&exts, boring_grease_group, 0, hybrid_pub != NULL) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_status_request(&exts) != 0 ||
            ext_sig_algs_qq(&exts) != 0 || ext_sct(&exts) != 0 || ext_key_share(&exts, boring_grease_group, client_pub, 0, hybrid_pub) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_supported_versions_qq(&exts, boring_grease_vers) != 0 ||
            ext_grease_1byte_zero(&exts, boring_grease_ext2) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
        size_t unpadded_len = header_len + 4 + exts.len + 2;
        size_t pad_len = boring_padding_len(unpadded_len);
        if (pad_len > 0 && ext_padding(&exts, pad_len) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
    } else if (cfg->fp_mode == FP_FIREFOX) {
        if (ext_server_name(&exts, cfg->sni) != 0 || ext_extended_master_secret(&exts) != 0 ||
            ext_renegotiation_info(&exts) != 0 || ext_supported_groups_firefox(&exts, hybrid_pub != NULL) != 0 ||
            ext_ec_point_formats(&exts) != 0 || ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 ||
            ext_status_request(&exts) != 0 ||
            ext_key_share_firefox(&exts, client_pub, hybrid_pub,retained) != 0 || ext_supported_versions_firefox(&exts) != 0 ||
            ext_sig_algs_firefox(&exts) != 0 || ext_psk_modes(&exts) != 0 || ext_record_size_limit_firefox(&exts) != 0 ||
            ext_ech_grease_firefox(&exts) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
    } else {
        enum { EX_SNI, EX_GROUPS, EX_SIGS, EX_ALPN, EX_VERS, EX_PSK, EX_KEYSHARE, EX_ECPF, EX_COUNT };
        size_t order[EX_COUNT];
        shuffle_indices(order, EX_COUNT);
        for (size_t i = 0; i < EX_COUNT; i++) {
            switch (order[i]) {
                case EX_SNI:
                    if (ext_server_name(&exts, cfg->sni) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_GROUPS:
                    if (ext_supported_groups(&exts, grease, 1, 0) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_SIGS:
                    if (ext_sig_algs(&exts) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_ALPN:
                    if (ext_alpn(&exts, 1) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_VERS:
                    if (ext_supported_versions(&exts, grease, 1) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_PSK:
                    if (ext_psk_modes(&exts) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_KEYSHARE:
                    if (ext_key_share(&exts, grease, client_pub, 1, NULL) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_ECPF:
                    if (ext_ec_point_formats(&exts) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    if (cfg->alpn[0]) {
        dynbuf_t replaced={0}; unsigned char protocols[128]; unsigned int protocol_length=0;
        if (build_xhttp_tls_alpn(cfg->alpn,protocols,sizeof(protocols),&protocol_length) != 0) { db_free(&exts); db_free(&hs); return -1; }
        for (size_t offset=0;offset+4 <= exts.len;) {
            unsigned type=((unsigned)exts.data[offset]<<8)|exts.data[offset+1];
            size_t count=4+((size_t)exts.data[offset+2]<<8)+exts.data[offset+3];
            if (count > exts.len-offset) { db_free(&replaced); db_free(&exts); db_free(&hs); return -1; }
            int result;
            if (type == 16) {
                uint8_t value[130]={(uint8_t)(protocol_length>>8),(uint8_t)protocol_length};
                memcpy(value+2,protocols,protocol_length); result=add_ext(&replaced,16,value,protocol_length+2);
            } else result=db_append(&replaced,exts.data+offset,count);
            if (result) { db_free(&replaced); db_free(&exts); db_free(&hs); return -1; }
            offset+=count;
        }
        db_free(&exts); exts=replaced;
    }
    uint8_t elen[2] = {(uint8_t)(exts.len >> 8), (uint8_t)(exts.len & 0xFF)};
    if (db_append(&hs, elen, 2) != 0 || db_append(&hs, exts.data, exts.len) != 0) {
        db_free(&exts);
        db_free(&hs);
        return -1;
    }
    db_free(&exts);

    size_t body_len = hs.len - 4;
    hs.data[1] = (uint8_t)((body_len >> 16) & 0xFF);
    hs.data[2] = (uint8_t)((body_len >> 8) & 0xFF);
    hs.data[3] = (uint8_t)(body_len & 0xFF);

    if (!use_reality) {
        *out = hs.data;
        *out_len = hs.len;
        return 0;
    }

    uint8_t sid_plain[16] = {0};
    sid_plain[0] = g_xray_version[0];
    sid_plain[1] = g_xray_version[1];
    sid_plain[2] = g_xray_version[2];
    sid_plain[3] = 0;

    uint32_t now = (uint32_t)time(NULL);
    sid_plain[4] = (uint8_t)(now >> 24);
    sid_plain[5] = (uint8_t)(now >> 16);
    sid_plain[6] = (uint8_t)(now >> 8);
    sid_plain[7] = (uint8_t)(now & 0xFF);

    if (cfg->short_id_len > 0) {
        size_t n = cfg->short_id_len;
        if (n > 8) {
            n = 8;
        }
        memcpy(sid_plain + 8, cfg->short_id, n);
    }

    uint8_t shared[32];
    if (x25519_shared(client_priv, cfg->pbk, shared) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t prk[32];
    if (hkdf_extract_md(EVP_sha256(), client_random, 20, shared, 32, prk, sizeof(prk)) != 0 ||
        hkdf_expand_md(EVP_sha256(), prk, sizeof(prk), (const uint8_t *)"REALITY", 7, auth_key, 32) != 0) {
        db_free(&hs);
        return -1;
    }

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    if (ectx == NULL) {
        db_free(&hs);
        return -1;
    }

    uint8_t ct[16];
    uint8_t tag[16];
    int outl = 0;
    int ok = EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_EncryptInit_ex(ectx, NULL, NULL, auth_key, client_random + 20) == 1 &&
             EVP_EncryptUpdate(ectx, NULL, &outl, hs.data, (int)hs.len) == 1 &&
             EVP_EncryptUpdate(ectx, ct, &outl, sid_plain, sizeof(sid_plain)) == 1;

    int finl = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ectx, ct + outl, &finl) == 1 &&
             EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    }
    EVP_CIPHER_CTX_free(ectx);

    if (!ok) {
        db_free(&hs);
        return -1;
    }

    memcpy(hs.data + *sid_pos, ct, 16);
    memcpy(hs.data + *sid_pos + 16, tag, 16);

    *out = hs.data;
    *out_len = hs.len;
    return 0;
}

static int read_record(int fd, uint8_t *rtype, uint8_t **payload, size_t *payload_len) {
    uint8_t hdr[5];
    size_t off = 0;
    while (off < sizeof(hdr)) {
        ssize_t count = core_recv(fd, hdr + off, sizeof(hdr) - off, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count == 0 && off == 0) return 1;
        if (count <= 0) {
            if (count == 0) errno = EPROTO;
            return -1;
        }
        off += (size_t)count;
    }

    size_t len = ((size_t)hdr[3] << 8) | hdr[4];
    if (hdr[1] != 3 || (hdr[2] != 3 && !(hdr[0] == 22 && hdr[2] == 1)) ||
        len > (hdr[0] == 23 ? 16640U : 16384U)) { errno=EMSGSIZE; return -1; }
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (buf == NULL) {
        return -1;
    }
    if (read_exact(fd, buf, len) != 0) {
        free(buf);
        return -1;
    }

    *rtype = hdr[0];
    *payload = buf;
    *payload_len = len;
    return 0;
}

static int configure_tls_cipher(tls13_conn_t *c, uint16_t suite) {
    c->tls_cipher_suite = suite;
    if (suite == 0x1301) {
        c->tls_md = EVP_sha256();
        c->tls_hash_len = 32;
        c->tls_key_len = 16;
        return 0;
    }
    if (suite == 0x1302) {
        c->tls_md = EVP_sha384();
        c->tls_hash_len = 48;
        c->tls_key_len = 32;
        return 0;
    }
    if (suite == 0x1303) {
        c->tls_md = EVP_sha256();
        c->tls_hash_len = 32;
        c->tls_key_len = 32;
        return 0;
    }
    return -1;
}

static int parse_server_hello_for_keyshare(const uint8_t *msg, size_t msg_len, uint16_t *cipher_out,
                                         uint8_t server_share[TLS_HYBRID_SERVER_SHARE_SIZE], size_t *share_len) {
    if (msg_len < 4 || msg[0] != 0x02) {
        return -1;
    }
    size_t body_len = ((size_t)msg[1] << 16) | ((size_t)msg[2] << 8) | msg[3];
    if (4 + body_len > msg_len) {
        return -1;
    }

    const uint8_t *p = msg + 4;
    size_t n = body_len;

    if (n < 2 + 32 + 1) {
        return -1;
    }
    p += 2;
    n -= 2;
    p += 32;
    n -= 32;

    uint8_t sid_len = *p++;
    n -= 1;
    if (n < (size_t)sid_len + 2 + 1 + 2) {
        return -1;
    }
    p += sid_len;
    n -= sid_len;

    uint16_t cipher = ((uint16_t)p[0] << 8) | p[1];
    p += 2;
    n -= 2;

    if (cipher != 0x1301 && cipher != 0x1302 && cipher != 0x1303) {
        return -1;
    }
    if (cipher_out != NULL) {
        *cipher_out = cipher;
    }

    p += 1;
    n -= 1;

    uint16_t ext_len = ((uint16_t)p[0] << 8) | p[1];
    p += 2;
    n -= 2;
    if (n < ext_len) {
        return -1;
    }

    size_t eoff = 0;
    while (eoff + 4 <= ext_len) {
        uint16_t et = ((uint16_t)p[eoff] << 8) | p[eoff + 1];
        uint16_t el = ((uint16_t)p[eoff + 2] << 8) | p[eoff + 3];
        eoff += 4;
        if (eoff + el > ext_len) {
            return -1;
        }

        if (et == 0x0033) {
            if (el < 4) {
                return -1;
            }
            const uint8_t *k = p + eoff;
            uint16_t group = ((uint16_t)k[0] << 8) | k[1];
            uint16_t klen = ((uint16_t)k[2] << 8) | k[3];
            if (!((group == 0x001d && klen == 32) || (group == 23 && klen == 65) || (group == 24 && klen == 97) || (group == 25 && klen == 133) ||
                  (group == TLS_GROUP_X25519MLKEM768 && klen == TLS_HYBRID_SERVER_SHARE_SIZE)) || el != 4 + klen) {
                return -1;
            }
            memcpy(server_share, k + 4, klen);
            *share_len = klen;
            return 0;
        }

        eoff += el;
    }

    return -1;
}

static int transcript_hash(const tls13_conn_t *c, uint8_t *out) {
    return digest_hash(c->tls_md, c->transcript.data, c->transcript.len, out, c->tls_hash_len);
}

static int parse_first_cert_der(const uint8_t *message, size_t length, const uint8_t **der, size_t *der_length) {
    if (!message || !der || !der_length || length < 8 || message[0] != 11 || message[4] ||
        (((size_t)message[1]<<16)|((size_t)message[2]<<8)|message[3]) != length-4 ||
        (((size_t)message[5]<<16)|((size_t)message[6]<<8)|message[7]) != length-8) return -1;
    *der=NULL; *der_length=0;
    for (size_t offset=8;offset < length;) {
        if (length-offset < 3) return -1;
        size_t size=((size_t)message[offset]<<16)|((size_t)message[offset+1]<<8)|message[offset+2]; offset+=3;
        if (!size || size > length-offset) return -1;
        if (!*der) { *der=message+offset; *der_length=size; }
        offset+=size;
        if (length-offset < 2) return -1;
        size_t extensions=((size_t)message[offset]<<8)|message[offset+1]; offset+=2;
        if (extensions > length-offset) return -1;
        size_t end=offset+extensions,count=0; unsigned seen[256];
        while (offset < end) {
            if (end-offset < 4 || count == sizeof(seen)/sizeof(seen[0])) return -1;
            unsigned type=((unsigned)message[offset]<<8)|message[offset+1];
            size_t entry=((size_t)message[offset+2]<<8)|message[offset+3]; offset+=4;
            if (entry > end-offset) return -1;
            for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
            seen[count++]=type; offset+=entry;
        }
    }
    return *der ? 0 : -1;
}

static int tls_cert_der_pin_hex(const uint8_t *der, size_t der_len, char pin_hex[65], char *err, size_t err_cap) {
    if (der == NULL || der_len == 0) {
        set_err(err, err_cap, "missing TLS leaf certificate");
        return -1;
    }

    if (sha256_hex(der, der_len, pin_hex) != 0) {
        set_err(err, err_cap, "failed to hash TLS leaf certificate");
        return -1;
    }

    return 0;
}

static int tls_cert_message_leaf_pin_hex(const uint8_t *cert_msg, size_t cert_msg_len, char pin_hex[65], char *err, size_t err_cap) {
    const uint8_t *der = NULL;
    size_t der_len = 0;
    if (parse_first_cert_der(cert_msg, cert_msg_len, &der, &der_len) != 0) {
        set_err(err, err_cap, "failed to parse TLS leaf certificate");
        return -1;
    }
    return tls_cert_der_pin_hex(der, der_len, pin_hex, err, err_cap);
}

static int tcp_tls_tofu_verify_or_store(const vless_config_t *cfg, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap) {
    char pin_key[320];
    const char *pin_host = cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host;
    if (xhttp_make_pin_key(pin_host, cfg->server_port, pin_key, sizeof(pin_key)) != 0) {
        set_err(err, err_cap, "failed to build TOFU pin key");
        return -1;
    }

    char peer_pin[65];
    if (tls_cert_message_leaf_pin_hex(cert_msg, cert_msg_len, peer_pin, err, err_cap) != 0) {
        return -1;
    }

    return tofu_verify_or_store_pin("tls", pin_key, peer_pin, 1, err, err_cap);
}

static int verify_reality_cert(const uint8_t auth_key[32], const uint8_t *cert_der, size_t cert_der_len) {
    const unsigned char *p = cert_der;
    X509 *x = d2i_X509(NULL, &p, (long)cert_der_len);
    if (x == NULL) {
        return -1;
    }

    EVP_PKEY *pk = X509_get_pubkey(x);
    int pk_base = (pk != NULL) ? EVP_PKEY_base_id(pk) : 0;
    if (pk == NULL || pk_base != EVP_PKEY_ED25519) {
        if (pk != NULL) {
            EVP_PKEY_free(pk);
        }
        X509_free(x);
        return -1;
    }

    uint8_t pub[32];
    size_t pub_len = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(pk, pub, &pub_len) != 1 || pub_len != 32) {
        EVP_PKEY_free(pk);
        X509_free(x);
        return -1;
    }

    uint8_t h[64];
    if (hmac_sha512(auth_key, 32, pub, sizeof(pub), h) != 0) {
        EVP_PKEY_free(pk);
        X509_free(x);
        return -1;
    }

    const ASN1_BIT_STRING *sig = NULL;
    const X509_ALGOR *alg = NULL;
    X509_get0_signature(&sig, &alg, x);

    int ok = (sig != NULL && sig->length == 64 && memcmp(sig->data, h, 64) == 0) ? 0 : -1;

    EVP_PKEY_free(pk);
    X509_free(x);
    return ok;
}

static int load_x509_store_paths(X509_STORE *store) {
    int default_paths_ready = (X509_STORE_set_default_paths(store) == 1) ? 1 : 0;
    int custom_ca_loaded = 0;
    const char *debug = getenv("VLESS_TLS_DEBUG");

    const char *env_ca = getenv("VLESS_CA_BUNDLE");
    const char *ca_paths[] = {
        env_ca,
        "/usr/share/vless-core/cacert.pem",
        "/Applications/vless-core.app/cacert.pem",
        "third_party/cacert.pem",
    };
    for (size_t i = 0; i < sizeof(ca_paths) / sizeof(ca_paths[0]); i++) {
        if (ca_paths[i] == NULL || ca_paths[i][0] == '\0') {
            continue;
        }
        if (X509_STORE_load_locations(store, ca_paths[i], NULL) == 1) {
            custom_ca_loaded = 1;
            if (debug != NULL && debug[0] != '\0') {
                vc_log_debug("tls", "loaded CA bundle: %s", ca_paths[i]);
            }
            break;
        } else if (debug != NULL && debug[0] != '\0') {
            vc_log_debug("tls", "failed to load CA bundle: %s", ca_paths[i]);
        }
    }

    if (debug != NULL && debug[0] != '\0') {
        vc_log_debug("tls", "default CA paths ready=%d custom_ca_loaded=%d",
                     default_paths_ready, custom_ca_loaded);
    }
    return (custom_ca_loaded || default_paths_ready) ? 0 : -1;
}

static int verify_tls_cert_message(const char *servername, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap) {
    const uint8_t *first=NULL; size_t first_length=0;
    if (parse_first_cert_der(cert_msg,cert_msg_len,&first,&first_length)) { set_err(err,err_cap,"invalid TLS Certificate structure"); return -1; }
    X509 *leaf = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int rc = -1;
    int cert_count = 0;
    const char *debug = getenv("VLESS_TLS_DEBUG");

    if (cert_msg_len < 4 || cert_msg[0] != 0x0b) {
        set_err(err, err_cap, "invalid TLS certificate message");
        return -1;
    }
    size_t body_len = ((size_t)cert_msg[1] << 16) | ((size_t)cert_msg[2] << 8) | cert_msg[3];
    if (4 + body_len > cert_msg_len) {
        set_err(err, err_cap, "truncated TLS certificate message");
        return -1;
    }

    const uint8_t *p = cert_msg + 4;
    const uint8_t *end_body = p + body_len;
    if (p >= end_body) {
        set_err(err, err_cap, "empty TLS certificate message");
        return -1;
    }

    uint8_t req_ctx_len = *p++;
    if ((size_t)(end_body - p) < (size_t)req_ctx_len + 3) {
        set_err(err, err_cap, "invalid TLS certificate request context");
        return -1;
    }
    p += req_ctx_len;

    size_t list_len = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
    p += 3;
    if ((size_t)(end_body - p) < list_len) {
        set_err(err, err_cap, "truncated TLS certificate list");
        return -1;
    }

    const uint8_t *end_list = p + list_len;
    untrusted = sk_X509_new_null();
    if (untrusted == NULL) {
        set_err(err, err_cap, "failed to allocate TLS certificate stack");
        goto out;
    }

    while (p < end_list) {
        if ((size_t)(end_list - p) < 3) {
            set_err(err, err_cap, "invalid TLS certificate entry");
            goto out;
        }
        size_t der_len = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
        p += 3;
        if (der_len == 0 || (size_t)(end_list - p) < der_len) {
            set_err(err, err_cap, "truncated TLS certificate entry");
            goto out;
        }

        const unsigned char *der = p;
        X509 *cert = d2i_X509(NULL, &der, (long)der_len);
        if (cert == NULL) {
            set_err(err, err_cap, "failed to parse TLS certificate");
            goto out;
        }
        if (leaf == NULL) {
            leaf = cert;
        } else if (sk_X509_push(untrusted, cert) == 0) {
            X509_free(cert);
            set_err(err, err_cap, "failed to store TLS certificate chain");
            goto out;
        }
        cert_count++;
        p += der_len;

        if ((size_t)(end_list - p) < 2) {
            set_err(err, err_cap, "invalid TLS certificate extensions");
            goto out;
        }
        size_t ext_len = ((size_t)p[0] << 8) | p[1];
        p += 2;
        if ((size_t)(end_list - p) < ext_len) {
            set_err(err, err_cap, "truncated TLS certificate extensions");
            goto out;
        }
        p += ext_len;
    }

    if (leaf == NULL) {
        set_err(err, err_cap, "missing TLS leaf certificate");
        goto out;
    }

    if (debug != NULL && debug[0] != '\0') {
        char subject[256];
        char issuer[256];
        X509_NAME_oneline(X509_get_subject_name(leaf), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(leaf), issuer, sizeof(issuer));
        vc_log_debug("tls", "cert chain entries=%d untrusted=%d", cert_count, sk_X509_num(untrusted));
        vc_log_debug("tls", "leaf subject=%s", subject);
        vc_log_debug("tls", "leaf issuer=%s", issuer);
    }

    const char *host = (servername != NULL && servername[0] != '\0') ? servername : NULL;
    if (host == NULL) {
        set_err(err, err_cap, "TLS certificate hostname mismatch");
        goto out;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        set_err(err, err_cap, "failed to allocate TLS certificate store");
        goto out;
    }
    (void)X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST);
    if (load_x509_store_paths(store) != 0) {
        set_err(err, err_cap, "no trusted CA bundle found (set VLESS_CA_BUNDLE or install /usr/share/vless-core/cacert.pem)");
        goto out;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL || X509_STORE_CTX_init(ctx, store, leaf, untrusted) != 1 ||
        X509_STORE_CTX_set_default(ctx,"ssl_server") != 1 ||
        tls_identity_parameters(X509_STORE_CTX_get0_param(ctx),host) != 0) {
        set_err(err, err_cap, "failed to initialize TLS certificate verification");
        goto out;
    }

    if (X509_verify_cert(ctx) != 1) {
        int verify_rc = X509_STORE_CTX_get_error(ctx);
        int verify_depth = X509_STORE_CTX_get_error_depth(ctx);
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "TLS certificate verify failed: %s", X509_verify_cert_error_string(verify_rc));
        }
        if (debug != NULL && debug[0] != '\0') {
            vc_log_error("tls", "cert verify failed depth=%d: %s",
                         verify_depth, X509_verify_cert_error_string(verify_rc));
        }
        goto out;
    }

    rc = 0;

out:
    if (ctx != NULL) {
        X509_STORE_CTX_free(ctx);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    if (leaf != NULL) {
        X509_free(leaf);
    }
    if (untrusted != NULL) {
        sk_X509_pop_free(untrusted, X509_free);
    }
    return rc;
}

static int calc_finished_verify(const tls13_conn_t *c, const uint8_t *traffic_secret, const uint8_t *transcript_hash_val, uint8_t *out) {
    uint8_t finished_key[64];
    uint8_t zero_ctx[1] = {0};
    if (hkdf_expand_label_md(c->tls_md, traffic_secret, c->tls_hash_len, "finished", zero_ctx, 0, finished_key, c->tls_hash_len) != 0) {
        OPENSSL_cleanse(finished_key,sizeof(finished_key)); return -1;
    }
    int result=hmac_digest(c->tls_md,finished_key,c->tls_hash_len,transcript_hash_val,c->tls_hash_len,out,c->tls_hash_len);
    OPENSSL_cleanse(finished_key,sizeof(finished_key)); return result;
}

static int derive_handshake_keys(tls13_conn_t *c, const uint8_t *shared, size_t shared_len) {
    int result=-1;
    uint8_t zero[64] = {0};
    uint8_t empty_hash[64];
    uint8_t early_secret[64];
    uint8_t derived[64];
    uint8_t thash[64];

    if (digest_hash(c->tls_md, NULL, 0, empty_hash, c->tls_hash_len) != 0) {
        goto cleanup;
    }

    if (hkdf_extract_md(c->tls_md, zero, c->tls_hash_len, zero, c->tls_hash_len, early_secret, c->tls_hash_len) != 0) {
        goto cleanup;
    }
    if (derive_secret_md(c->tls_md, early_secret, c->tls_hash_len, "derived", empty_hash, c->tls_hash_len, derived, c->tls_hash_len) != 0) {
        goto cleanup;
    }
    if (hkdf_extract_md(c->tls_md, derived, c->tls_hash_len, shared, shared_len, c->hs_secret, c->tls_hash_len) != 0) {
        goto cleanup;
    }
    if (transcript_hash(c, thash) != 0) {
        goto cleanup;
    }

    if (derive_secret_md(c->tls_md, c->hs_secret, c->tls_hash_len, "c hs traffic", thash, c->tls_hash_len, c->c_hs_traffic, c->tls_hash_len) != 0 ||
        derive_secret_md(c->tls_md, c->hs_secret, c->tls_hash_len, "s hs traffic", thash, c->tls_hash_len, c->s_hs_traffic, c->tls_hash_len) != 0) {
        goto cleanup;
    }

    if (derive_key_iv_md(c->tls_md, c->c_hs_traffic, c->tls_hash_len, c->tls_key_len, c->c_hs_key, c->c_hs_iv) != 0 ||
        derive_key_iv_md(c->tls_md, c->s_hs_traffic, c->tls_hash_len, c->tls_key_len, c->s_hs_key, c->s_hs_iv) != 0) {
        goto cleanup;
    }

    c->c_hs_seq = 0;
    c->s_hs_seq = 0;
    result=0;
cleanup:
    OPENSSL_cleanse(early_secret,sizeof(early_secret));
    OPENSSL_cleanse(derived,sizeof(derived));
    return result;
}

static int derive_app_keys(tls13_conn_t *c) {
    int result=-1;
    uint8_t zero[64] = {0};
    uint8_t empty_hash[64];
    uint8_t derived2[64];
    uint8_t master_secret[64];
    uint8_t thash[64];

    if (digest_hash(c->tls_md, NULL, 0, empty_hash, c->tls_hash_len) != 0) {
        goto cleanup;
    }

    if (derive_secret_md(c->tls_md, c->hs_secret, c->tls_hash_len, "derived", empty_hash, c->tls_hash_len, derived2, c->tls_hash_len) != 0) {
        goto cleanup;
    }
    if (hkdf_extract_md(c->tls_md, derived2, c->tls_hash_len, zero, c->tls_hash_len, master_secret, c->tls_hash_len) != 0) {
        goto cleanup;
    }

    if (transcript_hash(c, thash) != 0) {
        goto cleanup;
    }

    if (derive_secret_md(c->tls_md, master_secret, c->tls_hash_len, "c ap traffic", thash, c->tls_hash_len, c->c_app_traffic, c->tls_hash_len) != 0 ||
        derive_secret_md(c->tls_md, master_secret, c->tls_hash_len, "s ap traffic", thash, c->tls_hash_len, c->s_app_traffic, c->tls_hash_len) != 0) {
        goto cleanup;
    }

    if (derive_key_iv_md(c->tls_md, c->c_app_traffic, c->tls_hash_len, c->tls_key_len, c->c_app_key, c->c_app_iv) != 0 ||
        derive_key_iv_md(c->tls_md, c->s_app_traffic, c->tls_hash_len, c->tls_key_len, c->s_app_key, c->s_app_iv) != 0) {
        goto cleanup;
    }

    c->c_app_seq = 0;
    c->s_app_seq = 0;
    c->c_app_record_bytes = 0;
    result=0;
cleanup:
    OPENSSL_cleanse(master_secret,sizeof(master_secret));
    OPENSSL_cleanse(derived2,sizeof(derived2));
    return result;
}

static const EVP_CIPHER *record_cipher_for_conn(const tls13_conn_t *c) {
    if (c->tls_cipher_suite == 0x1301 && c->tls_key_len == 16) {
        return EVP_aes_128_gcm();
    }
    if (c->tls_cipher_suite == 0x1302 && c->tls_key_len == 32) {
        return EVP_aes_256_gcm();
    }
    if (c->tls_cipher_suite == 0x1303 && c->tls_key_len == 32) {
        return EVP_chacha20_poly1305();
    }
    return NULL;
}

static int encrypt_record(const tls13_conn_t *c, const uint8_t *key, const uint8_t iv[12], uint64_t *seq, uint8_t inner_type, const uint8_t *plain,
                          size_t plain_len, uint8_t **out, size_t *out_len) {
    *out=NULL; *out_len=0;
    if (plain_len > 16384 || *seq >= TLS_RECORD_HARD_LIMIT ||
        (c->tls_send_record_limit && plain_len+1 > c->tls_send_record_limit) ||
        (inner_type != 21 && inner_type != 22 && inner_type != 23)) { errno=EMSGSIZE; return -1; }
    size_t inner_len = plain_len + 1;
    uint8_t *inner = (uint8_t *)malloc(inner_len);
    if (inner == NULL) {
        return -1;
    }
    memcpy(inner, plain, plain_len);
    inner[plain_len] = inner_type;

    size_t c_len = inner_len + 16;
    uint8_t *record = (uint8_t *)malloc(5 + c_len);
    if (record == NULL) {
        free(inner);
        return -1;
    }

    record[0] = 0x17;
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = (uint8_t)(c_len >> 8);
    record[4] = (uint8_t)(c_len & 0xFF);

    uint8_t nonce[12];
    xor_seq_nonce(nonce, iv, *seq);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(inner);
        free(record);
        return -1;
    }
    const EVP_CIPHER *cipher = record_cipher_for_conn(c);
    if (cipher == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        free(inner);
        free(record);
        return -1;
    }

    int len1 = 0;
    int ok = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             EVP_EncryptUpdate(ctx, NULL, &len1, record, 5) == 1 &&
             EVP_EncryptUpdate(ctx, record + 5, &len1, inner, (int)inner_len) == 1;

    int len2 = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, record + 5 + len1, &len2) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, record + 5 + inner_len) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(inner,inner_len); free(inner);

    if (!ok) {
        free(record);
        return -1;
    }

    *seq += 1;
    *out = record;
    *out_len = 5 + c_len;
    return 0;
}

static int decrypt_record(const tls13_conn_t *c, const uint8_t *key, const uint8_t iv[12], uint64_t *seq, uint8_t rtype, const uint8_t *payload,
                          size_t payload_len, uint8_t **plain, size_t *plain_len, uint8_t *inner_type) {
    if (rtype != 0x17 || payload_len < 17 || payload_len > 16640 || *seq >= TLS_RECORD_HARD_LIMIT ||
        (c->tls_receive_record_limit && payload_len-16 > c->tls_receive_record_limit)) {
        return -1;
    }

    uint8_t hdr[5] = {rtype, 0x03, 0x03, (uint8_t)(payload_len >> 8), (uint8_t)(payload_len & 0xFF)};

    size_t ct_len = payload_len - 16;
    const uint8_t *ct = payload;
    const uint8_t *tag = payload + ct_len;

    uint8_t nonce[12];
    xor_seq_nonce(nonce, iv, *seq);

    uint8_t *buf = (uint8_t *)malloc(ct_len);
    if (buf == NULL) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(buf);
        return -1;
    }
    const EVP_CIPHER *cipher = record_cipher_for_conn(c);
    if (cipher == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    int len1 = 0;
    int ok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             EVP_DecryptUpdate(ctx, NULL, &len1, hdr, 5) == 1 && EVP_DecryptUpdate(ctx, buf, &len1, ct, (int)ct_len) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) == 1;

    int len2 = 0;
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, buf + len1, &len2) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        free(buf);
        return -1;
    }

    size_t pt_len = ct_len;
    size_t i = pt_len;
    while (i > 0 && buf[i - 1] == 0x00) {
        i--;
    }
    if (i == 0) {
        free(buf);
        return -1;
    }

    uint8_t ctype = buf[i - 1];
    size_t content_len = i - 1;

    if (content_len > 16384 || (ctype != 21 && ctype != 22 && ctype != 23)) { OPENSSL_cleanse(buf,ct_len); free(buf); return -1; }

    OPENSSL_cleanse(buf+content_len,ct_len-content_len);

    *seq += 1;
    *plain = buf;
    *plain_len = content_len;
    *inner_type = ctype;
    return 0;
}

int tls13_get_fd(const tls13_conn_t *c) {
    return c->fd;
}

int tls13_reality_is_raw_direct(const tls13_conn_t *c) {
    return (c != NULL && c->reality_raw_direct);
}

int tls13_needs_write(const tls13_conn_t *c) {
    if (c && c->relay_async && c->xmux_wire_output.len && !c->xmux_write_wants_read) return 1;
    if (c && c->mode == CONN_MODE_WS) return c->ws_want_write;
    return c != NULL && c->mode == CONN_MODE_XHTTP_TLS && c->ssl != NULL && SSL_want_write(c->ssl);
}

int tls13_idle_timeout(const tls13_conn_t *c) {
    if (!c || c->mode != CONN_MODE_WS || !c->ws_next_heartbeat || c->ws_close_sent || c->ws_decoder.closed) return -1;
    uint64_t now=core_now_ms();
    if (now >= c->ws_next_heartbeat) return 0;
    uint64_t remaining=c->ws_next_heartbeat-now;
    return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

int tls13_tick(tls13_conn_t *c) {
    if (c && c->xhttp_upload_reader_started) {
        pthread_mutex_lock(&g_tls_state_lock); int failed=c->xhttp_upload_failed; pthread_mutex_unlock(&g_tls_state_lock);
        if (failed) return -1;
    }
    if (tls13_idle_timeout(c) == 0) {
        if (ws_write_frame(c,9,NULL,0)) return -1;
        c->ws_next_heartbeat=core_now_ms()+c->ws_heartbeat_ms;
    }
    return 0;
}

int tls13_start_relay(tls13_conn_t *c) {
    if (c && c->xmux_stream) return core_http2_start_relay(c->xmux_stream);
    if (!c || (c->mode != CONN_MODE_PLAIN && c->mode != CONN_MODE_TLS && c->mode != CONN_MODE_REALITY && c->mode != CONN_MODE_WS)) return 0;
    int flags=fcntl(c->fd,F_GETFL,0);
    if (flags < 0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return -1;
    if (c->ssl) SSL_set_mode(c->ssl,SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
    c->relay_async=1; return 0;
}

int tls13_flush(tls13_conn_t *c) {
    if (!c || !c->relay_async) return 0;
    if (c->xmux_wire_output.len) {
        ssize_t sent;
        if (c->ssl) {
            if (!c->xmux_ssl_write_length) c->xmux_ssl_write_length=c->xmux_wire_output.len > 16384 ? 16384 : c->xmux_wire_output.len;
            ERR_clear_error(); sent=SSL_write(c->ssl,c->xmux_wire_output.data,(int)c->xmux_ssl_write_length);
            if (sent <= 0) {
                int error=SSL_get_error(c->ssl,(int)sent);
                c->xmux_write_wants_read=error == SSL_ERROR_WANT_READ;
                return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE || (error == SSL_ERROR_SYSCALL && errno == EINTR) ? 0 : -1;
            }
            c->xmux_ssl_write_length=0; c->xmux_write_wants_read=0;
        } else {
            sent=core_send(c->fd,c->xmux_wire_output.data,c->xmux_wire_output.len,MSG_DONTWAIT);
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
            if (sent <= 0) return -1;
        }
        db_consume(&c->xmux_wire_output,(size_t)sent);
    }
    if (c->relay_raw_finish && !c->xmux_wire_output.len) {
        c->relay_raw_finish=0;
        return shutdown(c->fd,SHUT_WR);
    }
    return 0;
}

int tls13_write_raw(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    return !c || c->send_closed ? -1 : relay_write_wire(c,buf,len);
}

int tls13_has_pending_raw(const tls13_conn_t *c) { return c && c->xmux_raw_input.len; }

int tls13_read_raw(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len=0;
    if (!c || !cap) return c ? 0 : -1;
    if (!c->xmux_raw_input.len) return fd_read_some(c->fd,buf,cap,out_len);
    size_t take=c->xmux_raw_input.len < cap ? c->xmux_raw_input.len : cap;
    memcpy(buf,c->xmux_raw_input.data,take); db_consume(&c->xmux_raw_input,take); *out_len=take; return 0;
}

int tls13_has_pending_app(const tls13_conn_t *c) {
    if (c && c->grpc_transport && (c->grpc_net_cache.len || core_grpc_pending(&c->grpc_decoder) || c->grpc_read_failed)) return 1;
    if (c && c->xmux_stream) return c->app_cache.len || core_xmux_pending(c->xmux_stream);
    if (tls13_uses_h2(c)) {
        return c->app_cache.len > 0 || c->h2_stream_eof || c->grpc_read_failed;
    }
    return tls13_has_pending_input(c);
}

int tls13_has_pending_input(const tls13_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    if (c->grpc_transport && (c->grpc_net_cache.len || core_grpc_pending(&c->grpc_decoder) || c->grpc_read_failed)) return 1;
    if (c->xmux_stream) return c->app_cache.len || core_xmux_pending(c->xmux_stream);
    if (c->app_cache.len > 0) {
        return 1;
    }
    if (c->relay_async && (c->mode == CONN_MODE_TLS || c->mode == CONN_MODE_REALITY)) {
        if (c->receive_closed) return 1;
        if (c->xmux_raw_input.len >= 5) {
            size_t length=((size_t)c->xmux_raw_input.data[3]<<8)|c->xmux_raw_input.data[4];
            if (length > 18432 || c->xmux_raw_input.len >= length+5) return 1;
        }
    }
    if (tls13_uses_h2(c) && c->h2_stream_eof) {
        return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
        core_http1_response_t parser=c->xhttp_http1_response; core_http1_event_t event;
        int result=core_http1_next(&parser,c->xhttp_net_cache.data,c->xhttp_net_cache.len,c->xhttp_wire_eof,8192,&event);
        if (result <= 0 || event.consumed || c->xhttp_eof || (c->ssl && SSL_pending(c->ssl) > 0)) return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS_H2 && (h2_cached_frame_ready(c) || (c->ssl && SSL_pending(c->ssl) > 0))) {
        return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_REALITY && c->h2_net_cache.len > 0) {
        return 1;
    }
    if (c->mode == CONN_MODE_GRPC_PLAIN && c->h2_net_cache.len > 0) {
        return 1;
    }
    if (c->mode == CONN_MODE_WS && (c->ws_net_cache.len > 0 || (c->ssl != NULL && SSL_pending(c->ssl) > 0))) {
        return 1;
    }
    return 0;
}

static int h2_cached_frame_ready(const tls13_conn_t *c) {
    if (c->h2_net_cache.len >= 9) {
        size_t frame_len = ((size_t)c->h2_net_cache.data[0] << 16) | ((size_t)c->h2_net_cache.data[1] << 8) |
                           (size_t)c->h2_net_cache.data[2];
        if (frame_len > H2_DEFAULT_MAX_FRAME || c->h2_net_cache.len >= 9 + frame_len) {
            return 1;
        }
    }
    return 0;
}

static int h2_input_ready(const tls13_conn_t *c) {
    if (h2_cached_frame_ready(c)) {
        return 1;
    }
    if (c->ssl != NULL && SSL_pending(c->ssl) > 0) {
        return 1;
    }
    if (c->fd < 0) {
        return 0;
    }

    return core_wait_socket(c->fd, POLLIN, 0) > 0;
}

int tls13_drain_h2_input(tls13_conn_t *c) {
    if (c && c->xmux_stream) { core_xmux_drain_notifications(c->xmux_stream); return 0; }
    if (c == NULL ||
        (c->mode != CONN_MODE_XHTTP_TLS_H2 && c->mode != CONN_MODE_XHTTP_REALITY && c->mode != CONN_MODE_GRPC_PLAIN)) {
        return 0;
    }
    if (c->grpc_transport && grpc_fill_app_cache(c) < 0) return c->app_cache.len ? 0 : -1;

    if (c->mode == CONN_MODE_XHTTP_TLS_H2 &&
        c->app_cache.len == 0 &&
        !h2_cached_frame_ready(c)) {
        if (h2_collect_tls_available(c, NULL) < 0) {
            return -1;
        }
    }

    int drain_limit = c->grpc_transport ? H2_GRPC_INPUT_DRAIN_LIMIT : H2_INPUT_DRAIN_LIMIT;
    int drained = 0;
    while (drained < drain_limit && c->app_cache.len == 0 &&
           (c->mode == CONN_MODE_XHTTP_TLS_H2 ?
                h2_cached_frame_ready(c) :
                h2_input_ready(c))) {
        if (h2_pump_one_frame(c) != 0) {
            return c->grpc_transport && c->app_cache.len ? drained : -1;
        }
        drained++;
    }
    return drained;
}

int tls13_uses_h2(const tls13_conn_t *c) {
    return c != NULL &&
           (c->mode == CONN_MODE_XHTTP_TLS_H2 ||
            c->mode == CONN_MODE_XHTTP_REALITY ||
            c->mode == CONN_MODE_GRPC_PLAIN);
}

int tls13_uses_async_io(const tls13_conn_t *c) { return c && c->xmux_stream; }

size_t tls13_write_batch_size(const tls13_conn_t *c) {
    if (c && c->xmux_stream) return 64U*1024U;
    if (c != NULL && c->grpc_transport) {
        return H2_WRITE_BATCH_SIZE;
    }
    if (c != NULL && strcmp(c->xhttp_transport_mode, "packet-up") == 0 &&
        (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_XHTTP_REALITY ||
         c->mode == CONN_MODE_XHTTP_PLAIN) &&
        c->xhttp_max_each_post_bytes > 0) {
        size_t size = (size_t)c->xhttp_max_each_post_bytes;
        return size > 1024U * 1024U ? 1024U * 1024U : size;
    }
    if (c != NULL && strcmp(c->xhttp_transport_mode, "packet-up") != 0 &&
        (c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_XHTTP_REALITY)) {
        return H2_WRITE_BATCH_SIZE;
    }
    return 8192;
}

size_t tls13_write_capacity(const tls13_conn_t *c) {
    if (c && c->relay_async) return c->send_closed ? 0 : 256U*1024U-c->xmux_wire_output.len;
    return c && c->xmux_stream ? core_xmux_write_capacity(c->xmux_stream) : SIZE_MAX;
}

int tls13_reserve_write(tls13_conn_t *c, size_t capacity) {
    return c && c->xmux_stream ? core_xmux_reserve_write(c->xmux_stream, capacity) : 1;
}

void tls13_release_write(tls13_conn_t *c) {
    if (c && c->xmux_stream) core_xmux_release_write(c->xmux_stream);
}

void tls13_mark_raw_direct(tls13_conn_t *c) {
    if (c != NULL) {
        c->reality_raw_direct = 1;
    }
}

static int append_transcript(tls13_conn_t *c, const uint8_t *msg, size_t msg_len) {
    if (tls_buffer_init(&c->transcript,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) return -1;
    return db_append(&c->transcript, msg, msg_len);
}

static int tls_update_keys(tls13_conn_t *c, int sending) {
    uint8_t next[64];
    uint8_t *secret=sending ? c->c_app_traffic : c->s_app_traffic;
    uint8_t *key=sending ? c->c_app_key : c->s_app_key;
    uint8_t *iv=sending ? c->c_app_iv : c->s_app_iv;
    if (hkdf_expand_label_md(c->tls_md,secret,c->tls_hash_len,"traffic upd",NULL,0,next,c->tls_hash_len) ||
        derive_key_iv_md(c->tls_md,next,c->tls_hash_len,c->tls_key_len,key,iv)) { OPENSSL_cleanse(next,sizeof(next)); return -1; }
    memcpy(secret,next,c->tls_hash_len); OPENSSL_cleanse(next,sizeof(next));
    if (sending) c->c_app_seq=0; else { c->s_app_seq=0; c->tls_receive_update_requested=0; }
    return 0;
}

static int tls_key_update_send(tls13_conn_t *c, unsigned request) {
    if (c->send_closed) return -1;
    const uint8_t message[]={24,0,0,1,(uint8_t)request}; uint8_t *record=NULL; size_t length=0;
    if (encrypt_record(c,c->c_app_key,c->c_app_iv,&c->c_app_seq,22,message,sizeof(message),&record,&length)) return -1;
    int result;
    if (c->xmux_async) result=length > 256U*1024U-c->xmux_wire_output.len ? -1 : db_append(&c->xmux_wire_output,record,length);
    else result=relay_write_wire(c,record,length);
    free(record);
    return result ? -1 : tls_update_keys(c,1);
}

static int tls_prepare_app_record(tls13_conn_t *c) {
    return c->c_app_seq >= TLS_RECORD_REKEY_LIMIT ? tls_key_update_send(c,0) : 0;
}

static int tls_session_ticket(const uint8_t *body, size_t length) {
    if (length < 13) return -1;
    uint32_t lifetime=((uint32_t)body[0]<<24)|((uint32_t)body[1]<<16)|((uint32_t)body[2]<<8)|body[3];
    if (lifetime > 604800) return -1;
    size_t offset=9+(size_t)body[8];
    if (offset+2 > length) return -1;
    size_t ticket=((size_t)body[offset]<<8)|body[offset+1]; offset+=2;
    if (!ticket || ticket > length-offset) return -1;
    offset+=ticket;
    if (length-offset < 2 || (((size_t)body[offset]<<8)|body[offset+1]) != length-offset-2) return -1;
    offset+=2; unsigned seen[256]; size_t count=0;
    while (offset < length) {
        if (length-offset < 4 || count == sizeof(seen)/sizeof(seen[0])) return -1;
        unsigned type=((unsigned)body[offset]<<8)|body[offset+1]; size_t size=((size_t)body[offset+2]<<8)|body[offset+3]; offset+=4;
        if (size > length-offset || (type == 42 && size != 4)) return -1;
        for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
        seen[count++]=type; offset+=size;
    }
    return 0;
}

static int tls_post_handshake(tls13_conn_t *c, const uint8_t *data, size_t length) {
    if (c->tls_auth_state != 4 || tls_buffer_init(&c->tls_post_handshake,TLS_POST_HANDSHAKE_LIMIT,NULL) ||
        length > TLS_POST_HANDSHAKE_LIMIT-c->tls_post_handshake.len || db_append(&c->tls_post_handshake,data,length)) return -1;
    while (c->tls_post_handshake.len >= 4) {
        const uint8_t *message=c->tls_post_handshake.data;
        size_t size=((size_t)message[1]<<16)|((size_t)message[2]<<8)|message[3];
        if (size > 256U*1024U-4 || (message[0] == 24 && size != 1) || (message[0] != 4 && message[0] != 24)) return -1;
        if (c->tls_post_handshake.len < size+4) return 0;
        if (message[0] == 24) {
            unsigned request=message[4];
            if (request > 1 || tls_update_keys(c,0) || (request && tls_key_update_send(c,0))) return -1;
        } else if (tls_session_ticket(message+4,size)) return -1;
        db_consume(&c->tls_post_handshake,size+4);
    }
    if (!c->tls_post_handshake.len) db_free(&c->tls_post_handshake);
    return 0;
}

static int tls_application_plain(tls13_conn_t *c, unsigned type, const uint8_t *data, size_t length, dynbuf_t *cache) {
    if (c->receive_closed) return -1;
    if (c->s_app_seq >= TLS_RECORD_REKEY_LIMIT && !c->tls_receive_update_requested && !c->send_closed) {
        if (tls_key_update_send(c,1)) return -1;
        c->tls_receive_update_requested=1;
    }
    if (type == 22) return tls_post_handshake(c,data,length);
    if (c->tls_post_handshake.len) return -1;
    if (type == 23) return db_append(cache,data,length);
    if (type == 21 && length == 2 && data[1] == 0) { c->receive_closed=1; return 1; }
    return -1;
}

static int tls_encrypted_extensions(tls13_conn_t *c, const uint8_t *data, size_t length) {
    if (length < 2 || (((size_t)data[0]<<8)|data[1]) != length-2) return -1;
    unsigned seen[32]; size_t count=0;
    for (size_t offset=2;offset < length;) {
        if (length-offset < 4 || count == 32) return -1;
        unsigned type=((unsigned)data[offset]<<8)|data[offset+1]; size_t size=((size_t)data[offset+2]<<8)|data[offset+3]; offset+=4;
        if (size > length-offset) return -1;
        for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
        seen[count++]=type;
        if (type != 0 && type != 1 && type != 10 && type != 16 && type != 28 && type != 0x4469) return -1;
        size_t offered_size=0;
        const uint8_t *offered=core_tls_hello_extension(c->tls_client_hello.data,c->tls_client_hello.len,type,&offered_size);
        if (!offered && (type != 16 || c->tls_client_hello.len)) return -1;
        if (type == 0 && size) return -1;
        if (type == 28) {
            if (size != 2) return -1;
            unsigned limit=((unsigned)data[offset]<<8)|data[offset+1];
            if (limit < 64 || limit > 16385) return -1;
            c->tls_send_record_limit=limit;
            if (offered_size != 2) return -1;
            c->tls_receive_record_limit=((unsigned)offered[0]<<8)|offered[1];
        }
        if (type == 1) {
            if (size != 1 || offered_size != 1 || data[offset] != offered[0] || data[offset] < 1 || data[offset] > 4) return -1;
            c->tls_send_record_limit=(1U<<(8+data[offset]))+1;
        }
        if (type == 10) {
            if (size < 4 || (size&1) || (((size_t)data[offset]<<8)|data[offset+1]) != size-2) return -1;
        }
        if (type == 16) {
            if (size < 3 || (((size_t)data[offset]<<8)|data[offset+1]) != size-2 || data[offset+2] != size-3 || size-3 >= sizeof(c->tls_selected_alpn)) return -1;
            memcpy(c->tls_selected_alpn,data+offset+3,size-3); c->tls_selected_alpn[size-3]=0;
            if (strlen(c->tls_selected_alpn) != size-3 || !alpn_csv_has_token(c->tls_offered_alpn,c->tls_selected_alpn)) return -1;
        }
        offset+=size;
    }
    return c->tls_h2_required && strcmp(c->tls_selected_alpn,"h2") &&
        !(c->tls_is_reality && !c->tls_selected_alpn[0]) ? -1 : 0;
}

static int verify_server_signature(const vless_config_t *cfg, tls13_conn_t *c, const uint8_t *body, size_t length) {
    if (!c->tls_peer_certificate || length < 4 || (((size_t)body[2]<<8)|body[3]) != length-4) return -1;
    unsigned scheme=((unsigned)body[0]<<8)|body[1];
    const EVP_MD *digest=NULL;
    int expected_type=0,curve=0,pss=0;
    switch (scheme) {
    case 0x0403: digest=EVP_sha256(); expected_type=EVP_PKEY_EC; curve=NID_X9_62_prime256v1; break;
    case 0x0503: digest=EVP_sha384(); expected_type=EVP_PKEY_EC; curve=NID_secp384r1; break;
    case 0x0603:
        if (cfg->fp_mode != FP_FIREFOX) return -1;
        digest=EVP_sha512(); expected_type=EVP_PKEY_EC; curve=NID_secp521r1; break;
    case 0x0804: digest=EVP_sha256(); expected_type=EVP_PKEY_RSA; pss=1; break;
    case 0x0805: digest=EVP_sha384(); expected_type=EVP_PKEY_RSA; pss=1; break;
    case 0x0806: digest=EVP_sha512(); expected_type=EVP_PKEY_RSA; pss=1; break;
    case 0x0807: expected_type=EVP_PKEY_ED25519; break;
    default: return -1;
    }
    EVP_PKEY *key=X509_get_pubkey(c->tls_peer_certificate);
    if (!key || EVP_PKEY_base_id(key) != expected_type) { EVP_PKEY_free(key); return -1; }
    if (curve) {
        char group[80]; size_t size=0;
        if (EVP_PKEY_get_utf8_string_param(key,OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&size) != 1 ||
            OBJ_txt2nid(group) != curve) { EVP_PKEY_free(key); return -1; }
    }
    uint8_t transcript[64],input[164];
    const char context[]="TLS 1.3, server CertificateVerify";
    memset(input,32,64); memcpy(input+64,context,sizeof(context));
    if (transcript_hash(c,transcript)) { EVP_PKEY_free(key); return -1; }
    memcpy(input+64+sizeof(context),transcript,c->tls_hash_len);
    EVP_MD_CTX *verify=EVP_MD_CTX_new(); EVP_PKEY_CTX *parameters=NULL;
    int ok=verify && EVP_DigestVerifyInit(verify,&parameters,digest,NULL,key) == 1;
    if (ok && pss) ok=EVP_PKEY_CTX_set_rsa_padding(parameters,RSA_PKCS1_PSS_PADDING) == 1 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters,EVP_MD_get_size(digest)) == 1 && EVP_PKEY_CTX_set_rsa_mgf1_md(parameters,digest) == 1;
    if (ok) ok=EVP_DigestVerify(verify,body+4,length-4,input,64+sizeof(context)+c->tls_hash_len) == 1;
    EVP_MD_CTX_free(verify); EVP_PKEY_free(key); return ok ? 0 : -1;
}

static int tls_certificate_request(const uint8_t *body, size_t length) {
    if (length < 3 || body[0] || (((size_t)body[1]<<8)|body[2]) != length-3) return -1;
    unsigned seen[256]; size_t count=0; int signatures=0;
    for (size_t offset=3;offset<length;) {
        if (length-offset < 4 || count == sizeof(seen)/sizeof(seen[0])) return -1;
        unsigned type=((unsigned)body[offset]<<8)|body[offset+1];
        size_t size=((size_t)body[offset+2]<<8)|body[offset+3]; offset+=4;
        if (size > length-offset) return -1;
        for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
        seen[count++]=type;
        if (type == 13 || type == 50) {
            if (size < 4 || (size&1) || (((size_t)body[offset]<<8)|body[offset+1]) != size-2) return -1;
            if (type == 13) signatures=1;
        }
        offset+=size;
    }
    return signatures ? 0 : -1;
}

static int server_handshake_message(const vless_config_t *cfg, tls13_conn_t *c, const uint8_t *message, size_t length, char *err, size_t err_cap) {
    if (length < 4) return -1;
    unsigned type=message[0]; size_t body_length=length-4;
    if (type == 13) {
        if (c->tls_auth_state != 1 || c->tls_client_certificate_requested || tls_certificate_request(message+4,body_length)) {
            set_err(err,err_cap,"invalid or unexpected TLS CertificateRequest"); return -1;
        }
        if (append_transcript(c,message,length)) return -1;
        c->tls_client_certificate_requested=1; return 0;
    }
    static const unsigned expected[]={8,11,15,20};
    if (c->tls_auth_state >= 4 || type != expected[c->tls_auth_state]) {
        set_err(err,err_cap,"unexpected TLS server handshake message"); return -1;
    }
    if (type == 8) {
        if (tls_encrypted_extensions(c,message+4,body_length)) {
            set_err(err,err_cap,"invalid TLS EncryptedExtensions"); return -1;
        }
    } else if (type == 11) {
        const uint8_t *der=NULL; size_t der_length=0;
        if (parse_first_cert_der(message,length,&der,&der_length)) { set_err(err,err_cap,"invalid TLS Certificate"); return -1; }
        const unsigned char *cursor=der;
        c->tls_peer_certificate=d2i_X509(NULL,&cursor,(long)der_length);
        if (!c->tls_peer_certificate || cursor != der+der_length) { set_err(err,err_cap,"invalid TLS leaf certificate"); return -1; }
        if (!strcmp(cfg->security,"reality")) {
            if (verify_reality_cert(c->auth_key,der,der_length)) { set_err(err,err_cap,"REALITY cert verify failed"); return -1; }
        } else if (c->tls_verify_policy == TLS_VERIFY_MODE_STRICT &&
            verify_tls_cert_message(cfg->sni[0] ? cfg->sni : cfg->server_host,message,length,err,err_cap)) return -1;
        if (db_append(&c->tls_certificate_message,message,length)) return -1;
    } else if (type == 15) {
        if (verify_server_signature(cfg,c,message+4,body_length)) { set_err(err,err_cap,"TLS CertificateVerify signature failed"); return -1; }
    } else {
        uint8_t transcript[64],finished[64];
        if (body_length != c->tls_hash_len || transcript_hash(c,transcript) ||
            calc_finished_verify(c,c->s_hs_traffic,transcript,finished) || CRYPTO_memcmp(finished,message+4,body_length)) {
            set_err(err,err_cap,"server Finished mismatch"); return -1;
        }
        if (strcmp(cfg->security,"reality") && c->tls_verify_policy == TLS_VERIFY_MODE_TOFU &&
            tcp_tls_tofu_verify_or_store(cfg,c->tls_certificate_message.data,c->tls_certificate_message.len,err,err_cap)) return -1;
    }
    if (append_transcript(c,message,length)) return -1;
    c->tls_auth_state++; return type == 20 ? 1 : 0;
}

static int run_tls_handshake_with_key(const vless_config_t *cfg, tls13_conn_t *c, tls_cipher_offer_t cipher_offer, EVP_PKEY *hybrid_key, const uint8_t *hybrid_pub, char *err, size_t err_cap) {
    uint8_t client_priv[32]={0},shared[96]={0};
    int use_reality = (strcmp(cfg->security, "reality") == 0);
    tls_verify_mode_t verify_mode = tls_verify_mode_for_config(cfg);
    c->tls_verify_policy = verify_mode;
    snprintf(c->tls_verify_mode, sizeof(c->tls_verify_mode), "%s",
             use_reality ? "reality" : tls_verify_mode_name(verify_mode));
    snprintf(c->tls_offered_alpn,sizeof(c->tls_offered_alpn),"%s",cfg->alpn[0] ? cfg->alpn :
        (cfg->fp_mode == FP_RANDOM || cfg->fp_mode == FP_RANDOMIZED ? "http/1.1,h2" : "h2,http/1.1"));
    c->tls_h2_required=cfg->transport_mode == TRANSPORT_GRPC || cfg->transport_mode == TRANSPORT_XHTTP;
    c->tls_is_reality=use_reality;
    c->tls_receive_record_limit=c->tls_send_record_limit=0; c->tls_receive_update_requested=0;
    if (tls_buffer_init(&c->tls_client_hello,65536,&c->tls_handshake_bytes) ||
        tls_buffer_init(&c->tls_certificate_message,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) {
        set_err(err,err_cap,"TLS handshake memory budget exhausted"); goto handshake_failure;
    }
    if (c->tls_h2_required && !alpn_csv_has_token(c->tls_offered_alpn,"h2")) { set_err(err,err_cap,"HTTP/2 transport requires h2 ALPN"); goto handshake_failure; }

    uint8_t client_pub[32];
    uint8_t client_random[32];
    uint8_t *ch = NULL;
    size_t ch_len = 0;
    size_t sid_pos = 0;

    EVP_PKEY_free(c->tls_retry_key); c->tls_retry_key=NULL;
    if (build_client_hello(cfg, use_reality, cipher_offer, client_priv, client_pub, client_random, c->auth_key, &ch, &ch_len, &sid_pos, hybrid_pub,&c->tls_retry_key) !=
        0) {
        set_err(err, err_cap, "failed to build ClientHello");
        goto handshake_failure;
    }
    if (c->tls_retry_key) c->tls_exchange_group=23;

    uint8_t *ch_record = (uint8_t *)malloc(5 + ch_len);
    if (ch_record == NULL) {
        free(ch);
        set_err(err, err_cap, "failed to allocate ClientHello record");
        goto handshake_failure;
    }
    ch_record[0] = 0x16;
    ch_record[1] = 0x03;
    ch_record[2] = 0x01;
    ch_record[3] = (uint8_t)(ch_len >> 8);
    ch_record[4] = (uint8_t)(ch_len & 0xFF);
    memcpy(ch_record + 5, ch, ch_len);
    if (write_exact(c->fd, ch_record, 5 + ch_len) != 0) {
        free(ch_record);
        free(ch);
        set_err(err, err_cap, "failed to send ClientHello");
        goto handshake_failure;
    }
    free(ch_record);

    if (append_transcript(c, ch, ch_len) != 0 || db_append(&c->tls_client_hello,ch,ch_len)) {
        free(ch);
        set_err(err, err_cap, "transcript append failed");
        goto handshake_failure;
    }
    free(ch);

    dynbuf_t plain_hs = {0};
    if (tls_buffer_init(&plain_hs,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) goto handshake_failure;
    uint8_t server_share[TLS_HYBRID_SERVER_SHARE_SIZE];
    size_t share_len = 0;
    uint16_t server_cipher = 0;
    uint16_t server_group = 0;
    int got_server_hello = 0;

    while (!got_server_hello) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            db_free(&plain_hs);
            set_err(err, err_cap, "failed to read ServerHello record");
            goto handshake_failure;
        }

        if (rtype == 0x16) {
            if (!pl_len) {
                free(pl); db_free(&plain_hs); set_err(err,err_cap,"empty TLS handshake record before ServerHello"); goto handshake_failure;
            }
            if (db_append(&plain_hs, pl, pl_len) != 0) {
                free(pl);
                db_free(&plain_hs);
                goto handshake_failure;
            }
            free(pl);

            while (plain_hs.len >= 4) {
                size_t mlen = ((size_t)plain_hs.data[1] << 16) | ((size_t)plain_hs.data[2] << 8) | plain_hs.data[3];
                if (mlen > TLS_HANDSHAKE_LIMIT-4) { db_free(&plain_hs); set_err(err,err_cap,"TLS ServerHello exceeds handshake limit"); goto handshake_failure; }
                if (plain_hs.len < 4 + mlen) {
                    break;
                }
                if (plain_hs.data[0] == 0x02) {
                    core_tls_hello_t server;
                    if (core_tls_hello_parse(plain_hs.data,4+mlen,c->tls_client_hello.data,c->tls_client_hello.len,&server)) {
                        db_free(&plain_hs); set_err(err,err_cap,"invalid TLS ServerHello parameters"); goto handshake_failure;
                    }
                    if (server.retry) {
                        if (c->tls_retry_seen || use_reality) { db_free(&plain_hs); set_err(err,err_cap,c->tls_retry_seen ? "repeated TLS HelloRetryRequest" : "REALITY HelloRetryRequest is unsupported"); goto handshake_failure; }
                        uint8_t hash[64],*retry=NULL; size_t retry_length=0;
                        EVP_PKEY *retry_key=NULL;
                        if (configure_tls_cipher(c,server.cipher) || transcript_hash(c,hash) ||
                            core_tls_hello_retry(c->tls_client_hello.data,c->tls_client_hello.len,&server,&retry,&retry_length,&retry_key)) {
                            db_free(&plain_hs); set_err(err,err_cap,"unsupported TLS HelloRetryRequest"); goto handshake_failure;
                        }
                        if (retry_key) { EVP_PKEY_free(c->tls_retry_key); c->tls_retry_key=retry_key; c->tls_exchange_group=server.group; }
                        c->transcript.len=0; uint8_t message_hash[]={254,0,0,(uint8_t)c->tls_hash_len};
                        int result=append_transcript(c,message_hash,4) || append_transcript(c,hash,c->tls_hash_len) ||
                            append_transcript(c,plain_hs.data,4+mlen) || append_transcript(c,retry,retry_length);
                        db_free(&c->tls_client_hello);
                        if (!result) result=tls_buffer_init(&c->tls_client_hello,65536,&c->tls_handshake_bytes) || db_append(&c->tls_client_hello,retry,retry_length);
                        uint8_t header[]={22,3,3,(uint8_t)(retry_length>>8),(uint8_t)retry_length};
                        if (!result) result=write_exact(c->fd,header,5) || write_exact(c->fd,retry,retry_length);
                        free(retry); c->tls_retry_seen=1; c->tls_retry_group=server.group;
                        if (result) { db_free(&plain_hs); set_err(err,err_cap,"failed to send retry ClientHello"); goto handshake_failure; }
                        db_consume(&plain_hs,4+mlen); break;
                    }
                    if (c->tls_retry_seen && (server.cipher != c->tls_cipher_suite || (c->tls_retry_group && server.group != c->tls_retry_group))) {
                        db_free(&plain_hs); set_err(err,err_cap,"ServerHello changed HelloRetryRequest parameters"); goto handshake_failure;
                    }
                    if (parse_server_hello_for_keyshare(plain_hs.data, 4 + mlen, &server_cipher, server_share, &share_len) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "invalid ServerHello");
                        goto handshake_failure;
                    }
                    if (configure_tls_cipher(c, server_cipher) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "unsupported TLS cipher suite");
                        goto handshake_failure;
                    }
                    if (append_transcript(c, plain_hs.data, 4 + mlen) != 0) {
                        db_free(&plain_hs);
                        goto handshake_failure;
                    }
                    server_group=server.group;
                    got_server_hello = 1;
                    db_consume(&plain_hs, 4 + mlen);
                    break;
                }
                db_free(&plain_hs); set_err(err,err_cap,"unexpected message before ServerHello"); goto handshake_failure;
            }
        } else if (rtype == 20 && pl_len == 1 && pl[0] == 1) {
            free(pl);
        } else {
            free(pl); db_free(&plain_hs); set_err(err,err_cap,"unexpected TLS record before ServerHello"); goto handshake_failure;
        }
    }

    if (plain_hs.len) { db_free(&plain_hs); set_err(err,err_cap,"unexpected plaintext after ServerHello"); goto handshake_failure; }
    db_free(&plain_hs);

    if (!got_server_hello) {
        set_err(err, err_cap, "ServerHello not received");
        goto handshake_failure;
    }

    size_t shared_len = 32;
    if (share_len == TLS_HYBRID_SERVER_SHARE_SIZE) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
        EVP_PKEY_CTX *kem = hybrid_key != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, hybrid_key, NULL) : NULL;
        size_t kem_len = 32;
        int ok = kem != NULL && EVP_PKEY_decapsulate_init(kem, NULL) == 1 &&
                 EVP_PKEY_decapsulate(kem, shared, &kem_len, server_share, TLS_MLKEM768_CIPHERTEXT_SIZE) == 1 && kem_len == 32;
        EVP_PKEY_CTX_free(kem);
        if (!ok) {
            set_err(err, err_cap, "TLS ML-KEM decapsulation failed");
            goto handshake_failure;
        }
        shared_len = 64;
#else
        (void)hybrid_key;
        set_err(err, err_cap, "TLS X25519MLKEM768 requires OpenSSL 3.5 or newer");
        goto handshake_failure;
#endif
    }
    int exchange_result;
    if (c->tls_retry_key && server_group == c->tls_exchange_group) {
        shared_len=sizeof(shared);
        exchange_result=core_tls_ecdh(c->tls_retry_key,server_group,server_share,share_len,shared,&shared_len);
    } else exchange_result=x25519_shared(client_priv, server_share + share_len - 32, shared + shared_len - 32);
    if (exchange_result != 0) {
        set_err(err, err_cap, "ECDH failed");
        goto handshake_failure;
    }

    if (derive_handshake_keys(c, shared, shared_len) != 0) {
        set_err(err, err_cap, "failed to derive handshake keys");
        goto handshake_failure;
    }
    vc_log_debug("tls", "selected key exchange=%s",server_group == 23 ? "P-256" : server_group == 24 ? "P-384" :
        server_group == 25 ? "P-521" : shared_len == 64 ? "X25519MLKEM768" : "X25519");

    dynbuf_t enc_hs = {0};
    if (tls_buffer_init(&enc_hs,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) goto handshake_failure;
    int got_finished = 0;

    while (!got_finished) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            db_free(&enc_hs);
            set_err(err, err_cap, "failed to read encrypted handshake");
            goto handshake_failure;
        }

        if (rtype != 0x17) {
            int compatibility=rtype == 20 && pl_len == 1 && pl[0] == 1;
            free(pl);
            if (compatibility) continue;
            db_free(&enc_hs); set_err(err,err_cap,"unexpected TLS record during server handshake"); goto handshake_failure;
        }

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        uint8_t inner_type = 0;
        if (decrypt_record(c, c->s_hs_key, c->s_hs_iv, &c->s_hs_seq, rtype, pl, pl_len, &dec, &dec_len, &inner_type) != 0) {
            free(pl);
            db_free(&enc_hs);
            set_err(err, err_cap, "failed to decrypt handshake record");
            goto handshake_failure;
        }
        free(pl);

        if (inner_type == 0x16) {
            if (db_append(&enc_hs, dec, dec_len) != 0) {
                free(dec);
                db_free(&enc_hs);
                goto handshake_failure;
            }
            free(dec);

            while (enc_hs.len >= 4) {
                size_t hlen = ((size_t)enc_hs.data[1] << 16) | ((size_t)enc_hs.data[2] << 8) | enc_hs.data[3];
                if (hlen > TLS_HANDSHAKE_LIMIT-4) { db_free(&enc_hs); set_err(err,err_cap,"TLS message exceeds handshake limit"); goto handshake_failure; }
                if (enc_hs.len < 4 + hlen) {
                    break;
                }
                int result=server_handshake_message(cfg,c,enc_hs.data,4+hlen,err,err_cap);
                if (result < 0) {
                    db_free(&enc_hs);
                    goto handshake_failure;
                }
                db_consume(&enc_hs, 4 + hlen);
                if (result > 0) { got_finished=1; break; }
            }
        } else {
            free(dec);
            db_free(&enc_hs); set_err(err,err_cap,"unexpected TLS inner record during handshake"); goto handshake_failure;
        }
    }

    if (enc_hs.len) { db_free(&enc_hs); set_err(err,err_cap,"unexpected handshake data after server Finished"); goto handshake_failure; }
    db_free(&enc_hs);

    // TLS 1.3 traffic_secret_0 is derived from transcript up to server Finished.
    if (derive_app_keys(c) != 0) {
        set_err(err, err_cap, "failed to derive application keys");
        goto handshake_failure;
    }

    static const uint8_t empty_certificate[]={11,0,0,4,0,0,0,0};
    if (c->tls_client_certificate_requested && append_transcript(c,empty_certificate,sizeof(empty_certificate))) goto handshake_failure;
    uint8_t thash[64],client_verify[64];
    if (transcript_hash(c,thash) || calc_finished_verify(c,c->c_hs_traffic,thash,client_verify)) {
        set_err(err,err_cap,"failed to create client Finished"); goto handshake_failure;
    }

    uint8_t flight[76],*fin_msg=flight+(c->tls_client_certificate_requested ? sizeof(empty_certificate) : 0);
    if (c->tls_client_certificate_requested) memcpy(flight,empty_certificate,sizeof(empty_certificate));
    size_t fin_msg_len = 4 + c->tls_hash_len;
    fin_msg[0] = 0x14;
    fin_msg[1] = 0x00;
    fin_msg[2] = 0x00;
    fin_msg[3] = (uint8_t)c->tls_hash_len;
    memcpy(fin_msg + 4, client_verify, c->tls_hash_len);

    uint8_t *enc_fin = NULL;
    size_t enc_fin_len = 0;
    if (encrypt_record(c, c->c_hs_key, c->c_hs_iv, &c->c_hs_seq, 0x16, flight, (size_t)(fin_msg-flight)+fin_msg_len, &enc_fin, &enc_fin_len) != 0) {
        set_err(err, err_cap, "failed to encrypt client Finished");
        goto handshake_failure;
    }

    /*
     * uTLS/Go middlebox-compat TLS 1.3 sends ChangeCipherSpec after the server
     * handshake flight and immediately before the encrypted Client Finished.
     * It is not included in the handshake transcript.
     */
    uint8_t ccs_rec[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    uint8_t *client_last_flight = (uint8_t *)malloc(sizeof(ccs_rec) + enc_fin_len);
    if (client_last_flight == NULL) {
        free(enc_fin);
        set_err(err, err_cap, "failed to allocate client Finished flight");
        goto handshake_failure;
    }
    memcpy(client_last_flight, ccs_rec, sizeof(ccs_rec));
    memcpy(client_last_flight + sizeof(ccs_rec), enc_fin, enc_fin_len);
    if (write_exact(c->fd, client_last_flight, sizeof(ccs_rec) + enc_fin_len) != 0) {
        free(client_last_flight);
        free(enc_fin);
        set_err(err, err_cap, "failed to send client Finished");
        goto handshake_failure;
    }
    free(client_last_flight);
    free(enc_fin);

    if (append_transcript(c, fin_msg, fin_msg_len) != 0) {
        goto handshake_failure;
    }

    OPENSSL_cleanse(client_priv,sizeof(client_priv)); OPENSSL_cleanse(shared,sizeof(shared));
    tls_handshake_material_clear(c);
    return 0;
handshake_failure: {
    int saved=errno;
    OPENSSL_cleanse(client_priv,sizeof(client_priv)); OPENSSL_cleanse(shared,sizeof(shared));
    tls_handshake_material_clear(c);
    OPENSSL_cleanse(c->c_app_traffic,sizeof(c->c_app_traffic)); OPENSSL_cleanse(c->s_app_traffic,sizeof(c->s_app_traffic));
    OPENSSL_cleanse(c->c_app_key,sizeof(c->c_app_key)); OPENSSL_cleanse(c->s_app_key,sizeof(c->s_app_key));
    OPENSSL_cleanse(c->c_app_iv,sizeof(c->c_app_iv)); OPENSSL_cleanse(c->s_app_iv,sizeof(c->s_app_iv));
    if (err && err_cap && !*err) set_err(err,err_cap,errno == ENOBUFS || errno == EMSGSIZE ? "TLS handshake memory or message limit exceeded" : "TLS handshake failed");
    errno=saved; return -1;
}
}

static int run_tls_handshake(const vless_config_t *cfg, tls13_conn_t *c, tls_cipher_offer_t cipher_offer, char *err, size_t err_cap) {
    EVP_PKEY *hybrid_key = NULL;
    uint8_t hybrid_pub[TLS_MLKEM768_PUBLIC_KEY_SIZE];
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    if (strcmp(cfg->security, "reality") == 0 &&
        (cfg->fp_mode == FP_CHROME || cfg->fp_mode == FP_EDGE || cfg->fp_mode == FP_FIREFOX)) {
        hybrid_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
        unsigned char *encoded = NULL;
        size_t encoded_len = hybrid_key != NULL ? EVP_PKEY_get1_encoded_public_key(hybrid_key, &encoded) : 0;
        if (encoded_len != sizeof(hybrid_pub)) {
            OPENSSL_free(encoded);
            EVP_PKEY_free(hybrid_key);
            set_err(err, err_cap, "TLS ML-KEM key generation failed");
            return -1;
        }
        memcpy(hybrid_pub, encoded, encoded_len);
        OPENSSL_free(encoded);
    }
#endif
    int result = run_tls_handshake_with_key(cfg, c, cipher_offer, hybrid_key,
                                          hybrid_key != NULL ? hybrid_pub : NULL, err, err_cap);
    int saved=errno;
    EVP_PKEY_free(hybrid_key);
    errno=saved; return result;
}

static const char *tls_cipher_suite_name(uint16_t suite) {
    if (suite == 0x1301) {
        return "TLS_AES_128_GCM_SHA256";
    }
    if (suite == 0x1302) {
        return "TLS_AES_256_GCM_SHA384";
    }
    if (suite == 0x1303) {
        return "TLS_CHACHA20_POLY1305_SHA256";
    }
    return "unknown";
}

static void reset_manual_tls_handshake(tls13_conn_t *c) {
    X509_free(c->tls_peer_certificate); c->tls_peer_certificate=NULL;
    db_free(&c->tls_certificate_message); c->tls_auth_state=0;
    c->tls_client_certificate_requested=0;
    c->tls_receive_record_limit=c->tls_send_record_limit=0; c->tls_receive_update_requested=0;
    db_free(&c->tls_post_handshake); c->tls_selected_alpn[0]=0;
    db_free(&c->tls_client_hello); EVP_PKEY_free(c->tls_retry_key); c->tls_retry_key=NULL; c->tls_retry_seen=0; c->tls_retry_group=0; c->tls_exchange_group=0;
    c->tls_cipher_suite = 0;
    c->tls_md = NULL;
    c->tls_hash_len = 0;
    c->tls_key_len = 0;
    memset(c->auth_key, 0, sizeof(c->auth_key));
    memset(c->hs_secret, 0, sizeof(c->hs_secret));
    memset(c->c_hs_traffic, 0, sizeof(c->c_hs_traffic));
    memset(c->s_hs_traffic, 0, sizeof(c->s_hs_traffic));
    memset(c->c_app_traffic, 0, sizeof(c->c_app_traffic));
    memset(c->s_app_traffic, 0, sizeof(c->s_app_traffic));
    memset(c->c_hs_key, 0, sizeof(c->c_hs_key));
    memset(c->c_hs_iv, 0, sizeof(c->c_hs_iv));
    memset(c->s_hs_key, 0, sizeof(c->s_hs_key));
    memset(c->s_hs_iv, 0, sizeof(c->s_hs_iv));
    memset(c->c_app_key, 0, sizeof(c->c_app_key));
    memset(c->c_app_iv, 0, sizeof(c->c_app_iv));
    memset(c->s_app_key, 0, sizeof(c->s_app_key));
    memset(c->s_app_iv, 0, sizeof(c->s_app_iv));
    c->c_hs_seq = 0;
    c->s_hs_seq = 0;
    c->c_app_seq = 0;
    c->s_app_seq = 0;
    c->c_app_record_bytes = 0;
    c->reality_raw_direct = 0;
    db_free(&c->transcript);
    memset(&c->transcript, 0, sizeof(c->transcript));
}

static int connect_manual_tls_endpoint(const vless_config_t *cfg, tls13_conn_t *c, const struct sockaddr *address,
                                       socklen_t address_len, int socktype, int protocol, int start_with_aes, int initial_fd,
                                       tls_cipher_offer_t *successful_offer, char *err, size_t err_cap) {
    static const tls_cipher_offer_t offer_order[] = {
        TLS_CIPHER_OFFER_CHACHA,
        TLS_CIPHER_OFFER_AES,
    };
    size_t first_offer = start_with_aes ? 1 : 0;
    core_connection_error_t failure={0};

    for (size_t i = first_offer; i < sizeof(offer_order) / sizeof(offer_order[0]); i++) {
        tls_cipher_offer_t offer = offer_order[i];
        reset_manual_tls_handshake(c);
        c->fd = i == first_offer ? initial_fd : tcp_connect_address(address->sa_family, socktype, protocol, address, address_len);
        if (c->fd < 0) {
            if (failure.kind && errno != ETIMEDOUT) { core_trace_error_set(failure); errno=failure.system_error; return -1; }
            set_connect_err(err, err_cap, "tcp connect failed");
            return -1;
        }

        core_set_socket_io_timeout(c->fd, CORE_TLS_HANDSHAKE_TIMEOUT_MS);
        char attempt_err[256] = {0};
        errno=0;
        if (run_tls_handshake(cfg, c, offer, attempt_err, sizeof(attempt_err)) == 0) {
            core_set_socket_io_timeout(c->fd, 0);
            *successful_offer = offer;
            core_trace_error_clear();
            return 0;
        }

        failure=core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,errno ? errno : EPROTO);
        close(c->fd);
        c->fd = -1;
        set_err(err, err_cap, attempt_err[0] != '\0' ? attempt_err : "TLS handshake failed");
    }
    core_trace_error_set(failure); errno=failure.system_error;
    return -1;
}

static void remember_manual_tls_success(const vless_config_t *cfg, tls13_conn_t *c, const char *sni,
                                        const struct sockaddr *address, socklen_t address_len,
                                        tls_cipher_offer_t successful_offer) {
    c->tls_use_aes_fallback = successful_offer == TLS_CIPHER_OFFER_AES;
    if (c->tls_use_aes_fallback) {
        cache_tls_aes_fallback(cfg->server_host, cfg->server_port, sni);
    }
    cache_tls_endpoint(cfg, sni, address, address_len);
    log_tls_cipher_once(tls_cipher_suite_name(c->tls_cipher_suite));
}

static int connect_manual_tls(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    const char *sni = cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host;
    int start_with_aes = c->tls_use_aes_fallback || tls_aes_fallback_cached(cfg->server_host, cfg->server_port, sni);
    struct sockaddr_storage cached_address;
    socklen_t cached_length = 0;
    int cached = get_cached_tls_endpoint(cfg, sni, &cached_address, &cached_length);
    core_dialer_t *dialer = core_dialer_start(cfg->server_host, cfg->server_port, !cfg->ignore_server_ips, CORE_CONNECT_TIMEOUT_MS,
        cached ? (const struct sockaddr *)&cached_address : NULL, cached_length);
    if (!dialer) { set_connect_err(err, err_cap, "tcp resolve failed"); return -1; }
    char last_err[256] = {0};
    core_connection_error_t failure={0};
    struct sockaddr_storage address; socklen_t length;
    int fd;
    while ((fd = core_dialer_next(dialer, &address, &length)) >= 0) {
        tls_cipher_offer_t offer;
        if (connect_manual_tls_endpoint(cfg, c, (const struct sockaddr *)&address, length, SOCK_STREAM, IPPROTO_TCP,
                                        start_with_aes, fd, &offer, last_err, sizeof(last_err)) == 0) {
            remember_manual_tls_success(cfg, c, sni, (const struct sockaddr *)&address, length, offer);
            core_dialer_free(dialer); return 0;
        }
        core_trace_error_get(&failure);
        if (!failure.kind) failure=core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,errno ? errno : EPROTO);
        if (cached && sockaddr_equal((const struct sockaddr *)&cached_address, cached_length,
                                     (const struct sockaddr *)&address, length))
            invalidate_cached_tls_endpoint(cfg, sni, (const struct sockaddr *)&address, length);
    }
    int saved=errno; core_dialer_free(dialer);
    if (failure.kind && saved != ETIMEDOUT) saved=failure.system_error;
    if (failure.kind) core_trace_error_set(core_connection_error(failure.stage,failure.kind,saved));
    errno=saved;
    if (saved == ETIMEDOUT) set_err(err,err_cap,"TLS connection budget exhausted");
    else if (last_err[0]) set_err(err, err_cap, last_err);
    else set_connect_err(err, err_cap, "tcp connect failed");
    return -1;
}

static int tcp_tls_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->mode = CONN_MODE_TLS;
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);

    if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    vc_log_info("tls", "connected mode=vision alpn=%s verify=%s",
                c->tls_selected_alpn[0] ? c->tls_selected_alpn : "none",
                c->tls_verify_mode[0] != '\0' ? c->tls_verify_mode : (cfg->allow_insecure ? "insecure" : "strict"));
    return 0;
}

static int ws_upgrade(tls13_conn_t *c, const uint8_t *early, size_t early_length, char *err, size_t err_cap) {
    char key[25],expected[29];
    if (ws_make_key(key) || ws_make_accept(key,expected)) { set_err(err,err_cap,"failed to build WebSocket key"); return -1; }
    char headers[8192]=
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nDNT: 1\r\n"
        "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
        "Sec-CH-UA: \"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"\r\n"
        "Sec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\n";
    for (const char *line=c->ws_headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!colon) return -1;
        char name[128],value[4096];
        size_t length=(size_t)(colon-line),value_length=(size_t)(end-colon-1);
        if (length >= sizeof(name) || value_length >= sizeof(value)) return -1;
        memcpy(name,line,length); name[length]=0;
        memcpy(value,colon+1,value_length); value[value_length]=0; trim_ascii(value);
        if (core_http_header_set(headers,sizeof(headers),name,value)) return -1;
        line=end+2;
    }
    size_t encoded_capacity=4*((early_length+2)/3)+1;
    char *encoded=calloc(1,encoded_capacity);
    if (!encoded) return -1;
    if (early_length) {
        if (base64_encode(early,early_length,encoded,encoded_capacity)) { free(encoded); return -1; }
        for (char *byte=encoded;*byte;byte++) {
            if (*byte == '+') *byte='-';
            else if (*byte == '/') *byte='_';
            else if (*byte == '=') { *byte=0; break; }
        }
    }
    size_t capacity=strlen(headers)+strlen(c->ws_path)+strlen(c->ws_host)+strlen(encoded)+256;
    char *request=malloc(capacity);
    if (!request) { free(encoded); return -1; }
    int length=snprintf(request,capacity,
        "GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n%s%s%s\r\n",
        c->ws_path,c->ws_host,headers,key,early_length ? "Sec-WebSocket-Protocol: " : "",
        early_length ? encoded : "",early_length ? "\r\n" : "");
    int result=length > 0 && (size_t)length < capacity ? ws_conn_write_all(c,request,(size_t)length) : -1;
    free(request);
    if (result) { free(encoded); set_err(err,err_cap,"failed to send WebSocket upgrade request"); return -1; }
    result=parse_ws_upgrade_response(c,&c->ws_net_cache,expected,encoded,err,err_cap);
    free(encoded);
    if (result) return -1;
    int flags=fcntl(c->fd,F_GETFL,0);
    if (flags < 0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return -1;
    c->ws_upgraded=1;
    c->ws_next_heartbeat=c->ws_heartbeat_ms ? core_now_ms()+c->ws_heartbeat_ms : 0;
    return 0;
}

static int ws_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->mode = CONN_MODE_WS;
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);
    int ws_tls = (strcmp(cfg->security, "tls") == 0);

    if (normalize_ws_path(cfg->xhttp_path, c->ws_path, sizeof(c->ws_path)) != 0) {
        set_err(err, err_cap, "invalid ws path");
        return -1;
    }

    const char *host = cfg->xhttp_host[0] != '\0' ? cfg->xhttp_host : (ws_tls ? c->remote_sni : cfg->server_host);
    if (http_host(host,c->ws_host,sizeof(c->ws_host))) { set_err(err,err_cap,"invalid ws host"); return -1; }

    int verify_peer = 0;
    if (ws_tls) {
        unsigned char h1_alpn[256]; unsigned int h1_alpn_length=0;
        const char *protocols=cfg->alpn[0] ? cfg->alpn : "http/1.1";
        if (!alpn_csv_has_token(protocols,"http/1.1") || build_xhttp_tls_alpn(protocols,h1_alpn,sizeof(h1_alpn),&h1_alpn_length)) {
            set_err(err,err_cap,"WebSocket requires http/1.1 ALPN"); return -1;
        }
        tls_verify_mode_t mode = tls_verify_mode_for_config(cfg);
        c->tls_verify_policy = mode;
        verify_peer = tls_verify_peer(mode);
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, verify_peer, h1_alpn, h1_alpn_length, &c->ssl_ctx, &c->ssl,
                            &c->fd, &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
        const unsigned char *selected=NULL; unsigned int selected_length=0;
        SSL_get0_alpn_selected(c->ssl,&selected,&selected_length);
        if (selected_length && (selected_length != 8 || memcmp(selected,"http/1.1",8))) {
            core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,EPROTO)); errno=EPROTO;
            set_err(err,err_cap,"WebSocket server selected incompatible ALPN"); return -1;
        }
        if (mode == TLS_VERIFY_MODE_TOFU) {
            if (xhttp_make_pin_key(c->remote_sni, c->remote_port, c->xhttp_pin_key, sizeof(c->xhttp_pin_key)) != 0 ||
                xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
                return -1;
            }
        }
    } else {
        c->fd = tcp_connect_host(c->remote_host, c->remote_port, !c->ignore_server_ips);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
    }

    memcpy(c->ws_headers,cfg->ws_headers,sizeof(c->ws_headers));
    c->ws_early_data=cfg->ws_early_data;
    c->ws_heartbeat_ms=(uint64_t)cfg->ws_heartbeat_period*1000;
    if (!c->ws_early_data && ws_upgrade(c,NULL,0,err,err_cap)) return -1;
    vc_log_info("ws","connected security=%s early_data=%d",cfg->security,c->ws_early_data);
    return 0;
}

static int xhttp_configure(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->xhttp_seq = 0;

    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);

    if (normalize_xhttp_path(cfg->xhttp_path, c->xhttp_base_path, sizeof(c->xhttp_base_path)) != 0) {
        set_err(err, err_cap, "invalid xhttp path");
        return -1;
    }

    const char *xhost = cfg->xhttp_host[0] != '\0' ? cfg->xhttp_host : c->remote_sni;
    if (http_host(xhost,c->xhttp_host,sizeof(c->xhttp_host))) { set_err(err,err_cap,"invalid xhttp host"); return -1; }
    snprintf(c->xhttp_transport_mode, sizeof(c->xhttp_transport_mode), "%s", cfg->xhttp_mode);
    snprintf(c->xhttp_session_placement, sizeof(c->xhttp_session_placement), "%s",
             cfg->xhttp_session_placement[0] != '\0' ? cfg->xhttp_session_placement : "path");
    snprintf(c->xhttp_session_key, sizeof(c->xhttp_session_key), "%s", cfg->xhttp_session_key);
    snprintf(c->xhttp_seq_placement, sizeof(c->xhttp_seq_placement), "%s",
             cfg->xhttp_seq_placement[0] != '\0' ? cfg->xhttp_seq_placement : "path");
    snprintf(c->xhttp_seq_key, sizeof(c->xhttp_seq_key), "%s", cfg->xhttp_seq_key);
    snprintf(c->xhttp_uplink_method, sizeof(c->xhttp_uplink_method), "%s",
             cfg->xhttp_uplink_method[0] != '\0' ? cfg->xhttp_uplink_method : "POST");
    memcpy(c->xhttp_headers,cfg->xhttp_headers,sizeof(c->xhttp_headers)); c->xhttp_no_grpc_header=cfg->xhttp_no_grpc_header;
    snprintf(c->xhttp_uplink_data_placement,sizeof(c->xhttp_uplink_data_placement),"%s",cfg->xhttp_uplink_data_placement[0] ? cfg->xhttp_uplink_data_placement : "body");
    snprintf(c->xhttp_uplink_data_key,sizeof(c->xhttp_uplink_data_key),"%s",cfg->xhttp_uplink_data_key);
    c->xhttp_uplink_chunks=(core_range_t){cfg->xhttp_uplink_chunk_min,cfg->xhttp_uplink_chunk_max};
    snprintf(c->xhttp_padding_placement, sizeof(c->xhttp_padding_placement), "%s",
             cfg->xhttp_padding_placement[0] != '\0' ? cfg->xhttp_padding_placement : "queryinheader");
    snprintf(c->xhttp_padding_key, sizeof(c->xhttp_padding_key), "%s",
             cfg->xhttp_padding_key[0] != '\0' ? cfg->xhttp_padding_key : "x_padding");
    snprintf(c->xhttp_padding_header, sizeof(c->xhttp_padding_header), "%s",
             cfg->xhttp_padding_header[0] != '\0' ? cfg->xhttp_padding_header : "X-Padding");
    snprintf(c->xhttp_padding_method, sizeof(c->xhttp_padding_method), "%s",
             cfg->xhttp_padding_method[0] != '\0' ? cfg->xhttp_padding_method : "repeat-x");
    c->xhttp_padding_obfs = cfg->xhttp_padding_obfs;
    c->xhttp_padding_min = cfg->xhttp_padding_max ? cfg->xhttp_padding_min : 100;
    c->xhttp_padding_max = cfg->xhttp_padding_max ? cfg->xhttp_padding_max : 1000;
    c->xhttp_max_each_post_bytes=core_xhttp_post_limit(cfg);
    c->xhttp_post_intervals=(core_range_t){cfg->xhttp_min_posts_interval_min,cfg->xhttp_min_posts_interval_max};
    if (c->xhttp_max_each_post_bytes < 0) { set_err(err,err_cap,"XHTTP packet size sampling failed"); return -1; }

    c->xhttp_session_id[0] = '\0';
    if (core_xhttp_session(cfg,c->xhttp_session_id,sizeof(c->xhttp_session_id)) != 0) {
        set_err(err, err_cap, "failed to create xhttp session id");
        return -1;
    }
    return 0;
}

static int xhttp_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->xmux_physical = cfg->xhttp_physical_only;
    if (xhttp_configure(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_XHTTP_PLAIN;
        c->fd = tcp_connect_host(c->remote_host, c->remote_port, !c->ignore_server_ips);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
        vc_log_info("xhttp", "plain mode=%s http=1.1 max_each_post=%d",
                    c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
        if (c->xmux_physical) return 0;
        if (strcmp(c->xhttp_transport_mode, "stream-one") == 0) {
            return xhttp_send_plain_stream_request(c, c->fd, err, err_cap);
        }
        if (xhttp_send_download_request(cfg, c, err, err_cap) != 0) {
            return -1;
        }
        if (strcmp(c->xhttp_transport_mode, "stream-up") == 0) {
            c->xhttp_upload_fd = tcp_connect_host(c->remote_host, c->remote_port, !c->ignore_server_ips);
            if (c->xhttp_upload_fd < 0) {
                set_err(err, err_cap, "xhttp upload tcp connect failed");
                return -1;
            }
            if (xhttp_send_plain_stream_request(c, c->xhttp_upload_fd, err, err_cap) != 0) {
                return -1;
            }
            if (xhttp_start_plain_upload_reader(c) != 0) {
                set_err(err, err_cap, "failed to start xhttp upload stream");
                return -1;
            }
        }
        return 0;
    }

    if (strcmp(cfg->security, "reality") == 0) {
        c->mode = CONN_MODE_XHTTP_REALITY;
        if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
            return -1;
        }

        vc_log_info("xhttp", "reality mode=%s http=2", c->xhttp_transport_mode);
        if (xhttp_h2_start_mode(c, err, err_cap) != 0) {
            return -1;
        }
        return 0;
    }

    c->mode = CONN_MODE_XHTTP_TLS;

    if (xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                           sizeof(c->xhttp_pin_key)) != 0) {
        set_err(err, err_cap, "failed to build xhttp pin key");
        return -1;
    }

    unsigned char xhttp_alpn[32];
    unsigned int xhttp_alpn_len = 0;
    if (build_xhttp_tls_alpn(cfg->alpn, xhttp_alpn, sizeof(xhttp_alpn), &xhttp_alpn_len) != 0) {
        set_err(err, err_cap, "failed to build xhttp TLS ALPN");
        return -1;
    }

    tls_verify_mode_t mode = tls_verify_mode_for_config(cfg);
    c->tls_verify_policy = mode;
    vc_log_info("xhttp", "tls_mode=%s", tls_verify_mode_name(mode));
    if (mode == TLS_VERIFY_MODE_TOFU) {
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, 0, xhttp_alpn, xhttp_alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
        if (xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = tls_verify_peer(mode);
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, verify_peer, xhttp_alpn, xhttp_alpn_len, &c->ssl_ctx, &c->ssl,
                            &c->fd, &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = verify_peer ? 0 : 1;
    }

    if (ssl_selected_alpn_is_h2(c->ssl)) {
        c->mode = CONN_MODE_XHTTP_TLS_H2;
        vc_log_info("xhttp", "tls mode=%s http=2 max_each_post=%d",
                    c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
        if (xhttp_h2_start_mode(c, err, err_cap) != 0) {
            return -1;
        }
        return 0;
    }

    if (!c->xmux_physical && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        set_err(err, err_cap, "xhttp stream-one and stream-up require HTTP/2");
        return -1;
    }
    vc_log_info("xhttp", "tls mode=%s http=1.1 max_each_post=%d",
                c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
    if (c->xmux_physical) return 0;
    if (xhttp_send_download_request(cfg, c, err, err_cap) != 0) {
        return -1;
    }
    return 0;
}

static int grpc_tls_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    if (xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                           sizeof(c->xhttp_pin_key)) != 0) {
        set_err(err, err_cap, "failed to build grpc pin key");
        return -1;
    }

    unsigned char alpn[32];
    unsigned int alpn_len = 0;
    if (build_xhttp_tls_alpn(cfg->alpn, alpn, sizeof(alpn), &alpn_len) != 0) {
        set_err(err, err_cap, "failed to build grpc TLS ALPN");
        return -1;
    }

    tls_verify_mode_t mode = tls_verify_mode_for_config(cfg);
    c->tls_verify_policy = mode;
    if (mode == TLS_VERIFY_MODE_TOFU) {
        vc_log_info("grpc", "tls_mode=tofu");
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, 0, alpn, alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0 ||
            xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = tls_verify_peer(mode);
        vc_log_info("grpc", "tls_mode=%s", tls_verify_mode_name(mode));
        if (open_tls_socket(!c->ignore_server_ips, c->remote_host, c->remote_port, c->remote_sni, verify_peer, alpn, alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = verify_peer ? 0 : 1;
    }

    if (!ssl_selected_alpn_is_h2(c->ssl)) {
        core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,EPROTO)); errno=EPROTO;
        set_err(err, err_cap, "grpc requires HTTP/2 ALPN");
        return -1;
    }
    c->mode = CONN_MODE_XHTTP_TLS_H2;
    return 0;
}

static int grpc_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->grpc_transport = 1;
    c->grpc_physical_only=cfg->grpc_physical_only;
    c->grpc_initial_window=cfg->grpc_initial_window ? (unsigned)cfg->grpc_initial_window : 256U*1024U;
    memcpy(c->grpc_user_agent,cfg->grpc_user_agent,sizeof(c->grpc_user_agent));
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);
    snprintf(c->grpc_service_name, sizeof(c->grpc_service_name), "%s", cfg->grpc_service_name);
    c->grpc_multi_mode = strcmp(cfg->xhttp_mode, "multi") == 0;
    c->grpc_decoder.multi=(unsigned)c->grpc_multi_mode;

    if (cfg->grpc_authority[0] != '\0') {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "%s", cfg->grpc_authority);
    } else if (strcmp(cfg->security, "none") != 0 && c->remote_sni[0] != '\0') {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "%s", c->remote_sni);
    } else if (strchr(c->remote_host, ':') != NULL) {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "[%s]:%u", c->remote_host, (unsigned)c->remote_port);
    } else {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "%s:%u", c->remote_host, (unsigned)c->remote_port);
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_GRPC_PLAIN;
        c->fd = tcp_connect_host(c->remote_host, c->remote_port, !c->ignore_server_ips);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
    } else if (strcmp(cfg->security, "reality") == 0) {
        c->mode = CONN_MODE_XHTTP_REALITY;
        if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
            return -1;
        }
    } else if (grpc_tls_connect(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    if (grpc_h2_start(c, err, err_cap) != 0) {
        return -1;
    }
    vc_log_info("grpc", "connected service=%s authority=%s security=%s mode=%s",
                c->grpc_service_name, c->grpc_authority,
                cfg->security, c->grpc_multi_mode ? "multi" : "single");
    return 0;
}

static int tls13_connect_budgeted(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap,
                                  core_buffer_budget_t *output_memory, core_buffer_budget_t *input_memory) {
    *out = NULL;
    tls13_conn_t *c = (tls13_conn_t *)calloc(1, sizeof(*c));
    if (c == NULL) {
        set_err(err, err_cap, "oom");
        return -1;
    }
    c->fd = -1;
    c->ignore_server_ips=cfg->ignore_server_ips;
    c->xhttp_upload_fd = -1;
    c->mode = CONN_MODE_REALITY;
    c->input_memory=input_memory; c->output_memory=output_memory;
    c->hpack.memory=input_memory;
    if (cfg->xhttp_physical_only || cfg->grpc_physical_only) {
        c->h2_net_cache=(dynbuf_t){.limit=65536,.memory=input_memory};
        c->xmux_raw_input=(dynbuf_t){.limit=65536,.memory=input_memory};
        c->h2_header_block=(dynbuf_t){.limit=1024U*1024U,.memory=input_memory};
        c->app_cache.memory=input_memory; c->app_cache.limit=65536;
        c->xmux_plain_output=(dynbuf_t){.limit=256U*1024U,.memory=output_memory};
        c->xmux_wire_output=(dynbuf_t){.limit=32768,.memory=output_memory};
        c->h2_send_buf=(dynbuf_t){.limit=1024U*1024U,.memory=output_memory};
    }

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        if (!cfg->xhttp_physical_only) {
            c->xmux_stream = core_xmux_connect(cfg, &xmux_backend, err, err_cap);
            if (!c->xmux_stream) { free(c); return -1; }
            c->fd = core_xmux_fd(c->xmux_stream);
            *out = c; return 0;
        }
        if (xhttp_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (cfg->transport_mode == TRANSPORT_GRPC) {
        if (!cfg->grpc_physical_only) {
            c->grpc_transport=1;
            c->grpc_decoder.multi=strcmp(cfg->xhttp_mode,"multi") == 0;
            c->xmux_stream=core_http2_connect(cfg,&xmux_backend,err,err_cap);
            if (!c->xmux_stream) { free(c); return -1; }
            c->fd=core_http2_fd(c->xmux_stream); *out=c; return 0;
        }
        if (grpc_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (cfg->transport_mode == TRANSPORT_WS) {
        if (ws_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_PLAIN;
        c->fd = tcp_connect_host(cfg->server_host, cfg->server_port, !cfg->ignore_server_ips);
        if (c->fd < 0) {
            tls13_reality_close(c);
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
        vc_log_info("tcp", "connected security=none");
        *out = c;
        return 0;
    }

    if (strcmp(cfg->security, "tls") == 0) {
        if (tcp_tls_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
        tls13_reality_close(c);
        return -1;
    }

    *out = c;
    return 0;
}

int tls13_reality_connect(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap) {
    int result=tls13_connect_budgeted(cfg,out,err,err_cap,NULL,NULL);
    int saved=errno;
    core_connection_error_t failure;
    if (result && !core_trace_error_get(&failure)) {
        core_connection_trace_t trace;
        core_trace_stage_t stage=core_trace_snapshot(&trace) && trace.stage != CORE_TRACE_NONE ? trace.stage : CORE_TRACE_TRANSPORT;
        core_trace_error_set(core_connection_error(stage,CORE_FAILURE_SYSTEM,saved ? saved : EIO));
    }
    errno=saved; return result;
}

void tls13_reality_close(tls13_conn_t *c) {
    if (c == NULL) {
        return;
    }
    int saved=errno;
    core_grpc_clear(&c->grpc_decoder); db_free(&c->grpc_net_cache);
    if (c->xmux_stream) { core_xmux_close(c->xmux_stream); db_free(&c->app_cache); OPENSSL_cleanse(c,sizeof(*c)); free(c); errno=saved; return; }
    h2_response_clear(c);
    if (!c->send_closed && c->mode == CONN_MODE_XHTTP_PLAIN && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        int upload_fd = strcmp(c->xhttp_transport_mode, "stream-one") == 0 ? c->fd : c->xhttp_upload_fd;
        if (upload_fd >= 0) {
            (void)write_exact(upload_fd, "0\r\n\r\n", 5);
        }
    }
    if (!c->send_closed && c->grpc_transport && !c->grpc_physical_only && c->h2_stream_id != 0 && c->fd >= 0) {
        (void)h2_send_frame(c, H2_FRAME_DATA, H2_FLAG_END_STREAM, c->h2_stream_id, NULL, 0);
    }
    if (c->xhttp_upload_fd >= 0) {
        pthread_mutex_lock(&g_tls_state_lock); c->xhttp_upload_stopping=1; pthread_mutex_unlock(&g_tls_state_lock);
        shutdown(c->xhttp_upload_fd, SHUT_RDWR);
        if (c->xhttp_upload_reader_started) {
            pthread_join(c->xhttp_upload_reader, NULL);
        }
        close(c->xhttp_upload_fd);
        c->xhttp_upload_fd = -1;
    }
    if (c->ssl != NULL) {
        if (!c->reality_raw_direct) {
            SSL_shutdown(c->ssl);
        }
        SSL_free(c->ssl);
    }
    if (c->ssl_ctx != NULL) {
        SSL_CTX_free(c->ssl_ctx);
    }
    if (c->fd >= 0) {
        close(c->fd);
    }
    core_hpack_clear(&c->hpack);
    X509_free(c->tls_peer_certificate);
    db_free(&c->tls_certificate_message);
    db_free(&c->tls_post_handshake);
    db_free(&c->tls_client_hello); EVP_PKEY_free(c->tls_retry_key);
    db_free(&c->xhttp_net_cache);
    db_free(&c->ws_net_cache);
    db_free(&c->h2_net_cache);
    db_free(&c->h2_send_buf);
    db_free(&c->h2_header_block);
    db_free(&c->transcript);
    db_free(&c->app_cache);
    db_free(&c->xmux_raw_input); db_free(&c->xmux_plain_output); db_free(&c->xmux_wire_output);
    OPENSSL_cleanse(c,sizeof(*c));
    free(c);
    errno=saved;
}

static int reality_write_app_records(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (tls_prepare_app_record(c)) return -1;
        size_t chunk = len - off;
        /*
         * Go/uTLS uses dynamic TLS record sizing and keeps early app records
         * near one TCP MSS. REALITY/Vision peers can be sensitive to this
         * fingerprint, especially for the first VLESS+Vision flush.
         */
        size_t dynamic_limit = (c->c_app_record_bytes < 128 * 1024) ? 1186 : 16384;
        if (chunk > dynamic_limit) {
            chunk = dynamic_limit;
        }
        if (chunk > 16384) {
            chunk = 16384;
        }
        if (c->tls_send_record_limit && chunk >= c->tls_send_record_limit) chunk=c->tls_send_record_limit-1;

        uint8_t *rec = NULL;
        size_t rec_len = 0;
        if (encrypt_record(c, c->c_app_key, c->c_app_iv, &c->c_app_seq, 0x17, buf + off, chunk, &rec, &rec_len) != 0) {
            return -1;
        }
        if (relay_write_wire(c, rec, rec_len) != 0) {
            free(rec);
            return -1;
        }
        c->c_app_record_bytes += rec_len;
        free(rec);
        off += chunk;
    }
    return 0;
}

int tls13_write_app(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    if (c->send_closed || (c->mode == CONN_MODE_WS && (c->ws_close_sent || c->ws_decoder.closed))) return -1;
    if (c->xmux_stream && !c->grpc_transport) return core_xmux_write(c->xmux_stream, buf, len);
    if (c->grpc_transport) {
        return grpc_write_hunk(c, buf, len);
    }

    if (c->mode == CONN_MODE_PLAIN) {
        return relay_write_wire(c,buf,len);
    }

    if (c->mode == CONN_MODE_WS) {
        if (!c->ws_upgraded) {
            char error[160]="WebSocket upgrade failed";
            int early=len && len <= (size_t)c->ws_early_data;
            if (ws_upgrade(c,early ? buf : NULL,early ? len : 0,error,sizeof(error))) {
                vc_log_error("ws","%s",error); return -1;
            }
            if (early) return 0;
        }
        return ws_write_frame(c, 0x2, buf, len);
    }

    if (c->mode == CONN_MODE_XHTTP_PLAIN && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        return xhttp_write_plain_stream(c, buf, len);
    }

    if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
        size_t max_post = c->xhttp_max_each_post_bytes > 0 ? (size_t)c->xhttp_max_each_post_bytes : 1000000U;
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            if (chunk > max_post) {
                chunk = max_post;
            }
            char err[128] = {0};
            if (xhttp_post_packet(c, buf + off, &chunk, err, sizeof(err)) != 0) {
                if (err[0] != '\0') {
                    vc_log_error("xhttp", "upload failed: %s", err);
                }
                return -1;
            }
            off += chunk;
        }
        return 0;
    }

    if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
        if (strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
            return h2_write_data(c, buf, len);
        }
        size_t max_post = c->xhttp_max_each_post_bytes > 0 ? (size_t)c->xhttp_max_each_post_bytes : 1000000U;
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            if (chunk > max_post) {
                chunk = max_post;
            }
            char err[128] = {0};
            if (xhttp_h2_post_packet(c, buf + off, &chunk, err, sizeof(err)) != 0) {
                if (err[0] != '\0') {
                    vc_log_error("xhttp", "h2 upload failed: %s", err);
                }
                return -1;
            }
            off += chunk;
        }
        return 0;
    }

    if (c->mode == CONN_MODE_XHTTP_REALITY) {
        if (strcmp(c->xhttp_transport_mode, "packet-up") == 0) {
            size_t max_post = c->xhttp_max_each_post_bytes > 0 ? (size_t)c->xhttp_max_each_post_bytes : 1000000U;
            size_t off = 0;
            while (off < len) {
                size_t chunk = len - off;
                if (chunk > max_post) {
                    chunk = max_post;
                }
                char err[128] = {0};
                if (xhttp_h2_post_packet(c, buf + off, &chunk, err, sizeof(err)) != 0) {
                    if (err[0] != '\0') {
                        vc_log_error("xhttp", "h2 upload failed: %s", err);
                    }
                    return -1;
                }
                off += chunk;
            }
            return 0;
        }
        return h2_write_data(c, buf, len);
    }
    return reality_write_app_records(c, buf, len);
}

static int relay_read_record(tls13_conn_t *c, uint8_t *type, uint8_t **payload, size_t *length) {
    for (;;) {
        if (c->xmux_raw_input.len >= 5) {
            size_t size=((size_t)c->xmux_raw_input.data[3]<<8)|c->xmux_raw_input.data[4];
            if (c->xmux_raw_input.data[0] != 23 || c->xmux_raw_input.data[1] != 3 || c->xmux_raw_input.data[2] != 3 || size > 16640) return -1;
            if (c->xmux_raw_input.len >= size+5) {
                *payload=malloc(size ? size : 1); if (!*payload) return -1;
                *type=c->xmux_raw_input.data[0]; *length=size;
                memcpy(*payload,c->xmux_raw_input.data+5,size); db_consume(&c->xmux_raw_input,size+5); return 0;
            }
        }
        uint8_t input[16384]; ssize_t received=core_recv(c->fd,input,sizeof(input),MSG_DONTWAIT);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 2;
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return received < 0 || c->xmux_raw_input.len ? -1 : 1;
        if (db_append(&c->xmux_raw_input,input,(size_t)received)) return -1;
    }
}

static int fill_reality_plain_cache(tls13_conn_t *c, dynbuf_t *cache) {
    if (c->receive_closed) return 0;
    for (;;) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        int record_result = c->relay_async ? relay_read_record(c,&rtype,&pl,&pl_len) : read_record(c->fd, &rtype, &pl, &pl_len);
        if (record_result == 2) return 1;
        if (record_result > 0) {
            if (c->tls_post_handshake.len) { vc_log_error("tls","truncated post-handshake message"); return -1; }
            vc_log_error("tls", "peer EOF without close_notify fd=%d", c->fd);
            return -1;
        }
        if (record_result < 0) {
            vc_log_error("tls", "read_record failed in app phase fd=%d errno=%d (%s)", c->fd, errno, strerror(errno));
            return -1;
        }

        if (rtype != 0x17) {
            vc_log_warning("tls", "non-app record type=0x%02x in app phase", rtype);
            free(pl);
            return -1;
        }

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        uint8_t inner = 0;
        if (decrypt_record(c, c->s_app_key, c->s_app_iv, &c->s_app_seq, rtype, pl, pl_len, &dec, &dec_len, &inner) != 0) {
            vc_log_error("tls", "decrypt_record failed in app phase");
            free(pl);
            return -1;
        }
        free(pl);
        int result=tls_application_plain(c,inner,dec,dec_len,cache); free(dec);
        if (result < 0) return -1;
        if (result > 0 || cache->len) return 0;
    }
}

static int fill_reality_app_cache(tls13_conn_t *c) {
    return fill_reality_plain_cache(c, &c->app_cache);
}

int tls13_read_app(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    if (c->xmux_stream && c->grpc_transport) return grpc_pool_read(c,buf,cap,out_len);
    if (c->xmux_stream) return core_xmux_read(c->xmux_stream, buf, cap, out_len);
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }

    if (c->mode == CONN_MODE_PLAIN) {
        return fd_read_some(c->fd, buf, cap, out_len);
    }

    if (c->app_cache.len == 0) {
        if (c->mode == CONN_MODE_WS) {
            int result=ws_fill_app_cache(c);
            if (result) return result;
        } else if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
            int rc = xhttp_fill_app_cache(c);
            if (rc < 0) {
                return c->xhttp_eof ? 0 : -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_GRPC_PLAIN) {
            int rc = h2_fill_app_cache(c);
            if (rc < 0) {
                return c->h2_stream_eof && !c->grpc_read_failed && (!c->grpc_transport || core_grpc_complete(&c->grpc_decoder)) ? 0 : -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_REALITY) {
            int rc = h2_fill_app_cache(c);
            if (rc < 0) {
                return c->h2_stream_eof && !c->grpc_read_failed && (!c->grpc_transport || core_grpc_complete(&c->grpc_decoder)) ? 0 : -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else {
            int result=fill_reality_app_cache(c);
            if (result) return result;
        }
    }

    size_t take = c->app_cache.len;
    if (take > cap) {
        take = cap;
    }
    if (take > 0) memcpy(buf, c->app_cache.data, take);
    db_consume(&c->app_cache, take);
    *out_len = take;
    return 0;
}

int tls13_read_exact_or_eof(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (core_deadline_active() && !core_deadline_remaining()) return -1;
        size_t got = 0;
        int rc = tls13_read_app(c, buf + off, len - off, &got);
        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            if (tls13_flush(c) || (!tls13_has_pending_input(c) && core_wait_socket(c->fd,tls13_needs_write(c) ? POLLOUT : POLLIN,-1) <= 0)) return -1;
            continue;
        }
        if (got == 0) {
            return off ? -1 : 1;
        }
        off += got;
    }
    return 0;
}

int tls13_read_exact_app(tls13_conn_t *c, uint8_t *buf, size_t len) {
    return tls13_read_exact_or_eof(c,buf,len) == 0 ? 0 : -1;
}

int tls13_finish_pending(const tls13_conn_t *c) {
    if (!c) return -1;
    if (c->xmux_stream) {
        int result=core_http2_finish_pending(c->xmux_stream);
        return result < 0 && (c->app_cache.len || (c->grpc_transport && (c->grpc_net_cache.len || core_grpc_pending(&c->grpc_decoder)))) ? 0 : result;
    }
    return c->send_closed && (c->xmux_wire_output.len || c->relay_raw_finish);
}

int tls13_full_close(const tls13_conn_t *c) {
    return c && c->mode == CONN_MODE_WS && c->ws_decoder.closed;
}

int tls13_finish_write(tls13_conn_t *c, int raw) {
    if (!c) return -1;
    if (c->send_closed) return 0;
    int result=0;
    if (c->xmux_stream) result=core_http2_finish_write(c->xmux_stream);
    else if (c->mode == CONN_MODE_PLAIN || raw) {
        if (c->relay_async) c->relay_raw_finish=1;
        else result=shutdown(c->fd,SHUT_WR);
    }
    else if (c->mode == CONN_MODE_WS) {
        const uint8_t code[]={3,0xe8};
        if (!c->ws_close_sent) result=ws_write_frame(c,8,code,sizeof(code));
        if (!result) c->ws_close_sent=1;
    } else if (c->mode == CONN_MODE_XHTTP_PLAIN) {
        if (strcmp(c->xhttp_transport_mode,"packet-up")) {
            int fd=!strcmp(c->xhttp_transport_mode,"stream-up") ? c->xhttp_upload_fd : c->fd;
            result=fd < 0 ? -1 : write_exact(fd,"0\r\n\r\n",5);
        }
    } else if (c->grpc_transport || tls13_uses_h2(c)) {
        if (strcmp(c->xhttp_transport_mode,"packet-up")) {
            uint32_t stream=!strcmp(c->xhttp_transport_mode,"stream-up") ? c->h2_upload_stream_id : c->h2_stream_id;
            result=stream ? h2_send_frame(c,H2_FRAME_DATA,H2_FLAG_END_STREAM,stream,NULL,0) : -1;
        }
    } else if (c->mode == CONN_MODE_TLS || c->mode == CONN_MODE_REALITY) {
        const uint8_t alert[]={1,0}; uint8_t *record=NULL; size_t length=0;
        result=encrypt_record(c,c->c_app_key,c->c_app_iv,&c->c_app_seq,21,alert,sizeof(alert),&record,&length);
        if (!result) result=relay_write_wire(c,record,length);
        free(record);
    }
    if (!result) {
        c->send_closed=1;
        for (h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next) entry->request_ended=1;
    }
    return result;
}

static int xmux_transport_open_budgeted(const vless_config_t *config, void **output, int *http2, char *error, size_t capacity,
                                       core_buffer_budget_t *upload, core_buffer_budget_t *download) {
    vless_config_t physical_config=*config;
    physical_config.xmux.present=0; physical_config.xhttp_physical_only=1;
    physical_config.grpc_physical_only=config->transport_mode == TRANSPORT_GRPC;
    tls13_conn_t *connection=NULL;
    if (tls13_connect_budgeted(&physical_config,&connection,error,capacity,upload,download) != 0) return -1;
    *output=connection; *http2=tls13_uses_h2(connection);
    if (!*http2) connection->h2_next_stream_id=3;
    int flags=fcntl(connection->fd,F_GETFL,0);
    if (flags < 0 || fcntl(connection->fd,F_SETFL,flags|O_NONBLOCK) != 0) return -1;
    if (connection->ssl) SSL_set_mode(connection->ssl,SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
    connection->xmux_async=1;
    return 0;
}

static int xmux_transport_open(const vless_config_t *config, void **output, int *http2, char *error, size_t capacity) {
    return xmux_transport_open_budgeted(config,output,http2,error,capacity,NULL,NULL);
}

static void xmux_transport_close(void *opaque) { tls13_reality_close(opaque); }
static int xmux_transport_fd(void *opaque) { return ((tls13_conn_t *)opaque)->fd; }
static size_t xmux_transport_pending(void *opaque) {
    tls13_conn_t *connection=opaque;
    return connection->xmux_plain_output.len+connection->xmux_wire_output.len;
}
static uint64_t xmux_transport_enqueued(void *opaque) { return ((tls13_conn_t *)opaque)->xmux_enqueued; }
static uint64_t xmux_transport_flushed(void *opaque) { return ((tls13_conn_t *)opaque)->xmux_flushed; }

static short xmux_transport_events(void *opaque) {
    tls13_conn_t *connection=opaque;
    short input=tls13_uses_h2(connection) || (!connection->xmux_http1_eof && connection->h2_net_cache.len < 65536) ? POLLIN : 0;
    return (short)(input|((xmux_transport_pending(connection) && !connection->xmux_write_wants_read) || connection->xmux_read_wants_write ? POLLOUT : 0));
}

static int xmux_transport_send_frame(void *opaque, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t *data, size_t length) {
    tls13_conn_t *connection=opaque;
    if (tls13_uses_h2(connection)) return h2_send_frame(connection,type,flags,stream,data,length);
    if (type == 8) return 0;
    if (type == 3) { shutdown(connection->fd,SHUT_RDWR); return 0; }
    if (type != 0 || stream != connection->xmux_http1_id || connection->xmux_plain_output.len+length+32 > 256U*1024U) return -1;
    size_t before=connection->xmux_plain_output.len;
    int result=0;
    if (connection->xmux_http1_role == 1 || connection->xmux_http1_role == 2 || connection->xmux_http1_role == 4) {
        char chunk[32]; int size=snprintf(chunk,sizeof(chunk),"%zx\r\n",length);
        if (size < 0 || (size_t)size >= sizeof(chunk)) return -1;
        result=db_append(&connection->xmux_plain_output,chunk,(size_t)size);
    }
    if (!result) result=db_append(&connection->xmux_plain_output,data,length);
    if (!result && (connection->xmux_http1_role == 1 || connection->xmux_http1_role == 2 || connection->xmux_http1_role == 4)) result=db_append(&connection->xmux_plain_output,"\r\n",2);
    if (!result && connection->xmux_http1_role == 4 && length && (flags&1)) result=db_append(&connection->xmux_plain_output,"0\r\n\r\n",5);
    if (!result) connection->xmux_enqueued+=connection->xmux_plain_output.len-before;
    return result;
}

static int xmux_transport_flush(void *opaque) {
    tls13_conn_t *connection=opaque;
    if (connection->mode == CONN_MODE_XHTTP_PLAIN || connection->mode == CONN_MODE_GRPC_PLAIN) {
        if (!connection->xmux_plain_output.len) return 0;
        ssize_t written=core_send(connection->fd,connection->xmux_plain_output.data,connection->xmux_plain_output.len,MSG_DONTWAIT);
        if (written > 0) { db_consume(&connection->xmux_plain_output,(size_t)written); connection->xmux_flushed+=(size_t)written; }
        else if (!written || (errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
        return 0;
    }
    if (connection->ssl) {
        if (!connection->xmux_plain_output.len) return 0;
        if (!connection->xmux_ssl_write_length) connection->xmux_ssl_write_length=connection->xmux_plain_output.len > 16384 ? 16384 : connection->xmux_plain_output.len;
        ERR_clear_error();
        int result=SSL_write(connection->ssl,connection->xmux_plain_output.data,(int)connection->xmux_ssl_write_length);
        if (result > 0) { db_consume(&connection->xmux_plain_output,(size_t)result); connection->xmux_flushed+=(size_t)result; connection->xmux_ssl_write_length=0; connection->xmux_write_wants_read=0; return 0; }
        int error=SSL_get_error(connection->ssl,result);
        connection->xmux_write_wants_read=error == SSL_ERROR_WANT_READ;
        return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? 0 : -1;
    }
    if (!connection->xmux_wire_output.len && connection->xmux_plain_output.len) {
        if (tls_prepare_app_record(connection)) return -1;
        if (connection->xmux_wire_output.len) return 0;
        size_t limit=connection->c_app_record_bytes < 128U*1024U ? 1186 : 16384;
        if (connection->tls_send_record_limit && limit >= connection->tls_send_record_limit) limit=connection->tls_send_record_limit-1;
        size_t length=connection->xmux_plain_output.len < limit ? connection->xmux_plain_output.len : limit;
        uint8_t *record=NULL; size_t record_length=0;
        size_t temporary=2*(length+22);
        if (connection->output_memory && core_buffer_hold(connection->output_memory,temporary)) return -1;
        if (encrypt_record(connection,connection->c_app_key,connection->c_app_iv,&connection->c_app_seq,0x17,
                           connection->xmux_plain_output.data,length,&record,&record_length) != 0) {
            if (connection->output_memory) core_buffer_drop(connection->output_memory,temporary);
            return -1;
        }
        int result=db_append(&connection->xmux_wire_output,record,record_length); free(record);
        if (connection->output_memory) core_buffer_drop(connection->output_memory,temporary);
        if (result != 0) return -1;
        connection->xmux_wire_plain_length=length;
        db_consume(&connection->xmux_plain_output,length);
    }
    if (connection->xmux_wire_output.len) {
        ssize_t written=core_send(connection->fd,connection->xmux_wire_output.data,connection->xmux_wire_output.len,MSG_DONTWAIT);
        if (written > 0) {
            db_consume(&connection->xmux_wire_output,(size_t)written); connection->c_app_record_bytes+=(size_t)written;
            if (!connection->xmux_wire_output.len) { connection->xmux_flushed+=connection->xmux_wire_plain_length; connection->xmux_wire_plain_length=0; }
        }
        else if (!written || (errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
    }
    return 0;
}

static int xmux_transport_collect(void *opaque) {
    tls13_conn_t *connection=opaque;
    if (tls13_uses_h2(connection) && h2_cached_frame_ready(connection)) return 1;
    if (connection->mode == CONN_MODE_GRPC_PLAIN) {
        if (h2_cached_frame_ready(connection)) return 1;
        uint8_t input[8192];
        ssize_t received=core_recv(connection->fd,input,sizeof(input),MSG_DONTWAIT);
        if (received > 0) return db_append(&connection->h2_net_cache,input,(size_t)received);
        return received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    }
    if (!tls13_uses_h2(connection)) {
        if (connection->h2_net_cache.len >= 65536 || connection->xmux_http1_eof) return 0;
        uint8_t data[16384]; int size;
        size_t capacity=65536-connection->h2_net_cache.len;
        if (capacity > sizeof(data)) capacity=sizeof(data);
        if (connection->ssl) {
            ERR_clear_error();
            size=SSL_read(connection->ssl,data,(int)capacity);
            if (size <= 0) {
                int error=SSL_get_error(connection->ssl,size);
                connection->xmux_read_wants_write=error == SSL_ERROR_WANT_WRITE;
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return 0;
                if (error != SSL_ERROR_ZERO_RETURN && !(error == SSL_ERROR_SYSCALL && !size)) {
                    unsigned long detail=ERR_peek_last_error();
                    const char *reason=detail ? ERR_reason_error_string(detail) : NULL;
                    vc_log_warning("xhttp","HTTP/1.1 TLS receive error=%d errno=%d reason=%s",error,errno,reason ? reason : "none");
                    return -1;
                }
            }
        } else {
            size=(int)core_recv(connection->fd,data,capacity,MSG_DONTWAIT);
            if (size < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
        }
        if (size > 0) return db_append(&connection->h2_net_cache,data,(size_t)size);
        connection->xmux_http1_eof=1; return 0;
    }
    if (connection->ssl) return h2_collect_tls_available(connection,&connection->xmux_read_wants_write);
    uint8_t input[16384];
    for (unsigned reads=0;reads<64;reads++) {
        while (connection->xmux_raw_input.len >= 5) {
            const uint8_t *record=connection->xmux_raw_input.data;
            size_t length=((size_t)record[3]<<8)|record[4];
            if (record[0] != 23 || record[1] != 3 || record[2] != 3 || length > 16640) return -1;
            if (connection->xmux_raw_input.len < length+5) break;
            if (record[0] == 0x17) {
                uint8_t *plain=NULL,inner=0; size_t plain_length=0;
                size_t temporary=2U*16640U;
                if (connection->input_memory && core_buffer_hold(connection->input_memory,temporary)) return -1;
                if (decrypt_record(connection,connection->s_app_key,connection->s_app_iv,&connection->s_app_seq,record[0],record+5,length,
                                   &plain,&plain_length,&inner) != 0) {
                    if (connection->input_memory) core_buffer_drop(connection->input_memory,temporary);
                    return -1;
                }
                int result=tls_application_plain(connection,inner,plain,plain_length,&connection->h2_net_cache);
                free(plain); if (connection->input_memory) core_buffer_drop(connection->input_memory,temporary);
                if (result != 0) return -1;
            }
            db_consume(&connection->xmux_raw_input,length+5);
            if (h2_cached_frame_ready(connection)) return 1;
        }
        ssize_t length=core_recv(connection->fd,input,sizeof(input),MSG_DONTWAIT);
        if (length > 0) { if (db_append(&connection->xmux_raw_input,input,(size_t)length) != 0) return -1; }
        else if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        else return -1;
    }
    return 0;
}

static int xmux_transport_read_frame(void *opaque, core_xmux_frame_t *frame, size_t capacity) {
    tls13_conn_t *connection=opaque;
    memset(frame,0,sizeof(*frame));
    if (!tls13_uses_h2(connection)) {
        if (!connection->xmux_http1_id) {
            if (connection->xmux_http1_eof && !connection->xmux_http1_eof_notified) { connection->xmux_http1_eof_notified=1; frame->event=4; return 0; }
            return 1;
        }
        core_http1_event_t event;
        int result=core_http1_next(&connection->xmux_http1_response,connection->h2_net_cache.data,connection->h2_net_cache.len,
                                   connection->xmux_http1_eof,capacity,&event);
        if (result < 0) vc_log_error("xhttp","%s response failed: invalid or truncated HTTP/1.1 response",
                                     connection->xmux_http1_role ? "upload" : "download");
        if (!result) {
            frame->event=event.kind; frame->status=event.status; frame->close_connection=event.close_connection;
            frame->id=connection->xmux_http1_id; frame->length=event.length;
            if (event.length) {
                if (connection->input_memory && core_buffer_hold(connection->input_memory,event.length)) return -1;
                frame->data=malloc(event.length);
                if (!frame->data) { if (connection->input_memory) core_buffer_drop(connection->input_memory,event.length); return -1; }
                memcpy(frame->data,connection->h2_net_cache.data+event.offset,event.length);
            }
            if (event.kind == 3) connection->xmux_http1_id=0;
        }
        db_consume(&connection->h2_net_cache,event.consumed); return result;
    }
    if (connection->h2_net_cache.len >= 9 && (connection->h2_net_cache.data[0] ||
        (((unsigned)connection->h2_net_cache.data[1]<<8)|connection->h2_net_cache.data[2]) > 16384)) return -1;
    if (!h2_cached_frame_ready(connection)) return 1;
    if (!connection->h2_net_cache.data[3]) {
        size_t length=((size_t)connection->h2_net_cache.data[0]<<16)|((size_t)connection->h2_net_cache.data[1]<<8)|connection->h2_net_cache.data[2];
        if (length > capacity) return 1;
    }
    size_t length=((size_t)connection->h2_net_cache.data[0]<<16)|((size_t)connection->h2_net_cache.data[1]<<8)|connection->h2_net_cache.data[2];
    if (connection->input_memory && core_buffer_hold(connection->input_memory,length)) return -1;
    int result=h2_read_frame(connection,&frame->type,&frame->flags,&frame->id,&frame->data,&frame->length);
    if (result && connection->input_memory) core_buffer_drop(connection->input_memory,length);
    return result;
}

static void xmux_transport_release_frame(void *opaque, core_http2_frame_t *frame) {
    tls13_conn_t *connection=opaque;
    free(frame->data);
    if (connection->input_memory && frame->length) core_buffer_drop(connection->input_memory,frame->length);
}

static int xmux_transport_request(void *opaque, const vless_config_t *config, const char *session, uint64_t sequence,
                                  int role, const uint8_t *data, size_t length, uint32_t *id, uint32_t header_limit, size_t *consumed, size_t *body_size) {
    tls13_conn_t *physical=opaque;
    tls13_conn_t request=*physical;
    request.h2_send_buf=(dynbuf_t){.limit=1024U*1024U,.memory=physical->output_memory}; request.xmux_owner=physical;
    if (config->transport_mode == TRANSPORT_GRPC) {
        if (role != 1 || physical->h2_next_stream_id > 0x7ffffffdU) return -1;
        *id=request.h2_stream_id=physical->h2_next_stream_id; physical->h2_next_stream_id+=2;
        char error[160]={0};
        int result=h2_send_grpc_request_headers(&request,error,sizeof(error));
        db_free(&request.h2_send_buf); *consumed=0; *body_size=0; return result;
    }
    char error[160];
    if (xhttp_configure(config,&request,error,sizeof(error)) != 0) return -1;
    if (strlen(session) >= sizeof(request.xhttp_session_id)) return -1;
    memcpy(request.xhttp_session_id,session,strlen(session)+1);
    char path[2048],headers[16384],seq[32];
    snprintf(seq,sizeof(seq),"%llu",(unsigned long long)sequence);
    core_xhttp_payload_t packet={0};
    if (role == 3 || role == 4) {
        if (xhttp_packet_headers(&request,seq,data,length,header_limit,path,&packet,error,sizeof(error)) != 0) { vc_log_warning("xhttp","%s",error); return -1; }
        *consumed=packet.consumed; *body_size=packet.body_size;
        if (role == 4) { *consumed=0; *body_size=SIZE_MAX; }
    } else if (xhttp_prepare_request(&request,"",path,sizeof(path),headers,sizeof(headers)) != 0) return -1;
    if (physical->h2_next_stream_id > 0x7ffffffdU) { core_xhttp_payload_clear(&packet); return -1; }
    *id=physical->h2_next_stream_id; physical->h2_next_stream_id+=2;
    const char *method=role == 0 ? "GET" : request.xhttp_uplink_method;
    if (!tls13_uses_h2(physical)) {
        if (physical->xmux_http1_id || physical->h2_net_cache.len || physical->xmux_http1_eof) { core_xhttp_payload_clear(&packet); return -1; }
        if (role == 3 || role == 4) {
            dynbuf_t message={.limit=256U*1024U,.memory=physical->output_memory};
            int result=role == 4 ? xhttp_http1_headers(&request,method,path,packet.headers,3,0,config->xmux.present ? "keep-alive" : "close",&message) :
                xhttp_http1_packet_request(&request,path,packet.headers,packet.body_size,config->xmux.present ? "keep-alive" : "close",&message);
            if (!result) { result=db_append(&physical->xmux_plain_output,message.data,message.len); if (!result) physical->xmux_enqueued+=message.len; }
            db_free(&message); core_xhttp_payload_clear(&packet);
            if (result) return -1;
            physical->xmux_http1_response=(core_http1_response_t){0};
            physical->xmux_http1_id=*id; physical->xmux_http1_role=role; return 0;
        }
        dynbuf_t message={.limit=256U*1024U,.memory=physical->output_memory};
        int result=xhttp_http1_headers(&request,method,path,headers,role == 0 ? 0 : 2,0,role == 0 ? "keep-alive" : "close",&message);
        if (!result) { result=db_append(&physical->xmux_plain_output,message.data,message.len); if (!result) physical->xmux_enqueued+=message.len; }
        db_free(&message); if (result) return -1;
        physical->xmux_http1_response=(core_http1_response_t){0};
        physical->xmux_http1_id=*id; physical->xmux_http1_role=role; return 0;
    }
    int has_body=role == 4 || (role == 3 ? packet.body_size != 0 : role != 0);
    int streaming=role == 4 ? 2 : role != 0 && role != 3;
    int result=h2_send_xhttp_request_headers(&request,*id,method,path,role == 3 || role == 4 ? packet.headers : headers,role == 3 ? packet.body_size : length,has_body,streaming,error,sizeof(error));
    core_xhttp_payload_clear(&packet); db_free(&request.h2_send_buf); return result;
}

static int xmux_transport_session(const vless_config_t *config, char *session, size_t capacity) {
    tls13_conn_t connection={0}; char error[160];
    if (xhttp_configure(config,&connection,error,sizeof(error)) != 0 || strlen(connection.xhttp_session_id) >= capacity) return -1;
    memcpy(session,connection.xhttp_session_id,strlen(connection.xhttp_session_id)+1); return 0;
}

static const core_xmux_backend_t xmux_backend={
    .open=xmux_transport_open,.close=xmux_transport_close,.fd=xmux_transport_fd,.events=xmux_transport_events,.collect=xmux_transport_collect,
    .open_budgeted=xmux_transport_open_budgeted,.release_frame=xmux_transport_release_frame,
    .read_frame=xmux_transport_read_frame,.send_frame=xmux_transport_send_frame,.flush=xmux_transport_flush,
    .pending=xmux_transport_pending,.enqueued=xmux_transport_enqueued,.flushed=xmux_transport_flushed,.request=xmux_transport_request,.session=xmux_transport_session,
};
