#define _POSIX_C_SOURCE 200112L

#include "socket_util.h"
#include "tls13_reality.h"

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
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
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
    XHTTP_TLS_MODE_AUTO = 0,
    XHTTP_TLS_MODE_STRICT = 1,
    XHTTP_TLS_MODE_INSECURE = 2,
    XHTTP_TLS_MODE_TOFU = 3
} xhttp_tls_mode_t;

typedef enum {
    TLS_CIPHER_OFFER_CHACHA = 0,
    TLS_CIPHER_OFFER_AES = 1
} tls_cipher_offer_t;

#define CORE_CONNECT_TIMEOUT_MS 12000
#define CORE_TLS_HANDSHAKE_TIMEOUT_MS 12000
#define CORE_OPENSSL_GROUPS "X25519:P-256:P-384"
#define TLS_AES_FALLBACK_CACHE_SIZE 16
#define TLS_ENDPOINT_CACHE_SIZE 16
#define XRAY_DEFAULT_VERSION_X 26
#define XRAY_DEFAULT_VERSION_Y 3
#define XRAY_DEFAULT_VERSION_Z 27

static int g_xhttp_auto_force_insecure = 0;
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

static tls_aes_fallback_entry_t g_tls_aes_fallback_cache[TLS_AES_FALLBACK_CACHE_SIZE];
static size_t g_tls_aes_fallback_count = 0;
static tls_endpoint_entry_t g_tls_endpoint_cache[TLS_ENDPOINT_CACHE_SIZE];
static size_t g_tls_endpoint_replace_index = 0;
static pthread_mutex_t g_tls_state_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_tls_cipher_logged = 0;

struct tls13_conn {
    int fd;
    conn_mode_t mode;
    int xhttp_upload_fd;
    pthread_t xhttp_upload_reader;
    int xhttp_upload_reader_started;

    uint8_t auth_key[32];

    uint16_t tls_cipher_suite;
    const EVP_MD *tls_md;
    size_t tls_hash_len;
    size_t tls_key_len;

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
    char xhttp_session_id[64];
    char xhttp_session_placement[16];
    char xhttp_session_key[64];
    char xhttp_seq_placement[16];
    char xhttp_seq_key[64];
    char xhttp_uplink_method[8];
    char xhttp_padding_placement[16];
    char xhttp_padding_key[64];
    char xhttp_padding_header[64];
    char xhttp_padding_method[16];
    int xhttp_padding_obfs;
    int xhttp_padding_min;
    int xhttp_padding_max;
    int xhttp_max_each_post_bytes;
    uint64_t xhttp_seq;
    int xhttp_chunked;
    int64_t xhttp_content_rem;
    int64_t xhttp_chunk_rem;
    int xhttp_eof;
    int xhttp_headers_read;
    int xhttp_tls_insecure;
    char xhttp_pin_key[320];
    char tls_verify_mode[16];
    int tls_use_aes_fallback;
    char ws_path[512];
    char ws_host[320];
    char grpc_service_name[256];
    char grpc_authority[320];
    int grpc_transport;
    int grpc_multi_mode;

    dynbuf_t xhttp_net_cache;
    dynbuf_t ws_net_cache;
    dynbuf_t h2_net_cache;
    dynbuf_t h2_send_buf;
    dynbuf_t grpc_recv_cache;
    dynbuf_t transcript;
    dynbuf_t app_cache;
    int reality_raw_direct;

    uint32_t h2_stream_id;
    uint32_t h2_next_stream_id;
    uint32_t h2_peer_initial_window;
    uint32_t h2_peer_max_frame_size;
    int64_t h2_peer_conn_window;
    int64_t h2_peer_stream_window;
    int64_t h2_peer_conn_refill_target;
    int64_t h2_peer_stream_refill_target;
    uint32_t h2_upload_stream_id;
    int64_t h2_upload_stream_window;
    int64_t h2_upload_stream_refill_target;
    uint32_t h2_recv_conn_pending;
    uint32_t h2_recv_stream_pending;
    int h2_stream_eof;
};

static int reality_write_app_records(tls13_conn_t *c, const uint8_t *buf, size_t len);
static int fill_reality_plain_cache(tls13_conn_t *c, dynbuf_t *cache);
static int h2_pump_one_frame(tls13_conn_t *c);
static int h2_cached_frame_ready(const tls13_conn_t *c);

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
        if (tls_aes_fallback_entry_matches(&g_tls_aes_fallback_cache[i], host, port, sni)) {
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
        if (tls_aes_fallback_entry_matches(&g_tls_aes_fallback_cache[i], host, port, sni)) {
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
        fprintf(stderr, "[tls] selected cipher=%s\n", cipher != NULL ? cipher : "unknown");
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
    if (b->len + n <= b->cap) {
        return 0;
    }
    size_t nc = (b->cap == 0) ? 1024 : b->cap;
    while (nc < b->len + n) {
        nc *= 2;
    }
    uint8_t *tmp = (uint8_t *)realloc(b->data, nc);
    if (tmp == NULL) {
        return -1;
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

static void db_consume(dynbuf_t *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

static void db_free(dynbuf_t *b) {
    if (b->data != NULL) {
        free(b->data);
    }
    memset(b, 0, sizeof(*b));
}

static int write_exact(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, 0);
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
        ssize_t n = recv(fd, p + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int tcp_connect_host(const char *host, uint16_t port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        core_tune_tcp_socket(fd);
        if (core_connect_with_timeout(fd, it->ai_addr, (socklen_t)it->ai_addrlen, CORE_CONNECT_TIMEOUT_MS) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
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
    close(fd);
    return -1;
}

static int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, p + off, (int)(len - off));
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
    int n = SSL_read(ssl, buf, (int)cap);
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
    ssize_t n = recv(fd, buf, cap, 0);
    if (n <= 0) {
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

static int normalize_xhttp_path(const char *in, char *out, size_t out_cap) {
    if (out_cap < 3) {
        return -1;
    }
    const char *src = (in != NULL && in[0] != '\0') ? in : "/";
    if (src[0] == '/') {
        snprintf(out, out_cap, "%s", src);
    } else {
        snprintf(out, out_cap, "/%s", src);
    }
    size_t n = strlen(out);
    if (n == 0) {
        snprintf(out, out_cap, "/");
        n = 1;
    }
    if (out[n - 1] != '/') {
        if (n + 1 >= out_cap) {
            return -1;
        }
        out[n] = '/';
        out[n + 1] = '\0';
    }
    return 0;
}

static int random_session_id(char out[64]) {
    uint8_t r[16];
    if (RAND_bytes(r, sizeof(r)) != 1) {
        return -1;
    }
    snprintf(out, 64, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", r[0], r[1], r[2], r[3], r[4],
             r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
    return 0;
}

static int random_range_int(int min, int max) {
    if (min <= 0) {
        min = 1;
    }
    if (max < min) {
        max = min;
    }
    uint32_t r = 0;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) {
        return min;
    }
    return min + (int)(r % (uint32_t)(max - min + 1));
}

static int random_xpadding_value(int min_len, int max_len, const char *method, char *buf, size_t cap) {
    if (buf == NULL || cap < 2) {
        return -1;
    }
    if (min_len <= 0) {
        min_len = 100;
    }
    if (max_len < min_len) {
        max_len = min_len;
    }

    int target = random_range_int(min_len, max_len);
    int len = target;
    (void)method;
    if (len <= 0 || (size_t)len + 1 > cap) {
        return -1;
    }

    memset(buf, 'X', (size_t)len);
    buf[len] = '\0';
    return 0;
}

static int is_cert_verify_error_msg(const char *err) {
    if (err == NULL || err[0] == '\0') {
        return 0;
    }
    return strstr(err, "certificate verify failed") != NULL || strstr(err, "unable to get local issuer") != NULL ||
           strstr(err, "self signed certificate") != NULL || strstr(err, "self-signed certificate") != NULL ||
           strstr(err, "hostname mismatch") != NULL || strstr(err, "no trusted CA bundle") != NULL;
}

static xhttp_tls_mode_t get_xhttp_tls_mode(void) {
    const char *v = getenv("VLESS_XHTTP_TLS_MODE");
    if (v == NULL || v[0] == '\0') {
        return XHTTP_TLS_MODE_AUTO;
    }
    if (strcmp(v, "strict") == 0) {
        return XHTTP_TLS_MODE_STRICT;
    }
    if (strcmp(v, "insecure") == 0) {
        return XHTTP_TLS_MODE_INSECURE;
    }
    if (strcmp(v, "tofu") == 0) {
        return XHTTP_TLS_MODE_TOFU;
    }
    return XHTTP_TLS_MODE_AUTO;
}

static const char *xhttp_tls_mode_name(xhttp_tls_mode_t mode) {
    switch (mode) {
    case XHTTP_TLS_MODE_STRICT:
        return "strict";
    case XHTTP_TLS_MODE_INSECURE:
        return "insecure";
    case XHTTP_TLS_MODE_TOFU:
        return "tofu";
    case XHTTP_TLS_MODE_AUTO:
    default:
        return "auto";
    }
}

static void xhttp_log_tls_mode_selected(xhttp_tls_mode_t mode, int verify_peer) {
    if (mode == XHTTP_TLS_MODE_AUTO) {
        fprintf(stderr, "[xhttp] tls_mode=auto(selected=%s)\n", verify_peer ? "strict" : "insecure+tofu");
        return;
    }
    fprintf(stderr, "[xhttp] tls_mode=%s\n", xhttp_tls_mode_name(mode));
}

static int xhttp_effective_verify_peer(void) {
    xhttp_tls_mode_t mode = get_xhttp_tls_mode();
    if (mode == XHTTP_TLS_MODE_STRICT) {
        return 1;
    }
    if (mode == XHTTP_TLS_MODE_INSECURE) {
        return 0;
    }
    if (mode == XHTTP_TLS_MODE_TOFU) {
        return 0;
    }
    return g_xhttp_auto_force_insecure ? 0 : 1;
}

static int xhttp_auto_fallback_allowed(void) {
    return get_xhttp_tls_mode() == XHTTP_TLS_MODE_AUTO;
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

static int add_path_if_missing(const char **paths, size_t *n, size_t cap, const char *path) {
    if (path == NULL || path[0] == '\0' || *n >= cap) {
        return -1;
    }
    for (size_t i = 0; i < *n; i++) {
        if (strcmp(paths[i], path) == 0) {
            return 0;
        }
    }
    paths[*n] = path;
    (*n)++;
    return 0;
}

static size_t xhttp_collect_pin_paths(const char **paths, size_t cap) {
    size_t n = 0;
    const char *env_path = getenv("VLESS_XHTTP_PIN_FILE");
    (void)add_path_if_missing(paths, &n, cap, env_path);
    (void)add_path_if_missing(paths, &n, cap, "/var/mobile/Library/Preferences/vless-core/xhttp-pins.txt");
    (void)add_path_if_missing(paths, &n, cap, "/tmp/vless-core-xhttp-pins.txt");
    return n;
}

static int xhttp_lookup_pin_in_file(const char *path, const char *key, char pin_hex[65]) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        char file_key[512];
        char file_pin[130];
        if (sscanf(line, "%511s %129s", file_key, file_pin) != 2) {
            continue;
        }
        if (strcmp(file_key, key) != 0) {
            continue;
        }
        if (strlen(file_pin) != 64) {
            continue;
        }
        int ok = 1;
        for (size_t i = 0; i < 64; i++) {
            if (!isxdigit((unsigned char)file_pin[i])) {
                ok = 0;
                break;
            }
        }
        if (!ok) {
            continue;
        }
        memcpy(pin_hex, file_pin, 64);
        pin_hex[64] = '\0';
        ascii_lower(pin_hex);
        fclose(f);
        return 0;
    }

    fclose(f);
    return 1;
}

static int xhttp_load_pin(const char *key, char pin_hex[65]) {
    const char *paths[4] = {0};
    size_t n = xhttp_collect_pin_paths(paths, sizeof(paths) / sizeof(paths[0]));
    for (size_t i = 0; i < n; i++) {
        if (xhttp_lookup_pin_in_file(paths[i], key, pin_hex) == 0) {
            return 0;
        }
    }
    return 1;
}

static int ensure_parent_dirs(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    char tmp[1024];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, path, n + 1);

    for (size_t i = 1; i < n; i++) {
        if (tmp[i] != '/') {
            continue;
        }
        tmp[i] = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        tmp[i] = '/';
    }
    return 0;
}

static int xhttp_store_pin(const char *key, const char *pin_hex, char *err, size_t err_cap) {
    const char *paths[4] = {0};
    size_t n = xhttp_collect_pin_paths(paths, sizeof(paths) / sizeof(paths[0]));

    for (size_t i = 0; i < n; i++) {
        char existing[65];
        if (xhttp_lookup_pin_in_file(paths[i], key, existing) == 0) {
            if (strcmp(existing, pin_hex) == 0) {
                return 0;
            }
            set_err(err, err_cap, "TOFU pin mismatch");
            return -1;
        }

        if (ensure_parent_dirs(paths[i]) != 0) {
            continue;
        }

        FILE *f = fopen(paths[i], "a");
        if (f == NULL) {
            continue;
        }
        int wr = fprintf(f, "%s %s\n", key, pin_hex);
        int fl = fflush(f);
        fclose(f);
        if (wr > 0 && fl == 0) {
            return 0;
        }
    }

    set_err(err, err_cap, "failed to persist TOFU pin (set VLESS_XHTTP_PIN_FILE)");
    return -1;
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

static int tofu_verify_or_store_pin(const char *log_prefix, const char *pin_key, const char *peer_pin, int log_ok, char *err, size_t err_cap) {
    char known_pin[65];
    if (xhttp_load_pin(pin_key, known_pin) == 0) {
        if (strcmp(known_pin, peer_pin) != 0) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "TOFU pin mismatch for %s", pin_key);
            }
            return -1;
        }
        if (log_ok) {
            fprintf(stderr, "%s TOFU pin verified for %s\n", log_prefix, pin_key);
        }
        return 0;
    }

    if (xhttp_store_pin(pin_key, peer_pin, err, err_cap) != 0) {
        return -1;
    }
    if (log_ok) {
        fprintf(stderr, "%s TOFU pin learned for %s\n", log_prefix, pin_key);
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
    if (tls_peer_leaf_pin_hex(ssl, peer_pin, err, err_cap) != 0) {
        return -1;
    }

    return tofu_verify_or_store_pin("[xhttp]", pin_key, peer_pin, log_ok, err, err_cap);
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
    int want_h2 = 0;
    int want_h1 = 0;
    if (cfg_alpn == NULL || cfg_alpn[0] == '\0') {
        want_h2 = 1;
        want_h1 = 1;
    } else {
        want_h2 = alpn_csv_has_token(cfg_alpn, "h2");
        want_h1 = alpn_csv_has_token(cfg_alpn, "http/1.1");
        if (!want_h2 && !want_h1) {
            want_h2 = 1;
            want_h1 = 1;
        }
    }

    *out_len = 0;
    if (want_h2 && append_alpn_token(out, cap, out_len, "h2") != 0) {
        return -1;
    }
    if (want_h1 && append_alpn_token(out, cap, out_len, "http/1.1") != 0) {
        return -1;
    }
    return *out_len > 0 ? 0 : -1;
}

static int ssl_selected_alpn_is_h2(SSL *ssl) {
    const unsigned char *selected = NULL;
    unsigned int selected_len = 0;
    SSL_get0_alpn_selected(ssl, &selected, &selected_len);
    return selected != NULL && selected_len == 2 && memcmp(selected, "h2", 2) == 0;
}

static int open_tls_socket_once(const char *connect_host, uint16_t connect_port, const char *sni, int verify_peer,
                                const unsigned char *alpn_protos, unsigned int alpn_protos_len, tls_cipher_offer_t cipher_offer,
                                SSL_CTX **out_ctx, SSL **out_ssl, int *out_fd, int *retry_with_aes, char *err, size_t err_cap) {
    *out_ctx = NULL;
    *out_ssl = NULL;
    *out_fd = -1;
    *retry_with_aes = 0;

    int fd = tcp_connect_host(connect_host, connect_port);
    if (fd < 0) {
        set_err(err, err_cap, "tcp connect failed");
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
    if (SSL_set_tlsext_host_name(ssl, servername) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to set SNI");
        return -1;
    }
    if (verify_peer) {
        if (SSL_set1_host(ssl, servername) != 1) {
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
    if (SSL_connect(ssl) != 1) {
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

static int open_tls_socket(const char *connect_host, uint16_t connect_port, const char *sni, int verify_peer,
                           const unsigned char *alpn_protos, unsigned int alpn_protos_len, SSL_CTX **out_ctx, SSL **out_ssl, int *out_fd,
                           int *use_aes_fallback, char *err, size_t err_cap) {
    if (!*use_aes_fallback && tls_aes_fallback_cached(connect_host, connect_port, sni)) {
        *use_aes_fallback = 1;
    }
    tls_cipher_offer_t offer = *use_aes_fallback ? TLS_CIPHER_OFFER_AES : TLS_CIPHER_OFFER_CHACHA;
    int retry_with_aes = 0;
    if (open_tls_socket_once(connect_host, connect_port, sni, verify_peer, alpn_protos, alpn_protos_len, offer, out_ctx, out_ssl, out_fd,
                             &retry_with_aes, err, err_cap) != 0) {
        if (offer != TLS_CIPHER_OFFER_CHACHA || !retry_with_aes) {
            return -1;
        }
        *use_aes_fallback = 1;
        if (open_tls_socket_once(connect_host, connect_port, sni, verify_peer, alpn_protos, alpn_protos_len, TLS_CIPHER_OFFER_AES, out_ctx,
                                 out_ssl, out_fd, &retry_with_aes, err, err_cap) != 0) {
            return -1;
        }
        offer = TLS_CIPHER_OFFER_AES;
    }
    if (offer == TLS_CIPHER_OFFER_AES) {
        cache_tls_aes_fallback(connect_host, connect_port, sni);
    }

    log_tls_cipher_once(SSL_get_cipher_name(*out_ssl));
    return 0;
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

static int contains_case_insensitive(const char *haystack, const char *needle) {
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (strncasecmp(haystack + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

static int parse_http_response_headers(SSL *ssl, int fd, dynbuf_t *cache, int *status_code, int *chunked, int64_t *content_len, char *err,
                                       size_t err_cap) {
    *status_code = 0;
    *chunked = 0;
    *content_len = -1;

    for (;;) {
        size_t hdr_bytes = find_double_crlf(cache->data, cache->len);
        if (hdr_bytes > 0) {
            char *headers = (char *)calloc(1, hdr_bytes + 1);
            if (headers == NULL) {
                set_err(err, err_cap, "oom");
                return -1;
            }
            memcpy(headers, cache->data, hdr_bytes);

            char *save = NULL;
            char *line = strtok_r(headers, "\r\n", &save);
            if (line == NULL || sscanf(line, "HTTP/%*s %d", status_code) != 1) {
                free(headers);
                set_err(err, err_cap, "invalid HTTP status line");
                return -1;
            }

            for (line = strtok_r(NULL, "\r\n", &save); line != NULL; line = strtok_r(NULL, "\r\n", &save)) {
                char *colon = strchr(line, ':');
                if (colon == NULL) {
                    continue;
                }
                *colon = '\0';
                char *key = line;
                char *val = colon + 1;
                trim_ascii(key);
                trim_ascii(val);
                if (strcasecmp(key, "Transfer-Encoding") == 0 && contains_case_insensitive(val, "chunked")) {
                    *chunked = 1;
                } else if (strcasecmp(key, "Content-Length") == 0) {
                    long long n = strtoll(val, NULL, 10);
                    if (n >= 0) {
                        *content_len = (int64_t)n;
                    }
                }
            }

            free(headers);
            db_consume(cache, hdr_bytes);
            return 0;
        }

        uint8_t tmp[4096];
        size_t got = 0;
        int read_rc = ssl != NULL ? ssl_read_some(ssl, tmp, sizeof(tmp), &got) : fd_read_some(fd, tmp, sizeof(tmp), &got);
        if (read_rc != 0 || got == 0) {
            set_err(err, err_cap, "failed to read HTTP headers");
            return -1;
        }
        if (db_append(cache, tmp, got) != 0) {
            set_err(err, err_cap, "oom");
            return -1;
        }
        if (cache->len > 32768) {
            set_err(err, err_cap, "HTTP headers too large");
            return -1;
        }
    }
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
    if (out_cap < 2) {
        return -1;
    }
    const char *src = (in != NULL && in[0] != '\0') ? in : "/";
    int n = 0;
    if (src[0] == '/') {
        n = snprintf(out, out_cap, "%s", src);
    } else {
        n = snprintf(out, out_cap, "/%s", src);
    }
    if (n <= 0 || (size_t)n >= out_cap) {
        return -1;
    }
    return 0;
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
        return ssl_read_some(c->ssl, buf, cap, out_len);
    }
    ssize_t n = recv(c->fd, buf, cap, 0);
    if (n <= 0) {
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

static int ws_conn_write_all(tls13_conn_t *c, const void *buf, size_t len) {
    if (c->ssl != NULL) {
        return ssl_write_all(c->ssl, buf, len);
    }
    return write_exact(c->fd, buf, len);
}

static int parse_ws_upgrade_response(tls13_conn_t *c, dynbuf_t *cache, int *status_code, char *accept, size_t accept_cap, int *has_upgrade,
                                     int *has_connection_upgrade, char *err, size_t err_cap) {
    *status_code = 0;
    *has_upgrade = 0;
    *has_connection_upgrade = 0;
    if (accept_cap > 0) {
        accept[0] = '\0';
    }

    for (;;) {
        size_t hdr_bytes = find_double_crlf(cache->data, cache->len);
        if (hdr_bytes > 0) {
            char *headers = (char *)calloc(1, hdr_bytes + 1);
            if (headers == NULL) {
                set_err(err, err_cap, "oom");
                return -1;
            }
            memcpy(headers, cache->data, hdr_bytes);

            char *save = NULL;
            char *line = strtok_r(headers, "\r\n", &save);
            if (line == NULL || sscanf(line, "HTTP/%*s %d", status_code) != 1) {
                free(headers);
                set_err(err, err_cap, "invalid WebSocket HTTP status line");
                return -1;
            }

            for (line = strtok_r(NULL, "\r\n", &save); line != NULL; line = strtok_r(NULL, "\r\n", &save)) {
                char *colon = strchr(line, ':');
                if (colon == NULL) {
                    continue;
                }
                *colon = '\0';
                char *key = line;
                char *val = colon + 1;
                trim_ascii(key);
                trim_ascii(val);
                if (strcasecmp(key, "Upgrade") == 0 && strcasecmp(val, "websocket") == 0) {
                    *has_upgrade = 1;
                } else if (strcasecmp(key, "Connection") == 0 && contains_case_insensitive(val, "upgrade")) {
                    *has_connection_upgrade = 1;
                } else if (strcasecmp(key, "Sec-WebSocket-Accept") == 0 && accept_cap > 0) {
                    snprintf(accept, accept_cap, "%s", val);
                }
            }

            free(headers);
            db_consume(cache, hdr_bytes);
            return 0;
        }

        uint8_t tmp[4096];
        size_t got = 0;
        if (ws_conn_read_some(c, tmp, sizeof(tmp), &got) != 0 || got == 0) {
            set_err(err, err_cap, "failed to read WebSocket upgrade response");
            return -1;
        }
        if (db_append(cache, tmp, got) != 0) {
            set_err(err, err_cap, "oom");
            return -1;
        }
        if (cache->len > 32768) {
            set_err(err, err_cap, "WebSocket response headers too large");
            return -1;
        }
    }
}

static int ws_stream_read_some(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    if (c->ws_net_cache.len > 0) {
        size_t take = c->ws_net_cache.len;
        if (take > cap) {
            take = cap;
        }
        memcpy(buf, c->ws_net_cache.data, take);
        db_consume(&c->ws_net_cache, take);
        *out_len = take;
        return 0;
    }
    return ws_conn_read_some(c, buf, cap, out_len);
}

static int ws_stream_read_exact(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t got = 0;
        if (ws_stream_read_some(c, buf + off, len - off, &got) != 0 || got == 0) {
            return -1;
        }
        off += got;
    }
    return 0;
}

static int ws_write_frame(tls13_conn_t *c, uint8_t opcode, const uint8_t *buf, size_t len) {
    uint8_t hdr[14];
    size_t hdr_len = 0;
    hdr[hdr_len++] = (uint8_t)(0x80 | (opcode & 0x0F));
    if (len <= 125) {
        hdr[hdr_len++] = (uint8_t)(0x80 | len);
    } else if (len <= 0xFFFFU) {
        hdr[hdr_len++] = 0x80 | 126;
        hdr[hdr_len++] = (uint8_t)(len >> 8);
        hdr[hdr_len++] = (uint8_t)len;
    } else {
        hdr[hdr_len++] = 0x80 | 127;
        uint64_t n = (uint64_t)len;
        for (int i = 7; i >= 0; i--) {
            hdr[hdr_len++] = (uint8_t)(n >> (i * 8));
        }
    }

    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof(mask)) != 1) {
        return -1;
    }
    memcpy(hdr + hdr_len, mask, sizeof(mask));
    hdr_len += sizeof(mask);

    if (ws_conn_write_all(c, hdr, hdr_len) != 0) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    uint8_t *masked = (uint8_t *)malloc(len);
    if (masked == NULL) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        masked[i] = (uint8_t)(buf[i] ^ mask[i % 4]);
    }
    int rc = ws_conn_write_all(c, masked, len);
    free(masked);
    return rc;
}

static int ws_fill_app_cache(tls13_conn_t *c) {
    for (;;) {
        uint8_t hdr[2];
        if (ws_stream_read_exact(c, hdr, sizeof(hdr)) != 0) {
            return -1;
        }

        int fin = (hdr[0] & 0x80) != 0;
        uint8_t opcode = hdr[0] & 0x0F;
        int masked = (hdr[1] & 0x80) != 0;
        uint64_t len = hdr[1] & 0x7F;
        if (len == 126) {
            uint8_t ext[2];
            if (ws_stream_read_exact(c, ext, sizeof(ext)) != 0) {
                return -1;
            }
            len = ((uint64_t)ext[0] << 8) | (uint64_t)ext[1];
        } else if (len == 127) {
            uint8_t ext[8];
            if (ws_stream_read_exact(c, ext, sizeof(ext)) != 0) {
                return -1;
            }
            len = 0;
            for (size_t i = 0; i < sizeof(ext); i++) {
                len = (len << 8) | (uint64_t)ext[i];
            }
            if ((ext[0] & 0x80) != 0) {
                return -1;
            }
        }
        if (len > 16ULL * 1024ULL * 1024ULL) {
            return -1;
        }

        uint8_t mask[4] = {0};
        if (masked && ws_stream_read_exact(c, mask, sizeof(mask)) != 0) {
            return -1;
        }

        uint8_t *payload = NULL;
        if (len > 0) {
            payload = (uint8_t *)malloc((size_t)len);
            if (payload == NULL) {
                return -1;
            }
            if (ws_stream_read_exact(c, payload, (size_t)len) != 0) {
                free(payload);
                return -1;
            }
            if (masked) {
                for (uint64_t i = 0; i < len; i++) {
                    payload[i] = (uint8_t)(payload[i] ^ mask[i % 4]);
                }
            }
        }

        int rc = 0;
        if (opcode == 0x0 || opcode == 0x1 || opcode == 0x2) {
            if (len > 0 && db_append(&c->app_cache, payload, (size_t)len) != 0) {
                rc = -1;
            }
        } else if (opcode == 0x8) {
            (void)ws_write_frame(c, 0x8, payload, (size_t)len);
            rc = -1;
        } else if (opcode == 0x9) {
            if (!fin || len > 125 || ws_write_frame(c, 0xA, payload, (size_t)len) != 0) {
                rc = -1;
            }
        } else if (opcode == 0xA) {
            rc = 0;
        } else {
            rc = -1;
        }
        free(payload);

        if (rc != 0) {
            return -1;
        }
        if (c->app_cache.len > 0) {
            return 0;
        }
    }
}

static int xhttp_stream_read_some(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    if (c->xhttp_net_cache.len > 0) {
        size_t take = c->xhttp_net_cache.len;
        if (take > cap) {
            take = cap;
        }
        memcpy(buf, c->xhttp_net_cache.data, take);
        db_consume(&c->xhttp_net_cache, take);
        *out_len = take;
        return 0;
    }
    return c->ssl != NULL ? ssl_read_some(c->ssl, buf, cap, out_len) : fd_read_some(c->fd, buf, cap, out_len);
}

static int xhttp_stream_read_exact(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t got = 0;
        if (xhttp_stream_read_some(c, buf + off, len - off, &got) != 0 || got == 0) {
            return -1;
        }
        off += got;
    }
    return 0;
}

static int xhttp_stream_read_line(tls13_conn_t *c, char *line, size_t cap) {
    if (cap < 2) {
        return -1;
    }
    size_t off = 0;
    for (;;) {
        uint8_t ch = 0;
        if (xhttp_stream_read_exact(c, &ch, 1) != 0) {
            return -1;
        }
        if (off + 1 >= cap) {
            return -1;
        }
        line[off++] = (char)ch;
        if (ch == '\n') {
            break;
        }
    }
    line[off] = '\0';
    while (off > 0 && (line[off - 1] == '\r' || line[off - 1] == '\n')) {
        line[--off] = '\0';
    }
    return 0;
}

static int xhttp_plain_buffer_available(tls13_conn_t *c) {
    if (c->mode != CONN_MODE_XHTTP_PLAIN) {
        return 0;
    }
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(c->fd, &rfds);
    struct timeval tv = {0, 0};
    int ready = select(c->fd + 1, &rfds, NULL, NULL, &tv);
    if (ready <= 0) {
        return ready < 0 && errno != EINTR ? -1 : 0;
    }
    uint8_t tmp[4096];
    ssize_t n = recv(c->fd, tmp, sizeof(tmp), 0);
    if (n > 0) {
        return db_append(&c->xhttp_net_cache, tmp, (size_t)n);
    }
    if (n == 0) {
        return -1;
    }
    return errno == EINTR ? 0 : -1;
}

static int xhttp_plain_line_ready(tls13_conn_t *c, size_t skip) {
    if (c->mode != CONN_MODE_XHTTP_PLAIN) {
        return 1;
    }
    if (xhttp_plain_buffer_available(c) != 0) {
        return -1;
    }
    if (c->xhttp_net_cache.len <= skip) {
        return 0;
    }
    return memchr(c->xhttp_net_cache.data + skip, '\n', c->xhttp_net_cache.len - skip) != NULL;
}

static int xhttp_fill_app_cache(tls13_conn_t *c) {
    if (c->xhttp_eof) {
        return -1;
    }

    if (!c->xhttp_headers_read) {
        int status = 0;
        int chunked = 0;
        int64_t content_len = -1;
        char err[160] = {0};
        if (parse_http_response_headers(c->ssl, c->fd, &c->xhttp_net_cache, &status, &chunked, &content_len, err, sizeof(err)) != 0) {
            if (err[0] != '\0') {
                fprintf(stderr, "[xhttp] %s\n", err);
            }
            return -1;
        }
        if (status != 200) {
            fprintf(stderr, "[xhttp] GET returned non-200: %d\n", status);
            return -1;
        }
        c->xhttp_chunked = chunked;
        c->xhttp_content_rem = content_len;
        c->xhttp_chunk_rem = -1;
        c->xhttp_headers_read = 1;
    }

    if (!c->xhttp_chunked) {
        if (c->xhttp_content_rem == 0) {
            c->xhttp_eof = 1;
            return -1;
        }

        uint8_t tmp[8192];
        size_t got = 0;
        size_t ask = sizeof(tmp);
        if (c->xhttp_content_rem > 0 && (int64_t)ask > c->xhttp_content_rem) {
            ask = (size_t)c->xhttp_content_rem;
        }
        if (xhttp_stream_read_some(c, tmp, ask, &got) != 0 || got == 0) {
            return -1;
        }
        if (db_append(&c->app_cache, tmp, got) != 0) {
            return -1;
        }
        if (c->xhttp_content_rem > 0) {
            c->xhttp_content_rem -= (int64_t)got;
        }
        return 0;
    }

    for (;;) {
        if (c->xhttp_chunk_rem < 0) {
            int line_ready = xhttp_plain_line_ready(c, 0);
            if (line_ready < 0) {
                return -1;
            }
            if (!line_ready) {
                return 1;
            }
            char line[128];
            if (xhttp_stream_read_line(c, line, sizeof(line)) != 0) {
                return -1;
            }
            char *semi = strchr(line, ';');
            if (semi != NULL) {
                *semi = '\0';
            }
            trim_ascii(line);
            if (line[0] == '\0') {
                continue;
            }
            unsigned long long n = strtoull(line, NULL, 16);
            c->xhttp_chunk_rem = (int64_t)n;
            if (c->xhttp_chunk_rem == 0) {
                for (;;) {
                    if (xhttp_stream_read_line(c, line, sizeof(line)) != 0) {
                        return -1;
                    }
                    if (line[0] == '\0') {
                        break;
                    }
                }
                c->xhttp_eof = 1;
                return -1;
            }
        }

        if (c->xhttp_chunk_rem == 0) {
            int line_ready = xhttp_plain_line_ready(c, 2);
            if (line_ready < 0) {
                return -1;
            }
            if (!line_ready) {
                return 1;
            }
            uint8_t crlf[2];
            if (xhttp_stream_read_exact(c, crlf, sizeof(crlf)) != 0) {
                return -1;
            }
            c->xhttp_chunk_rem = -1;
            continue;
        }

        uint8_t tmp[8192];
        size_t ask = sizeof(tmp);
        if ((int64_t)ask > c->xhttp_chunk_rem) {
            ask = (size_t)c->xhttp_chunk_rem;
        }
        size_t got = 0;
        if (c->mode == CONN_MODE_XHTTP_PLAIN && c->xhttp_net_cache.len == 0) {
            if (xhttp_plain_buffer_available(c) != 0) {
                return -1;
            }
            if (c->xhttp_net_cache.len == 0) {
                return 1;
            }
        }
        if (xhttp_stream_read_some(c, tmp, ask, &got) != 0 || got == 0) {
            return -1;
        }
        if (db_append(&c->app_cache, tmp, got) != 0) {
            return -1;
        }
        c->xhttp_chunk_rem -= (int64_t)got;
        if (c->app_cache.len > 0) {
            return 0;
        }
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

static int h2_note_recv_data(tls13_conn_t *c, size_t payload_len) {
    if (payload_len == 0) {
        return 0;
    }
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
    fd_set rfds;
    fd_set wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (want_write) {
        FD_SET(c->fd, &wfds);
    } else {
        FD_SET(c->fd, &rfds);
    }

    int rc;
    do {
        rc = select(c->fd + 1, &rfds, &wfds, NULL, NULL);
    } while (rc < 0 && errno == EINTR);
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
    uint8_t hdr[9];
    if (h2_read_exact(c, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    size_t len = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | (size_t)hdr[2];
    if (len > H2_MAX_INBOUND_FRAME) {
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

static int h2_decode_int(const uint8_t *buf, size_t len, size_t *off, uint8_t prefix_bits, uint32_t *value) {
    if (*off >= len) {
        return -1;
    }
    uint8_t first = buf[*off];
    (*off)++;
    uint32_t mask = (1U << prefix_bits) - 1U;
    uint32_t v = first & mask;
    if (v != mask) {
        *value = v;
        return 0;
    }

    uint32_t m = 0;
    for (;;) {
        if (*off >= len || m > 28) {
            return -1;
        }
        uint8_t b = buf[*off];
        (*off)++;
        v += (uint32_t)(b & 0x7F) << m;
        if ((b & 0x80) == 0) {
            *value = v;
            return 0;
        }
        m += 7;
    }
}

static int h2_skip_string(const uint8_t *buf, size_t len, size_t *off) {
    if (*off >= len) {
        return -1;
    }
    uint32_t slen = 0;
    if (h2_decode_int(buf, len, off, 7, &slen) != 0) {
        return -1;
    }
    if ((size_t)slen > len - *off) {
        return -1;
    }
    *off += (size_t)slen;
    return 0;
}

static int h2_read_string_plain(const uint8_t *buf, size_t len, size_t *off, char *out, size_t out_cap) {
    if (*off >= len || out_cap == 0) {
        return -1;
    }
    int huffman = (buf[*off] & 0x80) != 0;
    uint32_t slen = 0;
    if (h2_decode_int(buf, len, off, 7, &slen) != 0 || (size_t)slen > len - *off) {
        return -1;
    }
    if (huffman) {
        return -1;
    }
    size_t copy = (size_t)slen;
    if (copy >= out_cap) {
        copy = out_cap - 1;
    }
    memcpy(out, buf + *off, copy);
    out[copy] = '\0';
    *off += (size_t)slen;
    return 0;
}

static int hpack_static_status(uint32_t index) {
    switch (index) {
    case 8:
        return 200;
    case 9:
        return 204;
    case 10:
        return 206;
    case 11:
        return 304;
    case 12:
        return 400;
    case 13:
        return 404;
    case 14:
        return 500;
    default:
        return 0;
    }
}

static int h2_decode_status_header(const uint8_t *block, size_t len) {
    size_t off = 0;
    int status = 0;
    while (off < len) {
        uint8_t first = block[off];
        if ((first & 0x80) != 0) {
            uint32_t index = 0;
            if (h2_decode_int(block, len, &off, 7, &index) != 0) {
                return status;
            }
            int s = hpack_static_status(index);
            if (s != 0) {
                return s;
            }
        } else if ((first & 0x40) != 0) {
            uint32_t name_index = 0;
            if (h2_decode_int(block, len, &off, 6, &name_index) != 0) {
                return status;
            }
            if (name_index == 0) {
                if (h2_skip_string(block, len, &off) != 0) {
                    return status;
                }
            }
            if (name_index == 8) {
                char value[16];
                value[0] = '\0';
                if (h2_read_string_plain(block, len, &off, value, sizeof(value)) == 0) {
                    return atoi(value);
                }
                return status;
            }
            if (h2_skip_string(block, len, &off) != 0) {
                return status;
            }
        } else if ((first & 0x20) != 0) {
            uint32_t ignored = 0;
            if (h2_decode_int(block, len, &off, 5, &ignored) != 0) {
                return status;
            }
        } else {
            uint32_t name_index = 0;
            if (h2_decode_int(block, len, &off, 4, &name_index) != 0) {
                return status;
            }
            char value[16];
            value[0] = '\0';
            if (name_index == 0) {
                char name[32];
                name[0] = '\0';
                size_t name_off = off;
                if (h2_read_string_plain(block, len, &name_off, name, sizeof(name)) == 0) {
                    off = name_off;
                    if (h2_read_string_plain(block, len, &off, value, sizeof(value)) == 0 && strcmp(name, ":status") == 0) {
                        status = atoi(value);
                    }
                } else {
                    if (h2_skip_string(block, len, &off) != 0 || h2_skip_string(block, len, &off) != 0) {
                        return status;
                    }
                }
            } else {
                if (name_index == 8) {
                    if (h2_read_string_plain(block, len, &off, value, sizeof(value)) == 0) {
                        return atoi(value);
                    }
                    return status;
                }
                if (h2_skip_string(block, len, &off) != 0) {
                    return status;
                }
            }
        }
    }
    return status;
}

static int h2_process_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t payload_len, char *err,
                              size_t err_cap) {
    (void)c;

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

    int status = h2_decode_status_header(payload + off, payload_len - off);
    if (status != 0) {
        if (status != 200) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "%s h2 stream %u returned non-200: %d", c->grpc_transport ? "grpc" : "xhttp",
                         (unsigned)stream_id, status);
            }
            return -1;
        }
    }
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
            if (id == 4) {
                if (val > 0x7FFFFFFFU) {
                    set_err(err, err_cap, "invalid h2 initial window");
                    return -1;
                }
                int64_t delta = (int64_t)val - (int64_t)c->h2_peer_initial_window;
                c->h2_peer_initial_window = val;
                c->h2_peer_stream_window += delta;
                if (c->h2_peer_stream_window > c->h2_peer_stream_refill_target) {
                    c->h2_peer_stream_refill_target = c->h2_peer_stream_window;
                }
                if (c->h2_upload_stream_id != 0) {
                    c->h2_upload_stream_window += delta;
                    if (c->h2_upload_stream_window > c->h2_upload_stream_refill_target) {
                        c->h2_upload_stream_refill_target = c->h2_upload_stream_window;
                    }
                }
            } else if (id == 5 && val >= 16384 && val <= 16777215) {
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
                if (c->h2_peer_conn_window > c->h2_peer_conn_refill_target) {
                    c->h2_peer_conn_refill_target = c->h2_peer_conn_window;
                }
            } else if (stream_id == c->h2_stream_id) {
                if (h2_add_send_window(&c->h2_peer_stream_window, inc) != 0) {
                    set_err(err, err_cap, "h2 stream window overflow");
                    return -1;
                }
                if (c->h2_peer_stream_window > c->h2_peer_stream_refill_target) {
                    c->h2_peer_stream_refill_target = c->h2_peer_stream_window;
                }
            } else if (stream_id == c->h2_upload_stream_id) {
                if (h2_add_send_window(&c->h2_upload_stream_window, inc) != 0) {
                    set_err(err, err_cap, "h2 upload window overflow");
                    return -1;
                }
                if (c->h2_upload_stream_window > c->h2_upload_stream_refill_target) {
                    c->h2_upload_stream_refill_target = c->h2_upload_stream_window;
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
    case H2_FRAME_RST_STREAM:
        set_err(err, err_cap, "h2 stream reset");
        return -1;
    case H2_FRAME_GOAWAY:
        set_err(err, err_cap, "h2 goaway");
        return -1;
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

    uint8_t settings[6] = {
        0x00,
        0x04,
        (uint8_t)(H2_CLIENT_INITIAL_WINDOW >> 24),
        (uint8_t)(H2_CLIENT_INITIAL_WINDOW >> 16),
        (uint8_t)(H2_CLIENT_INITIAL_WINDOW >> 8),
        (uint8_t)H2_CLIENT_INITIAL_WINDOW,
    };
    if (h2_send_frame(c, H2_FRAME_SETTINGS, 0, 0, settings, sizeof(settings)) != 0 ||
        h2_send_window_update(c, 0, H2_CONNECTION_WINDOW_INC) != 0) {
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
        if (c->grpc_transport) {
            if (tls13_drain_h2_input(c) < 0) {
                return -1;
            }
            while (c->h2_peer_conn_window <= 0 || *stream_window <= 0) {
                if (h2_pump_one_frame(c) != 0) {
                    fprintf(stderr, "[grpc] failed while waiting for h2 upload window\n");
                    return -1;
                }
            }
        } else {
            int64_t *stream_refill_target =
                stream_up ? &c->h2_upload_stream_refill_target : &c->h2_peer_stream_refill_target;
            int64_t conn_low = c->h2_peer_conn_refill_target / 4;
            int64_t stream_low = *stream_refill_target / 4;
            if (c->h2_peer_conn_window <= conn_low || *stream_window <= stream_low) {
                int64_t conn_high = c->h2_peer_conn_refill_target / 2;
                int64_t stream_high = *stream_refill_target / 2;
                while (c->h2_peer_conn_window < conn_high || *stream_window < stream_high) {
                    if (h2_pump_one_frame(c) != 0) {
                        fprintf(stderr, "[xhttp] failed while waiting for h2 upload window\n");
                        return -1;
                    }
                    conn_high = c->h2_peer_conn_refill_target / 2;
                    stream_high = *stream_refill_target / 2;
                }
            }
        }
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

static int protobuf_read_varint(const uint8_t *buf, size_t len, size_t *off, uint64_t *value) {
    uint64_t v = 0;
    unsigned int shift = 0;
    while (*off < len && shift < 64) {
        uint8_t ch = buf[(*off)++];
        v |= (uint64_t)(ch & 0x7f) << shift;
        if ((ch & 0x80) == 0) {
            *value = v;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

static int grpc_append_hunk_payload(tls13_conn_t *c, const uint8_t *msg, size_t msg_len) {
    size_t off = 0;
    int found = 0;

    while (off < msg_len) {
        uint64_t key = 0;
        if (protobuf_read_varint(msg, msg_len, &off, &key) != 0 || key == 0) {
            return -1;
        }
        uint32_t field = (uint32_t)(key >> 3);
        uint32_t wire = (uint32_t)(key & 7);

        if (wire == 0) {
            uint64_t ignored = 0;
            if (protobuf_read_varint(msg, msg_len, &off, &ignored) != 0) {
                return -1;
            }
        } else if (wire == 1) {
            if (msg_len - off < 8) {
                return -1;
            }
            off += 8;
        } else if (wire == 2) {
            uint64_t field_len = 0;
            if (protobuf_read_varint(msg, msg_len, &off, &field_len) != 0 || field_len > msg_len - off) {
                return -1;
            }
            if (field == 1) {
                if (db_append(&c->app_cache, msg + off, (size_t)field_len) != 0) {
                    return -1;
                }
                found = 1;
            }
            off += (size_t)field_len;
        } else if (wire == 5) {
            if (msg_len - off < 4) {
                return -1;
            }
            off += 4;
        } else {
            return -1;
        }
    }
    return found || msg_len == 0 ? 0 : -1;
}

static int grpc_feed_data(tls13_conn_t *c, const uint8_t *data, size_t len) {
    if (db_append(&c->grpc_recv_cache, data, len) != 0) {
        return -1;
    }

    while (c->grpc_recv_cache.len >= 5) {
        const uint8_t *frame = c->grpc_recv_cache.data;
        uint32_t msg_len = ((uint32_t)frame[1] << 24) | ((uint32_t)frame[2] << 16) | ((uint32_t)frame[3] << 8) | (uint32_t)frame[4];
        if (frame[0] != 0 || msg_len > 16U * 1024U * 1024U) {
            return -1;
        }
        if (c->grpc_recv_cache.len < 5U + (size_t)msg_len) {
            break;
        }
        if (grpc_append_hunk_payload(c, frame + 5, msg_len) != 0) {
            return -1;
        }
        db_consume(&c->grpc_recv_cache, 5U + (size_t)msg_len);
    }
    return 0;
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

    int rc = h2_write_data(c, frame, frame_len);
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
    if (type == H2_FRAME_DATA && stream_id == c->h2_stream_id) {
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

        if (rc == 0 && h2_note_recv_data(c, payload_len) != 0) {
            rc = -1;
        }
        if (rc == 0 && data_len > 0) {
            if (c->grpc_transport) {
                rc = grpc_feed_data(c, payload + off, data_len);
            } else if (db_append(&c->app_cache, payload + off, data_len) != 0) {
                rc = -1;
            }
        }
        if ((flags & H2_FLAG_END_STREAM) != 0) {
            c->h2_stream_eof = 1;
        }
    } else {
        rc = h2_process_control_frame(c, type, flags, stream_id, payload, payload_len, err, sizeof(err));
        if (rc != 0 && err[0] != '\0') {
            fprintf(stderr, "[%s] %s\n", c->grpc_transport ? "grpc" : "xhttp", err);
        }
        if (rc == 0 && type == H2_FRAME_HEADERS && stream_id == c->h2_stream_id && (flags & H2_FLAG_END_STREAM) != 0) {
            c->h2_stream_eof = 1;
        }
    }

    free(payload);
    return rc;
}

static int h2_fill_app_cache(tls13_conn_t *c) {
    if (c->h2_stream_eof) {
        return -1;
    }
    if (h2_pump_one_frame(c) != 0) {
        return -1;
    }
    if (c->app_cache.len > 0) {
        return 0;
    }
    if (c->h2_stream_eof) {
        return -1;
    }
    return 1;
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
    size_t seg_len = strlen(segment);
    int need_slash = (path[len - 1] != '/');
    if (len + (need_slash ? 1U : 0U) + seg_len + 1U > cap) {
        return -1;
    }
    if (need_slash) {
        path[len++] = '/';
    }
    memcpy(path + len, segment, seg_len + 1);
    return 0;
}

static int xhttp_append_query_param(char *path, size_t cap, const char *key, const char *value) {
    if (path == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    size_t len = strlen(path);
    const char sep = strchr(path, '?') == NULL ? '?' : '&';
    size_t avail = cap > len ? cap - len : 0;
    if (avail == 0) {
        return -1;
    }
    int n = snprintf(path + len, avail, "%c%s=%s", sep, key, value);
    return (n > 0 && (size_t)n < avail) ? 0 : -1;
}

static int xhttp_append_header_line(char *headers, size_t cap, const char *key, const char *value) {
    if (headers == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL || strchr(value, '\r') != NULL || strchr(value, '\n') != NULL) {
        return -1;
    }
    size_t len = strlen(headers);
    size_t avail = cap > len ? cap - len : 0;
    if (avail == 0) {
        return -1;
    }
    int n = snprintf(headers + len, avail, "%s: %s\r\n", key, value);
    return (n > 0 && (size_t)n < avail) ? 0 : -1;
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
    char padding[9000];
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

    char referer[2048];
    const char *scheme = c->mode == CONN_MODE_XHTTP_PLAIN ? "http" : "https";
    int n = snprintf(referer, sizeof(referer), "%s://%s%s?%s=%s", scheme, c->xhttp_host, bare_path, key, padding);
    if (n <= 0 || (size_t)n >= sizeof(referer)) {
        return -1;
    }
    return xhttp_append_header_line(headers, headers_cap, header, referer);
}

static int xhttp_prepare_request(tls13_conn_t *c, const char *seq_str, char *path, size_t path_cap, char *headers, size_t headers_cap) {
    char cookies[1024];
    cookies[0] = '\0';
    headers[0] = '\0';
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

    if (cookies[0] != '\0' && xhttp_append_header_line(headers, headers_cap, "Cookie", cookies) != 0) {
        return -1;
    }
    return 0;
}

static int h2_append_regular_header(dynbuf_t *block, const char *name, size_t name_len, const char *value, size_t value_len) {
    if (name == NULL || value == NULL || name_len == 0) {
        return 0;
    }
    if (name_len >= 128 || value_len >= 4096) {
        return -1;
    }

    char lname[128];
    char vbuf[4096];
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
    memcpy(vbuf, value, value_len);
    vbuf[value_len] = '\0';

    if (strcmp(lname, "connection") == 0 || strcmp(lname, "keep-alive") == 0 || strcmp(lname, "proxy-connection") == 0 ||
        strcmp(lname, "transfer-encoding") == 0 || strcmp(lname, "upgrade") == 0) {
        return 0;
    }
    return hpack_append_literal_new_name(block, lname, vbuf);
}

static int h2_append_http1_header_lines(dynbuf_t *block, const char *headers) {
    const char *p = headers;
    while (p != NULL && *p != '\0') {
        const char *line_end = strstr(p, "\r\n");
        size_t line_len = line_end != NULL ? (size_t)(line_end - p) : strlen(p);
        if (line_len > 0) {
            const char *colon = memchr(p, ':', line_len);
            if (colon == NULL) {
                return -1;
            }
            if (h2_append_regular_header(block, p, (size_t)(colon - p), colon + 1, line_len - (size_t)(colon - p) - 1) != 0) {
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
    dynbuf_t block = {0};
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
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "user-agent",
                                           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                           "Chrome/149.0.0.0 Safari/537.36");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "accept", "*/*");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "cache-control", "no-cache");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "pragma", "no-cache");
    }
    if (rc == 0 && extra_headers != NULL && extra_headers[0] != '\0') {
        rc = h2_append_http1_header_lines(&block, extra_headers);
    }
    if (rc == 0 && has_body && streaming_body) {
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
    if (rc == 0 && h2_send_frame(c, H2_FRAME_HEADERS, flags, stream_id, block.data, block.len) != 0) {
        rc = -1;
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
    return 0;
}

static int xhttp_h2_begin(tls13_conn_t *c, char *err, size_t err_cap) {
    c->h2_stream_id = 1;
    c->h2_next_stream_id = 3;
    c->h2_peer_initial_window = H2_DEFAULT_WINDOW;
    c->h2_peer_max_frame_size = H2_DEFAULT_MAX_FRAME;
    c->h2_peer_conn_window = H2_DEFAULT_WINDOW;
    c->h2_peer_stream_window = H2_DEFAULT_WINDOW;
    c->h2_peer_conn_refill_target = H2_DEFAULT_WINDOW;
    c->h2_peer_stream_refill_target = H2_DEFAULT_WINDOW;
    c->h2_upload_stream_refill_target = H2_DEFAULT_WINDOW;
    c->h2_upload_stream_id = 0;
    c->h2_upload_stream_window = 0;
    c->h2_recv_conn_pending = 0;
    c->h2_recv_stream_pending = 0;
    c->h2_stream_eof = 0;

    if (h2_send_client_preface(c, err, err_cap) != 0) {
        return -1;
    }
    return 0;
}

static int xhttp_h2_send_download_request(tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[4096];
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
    char extra_headers[4096];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 stream-one request");
        return -1;
    }

    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    const char *method = strcmp(c->xhttp_uplink_method, "GET") == 0 ? "GET" : "POST";
    return h2_send_xhttp_request_headers(c, c->h2_stream_id, method, request_path, extra_headers, 0, 1, 1, err, err_cap);
}

static int xhttp_h2_send_stream_up_request(tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[4096];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 stream-up request");
        return -1;
    }

    uint32_t stream_id = c->h2_next_stream_id;
    c->h2_next_stream_id += 2;
    c->h2_upload_stream_id = stream_id;
    c->h2_upload_stream_window = c->h2_peer_initial_window;
    c->h2_upload_stream_refill_target = c->h2_peer_initial_window;
    const char *method = strcmp(c->xhttp_uplink_method, "GET") == 0 ? "GET" : "POST";
    return h2_send_xhttp_request_headers(c, stream_id, method, request_path, extra_headers, 0, 1, 1, err, err_cap);
}

static int xhttp_h2_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t len, char *err, size_t err_cap) {
    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    char extra_headers[4096];
    if (xhttp_prepare_request(c, seq, request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 upload request");
        return -1;
    }

    uint32_t stream_id = c->h2_next_stream_id;
    c->h2_next_stream_id += 2;
    const char *method = (strcmp(c->xhttp_uplink_method, "GET") == 0) ? "GET" : "POST";
    if (h2_send_xhttp_request_headers(c, stream_id, method, request_path, extra_headers, len, 1, 0, err, err_cap) != 0) {
        return -1;
    }
    return h2_send_xhttp_body(c, stream_id, buf, len, err, err_cap);
}

static int xhttp_h2_start_mode(tls13_conn_t *c, char *err, size_t err_cap) {
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

    dynbuf_t block = {0};
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
                                           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
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
    return h2_send_grpc_request_headers(c, err, err_cap);
}

static int xhttp_conn_write_all(tls13_conn_t *c, const void *buf, size_t len) {
    return c->ssl != NULL ? ssl_write_all(c->ssl, buf, len) : write_exact(c->fd, buf, len);
}

static void *xhttp_plain_upload_reader(void *arg) {
    int fd = (int)(intptr_t)arg;
    uint8_t buf[4096];
    while (recv(fd, buf, sizeof(buf), 0) > 0) {
    }
    return NULL;
}

static int xhttp_start_plain_upload_reader(tls13_conn_t *c) {
    if (pthread_create(&c->xhttp_upload_reader, NULL, xhttp_plain_upload_reader, (void *)(intptr_t)c->xhttp_upload_fd) != 0) {
        return -1;
    }
    c->xhttp_upload_reader_started = 1;
    return 0;
}

static int xhttp_send_plain_stream_request(tls13_conn_t *c, int fd, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[4096];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp stream request");
        return -1;
    }

    char req[8192];
    int req_len = snprintf(req, sizeof(req),
                           "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vless-core/1.0\r\nAccept: */*\r\n"
                           "%sContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                           request_path, c->xhttp_host, extra_headers);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        set_err(err, err_cap, "xhttp stream request too large");
        return -1;
    }
    if (write_exact(fd, req, (size_t)req_len) != 0) {
        set_err(err, err_cap, "failed to send xhttp stream request");
        return -1;
    }

    c->xhttp_chunked = 0;
    c->xhttp_content_rem = -1;
    c->xhttp_chunk_rem = -1;
    c->xhttp_eof = 0;
    c->xhttp_headers_read = 0;
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
    char extra_headers[4096];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp GET");
        return -1;
    }

    char req[8192];
    int req_len =
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vless-core/1.0\r\nAccept: */*\r\nCache-Control: no-cache\r\n"
                                   "%sConnection: keep-alive\r\n\r\n",
                 request_path, c->xhttp_host, extra_headers);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        set_err(err, err_cap, "xhttp GET request too large");
        return -1;
    }

    if (xhttp_conn_write_all(c, req, (size_t)req_len) != 0) {
        set_err(err, err_cap, "failed to send xhttp GET");
        return -1;
    }

    c->xhttp_chunked = 0;
    c->xhttp_content_rem = -1;
    c->xhttp_chunk_rem = -1;
    c->xhttp_eof = 0;
    c->xhttp_headers_read = 0;
    (void)cfg;
    return 0;
}

static int xhttp_post_packet_plain(tls13_conn_t *c, const uint8_t *buf, size_t len, char *err, size_t err_cap) {
    int fd = tcp_connect_host(c->remote_host, c->remote_port);
    if (fd < 0) {
        set_err(err, err_cap, "tcp connect failed");
        return -1;
    }

    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    char extra_headers[4096];
    if (xhttp_prepare_request(c, seq, request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        close(fd);
        set_err(err, err_cap, "failed to build xhttp upload request");
        return -1;
    }

    const char *method = (strcmp(c->xhttp_uplink_method, "GET") == 0) ? "GET" : "POST";
    char req[8192];
    int req_len = snprintf(req, sizeof(req),
                           "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vless-core/1.0\r\nAccept: */*\r\n"
                           "%sContent-Type: application/octet-stream\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                           method, request_path, c->xhttp_host, extra_headers, len);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        close(fd);
        set_err(err, err_cap, "xhttp POST request too large");
        return -1;
    }

    int rc = 0;
    if (write_exact(fd, req, (size_t)req_len) != 0 || (len > 0 && write_exact(fd, buf, len) != 0)) {
        rc = -1;
        set_err(err, err_cap, "failed to send xhttp POST");
    } else {
        dynbuf_t cache = {0};
        int status = 0;
        int chunked = 0;
        int64_t content_len = -1;
        if (parse_http_response_headers(NULL, fd, &cache, &status, &chunked, &content_len, err, err_cap) != 0) {
            rc = -1;
        } else if (status != 200) {
            rc = -1;
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "xhttp %s returned non-200: %d", method, status);
            }
        }
        db_free(&cache);
    }

    close(fd);
    return rc;
}

static int xhttp_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t len, char *err, size_t err_cap) {
    if (c->mode == CONN_MODE_XHTTP_PLAIN) {
        return xhttp_post_packet_plain(c, buf, len, err, err_cap);
    }

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    xhttp_tls_mode_t mode = get_xhttp_tls_mode();
    if (mode == XHTTP_TLS_MODE_TOFU) {
        if (c->xhttp_pin_key[0] == '\0' &&
            xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                               sizeof(c->xhttp_pin_key)) != 0) {
            set_err(err, err_cap, "failed to build TOFU pin key");
            return -1;
        }
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, NULL, 0, &ctx, &ssl, &fd, &c->tls_use_aes_fallback, err,
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
        int need_auto_pin_check = 0;
        int verify_peer = c->xhttp_tls_insecure ? 0 : xhttp_effective_verify_peer();
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, verify_peer, NULL, 0, &ctx, &ssl, &fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            if (!(verify_peer == 1 && xhttp_auto_fallback_allowed() && is_cert_verify_error_msg(err))) {
                return -1;
            }
            if (!g_xhttp_auto_force_insecure) {
                fprintf(stderr, "[xhttp] tls_mode=auto(selected=insecure+tofu): %s\n", err);
            }
            g_xhttp_auto_force_insecure = 1;
            if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, NULL, 0, &ctx, &ssl, &fd,
                                &c->tls_use_aes_fallback, err, err_cap) != 0) {
                return -1;
            }
            c->xhttp_tls_insecure = 1;
            if (mode == XHTTP_TLS_MODE_AUTO) {
                need_auto_pin_check = 1;
            }
        } else if (mode == XHTTP_TLS_MODE_AUTO && c->xhttp_tls_insecure) {
            need_auto_pin_check = 1;
        }
        if (need_auto_pin_check) {
            if (c->xhttp_pin_key[0] == '\0' &&
                xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                                   sizeof(c->xhttp_pin_key)) != 0) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(fd);
                set_err(err, err_cap, "failed to build xhttp pin key");
                return -1;
            }
            if (xhttp_tofu_verify_or_store(ssl, c->xhttp_pin_key, 0, err, err_cap) != 0) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(fd);
                return -1;
            }
        }
    }

    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    char extra_headers[4096];
    if (xhttp_prepare_request(c, seq, request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to build xhttp upload request");
        return -1;
    }

    const char *method = (strcmp(c->xhttp_uplink_method, "GET") == 0) ? "GET" : "POST";
    char req[8192];
    int req_len = snprintf(req, sizeof(req),
                           "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vless-core/1.0\r\nAccept: */*\r\n"
                           "%sContent-Type: application/octet-stream\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                           method, request_path, c->xhttp_host, extra_headers, len);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "xhttp POST request too large");
        return -1;
    }

    int rc = 0;
    if (ssl_write_all(ssl, req, (size_t)req_len) != 0 || (len > 0 && ssl_write_all(ssl, buf, len) != 0)) {
        rc = -1;
        set_err(err, err_cap, "failed to send xhttp POST");
    } else {
        dynbuf_t cache = {0};
        int status = 0;
        int chunked = 0;
        int64_t content_len = -1;
        if (parse_http_response_headers(ssl, fd, &cache, &status, &chunked, &content_len, err, err_cap) != 0) {
            rc = -1;
        } else if (status != 200) {
            rc = -1;
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "xhttp %s returned non-200: %d", method, status);
            }
        }
        db_free(&cache);
        (void)chunked;
        (void)content_len;
    }

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
static int p256_generate_public_legacy(uint8_t pub[65]) {
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
    EC_KEY_free(key);
    return ok ? 0 : -1;
}
#endif

static int p256_generate_public(uint8_t pub[65]) {
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

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
#else
    return p256_generate_public_legacy(pub);
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

static int ext_supported_groups(dynbuf_t *exts, uint16_t grease, int random_mode) {
    uint8_t data[32];
    uint16_t groups[4] = {grease, 0x001d, 0x0017, 0x0018};
    size_t gcount = random_mode ? 2 : 4;
    if (random_mode) {
        groups[0] = 0x001d;
        groups[1] = 0x0017;
    }

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

static int ext_supported_groups_firefox(dynbuf_t *exts) {
    uint16_t groups[] = {0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101};
    uint8_t data[32];
    size_t off = 0;
    size_t glen = sizeof(groups);
    data[off++] = (uint8_t)(glen >> 8);
    data[off++] = (uint8_t)(glen & 0xFF);
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
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
    uint16_t sigs[] = {0x0403, 0x0804, 0x0503, 0x0805, 0x0806, 0x0601, 0x0501, 0x0401};
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
    uint16_t sigs[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601};
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
    uint16_t sigs[] = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201};
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

static int ext_key_share(dynbuf_t *exts, uint16_t grease, const uint8_t pubkey[32], int random_mode) {
    uint8_t data[128];
    size_t off = 2;

    if (!random_mode) {
        data[off++] = (uint8_t)(grease >> 8);
        data[off++] = (uint8_t)(grease & 0xFF);
        data[off++] = 0x00;
        data[off++] = 0x01;
        data[off++] = 0x00;
    }

    data[off++] = 0x00;
    data[off++] = 0x1d;
    data[off++] = 0x00;
    data[off++] = 0x20;
    memcpy(data + off, pubkey, 32);
    off += 32;

    size_t list_len = off - 2;
    data[0] = (uint8_t)(list_len >> 8);
    data[1] = (uint8_t)(list_len & 0xFF);

    return add_ext(exts, 0x0033, data, off);
}

static int ext_key_share_firefox(dynbuf_t *exts, const uint8_t x25519_pub[32]) {
    uint8_t p256_pub[65];
    if (p256_generate_public(p256_pub) != 0) {
        return -1;
    }

    uint8_t data[2 + 4 + 32 + 4 + 65];
    size_t off = 2;

    data[off++] = 0x00;
    data[off++] = 0x1d;
    data[off++] = 0x00;
    data[off++] = 0x20;
    memcpy(data + off, x25519_pub, 32);
    off += 32;

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

static int ext_compress_cert_brotli(dynbuf_t *exts) {
    /* algorithm list length=2, brotli=0x0002 */
    uint8_t data[] = {0x02, 0x00, 0x02};
    return add_ext(exts, 0x001b, data, sizeof(data));
}

static int ext_delegated_credentials_firefox(dynbuf_t *exts) {
    uint8_t data[] = {0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03};
    return add_ext(exts, 0x0022, data, sizeof(data));
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
                              size_t *sid_pos) {
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
            ext_supported_groups(&exts, boring_grease_group, 0) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_status_request(&exts) != 0 ||
            ext_sig_algs_qq(&exts) != 0 || ext_sct(&exts) != 0 || ext_key_share(&exts, boring_grease_group, client_pub, 0) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_supported_versions_qq(&exts, boring_grease_vers) != 0 ||
            ext_compress_cert_brotli(&exts) != 0 || ext_application_settings_h2(&exts) != 0 ||
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
            ext_supported_groups(&exts, boring_grease_group, 0) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_status_request(&exts) != 0 ||
            ext_sig_algs_qq(&exts) != 0 || ext_sct(&exts) != 0 || ext_key_share(&exts, boring_grease_group, client_pub, 0) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_supported_versions_qq(&exts, boring_grease_vers) != 0 ||
            ext_compress_cert_brotli(&exts) != 0 || ext_grease_1byte_zero(&exts, boring_grease_ext2) != 0) {
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
            ext_renegotiation_info(&exts) != 0 || ext_supported_groups_firefox(&exts) != 0 ||
            ext_ec_point_formats(&exts) != 0 || ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 ||
            ext_status_request(&exts) != 0 || ext_delegated_credentials_firefox(&exts) != 0 ||
            ext_key_share_firefox(&exts, client_pub) != 0 || ext_supported_versions_firefox(&exts) != 0 ||
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
                    if (ext_supported_groups(&exts, grease, 1) != 0) {
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
                    if (ext_key_share(&exts, grease, client_pub, 1) != 0) {
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
    if (read_exact(fd, hdr, sizeof(hdr)) != 0) {
        return -1;
    }

    size_t len = ((size_t)hdr[3] << 8) | hdr[4];
    uint8_t *buf = (uint8_t *)malloc(len);
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

static int parse_server_hello_for_keyshare(const uint8_t *msg, size_t msg_len, uint16_t *cipher_out, uint8_t server_pub[32]) {
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
            if (group != 0x001d || klen != 32 || el < 4 + 32) {
                return -1;
            }
            memcpy(server_pub, k + 4, 32);
            return 0;
        }

        eoff += el;
    }

    return -1;
}

static int transcript_hash(const tls13_conn_t *c, uint8_t *out) {
    return digest_hash(c->tls_md, c->transcript.data, c->transcript.len, out, c->tls_hash_len);
}

static int parse_first_cert_der(const uint8_t *cert_msg, size_t cert_msg_len, const uint8_t **der, size_t *der_len) {
    if (cert_msg_len < 4 || cert_msg[0] != 0x0b) {
        return -1;
    }
    size_t body_len = ((size_t)cert_msg[1] << 16) | ((size_t)cert_msg[2] << 8) | cert_msg[3];
    if (4 + body_len > cert_msg_len) {
        return -1;
    }

    const uint8_t *p = cert_msg + 4;
    size_t n = body_len;

    if (n < 1) {
        return -1;
    }
    uint8_t req_ctx_len = p[0];
    p += 1;
    n -= 1;
    if (n < (size_t)req_ctx_len + 3) {
        return -1;
    }
    p += req_ctx_len;
    n -= req_ctx_len;

    size_t list_len = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
    p += 3;
    n -= 3;

    if (n < list_len || list_len < 3) {
        return -1;
    }

    size_t cert_len = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
    p += 3;
    if (cert_len == 0 || cert_len > n - 3) {
        return -1;
    }

    *der = p;
    *der_len = cert_len;
    return 0;
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

    return tofu_verify_or_store_pin("[tls]", pin_key, peer_pin, 1, err, err_cap);
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
        NULL,
    };
    for (size_t i = 0; ca_paths[i] != NULL; i++) {
        if (ca_paths[i] == NULL || ca_paths[i][0] == '\0') {
            continue;
        }
        if (X509_STORE_load_locations(store, ca_paths[i], NULL) == 1) {
            custom_ca_loaded = 1;
            if (debug != NULL && debug[0] != '\0') {
                fprintf(stderr, "[tls] loaded CA bundle: %s\n", ca_paths[i]);
            }
            break;
        } else if (debug != NULL && debug[0] != '\0') {
            fprintf(stderr, "[tls] failed to load CA bundle: %s\n", ca_paths[i]);
        }
    }

    if (debug != NULL && debug[0] != '\0') {
        fprintf(stderr, "[tls] default CA paths ready=%d custom_ca_loaded=%d\n", default_paths_ready, custom_ca_loaded);
    }
    return (custom_ca_loaded || default_paths_ready) ? 0 : -1;
}

static int verify_tls_cert_message(const char *servername, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap) {
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
        fprintf(stderr, "[tls] cert chain entries=%d untrusted=%d\n", cert_count, sk_X509_num(untrusted));
        fprintf(stderr, "[tls] leaf subject=%s\n", subject);
        fprintf(stderr, "[tls] leaf issuer=%s\n", issuer);
    }

    const char *host = (servername != NULL && servername[0] != '\0') ? servername : NULL;
    if (host == NULL || X509_check_host(leaf, host, 0, 0, NULL) != 1) {
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
    if (ctx == NULL || X509_STORE_CTX_init(ctx, store, leaf, untrusted) != 1) {
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
            fprintf(stderr, "[tls] cert verify failed depth=%d: %s\n", verify_depth, X509_verify_cert_error_string(verify_rc));
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
        return -1;
    }
    return hmac_digest(c->tls_md, finished_key, c->tls_hash_len, transcript_hash_val, c->tls_hash_len, out, c->tls_hash_len);
}

static int derive_handshake_keys(tls13_conn_t *c, const uint8_t shared[32]) {
    uint8_t zero[64] = {0};
    uint8_t empty_hash[64];
    uint8_t early_secret[64];
    uint8_t derived[64];
    uint8_t thash[64];

    if (digest_hash(c->tls_md, NULL, 0, empty_hash, c->tls_hash_len) != 0) {
        return -1;
    }

    if (hkdf_extract_md(c->tls_md, zero, c->tls_hash_len, zero, c->tls_hash_len, early_secret, c->tls_hash_len) != 0) {
        return -1;
    }
    if (derive_secret_md(c->tls_md, early_secret, c->tls_hash_len, "derived", empty_hash, c->tls_hash_len, derived, c->tls_hash_len) != 0) {
        return -1;
    }
    if (hkdf_extract_md(c->tls_md, derived, c->tls_hash_len, shared, 32, c->hs_secret, c->tls_hash_len) != 0) {
        return -1;
    }
    if (transcript_hash(c, thash) != 0) {
        return -1;
    }

    if (derive_secret_md(c->tls_md, c->hs_secret, c->tls_hash_len, "c hs traffic", thash, c->tls_hash_len, c->c_hs_traffic, c->tls_hash_len) != 0 ||
        derive_secret_md(c->tls_md, c->hs_secret, c->tls_hash_len, "s hs traffic", thash, c->tls_hash_len, c->s_hs_traffic, c->tls_hash_len) != 0) {
        return -1;
    }

    if (derive_key_iv_md(c->tls_md, c->c_hs_traffic, c->tls_hash_len, c->tls_key_len, c->c_hs_key, c->c_hs_iv) != 0 ||
        derive_key_iv_md(c->tls_md, c->s_hs_traffic, c->tls_hash_len, c->tls_key_len, c->s_hs_key, c->s_hs_iv) != 0) {
        return -1;
    }

    c->c_hs_seq = 0;
    c->s_hs_seq = 0;
    return 0;
}

static int derive_app_keys(tls13_conn_t *c) {
    uint8_t zero[64] = {0};
    uint8_t empty_hash[64];
    uint8_t derived2[64];
    uint8_t master_secret[64];
    uint8_t thash[64];

    if (digest_hash(c->tls_md, NULL, 0, empty_hash, c->tls_hash_len) != 0) {
        return -1;
    }

    if (derive_secret_md(c->tls_md, c->hs_secret, c->tls_hash_len, "derived", empty_hash, c->tls_hash_len, derived2, c->tls_hash_len) != 0) {
        return -1;
    }
    if (hkdf_extract_md(c->tls_md, derived2, c->tls_hash_len, zero, c->tls_hash_len, master_secret, c->tls_hash_len) != 0) {
        return -1;
    }

    if (transcript_hash(c, thash) != 0) {
        return -1;
    }

    if (derive_secret_md(c->tls_md, master_secret, c->tls_hash_len, "c ap traffic", thash, c->tls_hash_len, c->c_app_traffic, c->tls_hash_len) != 0 ||
        derive_secret_md(c->tls_md, master_secret, c->tls_hash_len, "s ap traffic", thash, c->tls_hash_len, c->s_app_traffic, c->tls_hash_len) != 0) {
        return -1;
    }

    if (derive_key_iv_md(c->tls_md, c->c_app_traffic, c->tls_hash_len, c->tls_key_len, c->c_app_key, c->c_app_iv) != 0 ||
        derive_key_iv_md(c->tls_md, c->s_app_traffic, c->tls_hash_len, c->tls_key_len, c->s_app_key, c->s_app_iv) != 0) {
        return -1;
    }

    c->c_app_seq = 0;
    c->s_app_seq = 0;
    c->c_app_record_bytes = 0;
    return 0;
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
    free(inner);

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
    if (rtype != 0x17 || payload_len < 16) {
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

    uint8_t *content = (uint8_t *)malloc(content_len);
    if (content == NULL) {
        free(buf);
        return -1;
    }
    memcpy(content, buf, content_len);
    free(buf);

    *seq += 1;
    *plain = content;
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

int tls13_has_pending_app(const tls13_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    if (c->app_cache.len > 0) {
        return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
        int cache_ready = c->xhttp_net_cache.len > 0;
        if (c->mode == CONN_MODE_XHTTP_PLAIN && c->xhttp_headers_read && c->xhttp_chunked && c->xhttp_chunk_rem <= 0) {
            size_t skip = c->xhttp_chunk_rem == 0 ? 2 : 0;
            cache_ready = c->xhttp_net_cache.len > skip &&
                          memchr(c->xhttp_net_cache.data + skip, '\n', c->xhttp_net_cache.len - skip) != NULL;
        }
        if (cache_ready || (c->ssl != NULL && SSL_pending(c->ssl) > 0)) {
            return 1;
        }
    }
    if (c->mode == CONN_MODE_XHTTP_TLS_H2 && h2_cached_frame_ready(c)) {
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
        if (frame_len <= H2_MAX_INBOUND_FRAME && c->h2_net_cache.len >= 9 + frame_len) {
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

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(c->fd, &rfds);
    struct timeval tv = {0, 0};
    int rc = select(c->fd + 1, &rfds, NULL, NULL, &tv);
    return rc > 0 && FD_ISSET(c->fd, &rfds);
}

int tls13_drain_h2_input(tls13_conn_t *c) {
    if (c == NULL ||
        (c->mode != CONN_MODE_XHTTP_TLS_H2 && c->mode != CONN_MODE_XHTTP_REALITY && c->mode != CONN_MODE_GRPC_PLAIN)) {
        return 0;
    }

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
            return -1;
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

size_t tls13_write_batch_size(const tls13_conn_t *c) {
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

void tls13_mark_raw_direct(tls13_conn_t *c) {
    if (c != NULL) {
        c->reality_raw_direct = 1;
    }
}

static int append_transcript(tls13_conn_t *c, const uint8_t *msg, size_t msg_len) {
    return db_append(&c->transcript, msg, msg_len);
}

static int run_tls_handshake(const vless_config_t *cfg, tls13_conn_t *c, tls_cipher_offer_t cipher_offer, char *err, size_t err_cap) {
    int use_reality = (strcmp(cfg->security, "reality") == 0);
    snprintf(c->tls_verify_mode, sizeof(c->tls_verify_mode), "%s", use_reality ? "reality" : (cfg->allow_insecure ? "insecure" : "strict"));

    uint8_t client_priv[32];
    uint8_t client_pub[32];
    uint8_t client_random[32];
    uint8_t *ch = NULL;
    size_t ch_len = 0;
    size_t sid_pos = 0;

    if (build_client_hello(cfg, use_reality, cipher_offer, client_priv, client_pub, client_random, c->auth_key, &ch, &ch_len, &sid_pos) !=
        0) {
        set_err(err, err_cap, "failed to build ClientHello");
        return -1;
    }

    uint8_t *ch_record = (uint8_t *)malloc(5 + ch_len);
    if (ch_record == NULL) {
        free(ch);
        set_err(err, err_cap, "failed to allocate ClientHello record");
        return -1;
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
        return -1;
    }
    free(ch_record);

    if (append_transcript(c, ch, ch_len) != 0) {
        free(ch);
        set_err(err, err_cap, "transcript append failed");
        return -1;
    }
    free(ch);

    dynbuf_t plain_hs = {0};
    uint8_t server_pub[32];
    uint16_t server_cipher = 0;
    int got_server_hello = 0;

    for (int attempts = 0; attempts < 16 && !got_server_hello; attempts++) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            db_free(&plain_hs);
            set_err(err, err_cap, "failed to read ServerHello record");
            return -1;
        }

        if (rtype == 0x16) {
            if (db_append(&plain_hs, pl, pl_len) != 0) {
                free(pl);
                db_free(&plain_hs);
                return -1;
            }
            free(pl);

            while (plain_hs.len >= 4) {
                size_t mlen = ((size_t)plain_hs.data[1] << 16) | ((size_t)plain_hs.data[2] << 8) | plain_hs.data[3];
                if (plain_hs.len < 4 + mlen) {
                    break;
                }
                if (plain_hs.data[0] == 0x02) {
                    if (parse_server_hello_for_keyshare(plain_hs.data, 4 + mlen, &server_cipher, server_pub) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "invalid ServerHello");
                        return -1;
                    }
                    if (configure_tls_cipher(c, server_cipher) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "unsupported TLS cipher suite");
                        return -1;
                    }
                    if (append_transcript(c, plain_hs.data, 4 + mlen) != 0) {
                        db_free(&plain_hs);
                        return -1;
                    }
                    got_server_hello = 1;
                    db_consume(&plain_hs, 4 + mlen);
                    break;
                }
                db_consume(&plain_hs, 4 + mlen);
            }
        } else {
            free(pl);
        }
    }

    db_free(&plain_hs);

    if (!got_server_hello) {
        set_err(err, err_cap, "ServerHello not received");
        return -1;
    }

    uint8_t shared[32];
    if (x25519_shared(client_priv, server_pub, shared) != 0) {
        set_err(err, err_cap, "ECDH failed");
        return -1;
    }

    if (derive_handshake_keys(c, shared) != 0) {
        set_err(err, err_cap, "failed to derive handshake keys");
        return -1;
    }

    dynbuf_t enc_hs = {0};
    int got_finished = 0;
    int cert_verified = use_reality ? 0 : (cfg->allow_insecure ? 1 : 0);

    while (!got_finished) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            db_free(&enc_hs);
            set_err(err, err_cap, "failed to read encrypted handshake");
            return -1;
        }

        if (rtype != 0x17) {
            free(pl);
            continue;
        }

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        uint8_t inner_type = 0;
        if (decrypt_record(c, c->s_hs_key, c->s_hs_iv, &c->s_hs_seq, rtype, pl, pl_len, &dec, &dec_len, &inner_type) != 0) {
            free(pl);
            db_free(&enc_hs);
            set_err(err, err_cap, "failed to decrypt handshake record");
            return -1;
        }
        free(pl);

        if (inner_type == 0x16) {
            if (db_append(&enc_hs, dec, dec_len) != 0) {
                free(dec);
                db_free(&enc_hs);
                return -1;
            }
            free(dec);

            while (enc_hs.len >= 4) {
                uint8_t htype = enc_hs.data[0];
                size_t hlen = ((size_t)enc_hs.data[1] << 16) | ((size_t)enc_hs.data[2] << 8) | enc_hs.data[3];
                if (enc_hs.len < 4 + hlen) {
                    break;
                }
                if (htype == 0x14) {
                    uint8_t thash[64];
                    uint8_t expect[64];
                    if (transcript_hash(c, thash) != 0 || calc_finished_verify(c, c->s_hs_traffic, thash, expect) != 0) {
                        db_free(&enc_hs);
                        set_err(err, err_cap, "failed to verify server finished");
                        return -1;
                    }
                    if (hlen != c->tls_hash_len || memcmp(expect, enc_hs.data + 4, c->tls_hash_len) != 0) {
                        db_free(&enc_hs);
                        set_err(err, err_cap, "server Finished mismatch");
                        return -1;
                    }
                    if (append_transcript(c, enc_hs.data, 4 + hlen) != 0) {
                        db_free(&enc_hs);
                        return -1;
                    }
                    db_consume(&enc_hs, 4 + hlen);
                    got_finished = 1;
                    break;
                }

                if (htype == 0x0b) {
                    if (use_reality) {
                        const uint8_t *der = NULL;
                        size_t der_len = 0;
                        if (parse_first_cert_der(enc_hs.data, 4 + hlen, &der, &der_len) == 0) {
                            if (verify_reality_cert(c->auth_key, der, der_len) == 0) {
                                cert_verified = 1;
                            }
                        }
                    } else if (!cfg->allow_insecure) {
                        char verify_err[256] = {0};
                        if (verify_tls_cert_message(cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host, enc_hs.data, 4 + hlen, verify_err,
                                                    sizeof(verify_err)) != 0) {
                            if (!is_cert_verify_error_msg(verify_err)) {
                                set_err(err, err_cap, verify_err[0] != '\0' ? verify_err : "TLS certificate verify failed");
                                db_free(&enc_hs);
                                return -1;
                            }
                            fprintf(stderr, "[tls] cert verify failed, using TOFU: %s\n", verify_err);
                            if (tcp_tls_tofu_verify_or_store(cfg, enc_hs.data, 4 + hlen, err, err_cap) != 0) {
                                db_free(&enc_hs);
                                return -1;
                            }
                            snprintf(c->tls_verify_mode, sizeof(c->tls_verify_mode), "tofu");
                        } else {
                            snprintf(c->tls_verify_mode, sizeof(c->tls_verify_mode), "strict");
                        }
                        cert_verified = 1;
                    }
                }

                if (append_transcript(c, enc_hs.data, 4 + hlen) != 0) {
                    db_free(&enc_hs);
                    return -1;
                }
                db_consume(&enc_hs, 4 + hlen);
            }
        } else {
            free(dec);
        }
    }

    db_free(&enc_hs);

    if (!cert_verified) {
        set_err(err, err_cap, use_reality ? "REALITY cert verify failed" : "TLS certificate verify failed");
        return -1;
    }

    uint8_t thash[64];
    uint8_t client_verify[64];
    if (transcript_hash(c, thash) != 0 || calc_finished_verify(c, c->c_hs_traffic, thash, client_verify) != 0) {
        set_err(err, err_cap, "failed to create client Finished");
        return -1;
    }

    // TLS 1.3 traffic_secret_0 is derived from transcript up to server Finished.
    if (derive_app_keys(c) != 0) {
        set_err(err, err_cap, "failed to derive application keys");
        return -1;
    }

    uint8_t fin_msg[68];
    size_t fin_msg_len = 4 + c->tls_hash_len;
    fin_msg[0] = 0x14;
    fin_msg[1] = 0x00;
    fin_msg[2] = 0x00;
    fin_msg[3] = (uint8_t)c->tls_hash_len;
    memcpy(fin_msg + 4, client_verify, c->tls_hash_len);

    uint8_t *enc_fin = NULL;
    size_t enc_fin_len = 0;
    if (encrypt_record(c, c->c_hs_key, c->c_hs_iv, &c->c_hs_seq, 0x16, fin_msg, fin_msg_len, &enc_fin, &enc_fin_len) != 0) {
        set_err(err, err_cap, "failed to encrypt client Finished");
        return -1;
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
        return -1;
    }
    memcpy(client_last_flight, ccs_rec, sizeof(ccs_rec));
    memcpy(client_last_flight + sizeof(ccs_rec), enc_fin, enc_fin_len);
    if (write_exact(c->fd, client_last_flight, sizeof(ccs_rec) + enc_fin_len) != 0) {
        free(client_last_flight);
        free(enc_fin);
        set_err(err, err_cap, "failed to send client Finished");
        return -1;
    }
    free(client_last_flight);
    free(enc_fin);

    if (append_transcript(c, fin_msg, fin_msg_len) != 0) {
        return -1;
    }

    return 0;
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
                                       socklen_t address_len, int socktype, int protocol, int start_with_aes,
                                       tls_cipher_offer_t *successful_offer, char *err, size_t err_cap) {
    static const tls_cipher_offer_t offer_order[] = {
        TLS_CIPHER_OFFER_CHACHA,
        TLS_CIPHER_OFFER_AES,
    };
    size_t first_offer = start_with_aes ? 1 : 0;

    for (size_t i = first_offer; i < sizeof(offer_order) / sizeof(offer_order[0]); i++) {
        tls_cipher_offer_t offer = offer_order[i];
        reset_manual_tls_handshake(c);
        c->fd = tcp_connect_address(address->sa_family, socktype, protocol, address, address_len);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }

        core_set_socket_io_timeout(c->fd, CORE_TLS_HANDSHAKE_TIMEOUT_MS);
        char attempt_err[256] = {0};
        if (run_tls_handshake(cfg, c, offer, attempt_err, sizeof(attempt_err)) == 0) {
            core_set_socket_io_timeout(c->fd, 0);
            *successful_offer = offer;
            return 0;
        }

        close(c->fd);
        c->fd = -1;
        set_err(err, err_cap, attempt_err[0] != '\0' ? attempt_err : "TLS handshake failed");
    }
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
    char last_err[256] = {0};

    struct sockaddr_storage cached_address;
    socklen_t cached_address_len = 0;
    int cached_endpoint_tried = get_cached_tls_endpoint(cfg, sni, &cached_address, &cached_address_len);
    if (cached_endpoint_tried) {
        tls_cipher_offer_t successful_offer;
        if (connect_manual_tls_endpoint(cfg, c, (const struct sockaddr *)&cached_address, cached_address_len, SOCK_STREAM, IPPROTO_TCP,
                                        start_with_aes, &successful_offer, last_err, sizeof(last_err)) == 0) {
            remember_manual_tls_success(cfg, c, sni, (const struct sockaddr *)&cached_address, cached_address_len, successful_offer);
            return 0;
        }
        invalidate_cached_tls_endpoint(cfg, sni, (const struct sockaddr *)&cached_address, cached_address_len);
    }

    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)cfg->server_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *addresses = NULL;
    if (getaddrinfo(cfg->server_host, port_text, &hints, &addresses) != 0) {
        set_err(err, err_cap, "tcp resolve failed");
        return -1;
    }

    for (struct addrinfo *it = addresses; it != NULL; it = it->ai_next) {
        if (cached_endpoint_tried &&
            sockaddr_equal((const struct sockaddr *)&cached_address, cached_address_len, it->ai_addr, (socklen_t)it->ai_addrlen)) {
            continue;
        }

        tls_cipher_offer_t successful_offer;
        if (connect_manual_tls_endpoint(cfg, c, it->ai_addr, (socklen_t)it->ai_addrlen, it->ai_socktype, it->ai_protocol,
                                        start_with_aes, &successful_offer, last_err, sizeof(last_err)) == 0) {
            remember_manual_tls_success(cfg, c, sni, it->ai_addr, (socklen_t)it->ai_addrlen, successful_offer);
            freeaddrinfo(addresses);
            return 0;
        }
    }
    freeaddrinfo(addresses);

    set_err(err, err_cap, last_err[0] != '\0' ? last_err : "tcp connect failed");
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

    fprintf(stderr, "[tls] connected mode=vision alpn=%s verify=%s\n", cfg->alpn[0] != '\0' ? cfg->alpn : "default",
            c->tls_verify_mode[0] != '\0' ? c->tls_verify_mode : (cfg->allow_insecure ? "insecure" : "strict"));
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
    snprintf(c->ws_host, sizeof(c->ws_host), "%s", host);

    int verify_peer = 0;
    if (ws_tls) {
        static const unsigned char h1_alpn[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        verify_peer = cfg->allow_insecure ? 0 : 1;
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, verify_peer, h1_alpn, sizeof(h1_alpn), &c->ssl_ctx, &c->ssl,
                            &c->fd, &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
    } else {
        c->fd = tcp_connect_host(c->remote_host, c->remote_port);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
    }

    char sec_key[25];
    char expected_accept[29];
    if (ws_make_key(sec_key) != 0 || ws_make_accept(sec_key, expected_accept) != 0) {
        set_err(err, err_cap, "failed to build WebSocket key");
        return -1;
    }

    char req[4096];
    int req_len = snprintf(
        req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: no-cache\r\n"
        "Pragma: no-cache\r\n"
        "DNT: 1\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-Fetch-Dest: empty\r\n"
        "Sec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\n"
        "Sec-CH-UA: \"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"\r\n"
        "Sec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\n"
        "\r\n",
        c->ws_path, c->ws_host, sec_key);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        set_err(err, err_cap, "WebSocket upgrade request too large");
        return -1;
    }
    if (ws_conn_write_all(c, req, (size_t)req_len) != 0) {
        set_err(err, err_cap, "failed to send WebSocket upgrade request");
        return -1;
    }

    int status = 0;
    int has_upgrade = 0;
    int has_connection_upgrade = 0;
    char accept[96];
    if (parse_ws_upgrade_response(c, &c->ws_net_cache, &status, accept, sizeof(accept), &has_upgrade, &has_connection_upgrade, err,
                                  err_cap) != 0) {
        return -1;
    }
    if (status != 101) {
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "WebSocket upgrade returned HTTP %d", status);
        }
        return -1;
    }
    if (!has_upgrade || !has_connection_upgrade || strcmp(accept, expected_accept) != 0) {
        set_err(err, err_cap, "invalid WebSocket upgrade response");
        return -1;
    }

    fprintf(stderr, "[ws] connected path=%s host=%s security=%s verify=%s\n", c->ws_path, c->ws_host, cfg->security,
            ws_tls ? (verify_peer ? "strict" : "insecure") : "none");
    return 0;
}

static int xhttp_configure(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->xhttp_seq = 0;
    c->xhttp_chunk_rem = -1;
    c->xhttp_content_rem = -1;

    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);

    if (normalize_xhttp_path(cfg->xhttp_path, c->xhttp_base_path, sizeof(c->xhttp_base_path)) != 0) {
        set_err(err, err_cap, "invalid xhttp path");
        return -1;
    }

    const char *xhost = cfg->xhttp_host[0] != '\0' ? cfg->xhttp_host : c->remote_sni;
    snprintf(c->xhttp_host, sizeof(c->xhttp_host), "%s", xhost);
    snprintf(c->xhttp_transport_mode, sizeof(c->xhttp_transport_mode), "%s", cfg->xhttp_mode);
    snprintf(c->xhttp_session_placement, sizeof(c->xhttp_session_placement), "%s",
             cfg->xhttp_session_placement[0] != '\0' ? cfg->xhttp_session_placement : "path");
    snprintf(c->xhttp_session_key, sizeof(c->xhttp_session_key), "%s", cfg->xhttp_session_key);
    snprintf(c->xhttp_seq_placement, sizeof(c->xhttp_seq_placement), "%s",
             cfg->xhttp_seq_placement[0] != '\0' ? cfg->xhttp_seq_placement : "path");
    snprintf(c->xhttp_seq_key, sizeof(c->xhttp_seq_key), "%s", cfg->xhttp_seq_key);
    snprintf(c->xhttp_uplink_method, sizeof(c->xhttp_uplink_method), "%s",
             cfg->xhttp_uplink_method[0] != '\0' ? cfg->xhttp_uplink_method : "POST");
    snprintf(c->xhttp_padding_placement, sizeof(c->xhttp_padding_placement), "%s",
             cfg->xhttp_padding_placement[0] != '\0' ? cfg->xhttp_padding_placement : "queryinheader");
    snprintf(c->xhttp_padding_key, sizeof(c->xhttp_padding_key), "%s",
             cfg->xhttp_padding_key[0] != '\0' ? cfg->xhttp_padding_key : "x_padding");
    snprintf(c->xhttp_padding_header, sizeof(c->xhttp_padding_header), "%s",
             cfg->xhttp_padding_header[0] != '\0' ? cfg->xhttp_padding_header : "X-Padding");
    snprintf(c->xhttp_padding_method, sizeof(c->xhttp_padding_method), "%s",
             cfg->xhttp_padding_method[0] != '\0' ? cfg->xhttp_padding_method : "repeat-x");
    c->xhttp_padding_obfs = cfg->xhttp_padding_obfs;
    c->xhttp_padding_min = cfg->xhttp_padding_min > 0 ? cfg->xhttp_padding_min : 100;
    c->xhttp_padding_max = cfg->xhttp_padding_max >= c->xhttp_padding_min ? cfg->xhttp_padding_max : c->xhttp_padding_min;
    int max_post_min = cfg->xhttp_max_each_post_min > 0 ? cfg->xhttp_max_each_post_min : 1000000;
    int max_post_max = cfg->xhttp_max_each_post_max >= max_post_min ? cfg->xhttp_max_each_post_max : max_post_min;
    c->xhttp_max_each_post_bytes = random_range_int(max_post_min, max_post_max);

    c->xhttp_session_id[0] = '\0';
    if (strcmp(c->xhttp_transport_mode, "stream-one") != 0 && random_session_id(c->xhttp_session_id) != 0) {
        set_err(err, err_cap, "failed to create xhttp session id");
        return -1;
    }
    return 0;
}

static int xhttp_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    if (xhttp_configure(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_XHTTP_PLAIN;
        c->fd = tcp_connect_host(c->remote_host, c->remote_port);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
        fprintf(stderr, "[xhttp] plain mode=%s http=1.1 max_each_post=%d\n", c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
        if (strcmp(c->xhttp_transport_mode, "stream-one") == 0) {
            return xhttp_send_plain_stream_request(c, c->fd, err, err_cap);
        }
        if (xhttp_send_download_request(cfg, c, err, err_cap) != 0) {
            return -1;
        }
        if (strcmp(c->xhttp_transport_mode, "stream-up") == 0) {
            c->xhttp_upload_fd = tcp_connect_host(c->remote_host, c->remote_port);
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

        fprintf(stderr, "[xhttp] reality mode=%s http=2\n", c->xhttp_transport_mode);
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

    xhttp_tls_mode_t mode = get_xhttp_tls_mode();
    if (mode == XHTTP_TLS_MODE_TOFU) {
        xhttp_log_tls_mode_selected(mode, 0);
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, xhttp_alpn, xhttp_alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
        if (xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = xhttp_effective_verify_peer();
        xhttp_log_tls_mode_selected(mode, verify_peer);
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, verify_peer, xhttp_alpn, xhttp_alpn_len, &c->ssl_ctx, &c->ssl,
                            &c->fd, &c->tls_use_aes_fallback, err, err_cap) != 0) {
            if (!(verify_peer == 1 && xhttp_auto_fallback_allowed() && is_cert_verify_error_msg(err))) {
                return -1;
            }
            if (!g_xhttp_auto_force_insecure) {
                fprintf(stderr, "[xhttp] tls_mode=auto(selected=insecure+tofu): %s\n", err);
            }
            g_xhttp_auto_force_insecure = 1;
            if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, xhttp_alpn, xhttp_alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                                &c->tls_use_aes_fallback, err, err_cap) != 0) {
                return -1;
            }
            if (mode == XHTTP_TLS_MODE_AUTO && xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
                return -1;
            }
            c->xhttp_tls_insecure = 1;
        } else {
            c->xhttp_tls_insecure = verify_peer ? 0 : 1;
        }
    }

    if (ssl_selected_alpn_is_h2(c->ssl)) {
        c->mode = CONN_MODE_XHTTP_TLS_H2;
        fprintf(stderr, "[xhttp] tls mode=%s http=2 max_each_post=%d\n", c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
        if (xhttp_h2_start_mode(c, err, err_cap) != 0) {
            return -1;
        }
        return 0;
    }

    if (strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        set_err(err, err_cap, "xhttp stream-one and stream-up require HTTP/2");
        return -1;
    }
    fprintf(stderr, "[xhttp] tls mode=%s http=1.1 max_each_post=%d\n", c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
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

    xhttp_tls_mode_t mode = get_xhttp_tls_mode();
    if (cfg->allow_insecure) {
        mode = XHTTP_TLS_MODE_INSECURE;
    }
    if (mode == XHTTP_TLS_MODE_TOFU) {
        fprintf(stderr, "[grpc] tls_mode=tofu\n");
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, alpn, alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0 ||
            xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = mode == XHTTP_TLS_MODE_INSECURE ? 0 : xhttp_effective_verify_peer();
        fprintf(stderr, "[grpc] tls_mode=%s\n", xhttp_tls_mode_name(mode));
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, verify_peer, alpn, alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            if (!(verify_peer == 1 && mode == XHTTP_TLS_MODE_AUTO && is_cert_verify_error_msg(err))) {
                return -1;
            }
            fprintf(stderr, "[grpc] tls_mode=auto(selected=insecure+tofu): %s\n", err);
            if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, alpn, alpn_len, &c->ssl_ctx, &c->ssl, &c->fd,
                                &c->tls_use_aes_fallback, err, err_cap) != 0 ||
                xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
                return -1;
            }
            c->xhttp_tls_insecure = 1;
        } else {
            c->xhttp_tls_insecure = verify_peer ? 0 : 1;
        }
    }

    if (!ssl_selected_alpn_is_h2(c->ssl)) {
        set_err(err, err_cap, "grpc requires HTTP/2 ALPN");
        return -1;
    }
    c->mode = CONN_MODE_XHTTP_TLS_H2;
    return 0;
}

static int grpc_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->grpc_transport = 1;
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);
    snprintf(c->grpc_service_name, sizeof(c->grpc_service_name), "%s", cfg->grpc_service_name);
    c->grpc_multi_mode = strcmp(cfg->xhttp_mode, "multi") == 0;

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
        c->fd = tcp_connect_host(c->remote_host, c->remote_port);
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
    fprintf(stderr, "[grpc] connected service=%s authority=%s security=%s mode=%s\n", c->grpc_service_name, c->grpc_authority,
            cfg->security, c->grpc_multi_mode ? "multi" : "single");
    return 0;
}

int tls13_reality_connect(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap) {
    *out = NULL;
    tls13_conn_t *c = (tls13_conn_t *)calloc(1, sizeof(*c));
    if (c == NULL) {
        set_err(err, err_cap, "oom");
        return -1;
    }
    c->fd = -1;
    c->xhttp_upload_fd = -1;
    c->mode = CONN_MODE_REALITY;

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        if (xhttp_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (cfg->transport_mode == TRANSPORT_GRPC) {
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
        c->fd = tcp_connect_host(cfg->server_host, cfg->server_port);
        if (c->fd < 0) {
            tls13_reality_close(c);
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
        fprintf(stderr, "[tcp] connected security=none\n");
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

void tls13_reality_close(tls13_conn_t *c) {
    if (c == NULL) {
        return;
    }
    if (c->mode == CONN_MODE_XHTTP_PLAIN && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        int upload_fd = strcmp(c->xhttp_transport_mode, "stream-one") == 0 ? c->fd : c->xhttp_upload_fd;
        if (upload_fd >= 0) {
            (void)write_exact(upload_fd, "0\r\n\r\n", 5);
        }
    }
    if (c->grpc_transport && c->h2_stream_id != 0 && c->fd >= 0) {
        (void)h2_send_frame(c, H2_FRAME_DATA, H2_FLAG_END_STREAM, c->h2_stream_id, NULL, 0);
    }
    if (c->xhttp_upload_fd >= 0) {
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
    db_free(&c->xhttp_net_cache);
    db_free(&c->ws_net_cache);
    db_free(&c->h2_net_cache);
    db_free(&c->h2_send_buf);
    db_free(&c->grpc_recv_cache);
    db_free(&c->transcript);
    db_free(&c->app_cache);
    free(c);
}

static int reality_write_app_records(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
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

        uint8_t *rec = NULL;
        size_t rec_len = 0;
        if (encrypt_record(c, c->c_app_key, c->c_app_iv, &c->c_app_seq, 0x17, buf + off, chunk, &rec, &rec_len) != 0) {
            return -1;
        }
        if (write_exact(c->fd, rec, rec_len) != 0) {
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
    if (c->grpc_transport) {
        return grpc_write_hunk(c, buf, len);
    }

    if (c->mode == CONN_MODE_PLAIN) {
        return write_exact(c->fd, buf, len);
    }

    if (c->mode == CONN_MODE_WS) {
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
            if (xhttp_post_packet(c, buf + off, chunk, err, sizeof(err)) != 0) {
                if (err[0] != '\0') {
                    fprintf(stderr, "[xhttp] upload failed: %s\n", err);
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
            if (xhttp_h2_post_packet(c, buf + off, chunk, err, sizeof(err)) != 0) {
                if (err[0] != '\0') {
                    fprintf(stderr, "[xhttp] h2 upload failed: %s\n", err);
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
                if (xhttp_h2_post_packet(c, buf + off, chunk, err, sizeof(err)) != 0) {
                    if (err[0] != '\0') {
                        fprintf(stderr, "[xhttp] h2 upload failed: %s\n", err);
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

static int fill_reality_plain_cache(tls13_conn_t *c, dynbuf_t *cache) {
    for (;;) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            fprintf(stderr, "[tls] read_record failed in app phase\n");
            return -1;
        }

        if (rtype != 0x17) {
            fprintf(stderr, "[tls] non-app record type=0x%02x in app phase\n", rtype);
            free(pl);
            continue;
        }

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        uint8_t inner = 0;
        if (decrypt_record(c, c->s_app_key, c->s_app_iv, &c->s_app_seq, rtype, pl, pl_len, &dec, &dec_len, &inner) != 0) {
            if (rtype == 0x17 && pl_len > 0 && pl_len <= 18432) {
                uint8_t hdr[5] = {0x17, 0x03, 0x03, (uint8_t)(pl_len >> 8), (uint8_t)(pl_len & 0xFF)};
                int rc = db_append(cache, hdr, sizeof(hdr));
                if (rc == 0) {
                    rc = db_append(cache, pl, pl_len);
                }
                free(pl);
                if (rc != 0) {
                    return -1;
                }
                c->reality_raw_direct = 1;
                fprintf(stderr, "[tls] decrypt_record failed in app phase, switching to raw direct fallback\n");
                return 0;
            }
            fprintf(stderr, "[tls] decrypt_record failed in app phase\n");
            free(pl);
            return -1;
        }
        free(pl);

        if (inner == 0x17) {
            int rc = db_append(cache, dec, dec_len);
            free(dec);
            if (rc != 0) {
                return -1;
            }
            if (cache->len > 0) {
                return 0;
            }
        } else {
            if (inner == 0x15) {
                if (dec_len >= 2) {
                    fprintf(stderr, "[tls] alert level=%u desc=%u\n", (unsigned)dec[0], (unsigned)dec[1]);
                } else {
                    fprintf(stderr, "[tls] alert with short payload len=%zu\n", dec_len);
                }
            } else {
                fprintf(stderr, "[tls] inner content type=0x%02x in app phase\n", inner);
            }
            free(dec);
            if (inner == 0x15) {
                return -1;
            }
        }
    }
}

static int fill_reality_app_cache(tls13_conn_t *c) {
    return fill_reality_plain_cache(c, &c->app_cache);
}

int tls13_read_app(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }

    if (c->mode == CONN_MODE_PLAIN) {
        return fd_read_some(c->fd, buf, cap, out_len);
    }

    if (c->app_cache.len == 0) {
        if (c->mode == CONN_MODE_WS) {
            if (ws_fill_app_cache(c) != 0) {
                return -1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
            int rc = xhttp_fill_app_cache(c);
            if (rc < 0) {
                return -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_GRPC_PLAIN) {
            int rc = h2_fill_app_cache(c);
            if (rc < 0) {
                return -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_REALITY) {
            int rc = h2_fill_app_cache(c);
            if (rc < 0) {
                return -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (fill_reality_app_cache(c) != 0) {
            return -1;
        }
    }

    size_t take = c->app_cache.len;
    if (take > cap) {
        take = cap;
    }
    memcpy(buf, c->app_cache.data, take);
    db_consume(&c->app_cache, take);
    *out_len = take;
    return 0;
}

int tls13_read_exact_app(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t got = 0;
        int rc = tls13_read_app(c, buf + off, len - off, &got);
        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            continue;
        }
        if (got == 0) {
            return -1;
        }
        off += got;
    }
    return 0;
}
