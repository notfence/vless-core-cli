#define _POSIX_C_SOURCE 200112L

#include "tls13_reality.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
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
    CONN_MODE_XHTTP = 1
} conn_mode_t;

typedef enum {
    XHTTP_TLS_MODE_AUTO = 0,
    XHTTP_TLS_MODE_STRICT = 1,
    XHTTP_TLS_MODE_INSECURE = 2,
    XHTTP_TLS_MODE_TOFU = 3
} xhttp_tls_mode_t;

static int g_xhttp_auto_force_insecure = 0;

struct tls13_conn {
    int fd;
    conn_mode_t mode;

    uint8_t auth_key[32];

    uint8_t hs_secret[32];
    uint8_t c_hs_traffic[32];
    uint8_t s_hs_traffic[32];

    uint8_t c_app_traffic[32];
    uint8_t s_app_traffic[32];

    uint8_t c_hs_key[16], c_hs_iv[12];
    uint8_t s_hs_key[16], s_hs_iv[12];

    uint8_t c_app_key[16], c_app_iv[12];
    uint8_t s_app_key[16], s_app_iv[12];

    uint64_t c_hs_seq;
    uint64_t s_hs_seq;
    uint64_t c_app_seq;
    uint64_t s_app_seq;

    SSL_CTX *ssl_ctx;
    SSL *ssl;

    char remote_host[256];
    uint16_t remote_port;
    char remote_sni[256];

    char xhttp_base_path[512];
    char xhttp_host[256];
    char xhttp_session_id[64];
    uint64_t xhttp_seq;
    int xhttp_chunked;
    int64_t xhttp_content_rem;
    int64_t xhttp_chunk_rem;
    int xhttp_eof;
    int xhttp_tls_insecure;
    char xhttp_pin_key[320];

    dynbuf_t xhttp_net_cache;
    dynbuf_t transcript;
    dynbuf_t app_cache;
};

static void set_err(char *err, size_t cap, const char *msg) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
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
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
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

static int random_xpadding(char *buf, size_t cap) {
    if (cap < 1002) {
        return -1;
    }
    uint8_t b = 0;
    if (RAND_bytes(&b, 1) != 1) {
        return -1;
    }
    int len = 100 + (b % 901); // [100,1000]
    memset(buf, 'X', (size_t)len);
    buf[len] = '\0';
    return 0;
}

static int is_cert_verify_error_msg(const char *err) {
    if (err == NULL || err[0] == '\0') {
        return 0;
    }
    return strstr(err, "certificate verify failed") != NULL || strstr(err, "unable to get local issuer") != NULL ||
           strstr(err, "self signed certificate") != NULL || strstr(err, "hostname mismatch") != NULL;
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

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (SHA256(der, (size_t)der_len, digest) == NULL) {
        OPENSSL_free(der);
        X509_free(peer);
        set_err(err, err_cap, "failed to hash peer certificate");
        return -1;
    }

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(pin_hex + (i * 2), 3, "%02x", digest[i]);
    }
    pin_hex[64] = '\0';

    OPENSSL_free(der);
    X509_free(peer);
    return 0;
}

static int xhttp_tofu_verify_or_store(SSL *ssl, const char *pin_key, int log_ok, char *err, size_t err_cap) {
    char peer_pin[65];
    if (tls_peer_leaf_pin_hex(ssl, peer_pin, err, err_cap) != 0) {
        return -1;
    }

    char known_pin[65];
    if (xhttp_load_pin(pin_key, known_pin) == 0) {
        if (strcmp(known_pin, peer_pin) != 0) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "TOFU pin mismatch for %s", pin_key);
            }
            return -1;
        }
        if (log_ok) {
            fprintf(stderr, "[xhttp] TOFU pin verified for %s\n", pin_key);
        }
        return 0;
    }

    if (xhttp_store_pin(pin_key, peer_pin, err, err_cap) != 0) {
        return -1;
    }
    if (log_ok) {
        fprintf(stderr, "[xhttp] TOFU pin learned for %s\n", pin_key);
    }
    return 0;
}

static int open_tls_socket(const char *connect_host, uint16_t connect_port, const char *sni, int verify_peer, SSL_CTX **out_ctx, SSL **out_ssl,
                           int *out_fd, char *err, size_t err_cap) {
    *out_ctx = NULL;
    *out_ssl = NULL;
    *out_fd = -1;

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

    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        int default_paths_ready = (SSL_CTX_set_default_verify_paths(ctx) == 1) ? 1 : 0;
        int custom_ca_loaded = 0;

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
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_get_error();
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

static int parse_http_response_headers(SSL *ssl, dynbuf_t *cache, int *status_code, int *chunked, int64_t *content_len, char *err,
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
        if (ssl_read_some(ssl, tmp, sizeof(tmp), &got) != 0 || got == 0) {
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
    return ssl_read_some(c->ssl, buf, cap, out_len);
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

static int xhttp_fill_app_cache(tls13_conn_t *c) {
    if (c->xhttp_eof) {
        return -1;
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

static int xhttp_send_download_request(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[768];
    snprintf(request_path, sizeof(request_path), "%s%s", c->xhttp_base_path, c->xhttp_session_id);

    char xpadding[1100];
    if (random_xpadding(xpadding, sizeof(xpadding)) != 0) {
        set_err(err, err_cap, "failed to generate x_padding");
        return -1;
    }

    char referer[2048];
    snprintf(referer, sizeof(referer), "https://%s%s?x_padding=%s", c->xhttp_host, c->xhttp_base_path, xpadding);

    char req[4096];
    int req_len =
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vless-core/1.0\r\nAccept: */*\r\nCache-Control: no-cache\r\n"
                                   "Referer: %s\r\nConnection: keep-alive\r\n\r\n",
                 request_path, c->xhttp_host, referer);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        set_err(err, err_cap, "xhttp GET request too large");
        return -1;
    }

    if (ssl_write_all(c->ssl, req, (size_t)req_len) != 0) {
        set_err(err, err_cap, "failed to send xhttp GET");
        return -1;
    }

    int status = 0;
    int chunked = 0;
    int64_t content_len = -1;
    if (parse_http_response_headers(c->ssl, &c->xhttp_net_cache, &status, &chunked, &content_len, err, err_cap) != 0) {
        return -1;
    }
    if (status != 200) {
        set_err(err, err_cap, "xhttp GET returned non-200");
        return -1;
    }

    c->xhttp_chunked = chunked;
    c->xhttp_content_rem = content_len;
    c->xhttp_chunk_rem = -1;
    c->xhttp_eof = 0;
    (void)cfg;
    return 0;
}

static int xhttp_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t len, char *err, size_t err_cap) {
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
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, &ctx, &ssl, &fd, err, err_cap) != 0) {
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
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, verify_peer, &ctx, &ssl, &fd, err, err_cap) != 0) {
            if (!(verify_peer == 1 && xhttp_auto_fallback_allowed() && is_cert_verify_error_msg(err))) {
                return -1;
            }
            if (!g_xhttp_auto_force_insecure) {
                fprintf(stderr, "[xhttp] tls_mode=auto(selected=insecure+tofu): %s\n", err);
            }
            g_xhttp_auto_force_insecure = 1;
            if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, &ctx, &ssl, &fd, err, err_cap) != 0) {
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

    char request_path[1024];
    snprintf(request_path, sizeof(request_path), "%s%s/%s", c->xhttp_base_path, c->xhttp_session_id, seq);

    char xpadding[1100];
    if (random_xpadding(xpadding, sizeof(xpadding)) != 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "failed to generate x_padding");
        return -1;
    }

    char referer[2048];
    snprintf(referer, sizeof(referer), "https://%s%s?x_padding=%s", c->xhttp_host, c->xhttp_base_path, xpadding);

    char req[4096];
    int req_len = snprintf(req, sizeof(req),
                           "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vless-core/1.0\r\nAccept: */*\r\nReferer: %s\r\n"
                           "Content-Type: application/octet-stream\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                           request_path, c->xhttp_host, referer, len);
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
        if (parse_http_response_headers(ssl, &cache, &status, &chunked, &content_len, err, err_cap) != 0) {
            rc = -1;
        } else if (status != 200) {
            rc = -1;
            set_err(err, err_cap, "xhttp POST returned non-200");
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

static int sha256_hash(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    if (m == NULL) {
        return -1;
    }
    int ok = EVP_DigestInit_ex(m, EVP_sha256(), NULL) == 1;
    if (ok && in_len > 0) {
        ok = EVP_DigestUpdate(m, in, in_len) == 1;
    }
    if (ok) {
        ok = EVP_DigestFinal_ex(m, out, NULL) == 1;
    }
    EVP_MD_CTX_free(m);
    return ok ? 0 : -1;
}

static int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len, uint8_t out[32]) {
    unsigned int out_len = 0;
    unsigned char *ret = HMAC(EVP_sha256(), key, (int)key_len, in, in_len, out, &out_len);
    return (ret != NULL && out_len == 32) ? 0 : -1;
}

static int hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len, uint8_t out[64]) {
    unsigned int out_len = 0;
    unsigned char *ret = HMAC(EVP_sha512(), key, (int)key_len, in, in_len, out, &out_len);
    return (ret != NULL && out_len == 64) ? 0 : -1;
}

static int hkdf_extract_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
    return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static int hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t t[32];
    size_t pos = 0;
    uint8_t counter = 1;
    size_t t_len = 0;

    while (pos < out_len) {
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (ctx == NULL) {
            return -1;
        }
        if (HMAC_Init_ex(ctx, prk, 32, EVP_sha256(), NULL) != 1) {
            HMAC_CTX_free(ctx);
            return -1;
        }
        if (t_len > 0 && HMAC_Update(ctx, t, t_len) != 1) {
            HMAC_CTX_free(ctx);
            return -1;
        }
        if (info_len > 0 && HMAC_Update(ctx, info, info_len) != 1) {
            HMAC_CTX_free(ctx);
            return -1;
        }
        if (HMAC_Update(ctx, &counter, 1) != 1) {
            HMAC_CTX_free(ctx);
            return -1;
        }
        unsigned int got = 0;
        if (HMAC_Final(ctx, t, &got) != 1 || got != 32) {
            HMAC_CTX_free(ctx);
            return -1;
        }
        HMAC_CTX_free(ctx);

        size_t take = out_len - pos;
        if (take > 32) {
            take = 32;
        }
        memcpy(out + pos, t, take);
        pos += take;
        t_len = 32;
        counter++;
    }

    return 0;
}

static int hkdf_expand_label_sha256(const uint8_t secret[32], const char *label, const uint8_t *ctx, size_t ctx_len, uint8_t *out,
                                    size_t out_len) {
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

    return hkdf_expand_sha256(secret, info, off, out, out_len);
}

static int derive_secret(const uint8_t secret[32], const char *label, const uint8_t transcript_hash[32], uint8_t out[32]) {
    return hkdf_expand_label_sha256(secret, label, transcript_hash, 32, out, 32);
}

static int derive_key_iv(const uint8_t traffic_secret[32], uint8_t key[16], uint8_t iv[12]) {
    uint8_t zero_ctx[1] = {0};
    if (hkdf_expand_label_sha256(traffic_secret, "key", zero_ctx, 0, key, 16) != 0) {
        return -1;
    }
    if (hkdf_expand_label_sha256(traffic_secret, "iv", zero_ctx, 0, iv, 12) != 0) {
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

static int ext_padding(dynbuf_t *exts, size_t pad_len) {
    uint8_t *z = (uint8_t *)calloc(1, pad_len);
    if (z == NULL) {
        return -1;
    }
    int rc = add_ext(exts, 0x0015, z, pad_len);
    free(z);
    return rc;
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

static int build_client_hello(const vless_config_t *cfg, uint8_t client_priv[32], uint8_t client_pub[32], uint8_t client_random[32],
                              uint8_t auth_key[32], uint8_t **out, size_t *out_len, size_t *sid_pos) {
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
    uint8_t sid_zero[32] = {0};
    if (db_append(&hs, sid_zero, sizeof(sid_zero)) != 0) {
        db_free(&hs);
        return -1;
    }

    uint16_t grease = random_grease_value();
    uint8_t suites[8];
    size_t soff = 0;
    if (cfg->fp_mode == FP_CHROME) {
        suites[soff++] = (uint8_t)(grease >> 8);
        suites[soff++] = (uint8_t)(grease & 0xFF);
    }
    suites[soff++] = 0x13;
    suites[soff++] = 0x01;

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

    int random_mode = (cfg->fp_mode == FP_RANDOM) ? 1 : 0;
    if (!random_mode) {
        if (ext_server_name(&exts, cfg->sni) != 0 || ext_supported_groups(&exts, grease, 0) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_sig_algs(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_supported_versions(&exts, grease, 0) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_key_share(&exts, grease, client_pub, 0) != 0 || ext_padding(&exts, 16) != 0) {
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

    uint8_t sid_plain[16] = {0};
    uint8_t vx = 26, vy = 3, vz = 27;
    const char *ver_env = getenv("V2IOS6_VER");
    if (ver_env != NULL) {
        unsigned int tx = 0, ty = 0, tz = 0;
        if (sscanf(ver_env, "%u.%u.%u", &tx, &ty, &tz) == 3 && tx <= 255 && ty <= 255 && tz <= 255) {
            vx = (uint8_t)tx;
            vy = (uint8_t)ty;
            vz = (uint8_t)tz;
        }
    }
    sid_plain[0] = vx;
    sid_plain[1] = vy;
    sid_plain[2] = vz;
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
    if (hkdf_extract_sha256(client_random, 20, shared, 32, prk) != 0 ||
        hkdf_expand_sha256(prk, (const uint8_t *)"REALITY", 7, auth_key, 32) != 0) {
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

static int parse_server_hello_for_keyshare(const uint8_t *msg, size_t msg_len, uint8_t server_pub[32]) {
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

    if (cipher != 0x1301) {
        return -1;
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

static int transcript_hash(const tls13_conn_t *c, uint8_t out[32]) {
    return sha256_hash(c->transcript.data, c->transcript.len, out);
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

static int verify_reality_cert(const uint8_t auth_key[32], const uint8_t *cert_der, size_t cert_der_len) {
    const unsigned char *p = cert_der;
    X509 *x = d2i_X509(NULL, &p, (long)cert_der_len);
    if (x == NULL) {
        return -1;
    }

    EVP_PKEY *pk = X509_get_pubkey(x);
    if (pk == NULL || EVP_PKEY_base_id(pk) != EVP_PKEY_ED25519) {
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

static int calc_finished_verify(const uint8_t traffic_secret[32], const uint8_t transcript_hash_val[32], uint8_t out[32]) {
    uint8_t finished_key[32];
    uint8_t zero_ctx[1] = {0};
    if (hkdf_expand_label_sha256(traffic_secret, "finished", zero_ctx, 0, finished_key, 32) != 0) {
        return -1;
    }
    return hmac_sha256(finished_key, 32, transcript_hash_val, 32, out);
}

static int derive_handshake_keys(tls13_conn_t *c, const uint8_t shared[32]) {
    uint8_t zero[32] = {0};
    uint8_t empty_hash[32];
    uint8_t early_secret[32];
    uint8_t derived[32];
    uint8_t thash[32];

    if (sha256_hash(NULL, 0, empty_hash) != 0) {
        return -1;
    }

    if (hkdf_extract_sha256(zero, sizeof(zero), zero, sizeof(zero), early_secret) != 0) {
        return -1;
    }
    if (derive_secret(early_secret, "derived", empty_hash, derived) != 0) {
        return -1;
    }
    if (hkdf_extract_sha256(derived, sizeof(derived), shared, 32, c->hs_secret) != 0) {
        return -1;
    }
    if (transcript_hash(c, thash) != 0) {
        return -1;
    }

    if (derive_secret(c->hs_secret, "c hs traffic", thash, c->c_hs_traffic) != 0 ||
        derive_secret(c->hs_secret, "s hs traffic", thash, c->s_hs_traffic) != 0) {
        return -1;
    }

    if (derive_key_iv(c->c_hs_traffic, c->c_hs_key, c->c_hs_iv) != 0 ||
        derive_key_iv(c->s_hs_traffic, c->s_hs_key, c->s_hs_iv) != 0) {
        return -1;
    }

    c->c_hs_seq = 0;
    c->s_hs_seq = 0;
    return 0;
}

static int derive_app_keys(tls13_conn_t *c) {
    uint8_t zero[32] = {0};
    uint8_t empty_hash[32];
    uint8_t derived2[32];
    uint8_t master_secret[32];
    uint8_t thash[32];

    if (sha256_hash(NULL, 0, empty_hash) != 0) {
        return -1;
    }

    if (derive_secret(c->hs_secret, "derived", empty_hash, derived2) != 0) {
        return -1;
    }
    if (hkdf_extract_sha256(derived2, sizeof(derived2), zero, sizeof(zero), master_secret) != 0) {
        return -1;
    }

    if (transcript_hash(c, thash) != 0) {
        return -1;
    }

    if (derive_secret(master_secret, "c ap traffic", thash, c->c_app_traffic) != 0 ||
        derive_secret(master_secret, "s ap traffic", thash, c->s_app_traffic) != 0) {
        return -1;
    }

    if (derive_key_iv(c->c_app_traffic, c->c_app_key, c->c_app_iv) != 0 ||
        derive_key_iv(c->s_app_traffic, c->s_app_key, c->s_app_iv) != 0) {
        return -1;
    }

    c->c_app_seq = 0;
    c->s_app_seq = 0;
    return 0;
}

static int encrypt_record(const uint8_t key[16], const uint8_t iv[12], uint64_t *seq, uint8_t inner_type, const uint8_t *plain,
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

    int len1 = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             EVP_EncryptUpdate(ctx, NULL, &len1, record, 5) == 1 &&
             EVP_EncryptUpdate(ctx, record + 5, &len1, inner, (int)inner_len) == 1;

    int len2 = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, record + 5 + len1, &len2) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, record + 5 + inner_len) == 1;
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

static int decrypt_record(const uint8_t key[16], const uint8_t iv[12], uint64_t *seq, uint8_t rtype, const uint8_t *payload,
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

    int len1 = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             EVP_DecryptUpdate(ctx, NULL, &len1, hdr, 5) == 1 && EVP_DecryptUpdate(ctx, buf, &len1, ct, (int)ct_len) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1;

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

static int append_transcript(tls13_conn_t *c, const uint8_t *msg, size_t msg_len) {
    return db_append(&c->transcript, msg, msg_len);
}

static int run_tls_handshake(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    uint8_t client_priv[32];
    uint8_t client_pub[32];
    uint8_t client_random[32];
    uint8_t *ch = NULL;
    size_t ch_len = 0;
    size_t sid_pos = 0;

    if (build_client_hello(cfg, client_priv, client_pub, client_random, c->auth_key, &ch, &ch_len, &sid_pos) != 0) {
        set_err(err, err_cap, "failed to build ClientHello");
        return -1;
    }

    uint8_t rec_hdr[5] = {0x16, 0x03, 0x01, (uint8_t)(ch_len >> 8), (uint8_t)(ch_len & 0xFF)};
    if (write_exact(c->fd, rec_hdr, sizeof(rec_hdr)) != 0 || write_exact(c->fd, ch, ch_len) != 0) {
        free(ch);
        set_err(err, err_cap, "failed to send ClientHello");
        return -1;
    }

    if (append_transcript(c, ch, ch_len) != 0) {
        free(ch);
        set_err(err, err_cap, "transcript append failed");
        return -1;
    }
    free(ch);

    dynbuf_t plain_hs = {0};
    uint8_t server_pub[32];
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
                    if (parse_server_hello_for_keyshare(plain_hs.data, 4 + mlen, server_pub) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "invalid ServerHello");
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
    int cert_verified = 0;

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
        if (decrypt_record(c->s_hs_key, c->s_hs_iv, &c->s_hs_seq, rtype, pl, pl_len, &dec, &dec_len, &inner_type) != 0) {
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
                    uint8_t thash[32];
                    uint8_t expect[32];
                    if (transcript_hash(c, thash) != 0 || calc_finished_verify(c->s_hs_traffic, thash, expect) != 0) {
                        db_free(&enc_hs);
                        set_err(err, err_cap, "failed to verify server finished");
                        return -1;
                    }
                    if (hlen != 32 || memcmp(expect, enc_hs.data + 4, 32) != 0) {
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
                    const uint8_t *der = NULL;
                    size_t der_len = 0;
                    if (parse_first_cert_der(enc_hs.data, 4 + hlen, &der, &der_len) == 0) {
                        if (verify_reality_cert(c->auth_key, der, der_len) == 0) {
                            cert_verified = 1;
                        }
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
        set_err(err, err_cap, "REALITY cert verify failed");
        return -1;
    }

    uint8_t thash[32];
    uint8_t client_verify[32];
    if (transcript_hash(c, thash) != 0 || calc_finished_verify(c->c_hs_traffic, thash, client_verify) != 0) {
        set_err(err, err_cap, "failed to create client Finished");
        return -1;
    }

    // TLS 1.3 traffic_secret_0 is derived from transcript up to server Finished.
    if (derive_app_keys(c) != 0) {
        set_err(err, err_cap, "failed to derive application keys");
        return -1;
    }

    uint8_t fin_msg[36];
    fin_msg[0] = 0x14;
    fin_msg[1] = 0x00;
    fin_msg[2] = 0x00;
    fin_msg[3] = 0x20;
    memcpy(fin_msg + 4, client_verify, 32);

    uint8_t *enc_fin = NULL;
    size_t enc_fin_len = 0;
    if (encrypt_record(c->c_hs_key, c->c_hs_iv, &c->c_hs_seq, 0x16, fin_msg, sizeof(fin_msg), &enc_fin, &enc_fin_len) != 0) {
        set_err(err, err_cap, "failed to encrypt client Finished");
        return -1;
    }

    if (write_exact(c->fd, enc_fin, enc_fin_len) != 0) {
        free(enc_fin);
        set_err(err, err_cap, "failed to send client Finished");
        return -1;
    }
    free(enc_fin);

    if (append_transcript(c, fin_msg, sizeof(fin_msg)) != 0) {
        return -1;
    }

    return 0;
}

static int xhttp_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->mode = CONN_MODE_XHTTP;
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
    if (random_session_id(c->xhttp_session_id) != 0) {
        set_err(err, err_cap, "failed to create xhttp session id");
        return -1;
    }

    if (xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                           sizeof(c->xhttp_pin_key)) != 0) {
        set_err(err, err_cap, "failed to build xhttp pin key");
        return -1;
    }

    xhttp_tls_mode_t mode = get_xhttp_tls_mode();
    if (mode == XHTTP_TLS_MODE_TOFU) {
        xhttp_log_tls_mode_selected(mode, 0);
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, &c->ssl_ctx, &c->ssl, &c->fd, err, err_cap) != 0) {
            return -1;
        }
        if (xhttp_tofu_verify_or_store(c->ssl, c->xhttp_pin_key, 1, err, err_cap) != 0) {
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = xhttp_effective_verify_peer();
        xhttp_log_tls_mode_selected(mode, verify_peer);
        if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, verify_peer, &c->ssl_ctx, &c->ssl, &c->fd, err, err_cap) != 0) {
            if (!(verify_peer == 1 && xhttp_auto_fallback_allowed() && is_cert_verify_error_msg(err))) {
                return -1;
            }
            if (!g_xhttp_auto_force_insecure) {
                fprintf(stderr, "[xhttp] tls_mode=auto(selected=insecure+tofu): %s\n", err);
            }
            g_xhttp_auto_force_insecure = 1;
            if (open_tls_socket(c->remote_host, c->remote_port, c->remote_sni, 0, &c->ssl_ctx, &c->ssl, &c->fd, err, err_cap) != 0) {
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
    if (xhttp_send_download_request(cfg, c, err, err_cap) != 0) {
        return -1;
    }
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
    c->mode = CONN_MODE_REALITY;

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        if (xhttp_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    int fd = tcp_connect_host(cfg->server_host, cfg->server_port);
    if (fd < 0) {
        tls13_reality_close(c);
        set_err(err, err_cap, "tcp connect failed");
        return -1;
    }
    c->fd = fd;

    if (run_tls_handshake(cfg, c, err, err_cap) != 0) {
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
    if (c->ssl != NULL) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ssl_ctx != NULL) {
        SSL_CTX_free(c->ssl_ctx);
    }
    if (c->fd >= 0) {
        close(c->fd);
    }
    db_free(&c->xhttp_net_cache);
    db_free(&c->transcript);
    db_free(&c->app_cache);
    free(c);
}

int tls13_write_app(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    if (c->mode == CONN_MODE_XHTTP) {
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            if (chunk > 900000) {
                chunk = 900000;
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

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 16384) {
            chunk = 16384;
        }

        uint8_t *rec = NULL;
        size_t rec_len = 0;
        if (encrypt_record(c->c_app_key, c->c_app_iv, &c->c_app_seq, 0x17, buf + off, chunk, &rec, &rec_len) != 0) {
            return -1;
        }
        if (write_exact(c->fd, rec, rec_len) != 0) {
            free(rec);
            return -1;
        }
        free(rec);
        off += chunk;
    }
    return 0;
}

static int fill_reality_app_cache(tls13_conn_t *c) {
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
        if (decrypt_record(c->s_app_key, c->s_app_iv, &c->s_app_seq, rtype, pl, pl_len, &dec, &dec_len, &inner) != 0) {
            fprintf(stderr, "[tls] decrypt_record failed in app phase\n");
            free(pl);
            return -1;
        }
        free(pl);

        if (inner == 0x17) {
            int rc = db_append(&c->app_cache, dec, dec_len);
            free(dec);
            if (rc != 0) {
                return -1;
            }
            if (c->app_cache.len > 0) {
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

int tls13_read_app(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }

    if (c->app_cache.len == 0) {
        if (c->mode == CONN_MODE_XHTTP) {
            if (xhttp_fill_app_cache(c) != 0) {
                return -1;
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
        if (tls13_read_app(c, buf + off, len - off, &got) != 0) {
            return -1;
        }
        if (got == 0) {
            return -1;
        }
        off += got;
    }
    return 0;
}
