#include "tls_transport_internal.h"

static tls_aes_fallback_entry_t g_tls_aes_fallback_cache[TLS_AES_FALLBACK_CACHE_SIZE];
static size_t g_tls_aes_fallback_count = 0;
static tls_endpoint_entry_t g_tls_endpoint_cache[TLS_ENDPOINT_CACHE_SIZE];
static size_t g_tls_endpoint_replace_index = 0;
pthread_mutex_t g_tls_state_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_tls_cipher_logged = 0;

static int tls_aes_fallback_entry_matches(const tls_aes_fallback_entry_t *entry, const char *host, uint16_t port, const char *sni);
static int tls_aes_fallback_cached(const char *host, uint16_t port, const char *sni);
static void cache_tls_aes_fallback(const char *host, uint16_t port, const char *sni);
static void log_tls_cipher_once(const char *cipher);
static int tls_endpoint_entry_matches(const tls_endpoint_entry_t *entry, const vless_config_t *cfg, const char *sni);
static int sockaddr_equal(const struct sockaddr *a, socklen_t a_len, const struct sockaddr *b, socklen_t b_len);
static int tls_address_aes_cached(const char *host, uint16_t port, const char *sni, const struct sockaddr *address, socklen_t length);
static void cache_tls_address_aes(const char *host, uint16_t port, const char *sni, const struct sockaddr *address, socklen_t length);
static int get_cached_tls_endpoint(const vless_config_t *cfg, const char *sni, struct sockaddr_storage *address,
                                   socklen_t *address_len);
static void cache_tls_endpoint(const vless_config_t *cfg, const char *sni, const struct sockaddr *address, socklen_t address_len);
static void invalidate_cached_tls_endpoint(const vless_config_t *cfg, const char *sni, const struct sockaddr *address,
                                           socklen_t address_len);
static int tcp_connect_address(int family, int socktype, int protocol, const struct sockaddr *address, socklen_t address_len);
static void set_connect_err(char *err, size_t err_cap, const char *prefix);
static int ssl_budget_call(SSL *ssl, void *buffer, int length, int operation);
static int append_alpn_token(unsigned char *out, unsigned int cap, unsigned int *len, const char *token);
static int open_tls_socket_once(int fd, const char *connect_host, const char *sni, int verify_peer,
                                const unsigned char *alpn_protos, unsigned int alpn_protos_len, tls_cipher_offer_t cipher_offer,
                                SSL_CTX **out_ctx, SSL **out_ssl, int *out_fd, int *retry_with_aes, char *err, size_t err_cap);
static const char *tls_cipher_suite_name(uint16_t suite);
static void reset_manual_tls_handshake(tls13_conn_t *c);
static int connect_manual_tls_endpoint(const vless_config_t *cfg, tls13_conn_t *c, const struct sockaddr *address,
                                       socklen_t address_len, int socktype, int protocol, int start_with_aes, int initial_fd,
                                       tls_cipher_offer_t *successful_offer, char *err, size_t err_cap);
static void remember_manual_tls_success(const vless_config_t *cfg, tls13_conn_t *c, const char *sni,
                                        const struct sockaddr *address, socklen_t address_len,
                                        tls_cipher_offer_t successful_offer);
static int xmux_transport_open_budgeted(const vless_config_t *config, void **output, int *http2, char *error, size_t capacity,
                                       core_buffer_budget_t *upload, core_buffer_budget_t *download);
static int xmux_transport_open(const vless_config_t *config, void **output, int *http2, char *error, size_t capacity);
static void xmux_transport_close(void *opaque);
static int xmux_transport_fd(void *opaque);
static size_t xmux_transport_pending(void *opaque);
static uint64_t xmux_transport_enqueued(void *opaque);
static uint64_t xmux_transport_flushed(void *opaque);
static int xmux_transport_retire(void *opaque);
static short xmux_transport_events(void *opaque);
static int xmux_transport_send_frame(void *opaque, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t *data, size_t length);
static int xmux_transport_flush(void *opaque);
static int xmux_transport_collect(void *opaque);
static int xmux_transport_read_frame(void *opaque, core_xmux_frame_t *frame, size_t capacity);
static void xmux_transport_release_frame(void *opaque, core_http2_frame_t *frame);
static int xmux_transport_request(void *opaque, const vless_config_t *config, const char *session, uint64_t sequence,
                                  int role, const uint8_t *data, size_t length, uint32_t *id, uint32_t header_limit, size_t *consumed, size_t *body_size);
static int xmux_transport_session(const vless_config_t *config, char *session, size_t capacity);

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

int tcp_connect_host(const char *host, uint16_t port, int use_server_ips) {
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

int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
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

int ssl_read_some(SSL *ssl, uint8_t *buf, size_t cap, size_t *out_len) {
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

int fd_read_some(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
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

int alpn_csv_has_token(const char *csv, const char *token) {
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

int build_xhttp_tls_alpn(const char *cfg_alpn, unsigned char *out, unsigned int cap, unsigned int *out_len) {
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

int open_tls_socket(int use_server_ips, const char *connect_host, uint16_t connect_port, const char *sni, int verify_peer,
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

int ws_conn_read_some(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    if (c->tls_md) return manual_stream_read(c,buf,cap,out_len);
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

int ws_conn_write_all(tls13_conn_t *c, const void *buf, size_t len) {
    if (c->tls_md) return reality_write_app_records(c,buf,len);
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

static const char *tls_cipher_suite_name(uint16_t suite) {
    const core_tls12_suite_t *legacy=core_tls12_suite(suite);
    if (legacy) return legacy->name;
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
    tls_record_work_clear(c);
    c->tls12_suite=NULL; c->tls12_etm=c->tls12_ems=c->tls12_ticket=c->tls12_status=0;
    OPENSSL_cleanse(c->tls12_c_mac,sizeof(c->tls12_c_mac)); OPENSSL_cleanse(c->tls12_s_mac,sizeof(c->tls12_s_mac));
    X509_free(c->tls_peer_certificate); c->tls_peer_certificate=NULL;
    db_free(&c->tls_certificate_message); c->tls_auth_state=0;
    c->tls_client_certificate_requested=0;
    c->tls_alps_received=0; memset(&c->tls_alps_settings,0,sizeof(c->tls_alps_settings));
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

int connect_manual_tls(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    const char *sni = cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host;
    int start_with_aes = c->tls_use_aes_fallback || tls_aes_fallback_cached(cfg->server_host, cfg->server_port, sni);
    struct sockaddr_storage cached_address;
    socklen_t cached_length = 0;
    int cached = get_cached_tls_endpoint(cfg, sni, &cached_address, &cached_length);
    core_dialer_t *dialer = core_dialer_start(cfg->server_host, cfg->server_port, core_config_ip_source(cfg), CORE_CONNECT_TIMEOUT_MS,
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

static void xmux_transport_close(void *opaque) {
    int saved=errno;
    tls13_conn_t *connection=opaque;
    if (connection && connection->fd >= 0 && connection->tls_md && connection->tls_auth_state == 4 && !connection->send_closed) {
        core_deadline_scope_t scope;
        if (!core_deadline_scope_begin(&scope,100)) {
            while ((connection->xmux_plain_output.len || connection->xmux_wire_output.len) && core_deadline_remaining()) {
                if (xmux_transport_flush(connection) || ((connection->xmux_plain_output.len || connection->xmux_wire_output.len) && core_wait_socket(connection->fd,POLLOUT,-1) <= 0)) break;
            }
            if (!connection->xmux_plain_output.len && !connection->xmux_wire_output.len && core_deadline_remaining()) {
                const uint8_t alert[]={1,0}; uint8_t *record=NULL; size_t length=0;
                if (!encrypt_record(connection,connection->c_app_key,connection->c_app_iv,&connection->c_app_seq,21,alert,sizeof(alert),&record,&length))
                    (void)write_exact(connection->fd,record,length);
                free(record);
            }
            core_deadline_scope_end(&scope);
        }
    }
    errno=saved; tls13_reality_close(connection);
}

static int xmux_transport_fd(void *opaque) { return ((tls13_conn_t *)opaque)->fd; }

static size_t xmux_transport_pending(void *opaque) {
    tls13_conn_t *connection=opaque;
    return connection->xmux_plain_output.len+connection->xmux_wire_output.len;
}

static uint64_t xmux_transport_enqueued(void *opaque) { return ((tls13_conn_t *)opaque)->xmux_enqueued; }

static uint64_t xmux_transport_flushed(void *opaque) { return ((tls13_conn_t *)opaque)->xmux_flushed; }

static int xmux_transport_retire(void *opaque) {
    tls13_conn_t *connection=opaque;
    return connection->tls12_suite && (connection->c_app_seq >= TLS_RECORD_REKEY_LIMIT || connection->s_app_seq >= TLS_RECORD_REKEY_LIMIT);
}

static short xmux_transport_events(void *opaque) {
    tls13_conn_t *connection=opaque;
    size_t limit=connection->tls_md && !connection->ssl ? 49152 : 65536;
    short input=tls13_uses_h2(connection) || (!connection->xmux_http1_eof && connection->h2_net_cache.len < limit) ? POLLIN : 0;
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
        if (connection->tls_send_record_limit && limit >= connection->tls_send_record_limit) limit=connection->tls_send_record_limit-(connection->tls12_suite ? 0U : 1U);
        size_t length=connection->xmux_plain_output.len < limit ? connection->xmux_plain_output.len : limit;
        uint8_t *record=NULL; size_t record_length=0;
        size_t temporary=2*(length+(connection->tls12_suite ? 384U : 22U));
        if (!connection->crypto_reuse && connection->output_memory && core_buffer_hold(connection->output_memory,temporary)) return -1;
        int encrypted=connection->crypto_reuse ? tls_record_seal_owned(connection,23,connection->xmux_plain_output.data,length,&record,&record_length) :
            encrypt_record(connection,connection->c_app_key,connection->c_app_iv,&connection->c_app_seq,23,connection->xmux_plain_output.data,length,&record,&record_length);
        if (encrypted != 0) {
            if (!connection->crypto_reuse && connection->output_memory) core_buffer_drop(connection->output_memory,temporary);
            return -1;
        }
        int result=db_append(&connection->xmux_wire_output,record,record_length);
        if (!connection->crypto_reuse) free(record);
        if (!connection->crypto_reuse && connection->output_memory) core_buffer_drop(connection->output_memory,temporary);
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
        if (received > 0) return db_append(&connection->h2_net_cache,input,(size_t)received) ? -1 : CORE_HTTP2_INPUT_PROGRESS;
        return received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    }
    if (!tls13_uses_h2(connection) && !connection->tls_md) {
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
        if (size > 0) return db_append(&connection->h2_net_cache,data,(size_t)size) ? -1 : CORE_HTTP2_INPUT_PROGRESS;
        connection->xmux_http1_eof=1; return CORE_HTTP2_INPUT_PROGRESS;
    }
    if (connection->ssl) {
        int result=h2_collect_tls_available(connection,&connection->xmux_read_wants_write);
        return result > 0 ? CORE_HTTP2_INPUT_PROGRESS : result;
    }
    if (!tls13_uses_h2(connection) && (connection->h2_net_cache.len >= 49152 || connection->xmux_http1_eof)) return 0;
    uint8_t input[16384];
    int progressed=0;
    for (unsigned reads=0;reads<64;reads++) {
        while (connection->xmux_raw_input.len >= 5) {
            const uint8_t *record=connection->xmux_raw_input.data;
            size_t length=((size_t)record[3]<<8)|record[4];
            if ((record[0] != 23 && !(connection->tls12_suite && (record[0] == 21 || record[0] == 22))) || record[1] != 3 || record[2] != 3 ||
                length > (connection->tls12_suite ? 18432U : 16640U)) return -1;
            if (connection->xmux_raw_input.len < length+5) break;
            if (record[0] == 0x17 || connection->tls12_suite) {
                uint8_t *plain=NULL,inner=0; size_t plain_length=0;
                size_t temporary=2U*(connection->tls12_suite ? 18432U : 16640U);
                if (!connection->crypto_reuse && connection->input_memory && core_buffer_hold(connection->input_memory,temporary)) return -1;
                int decoded=connection->crypto_reuse ? tls_record_open_owned(connection,record[0],record+5,length,&plain,&plain_length,&inner) :
                    decrypt_record(connection,connection->s_app_key,connection->s_app_iv,&connection->s_app_seq,record[0],record+5,length,&plain,&plain_length,&inner);
                if (decoded != 0) {
                    if (!connection->crypto_reuse && connection->input_memory) core_buffer_drop(connection->input_memory,temporary);
                    return -1;
                }
                int result=tls_application_plain(connection,inner,plain,plain_length,&connection->h2_net_cache);
                if (connection->crypto_reuse) { OPENSSL_cleanse(connection->record_plain.data,connection->record_plain.cap); connection->record_plain.len=0; }
                else { OPENSSL_cleanse(plain,plain_length); free(plain); if (connection->input_memory) core_buffer_drop(connection->input_memory,temporary); }
                if (result < 0 || (result > 0 && tls13_uses_h2(connection))) return -1;
                if (result > 0) { connection->xmux_http1_eof=1; db_consume(&connection->xmux_raw_input,length+5); return CORE_HTTP2_INPUT_PROGRESS; }
            }
            db_consume(&connection->xmux_raw_input,length+5);
            progressed=1;
            if (tls13_uses_h2(connection) ? h2_cached_frame_ready(connection) : connection->h2_net_cache.len != 0) return CORE_HTTP2_INPUT_PROGRESS;
        }
        ssize_t length=core_recv(connection->fd,input,sizeof(input),MSG_DONTWAIT);
        if (length > 0) { if (db_append(&connection->xmux_raw_input,input,(size_t)length) != 0) return -1; progressed=1; }
        else if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return progressed ? CORE_HTTP2_INPUT_PROGRESS : 0;
        else return -1;
    }
    return progressed ? CORE_HTTP2_INPUT_PROGRESS : 0;
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
        db_consume(&connection->h2_net_cache,event.consumed);
        if (result == 1 && !capacity && connection->h2_net_cache.len &&
            (connection->xmux_http1_response.state == 1 || connection->xmux_http1_response.state == 3) && connection->xmux_http1_response.remaining)
            return CORE_HTTP2_INPUT_BLOCKED;
        return result;
    }
    if (connection->h2_net_cache.len >= 9 && (connection->h2_net_cache.data[0] ||
        (((unsigned)connection->h2_net_cache.data[1]<<8)|connection->h2_net_cache.data[2]) > 16384)) return -1;
    if (!h2_cached_frame_ready(connection)) return 1;
    if (!connection->h2_net_cache.data[3]) {
        size_t length=((size_t)connection->h2_net_cache.data[0]<<16)|((size_t)connection->h2_net_cache.data[1]<<8)|connection->h2_net_cache.data[2];
        if (length > capacity) return CORE_HTTP2_INPUT_BLOCKED;
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

static int xmux_transport_initial_settings(void *opaque,core_http2_settings_t *settings,core_http2_validation_t *validation) {
    tls13_conn_t *connection=opaque;
    if (!connection->tls_alps_received || connection->tls_auth_state != 4) return 0;
    *settings=connection->tls_alps_settings; *validation=connection->h2_validation; return 1;
}

const core_xmux_backend_t xmux_backend={
    .open=xmux_transport_open,.close=xmux_transport_close,.fd=xmux_transport_fd,.events=xmux_transport_events,.collect=xmux_transport_collect,
    .open_budgeted=xmux_transport_open_budgeted,.release_frame=xmux_transport_release_frame,
    .read_frame=xmux_transport_read_frame,.send_frame=xmux_transport_send_frame,.flush=xmux_transport_flush,
    .pending=xmux_transport_pending,.enqueued=xmux_transport_enqueued,.flushed=xmux_transport_flushed,.retire=xmux_transport_retire,.request=xmux_transport_request,.session=xmux_transport_session,
    .initial_settings=xmux_transport_initial_settings,
};
