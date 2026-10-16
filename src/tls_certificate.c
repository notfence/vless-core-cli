#include "tls_internal.h"

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

tls_verify_mode_t tls_verify_mode_for_config(const vless_config_t *cfg) {
    return cfg != NULL && cfg->allow_insecure ? TLS_VERIFY_MODE_INSECURE : get_tls_verify_mode();
}

const char *tls_verify_mode_name(tls_verify_mode_t mode) {
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

int tls_verify_peer(tls_verify_mode_t mode) {
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

int xhttp_make_pin_key(const char *host, uint16_t port, char *out, size_t out_cap) {
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

int xhttp_tofu_verify_or_store(SSL *ssl, const char *pin_key, int log_ok, char *err, size_t err_cap) {
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

int tls_identity_is_ip(const char *identity) {
    unsigned char address[16];
    return identity && (inet_pton(AF_INET,identity,address) == 1 || inet_pton(AF_INET6,identity,address) == 1);
}

int tls_identity_parameters(X509_VERIFY_PARAM *parameters, const char *identity) {
    if (!parameters || !identity || !*identity) return -1;
    return (tls_identity_is_ip(identity) ? X509_VERIFY_PARAM_set1_ip_asc(parameters,identity) :
            X509_VERIFY_PARAM_set1_host(parameters,identity,0)) == 1 ? 0 : -1;
}

int parse_first_cert_der(const uint8_t *message, size_t length, const uint8_t **der, size_t *der_length) {
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

int tcp_tls_tofu_verify_or_store(const vless_config_t *cfg, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap) {
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

int tls_certificate_key_usage(X509 *certificate, int signing) {
    if (!certificate) return -1;
    int critical=-1;
    ASN1_BIT_STRING *usage=X509_get_ext_d2i(certificate,NID_key_usage,&critical,NULL);
    if (!usage) return critical == -1 ? 0 : -1;
    int allowed=ASN1_BIT_STRING_get_bit(usage,signing ? 0 : 2);
    ASN1_BIT_STRING_free(usage);
    return allowed ? 0 : -1;
}

int verify_reality_cert(const uint8_t auth_key[32], const uint8_t *cert_der, size_t cert_der_len) {
    const unsigned char *p = cert_der;
    X509 *x = d2i_X509(NULL, &p, (long)cert_der_len);
    if (x == NULL || p != cert_der+cert_der_len || tls_certificate_key_usage(x,1)) {
        X509_free(x);
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

int verify_tls_cert_message(const char *servername, const uint8_t *cert_msg, size_t cert_msg_len, char *err, size_t err_cap) {
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
