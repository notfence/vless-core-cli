#include "tls_internal.h"

static pthread_mutex_t tls_buffer_lock=PTHREAD_MUTEX_INITIALIZER;
static size_t tls_buffer_bytes;

void set_err(char *err, size_t cap, const char *msg) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
}

int db_reserve(dynbuf_t *b, size_t n) {
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

int db_append(dynbuf_t *b, const void *src, size_t n) {
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

int relay_write_wire(tls13_conn_t *c, const void *data, size_t length) {
    if (!c->relay_async) return write_exact(c->fd,data,length);
    if (length > 256U*1024U-c->xmux_wire_output.len) { errno=EAGAIN; return -1; }
    return db_append(&c->xmux_wire_output,data,length);
}

void db_consume(dynbuf_t *b, size_t n) {
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

void db_free(dynbuf_t *b) {
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

int tls_buffer_init(dynbuf_t *buffer, size_t limit, size_t *owner) {
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

void tls_handshake_material_clear(tls13_conn_t *connection) {
    if (connection->record_encrypt) EVP_CIPHER_CTX_reset(connection->record_encrypt);
    if (connection->record_decrypt) EVP_CIPHER_CTX_reset(connection->record_decrypt);
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

int write_exact(int fd, const void *buf, size_t len) {
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

int read_exact(int fd, void *buf, size_t len) {
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

int hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len, uint8_t out[64]) {
    return hmac_digest(EVP_sha512(), key, key_len, in, in_len, out, 64);
}

int hkdf_extract_md(const EVP_MD *md, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk,
                           size_t prk_len) {
    return hmac_digest(md, salt, salt_len, ikm, ikm_len, prk, prk_len);
}

int hkdf_expand_md(const EVP_MD *md, const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *out,
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

static int read_record_header(int fd,uint8_t *rtype,size_t *payload_len,int tls12_encrypted) {
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
        len > (tls12_encrypted ? 18432U : hdr[0] == 23 ? 16640U : 16384U)) { errno=EMSGSIZE; return -1; }
    *rtype=hdr[0]; *payload_len=len; return 0;
}

int read_record_bounded(int fd, uint8_t *rtype, uint8_t **payload, size_t *payload_len, int tls12_encrypted) {
    size_t len=0; int result=read_record_header(fd,rtype,&len,tls12_encrypted);
    if (result) return result;
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (buf == NULL) {
        return -1;
    }
    if (read_exact(fd, buf, len) != 0) {
        free(buf);
        return -1;
    }

    *payload = buf;
    *payload_len = len;
    return 0;
}

int read_record(int fd, uint8_t *rtype, uint8_t **payload, size_t *payload_len) {
    return read_record_bounded(fd,rtype,payload,payload_len,0);
}

int configure_tls_cipher(tls13_conn_t *c, uint16_t suite) {
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

int parse_server_hello_for_keyshare(const uint8_t *msg, size_t msg_len, uint16_t *cipher_out,
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

int transcript_hash(const tls13_conn_t *c, uint8_t *out) {
    return digest_hash(c->tls_md, c->transcript.data, c->transcript.len, out, c->tls_hash_len);
}

int calc_finished_verify(const tls13_conn_t *c, const uint8_t *traffic_secret, const uint8_t *transcript_hash_val, uint8_t *out) {
    uint8_t finished_key[64];
    uint8_t zero_ctx[1] = {0};
    if (hkdf_expand_label_md(c->tls_md, traffic_secret, c->tls_hash_len, "finished", zero_ctx, 0, finished_key, c->tls_hash_len) != 0) {
        OPENSSL_cleanse(finished_key,sizeof(finished_key)); return -1;
    }
    int result=hmac_digest(c->tls_md,finished_key,c->tls_hash_len,transcript_hash_val,c->tls_hash_len,out,c->tls_hash_len);
    OPENSSL_cleanse(finished_key,sizeof(finished_key)); return result;
}

int derive_handshake_keys(tls13_conn_t *c, const uint8_t *shared, size_t shared_len) {
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

int derive_app_keys(tls13_conn_t *c) {
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

static EVP_CIPHER_CTX *tls_record_context(tls13_conn_t *c,int sending) {
    if (!c->crypto_reuse) return EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX **context=sending ? &c->record_encrypt : &c->record_decrypt;
    if (!*context) *context=EVP_CIPHER_CTX_new();
    if (!*context) errno=ENOMEM;
    return *context;
}

static int encrypt_record_into(const tls13_conn_t *c,EVP_CIPHER_CTX *context,const uint8_t *key,const uint8_t iv[12],uint64_t *seq,
                               uint8_t inner_type,const uint8_t *plain,size_t plain_len,uint8_t *record,size_t capacity,size_t *out_len) {
    *out_len=0;
    if (c->tls12_suite) {
        if (c->tls_send_record_limit && plain_len > c->tls_send_record_limit) { errno=EMSGSIZE; return -1; }
        return core_tls12_record_seal_into(c->tls12_suite,c->tls12_etm,context,key,iv,c->tls12_c_mac,seq,inner_type,plain,plain_len,record,capacity,out_len);
    }
    if (plain_len > 16384 || *seq >= TLS_RECORD_HARD_LIMIT ||
        (c->tls_send_record_limit && plain_len+1 > c->tls_send_record_limit) ||
        (inner_type != 21 && inner_type != 22 && inner_type != 23)) { if (context) EVP_CIPHER_CTX_reset(context); errno=EMSGSIZE; return -1; }
    size_t inner_len=plain_len+1,c_len=inner_len+16;
    const EVP_CIPHER *cipher=record_cipher_for_conn(c);
    if (!context || !cipher || !record || capacity < 5+c_len) { if (context) EVP_CIPHER_CTX_reset(context); errno=ENOBUFS; return -1; }
    if (EVP_CIPHER_CTX_cipher(context) && EVP_CIPHER_CTX_nid(context) != EVP_CIPHER_nid(cipher)) EVP_CIPHER_CTX_reset(context);
    const EVP_CIPHER *initial=EVP_CIPHER_CTX_cipher(context) ? NULL : cipher;
    record[0]=23; record[1]=3; record[2]=3; record[3]=(uint8_t)(c_len>>8); record[4]=(uint8_t)c_len;
    memmove(record+5,plain,plain_len); record[5+plain_len]=inner_type;
    uint8_t nonce[12]; xor_seq_nonce(nonce,iv,*seq); int n=0,final=0;
    int ok=EVP_EncryptInit_ex(context,initial,NULL,NULL,NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) == 1 &&
        EVP_EncryptInit_ex(context,NULL,NULL,key,nonce) == 1 &&
        EVP_EncryptUpdate(context,NULL,&n,record,5) == 1 &&
        EVP_EncryptUpdate(context,record+5,&n,record+5,(int)inner_len) == 1 &&
        EVP_EncryptFinal_ex(context,record+5+n,&final) == 1 && (size_t)(n+final) == inner_len &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_GET_TAG,16,record+5+inner_len) == 1;
    OPENSSL_cleanse(nonce,sizeof(nonce));
    if (!ok) { OPENSSL_cleanse(record,5+c_len); EVP_CIPHER_CTX_reset(context); errno=EPROTO; return -1; }
    (*seq)++; *out_len=5+c_len; return 0;
}

static int decrypt_record_into(const tls13_conn_t *c,EVP_CIPHER_CTX *context,const uint8_t *key,const uint8_t iv[12],uint64_t *seq,
                               uint8_t rtype,const uint8_t *payload,size_t payload_len,uint8_t *plain,size_t capacity,size_t *plain_len,uint8_t *inner_type) {
    *plain_len=0; *inner_type=0;
    if (c->tls12_suite) {
        if (c->tls_receive_record_limit && c->tls_receive_record_limit < 16384 && c->tls12_suite->cipher == CORE_TLS12_CBC) {
            size_t mac=(size_t)EVP_MD_get_size(core_tls12_digest(c->tls12_suite->mac_hash));
            size_t bound=16+((c->tls_receive_record_limit+(c->tls12_etm ? 0 : mac)+16)/16)*16+(c->tls12_etm ? mac : 0);
            if (payload_len > bound) { errno=EMSGSIZE; return -1; }
        }
        int result=core_tls12_record_open_into(c->tls12_suite,c->tls12_etm,context,key,iv,c->tls12_s_mac,seq,rtype,payload,payload_len,plain,capacity,plain_len);
        if (!result && c->tls_receive_record_limit && *plain_len > c->tls_receive_record_limit) {
            OPENSSL_cleanse(plain,*plain_len); *plain_len=0; EVP_CIPHER_CTX_reset(context); errno=EMSGSIZE; return -1;
        }
        if (!result) *inner_type=rtype;
        return result;
    }
    if (rtype != 23 || payload_len < 17 || payload_len > 16640 || *seq >= TLS_RECORD_HARD_LIMIT ||
        (c->tls_receive_record_limit && payload_len-16 > c->tls_receive_record_limit)) { if (context) EVP_CIPHER_CTX_reset(context); errno=EMSGSIZE; return -1; }
    size_t ct_len=payload_len-16;
    const EVP_CIPHER *cipher=record_cipher_for_conn(c);
    if (!context || !cipher || !plain || capacity < ct_len) { if (context) EVP_CIPHER_CTX_reset(context); errno=ENOBUFS; return -1; }
    if (EVP_CIPHER_CTX_cipher(context) && EVP_CIPHER_CTX_nid(context) != EVP_CIPHER_nid(cipher)) EVP_CIPHER_CTX_reset(context);
    const EVP_CIPHER *initial=EVP_CIPHER_CTX_cipher(context) ? NULL : cipher;
    uint8_t header[]={rtype,3,3,(uint8_t)(payload_len>>8),(uint8_t)payload_len},nonce[12];
    xor_seq_nonce(nonce,iv,*seq); int n=0,final=0;
    int ok=EVP_DecryptInit_ex(context,initial,NULL,NULL,NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) == 1 &&
        EVP_DecryptInit_ex(context,NULL,NULL,key,nonce) == 1 &&
        EVP_DecryptUpdate(context,NULL,&n,header,sizeof(header)) == 1 &&
        EVP_DecryptUpdate(context,plain,&n,payload,(int)ct_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_AEAD_SET_TAG,16,(void *)(payload+ct_len)) == 1 &&
        EVP_DecryptFinal_ex(context,plain+n,&final) == 1 && (size_t)(n+final) == ct_len;
    OPENSSL_cleanse(nonce,sizeof(nonce));
    size_t end=ct_len;
    if (ok) while (end && !plain[end-1]) end--;
    if (!ok || !end || end-1 > 16384 || (plain[end-1] != 21 && plain[end-1] != 22 && plain[end-1] != 23)) {
        OPENSSL_cleanse(plain,ct_len); EVP_CIPHER_CTX_reset(context); errno=EPROTO; return -1;
    }
    *inner_type=plain[end-1]; *plain_len=end-1;
    OPENSSL_cleanse(plain+end-1,ct_len-end+1);
    (*seq)++; return 0;
}

int encrypt_record(tls13_conn_t *c,const uint8_t *key,const uint8_t iv[12],uint64_t *seq,uint8_t inner_type,
                   const uint8_t *plain,size_t plain_len,uint8_t **out,size_t *out_len) {
    *out=NULL; *out_len=0;
    if (plain_len > 16384) { errno=EMSGSIZE; return -1; }
    size_t capacity=c->tls12_suite ? core_tls12_record_bound(c->tls12_suite,c->tls12_etm,plain_len) : plain_len+22;
    if (!capacity) return -1;
    uint8_t *record=malloc(capacity); EVP_CIPHER_CTX *context=tls_record_context(c,1);
    int result=record && context ? encrypt_record_into(c,context,key,iv,seq,inner_type,plain,plain_len,record,capacity,out_len) : -1;
    if (!c->crypto_reuse) EVP_CIPHER_CTX_free(context);
    if (result) { if (record) { OPENSSL_cleanse(record,capacity); free(record); } if (!record || !context) errno=ENOMEM; }
    else *out=record;
    return result;
}

int decrypt_record(tls13_conn_t *c,const uint8_t *key,const uint8_t iv[12],uint64_t *seq,uint8_t rtype,
                   const uint8_t *payload,size_t payload_len,uint8_t **plain,size_t *plain_len,uint8_t *inner_type) {
    *plain=NULL; *plain_len=0; *inner_type=0;
    if (payload_len > 18432) { errno=EMSGSIZE; return -1; }
    size_t capacity=payload_len ? payload_len : 1;
    uint8_t *data=malloc(capacity); EVP_CIPHER_CTX *context=tls_record_context(c,0);
    int result=data && context ? decrypt_record_into(c,context,key,iv,seq,rtype,payload,payload_len,data,capacity,plain_len,inner_type) : -1;
    if (!c->crypto_reuse) EVP_CIPHER_CTX_free(context);
    if (result) { if (data) { OPENSSL_cleanse(data,capacity); free(data); } if (!data || !context) errno=ENOMEM; }
    else *plain=data;
    return result;
}

static int tls_record_buffer(tls13_conn_t *c,dynbuf_t *buffer,size_t needed,int writing) {
    if (buffer->data && (needed > buffer->cap || (buffer == &c->record_plain && buffer->len))) OPENSSL_cleanse(buffer->data,buffer->cap);
    if (buffer->tls_budget && c->tls_auth_state == 4) db_free(buffer);
    buffer->len=0;
    if (!buffer->memory && !buffer->tls_budget) {
        if (c->tls_auth_state != 4 && c->tls_md) {
            if (tls_buffer_init(buffer,18944,&c->tls_handshake_bytes)) return -1;
        } else {
            if (core_buffer_budget_init(&c->record_memory,CORE_BUFFER_RELAY,0)) return -1;
            buffer->memory=writing ? c->output_memory : c->input_memory;
            if (!buffer->memory) buffer->memory=&c->record_memory;
            buffer->limit=18944;
        }
    }
    size_t previous=buffer->cap;
    int result=db_reserve(buffer,needed ? needed : 1);
    if (!result && buffer->cap != previous) OPENSSL_cleanse(buffer->data,buffer->cap);
    return result;
}

int tls_record_seal_owned(tls13_conn_t *c,uint8_t type,const uint8_t *plain,size_t length,uint8_t **output,size_t *output_length) {
    *output=NULL; *output_length=0;
    if (length > 16384) { errno=EMSGSIZE; return -1; }
    size_t needed=c->tls12_suite ? core_tls12_record_bound(c->tls12_suite,c->tls12_etm,length) : length+22;
    if (!needed || tls_record_buffer(c,&c->record_output,needed,1)) return -1;
    EVP_CIPHER_CTX *context=tls_record_context(c,1);
    if (!context) { OPENSSL_cleanse(c->record_output.data,c->record_output.cap); return -1; }
    int result=encrypt_record_into(c,context,c->c_app_key,c->c_app_iv,&c->c_app_seq,type,plain,length,c->record_output.data,c->record_output.cap,output_length);
    if (!c->crypto_reuse) EVP_CIPHER_CTX_free(context);
    if (!result) { c->record_output.len=*output_length; *output=c->record_output.data; }
    else OPENSSL_cleanse(c->record_output.data,c->record_output.cap);
    return result;
}

int tls_record_open_owned(tls13_conn_t *c,uint8_t type,const uint8_t *payload,size_t length,uint8_t **plain,size_t *plain_length,uint8_t *inner) {
    *plain=NULL; *plain_length=0; *inner=0;
    if (length > 18432 || tls_record_buffer(c,&c->record_plain,length,0)) return -1;
    EVP_CIPHER_CTX *context=tls_record_context(c,0);
    if (!context) { OPENSSL_cleanse(c->record_plain.data,c->record_plain.cap); return -1; }
    int result=decrypt_record_into(c,context,c->s_app_key,c->s_app_iv,&c->s_app_seq,type,payload,length,c->record_plain.data,c->record_plain.cap,plain_length,inner);
    if (!c->crypto_reuse) EVP_CIPHER_CTX_free(context);
    if (!result) { c->record_plain.len=*plain_length; *plain=c->record_plain.data; }
    else OPENSSL_cleanse(c->record_plain.data,c->record_plain.cap);
    return result;
}

void tls_record_work_clear(tls13_conn_t *c) {
    EVP_CIPHER_CTX_free(c->record_encrypt); EVP_CIPHER_CTX_free(c->record_decrypt);
    c->record_encrypt=c->record_decrypt=NULL;
    dynbuf_t *buffers[]={&c->record_output,&c->record_plain,&c->record_wire};
    for (size_t i=0;i<sizeof(buffers)/sizeof(*buffers);i++) {
        if (buffers[i]->data) OPENSSL_cleanse(buffers[i]->data,buffers[i]->cap);
        db_free(buffers[i]);
    }
    if (!c->record_memory.allocated) core_buffer_budget_clear(&c->record_memory);
}

int append_transcript(tls13_conn_t *c, const uint8_t *msg, size_t msg_len) {
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
    EVP_CIPHER_CTX *context=sending ? c->record_encrypt : c->record_decrypt;
    if (context) EVP_CIPHER_CTX_reset(context);
    if (sending) c->c_app_seq=0; else { c->s_app_seq=0; c->tls_receive_update_requested=0; }
    return 0;
}

static int tls_key_update_send(tls13_conn_t *c, unsigned request) {
    if (c->send_closed) return -1;
    const uint8_t message[]={24,0,0,1,(uint8_t)request}; uint8_t *record=NULL; size_t length=0;
    int encrypted=c->crypto_reuse ? tls_record_seal_owned(c,22,message,sizeof(message),&record,&length) :
        encrypt_record(c,c->c_app_key,c->c_app_iv,&c->c_app_seq,22,message,sizeof(message),&record,&length);
    if (encrypted) return -1;
    int result;
    if (c->xmux_async) result=length > 256U*1024U-c->xmux_wire_output.len ? -1 : db_append(&c->xmux_wire_output,record,length);
    else result=relay_write_wire(c,record,length);
    if (!c->crypto_reuse) free(record);
    return result ? -1 : tls_update_keys(c,1);
}

int tls_prepare_app_record(tls13_conn_t *c) {
    if (c->tls12_suite) { if (c->c_app_seq >= TLS_RECORD_HARD_LIMIT) { errno=EOVERFLOW; return -1; } return 0; }
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
    if (!length || c->tls_auth_state != 4 || tls_buffer_init(&c->tls_post_handshake,TLS_POST_HANDSHAKE_LIMIT,NULL) ||
        length > TLS_POST_HANDSHAKE_LIMIT-c->tls_post_handshake.len || db_append(&c->tls_post_handshake,data,length)) return -1;
    while (c->tls_post_handshake.len >= 4) {
        const uint8_t *message=c->tls_post_handshake.data;
        size_t size=((size_t)message[1]<<16)|((size_t)message[2]<<8)|message[3];
        if (size > 256U*1024U-4 || (message[0] == 24 && size != 1) || (message[0] != 4 && message[0] != 24)) return -1;
        if (c->tls_post_handshake.len < size+4) return 0;
        if (message[0] == 24) {
            unsigned request=message[4];
            if (request > 1 || c->tls_post_handshake.len != size+4) { errno=EPROTO; return -1; }
            if (tls_update_keys(c,0) || (request && tls_key_update_send(c,0))) return -1;
        } else if (tls_session_ticket(message+4,size)) return -1;
        db_consume(&c->tls_post_handshake,size+4);
    }
    if (!c->tls_post_handshake.len) db_free(&c->tls_post_handshake);
    return 0;
}

int tls_application_plain(tls13_conn_t *c, unsigned type, const uint8_t *data, size_t length, dynbuf_t *cache) {
    if (c->receive_closed) return -1;
    if (c->tls12_suite) {
        if (type == 23) return db_append(cache,data,length);
        if (type == 21 && length == 2 && data[1] == 0) { c->receive_closed=1; return 1; }
        errno=EPROTO; return -1;
    }
    int result;
    if (type == 22) result=tls_post_handshake(c,data,length);
    else if (c->tls_post_handshake.len) return -1;
    else if (type == 23) result=db_append(cache,data,length);
    else if (type == 21 && length == 2 && data[1] == 0) { c->receive_closed=1; return 1; }
    else return -1;
    if (result < 0) return result;
    if (!c->tls_post_handshake.len && c->s_app_seq >= TLS_RECORD_REKEY_LIMIT && !c->tls_receive_update_requested && !c->send_closed) {
        if (tls_key_update_send(c,1)) return -1;
        c->tls_receive_update_requested=1;
    }
    return result;
}

int reality_write_app_records(tls13_conn_t *c, const uint8_t *buf, size_t len) {
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
        if (c->tls_send_record_limit && chunk >= c->tls_send_record_limit) chunk=c->tls_send_record_limit-(c->tls12_suite ? 0U : 1U);

        uint8_t *rec = NULL;
        size_t rec_len = 0;
        int encrypted=c->crypto_reuse ? tls_record_seal_owned(c,23,buf+off,chunk,&rec,&rec_len) :
            encrypt_record(c,c->c_app_key,c->c_app_iv,&c->c_app_seq,23,buf+off,chunk,&rec,&rec_len);
        if (encrypted != 0) {
            return -1;
        }
        if (relay_write_wire(c, rec, rec_len) != 0) {
            if (!c->crypto_reuse) free(rec);
            return -1;
        }
        c->c_app_record_bytes += rec_len;
        if (!c->crypto_reuse) free(rec);
        off += chunk;
    }
    return 0;
}

static int relay_read_record(tls13_conn_t *c, uint8_t *type, uint8_t **payload, size_t *length) {
    for (;;) {
        if (c->xmux_raw_input.len >= 5) {
            size_t size=((size_t)c->xmux_raw_input.data[3]<<8)|c->xmux_raw_input.data[4];
            unsigned record_type=c->xmux_raw_input.data[0];
            if ((record_type != 23 && !(c->tls12_suite && (record_type == 21 || record_type == 22))) || c->xmux_raw_input.data[1] != 3 ||
                c->xmux_raw_input.data[2] != 3 || size > (c->tls12_suite ? 18432U : 16640U)) return -1;
            if (c->xmux_raw_input.len >= size+5) {
                if (c->crypto_reuse) {
                    if (tls_record_buffer(c,&c->record_wire,size,0)) return -1;
                    *payload=c->record_wire.data;
                } else { *payload=malloc(size ? size : 1); if (!*payload) return -1; }
                *type=c->xmux_raw_input.data[0]; *length=size;
                memcpy(*payload,c->xmux_raw_input.data+5,size); db_consume(&c->xmux_raw_input,size+5); return 0;
            }
        }
        uint8_t input[16384]; ssize_t received=recv(c->fd,input,sizeof(input),MSG_DONTWAIT);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 2;
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return received < 0 || c->xmux_raw_input.len ? -1 : 1;
        if (db_append(&c->xmux_raw_input,input,(size_t)received)) return -1;
    }
}

int fill_reality_plain_cache(tls13_conn_t *c, dynbuf_t *cache) {
    if (c->receive_closed) return 0;
    for (;;) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        int record_result;
        if (c->relay_async) record_result=relay_read_record(c,&rtype,&pl,&pl_len);
        else if (!c->crypto_reuse) record_result=read_record_bounded(c->fd,&rtype,&pl,&pl_len,c->tls12_suite != NULL);
        else {
            record_result=read_record_header(c->fd,&rtype,&pl_len,c->tls12_suite != NULL);
            if (!record_result) {
                if (tls_record_buffer(c,&c->record_wire,pl_len,0)) record_result=-1;
                else { pl=c->record_wire.data; record_result=read_exact(c->fd,pl,pl_len); }
            }
        }
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

        if (rtype != 0x17 && !(c->tls12_suite && (rtype == 21 || rtype == 22))) {
            vc_log_warning("tls", "non-app record type=0x%02x in app phase", rtype);
            if (!c->crypto_reuse) free(pl);
            return -1;
        }

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        uint8_t inner = 0;
        int decoded=c->crypto_reuse ? tls_record_open_owned(c,rtype,pl,pl_len,&dec,&dec_len,&inner) :
            decrypt_record(c,c->s_app_key,c->s_app_iv,&c->s_app_seq,rtype,pl,pl_len,&dec,&dec_len,&inner);
        if (decoded != 0) {
            vc_log_error("tls", "decrypt_record failed in app phase");
            if (!c->crypto_reuse) free(pl);
            return -1;
        }
        if (!c->crypto_reuse) free(pl);
        int result=tls_application_plain(c,inner,dec,dec_len,cache);
        if (c->crypto_reuse) { OPENSSL_cleanse(c->record_plain.data,c->record_plain.cap); c->record_plain.len=0; }
        else { OPENSSL_cleanse(dec,dec_len); free(dec); }
        if (result < 0) return -1;
        if (result > 0 || cache->len) return 0;
    }
}

int fill_reality_app_cache(tls13_conn_t *c) {
    return fill_reality_plain_cache(c, &c->app_cache);
}

int manual_stream_read(tls13_conn_t *c,uint8_t *data,size_t capacity,size_t *length) {
    *length=0;
    if (!capacity) return 0;
    c->tls_stream_input.limit=16384;
    c->tls_stream_input.memory=c->input_memory ? c->input_memory : c->crypto_reuse ? &c->record_memory : NULL;
    if (!c->tls_stream_input.len) { int result=fill_reality_plain_cache(c,&c->tls_stream_input); if (result) return result; }
    size_t take=c->tls_stream_input.len < capacity ? c->tls_stream_input.len : capacity;
    if (take) memcpy(data,c->tls_stream_input.data,take);
    db_consume(&c->tls_stream_input,take); *length=take; return 0;
}
