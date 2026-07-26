#include "vless_encryption.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3.h"

typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
} vless_aead_t;

struct vless_encryption_conn {
    tls13_conn_t *transport;
    uint8_t united_key[96];
    size_t united_key_len;
    vless_aead_t outgoing;
    vless_aead_t incoming;
    EVP_CIPHER_CTX *outgoing_header_ctr;
    EVP_CIPHER_CTX *incoming_header_ctr;
    uint8_t outgoing_raw_header[5];
    size_t outgoing_raw_header_len;
    size_t outgoing_raw_skip;
    uint8_t incoming_raw_header[5];
    size_t incoming_raw_header_len;
    size_t incoming_raw_skip;
    uint8_t *input;
    size_t input_len;
    size_t input_off;
};

static void set_err(char *err, size_t cap, const char *msg) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
}

static uint32_t random_u32(void) {
    uint32_t value = 0;
    if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) {
        return 0;
    }
    return value;
}

static int random_range(int min, int max) {
    if (max <= min) {
        return min;
    }
    return min + (int)(random_u32() % (uint32_t)(max - min + 1));
}

static void increase_nonce(uint8_t nonce[12]) {
    for (int i = 11; i >= 0; i--) {
        nonce[i]++;
        if (nonce[i] != 0) {
            break;
        }
    }
}

static void aead_init(vless_aead_t *aead, const uint8_t *context,
                      size_t context_len, const uint8_t *key,
                      size_t key_len) {
    memset(aead, 0, sizeof(*aead));
    blake3_derive_key(context, context_len, key, key_len, aead->key);
}

static int aead_seal(vless_aead_t *aead, const uint8_t *nonce_override,
                     const uint8_t *plain, size_t plain_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t *out_len) {
    uint8_t nonce[12];
    if (nonce_override != NULL) {
        memcpy(nonce, nonce_override, sizeof(nonce));
    } else {
        increase_nonce(aead->nonce);
        memcpy(nonce, aead->nonce, sizeof(nonce));
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    int n = 0;
    int total = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, aead->key, nonce) == 1;
    if (ok && aad_len > 0) {
        ok = EVP_EncryptUpdate(ctx, NULL, &n, aad, (int)aad_len) == 1;
    }
    if (ok && plain_len > 0) {
        ok = EVP_EncryptUpdate(ctx, out, &n, plain, (int)plain_len) == 1;
        total = n;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, out + total, &n) == 1;
        total += n;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                 out + total) == 1;
        total += 16;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return -1;
    }
    *out_len = (size_t)total;
    return 0;
}

static int aead_open(vless_aead_t *aead, const uint8_t *nonce_override,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t *out_len) {
    if (ciphertext_len < 16) {
        return -1;
    }
    uint8_t nonce[12];
    if (nonce_override != NULL) {
        memcpy(nonce, nonce_override, sizeof(nonce));
    } else {
        increase_nonce(aead->nonce);
        memcpy(nonce, aead->nonce, sizeof(nonce));
    }

    size_t data_len = ciphertext_len - 16;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    int n = 0;
    int total = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, aead->key, nonce) == 1;
    if (ok && aad_len > 0) {
        ok = EVP_DecryptUpdate(ctx, NULL, &n, aad, (int)aad_len) == 1;
    }
    if (ok && data_len > 0) {
        ok = EVP_DecryptUpdate(ctx, out, &n, ciphertext, (int)data_len) == 1;
        total = n;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                 (void *)(ciphertext + data_len)) == 1;
    }
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, out + total, &n) == 1;
        total += n;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return -1;
    }
    *out_len = (size_t)total;
    return 0;
}

static int x25519_generate(EVP_PKEY **out_key, uint8_t public_key[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t public_len = 32;
    int ok = ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1 &&
             EVP_PKEY_keygen(ctx, &key) == 1 &&
             EVP_PKEY_get_raw_public_key(key, public_key, &public_len) == 1 &&
             public_len == 32;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        EVP_PKEY_free(key);
        return -1;
    }
    *out_key = key;
    return 0;
}

static int x25519_derive(EVP_PKEY *private_key,
                         const uint8_t peer_public[32],
                         uint8_t secret[32]) {
    EVP_PKEY *peer =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, 32);
    EVP_PKEY_CTX *ctx =
        peer != NULL ? EVP_PKEY_CTX_new(private_key, NULL) : NULL;
    size_t secret_len = 32;
    int ok = ctx != NULL && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
             EVP_PKEY_derive(ctx, secret, &secret_len) == 1 &&
             secret_len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return ok ? 0 : -1;
}

static EVP_PKEY *mlkem_generate(uint8_t public_key[1184]) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    unsigned char *encoded = NULL;
    size_t encoded_len =
        key != NULL ? EVP_PKEY_get1_encoded_public_key(key, &encoded) : 0;
    if (encoded_len != 1184) {
        OPENSSL_free(encoded);
        EVP_PKEY_free(key);
        return NULL;
    }
    memcpy(public_key, encoded, encoded_len);
    OPENSSL_free(encoded);
    return key;
}

static int mlkem_encapsulate_public(const uint8_t public_key[1184],
                                    uint8_t ciphertext[1088],
                                    uint8_t secret[32]) {
    EVP_PKEY *template = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = NULL;
    size_t ciphertext_len = 1088;
    size_t secret_len = 32;
    int ok = template != NULL && key != NULL &&
             EVP_PKEY_copy_parameters(key, template) == 1 &&
             EVP_PKEY_set1_encoded_public_key(key, public_key, 1184) == 1;
    if (ok) {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
        ok = ctx != NULL && EVP_PKEY_encapsulate_init(ctx, NULL) == 1 &&
             EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len,
                                  secret, &secret_len) == 1 &&
             ciphertext_len == 1088 && secret_len == 32;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    EVP_PKEY_free(template);
    return ok ? 0 : -1;
}

static int mlkem_decapsulate(EVP_PKEY *key,
                             const uint8_t ciphertext[1088],
                             uint8_t secret[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    size_t secret_len = 32;
    int ok = ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) == 1 &&
             EVP_PKEY_decapsulate(ctx, secret, &secret_len,
                                  ciphertext, 1088) == 1 &&
             secret_len == 32;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int aes_ctr_init(EVP_CIPHER_CTX **out, const uint8_t *key,
                        size_t key_len, const uint8_t iv[16]) {
    uint8_t derived[32];
    blake3_derive_key((const uint8_t *)"VLESS", 5, key, key_len, derived);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, derived, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *out = ctx;
    return 0;
}

static int aes_ctr_xor(EVP_CIPHER_CTX *ctx, uint8_t *data, size_t len) {
    int out_len = 0;
    return EVP_EncryptUpdate(ctx, data, &out_len, data, (int)len) == 1 &&
                   out_len == (int)len
               ? 0
               : -1;
}

static size_t raw_record_length(const uint8_t header[5]) {
    size_t len = ((size_t)header[3] << 8) | header[4];
    if (header[0] != 23 || header[1] != 3 || header[2] != 3 ||
        len < 17 || len > 16640) {
        return 0;
    }
    return len;
}

static int xor_raw_headers(EVP_CIPHER_CTX *ctr, uint8_t *data, size_t len,
                           uint8_t header[5], size_t *header_len,
                           size_t *skip, int incoming) {
    size_t off = 0;
    while (off < len) {
        if (*skip > 0) {
            size_t take = len - off;
            if (take > *skip) {
                take = *skip;
            }
            *skip -= take;
            off += take;
            continue;
        }

        size_t take = 5 - *header_len;
        if (take > len - off) {
            take = len - off;
        }
        if (incoming) {
            if (aes_ctr_xor(ctr, data + off, take) != 0) {
                return -1;
            }
            memcpy(header + *header_len, data + off, take);
        } else {
            memcpy(header + *header_len, data + off, take);
            if (aes_ctr_xor(ctr, data + off, take) != 0) {
                return -1;
            }
        }
        *header_len += take;
        off += take;
        if (*header_len == 5) {
            *skip = raw_record_length(header);
            *header_len = 0;
        }
    }
    return 0;
}

static int build_relays(const vless_config_t *cfg, const uint8_t iv[16],
                        uint8_t *out, uint8_t nfs_key[32]) {
    EVP_CIPHER_CTX *previous_ctr = NULL;
    size_t off = 0;

    for (size_t i = 0; i < cfg->encryption_relay_count; i++) {
        const vless_encryption_relay_t *relay = &cfg->encryption_relays[i];
        size_t relay_len = relay->key_len == 32 ? 32 : 1088;
        uint8_t current_key[32];

        if (relay->key_len == 32) {
            EVP_PKEY *private_key = NULL;
            if (x25519_generate(&private_key, out + off) != 0 ||
                x25519_derive(private_key, relay->key, current_key) != 0) {
                EVP_PKEY_free(private_key);
                EVP_CIPHER_CTX_free(previous_ctr);
                return -1;
            }
            EVP_PKEY_free(private_key);
        } else if (mlkem_encapsulate_public(relay->key, out + off,
                                            current_key) != 0) {
            EVP_CIPHER_CTX_free(previous_ctr);
            return -1;
        }

        if (cfg->encryption_xor_mode != 0) {
            EVP_CIPHER_CTX *public_ctr = NULL;
            if (aes_ctr_init(&public_ctr, relay->key, relay->key_len, iv) != 0 ||
                aes_ctr_xor(public_ctr, out + off, relay_len) != 0) {
                EVP_CIPHER_CTX_free(public_ctr);
                EVP_CIPHER_CTX_free(previous_ctr);
                return -1;
            }
            EVP_CIPHER_CTX_free(public_ctr);
        }
        if (previous_ctr != NULL &&
            aes_ctr_xor(previous_ctr, out + off, 32) != 0) {
            EVP_CIPHER_CTX_free(previous_ctr);
            return -1;
        }

        if (i + 1 < cfg->encryption_relay_count) {
            uint8_t hash[32];
            blake3_hash(cfg->encryption_relays[i + 1].key,
                        cfg->encryption_relays[i + 1].key_len, hash);
            memcpy(out + off + relay_len, hash, sizeof(hash));
            EVP_CIPHER_CTX_free(previous_ctr);
            previous_ctr = NULL;
            if (aes_ctr_init(&previous_ctr, current_key, sizeof(current_key),
                             iv) != 0 ||
                aes_ctr_xor(previous_ctr, out + off + relay_len,
                            sizeof(hash)) != 0) {
                EVP_CIPHER_CTX_free(previous_ctr);
                return -1;
            }
            off += relay_len + sizeof(hash);
        } else {
            memcpy(nfs_key, current_key, sizeof(current_key));
            off += relay_len;
        }
    }
    EVP_CIPHER_CTX_free(previous_ctr);
    return 0;
}

static int transport_read_exact(tls13_conn_t *transport,
                                uint8_t *buf, size_t len) {
    return tls13_read_exact_app(transport, buf, len);
}

int vless_encryption_connect(const vless_config_t *cfg, tls13_conn_t *transport,
                             vless_encryption_conn_t **out,
                             char *err, size_t err_cap) {
    *out = NULL;
    if (!cfg->encryption_enabled || cfg->encryption_relay_count == 0) {
        set_err(err, err_cap, "VLESS encryption is not configured");
        return -1;
    }
    size_t relays_len = 0;
    for (size_t i = 0; i < cfg->encryption_relay_count; i++) {
        relays_len += cfg->encryption_relays[i].key_len == 32 ? 32 : 1088;
        if (i + 1 < cfg->encryption_relay_count) {
            relays_len += 32;
        }
    }

    int padding_len = random_range(111, 1111);
    if ((random_u32() % 100U) < 50U) {
        padding_len += random_range(0, 3333);
    }
    const size_t pfs_exchange_len = 18 + 1184 + 32 + 16;
    size_t hello_len = 16 + relays_len + pfs_exchange_len +
                       (size_t)padding_len;
    uint8_t *hello = (uint8_t *)calloc(1, hello_len);
    if (hello == NULL || RAND_bytes(hello, 16) != 1) {
        free(hello);
        set_err(err, err_cap, "failed to allocate VLESS encryption hello");
        return -1;
    }
    uint8_t client_iv[16];
    memcpy(client_iv, hello, sizeof(client_iv));

    uint8_t nfs_key[32];
    if (build_relays(cfg, hello, hello + 16, nfs_key) != 0) {
        free(hello);
        set_err(err, err_cap, "failed to build VLESS encryption relay");
        return -1;
    }

    vless_aead_t nfs_aead;
    aead_init(&nfs_aead, hello, 16, nfs_key, sizeof(nfs_key));

    uint8_t client_pfs_public[1216];
    EVP_PKEY *mlkem_key = mlkem_generate(client_pfs_public);
    EVP_PKEY *x25519_key = NULL;
    if (mlkem_key == NULL ||
        x25519_generate(&x25519_key, client_pfs_public + 1184) != 0) {
        EVP_PKEY_free(mlkem_key);
        EVP_PKEY_free(x25519_key);
        free(hello);
        set_err(err, err_cap, "ML-KEM-768 is unavailable");
        return -1;
    }

    size_t off = 16 + relays_len;
    uint8_t length_bytes[2] = {
        (uint8_t)((pfs_exchange_len - 18) >> 8),
        (uint8_t)(pfs_exchange_len - 18),
    };
    size_t written = 0;
    if (aead_seal(&nfs_aead, NULL, length_bytes, sizeof(length_bytes),
                  NULL, 0, hello + off, &written) != 0 ||
        written != 18) {
        goto handshake_error;
    }
    off += written;
    if (aead_seal(&nfs_aead, NULL, client_pfs_public,
                  sizeof(client_pfs_public), NULL, 0,
                  hello + off, &written) != 0 ||
        written != sizeof(client_pfs_public) + 16) {
        goto handshake_error;
    }
    off += written;

    uint8_t padding_length_bytes[2] = {
        (uint8_t)(((size_t)padding_len - 18) >> 8),
        (uint8_t)((size_t)padding_len - 18),
    };
    if (aead_seal(&nfs_aead, NULL, padding_length_bytes,
                  sizeof(padding_length_bytes), NULL, 0,
                  hello + off, &written) != 0 ||
        written != 18) {
        goto handshake_error;
    }
    off += written;
    size_t padding_plain_len = (size_t)padding_len - 34;
    if (aead_seal(&nfs_aead, NULL, hello + off, padding_plain_len,
                  NULL, 0, hello + off, &written) != 0 ||
        written != padding_plain_len + 16) {
        goto handshake_error;
    }
    off += written;
    if (off != hello_len ||
        tls13_write_app(transport, hello, hello_len) != 0) {
        goto handshake_error;
    }
    free(hello);
    hello = NULL;

    uint8_t encrypted_server_pfs[1136];
    uint8_t server_pfs_public[1120];
    static const uint8_t max_nonce[12] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    size_t plain_len = 0;
    if (transport_read_exact(transport, encrypted_server_pfs,
                             sizeof(encrypted_server_pfs)) != 0 ||
        aead_open(&nfs_aead, max_nonce, encrypted_server_pfs,
                  sizeof(encrypted_server_pfs), NULL, 0,
                  server_pfs_public, &plain_len) != 0 ||
        plain_len != sizeof(server_pfs_public)) {
        set_err(err, err_cap, "invalid VLESS encryption server key");
        goto cleanup_keys;
    }

    uint8_t pfs_key[64];
    if (mlkem_decapsulate(mlkem_key, server_pfs_public, pfs_key) != 0 ||
        x25519_derive(x25519_key, server_pfs_public + 1088,
                     pfs_key + 32) != 0) {
        set_err(err, err_cap, "VLESS encryption key exchange failed");
        goto cleanup_keys;
    }

    vless_encryption_conn_t *conn =
        (vless_encryption_conn_t *)calloc(1, sizeof(*conn));
    if (conn == NULL) {
        set_err(err, err_cap, "failed to allocate VLESS encryption state");
        goto cleanup_keys;
    }
    conn->transport = transport;
    memcpy(conn->united_key, pfs_key, sizeof(pfs_key));
    memcpy(conn->united_key + sizeof(pfs_key), nfs_key, sizeof(nfs_key));
    conn->united_key_len = sizeof(pfs_key) + sizeof(nfs_key);
    aead_init(&conn->outgoing, client_pfs_public,
              sizeof(client_pfs_public), conn->united_key,
              conn->united_key_len);
    aead_init(&conn->incoming, server_pfs_public,
              sizeof(server_pfs_public), conn->united_key,
              conn->united_key_len);

    uint8_t encrypted_ticket[32];
    uint8_t ticket[16];
    uint8_t encrypted_length[18];
    uint8_t decoded_length[2];
    if (transport_read_exact(transport, encrypted_ticket,
                             sizeof(encrypted_ticket)) != 0 ||
        aead_open(&conn->incoming, NULL, encrypted_ticket,
                  sizeof(encrypted_ticket), NULL, 0,
                  ticket, &plain_len) != 0 ||
        plain_len != sizeof(ticket) ||
        transport_read_exact(transport, encrypted_length,
                             sizeof(encrypted_length)) != 0 ||
        aead_open(&conn->incoming, NULL, encrypted_length,
                  sizeof(encrypted_length), NULL, 0,
                  decoded_length, &plain_len) != 0 ||
        plain_len != sizeof(decoded_length)) {
        vless_encryption_close(conn);
        set_err(err, err_cap, "invalid VLESS encryption server hello");
        goto cleanup_keys;
    }

    size_t peer_padding_len =
        ((size_t)decoded_length[0] << 8) | decoded_length[1];
    if (peer_padding_len < 16 || peer_padding_len > 65535) {
        vless_encryption_close(conn);
        set_err(err, err_cap, "invalid VLESS encryption server padding");
        goto cleanup_keys;
    }
    uint8_t *peer_padding = (uint8_t *)malloc(peer_padding_len);
    uint8_t *decoded_padding =
        (uint8_t *)malloc(peer_padding_len - 16);
    if (peer_padding == NULL || decoded_padding == NULL ||
        transport_read_exact(transport, peer_padding,
                             peer_padding_len) != 0 ||
        aead_open(&conn->incoming, NULL, peer_padding,
                  peer_padding_len, NULL, 0,
                  decoded_padding, &plain_len) != 0) {
        free(peer_padding);
        free(decoded_padding);
        vless_encryption_close(conn);
        set_err(err, err_cap, "invalid VLESS encryption server padding");
        goto cleanup_keys;
    }
    free(peer_padding);
    free(decoded_padding);

    if (cfg->encryption_xor_mode == 2 &&
        (aes_ctr_init(&conn->outgoing_header_ctr, conn->united_key,
                      conn->united_key_len, client_iv) != 0 ||
         aes_ctr_init(&conn->incoming_header_ctr, conn->united_key,
                      conn->united_key_len, ticket) != 0)) {
        vless_encryption_close(conn);
        set_err(err, err_cap, "failed to initialize VLESS random mode");
        goto cleanup_keys;
    }

    EVP_PKEY_free(mlkem_key);
    EVP_PKEY_free(x25519_key);
    *out = conn;
    return 0;

handshake_error:
    set_err(err, err_cap, "failed to send VLESS encryption hello");
cleanup_keys:
    EVP_PKEY_free(mlkem_key);
    EVP_PKEY_free(x25519_key);
    free(hello);
    return -1;
}

void vless_encryption_close(vless_encryption_conn_t *conn) {
    if (conn == NULL) {
        return;
    }
    free(conn->input);
    EVP_CIPHER_CTX_free(conn->outgoing_header_ctr);
    EVP_CIPHER_CTX_free(conn->incoming_header_ctr);
    OPENSSL_cleanse(conn->united_key, sizeof(conn->united_key));
    OPENSSL_cleanse(&conn->outgoing, sizeof(conn->outgoing));
    OPENSSL_cleanse(&conn->incoming, sizeof(conn->incoming));
    free(conn);
}

int vless_encryption_write(vless_encryption_conn_t *conn,
                           const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 8192) {
            chunk = 8192;
        }
        size_t record_len = 5 + chunk + 16;
        uint8_t *record = (uint8_t *)malloc(record_len);
        if (record == NULL) {
            return -1;
        }
        size_t encrypted_len = chunk + 16;
        record[0] = 23;
        record[1] = 3;
        record[2] = 3;
        record[3] = (uint8_t)(encrypted_len >> 8);
        record[4] = (uint8_t)encrypted_len;
        size_t written = 0;
        int ok = aead_seal(&conn->outgoing, NULL, buf + off, chunk,
                           record, 5, record + 5, &written) == 0 &&
                 written == encrypted_len;
        if (ok && conn->outgoing_header_ctr != NULL) {
            ok = aes_ctr_xor(conn->outgoing_header_ctr, record, 5) == 0;
        }
        if (ok) {
            ok = tls13_write_app(conn->transport, record, record_len) == 0;
        }
        free(record);
        if (!ok) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}

int vless_encryption_write_raw(vless_encryption_conn_t *conn,
                               const uint8_t *buf, size_t len) {
    if (len == 0) {
        return 0;
    }
    if (conn->outgoing_header_ctr == NULL) {
        return tls13_write_app(conn->transport, buf, len);
    }
    uint8_t *encoded = (uint8_t *)malloc(len);
    if (encoded == NULL) {
        return -1;
    }
    memcpy(encoded, buf, len);
    int rc = xor_raw_headers(
        conn->outgoing_header_ctr, encoded, len,
        conn->outgoing_raw_header, &conn->outgoing_raw_header_len,
        &conn->outgoing_raw_skip, 0);
    if (rc == 0) {
        rc = tls13_write_app(conn->transport, encoded, len);
    }
    free(encoded);
    return rc;
}

static int read_record(vless_encryption_conn_t *conn) {
    uint8_t header[5];
    if (transport_read_exact(conn->transport, header, sizeof(header)) != 0) {
        return -1;
    }
    if (conn->incoming_header_ctr != NULL &&
        aes_ctr_xor(conn->incoming_header_ctr, header, sizeof(header)) != 0) {
        return -1;
    }
    if (header[0] != 23 || header[1] != 3 || header[2] != 3) {
        return -1;
    }
    size_t encrypted_len = ((size_t)header[3] << 8) | header[4];
    if (encrypted_len < 17 || encrypted_len > 16640) {
        return -1;
    }
    uint8_t *encrypted = (uint8_t *)malloc(encrypted_len);
    uint8_t *plain = (uint8_t *)malloc(encrypted_len - 16);
    if (encrypted == NULL || plain == NULL ||
        transport_read_exact(conn->transport, encrypted,
                             encrypted_len) != 0) {
        free(encrypted);
        free(plain);
        return -1;
    }
    size_t plain_len = 0;
    int rc = aead_open(&conn->incoming, NULL, encrypted, encrypted_len,
                       header, sizeof(header), plain, &plain_len);
    free(encrypted);
    if (rc != 0) {
        free(plain);
        return -1;
    }
    free(conn->input);
    conn->input = plain;
    conn->input_len = plain_len;
    conn->input_off = 0;
    return 0;
}

int vless_encryption_read(vless_encryption_conn_t *conn,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    if (conn->input_off == conn->input_len && read_record(conn) != 0) {
        return -1;
    }
    size_t available = conn->input_len - conn->input_off;
    size_t take = available < cap ? available : cap;
    memcpy(buf, conn->input + conn->input_off, take);
    conn->input_off += take;
    *out_len = take;
    return 0;
}

int vless_encryption_read_raw(vless_encryption_conn_t *conn,
                              uint8_t *buf, size_t cap, size_t *out_len) {
    int rc = tls13_read_app(conn->transport, buf, cap, out_len);
    if (rc == 0 && *out_len > 0 && conn->incoming_header_ctr != NULL &&
        xor_raw_headers(conn->incoming_header_ctr, buf, *out_len,
                        conn->incoming_raw_header,
                        &conn->incoming_raw_header_len,
                        &conn->incoming_raw_skip, 1) != 0) {
        return -1;
    }
    return rc;
}

int vless_encryption_read_exact(vless_encryption_conn_t *conn,
                                uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t got = 0;
        if (vless_encryption_read(conn, buf + off, len - off, &got) != 0 ||
            got == 0) {
            return -1;
        }
        off += got;
    }
    return 0;
}
