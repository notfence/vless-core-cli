#include "vless_encryption.h"
#include "core_random.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include <errno.h>

#include "blake3.h"
#include "socket_util.h"
#include "deadline.h"
#include "server_ips.h"
#include "buffer_budget.h"

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
    EVP_CIPHER_CTX *record_encrypt,*record_decrypt;
    core_buffer_budget_t working_memory;
    uint8_t *write_buffer;
    size_t write_capacity,record_capacity;
    uint8_t outgoing_raw_header[5];
    size_t outgoing_raw_header_len;
    size_t outgoing_raw_skip;
    uint8_t incoming_raw_header[5];
    size_t incoming_raw_header_len;
    size_t incoming_raw_skip;
    uint8_t *input;
    size_t input_capacity;
    size_t input_len;
    size_t input_off;
    int read_eof;
    uint8_t incoming_random[16],record_header[5];
    size_t incoming_random_length,record_header_length,record_length,record_received;
    uint8_t *record_data;
    uint8_t cache_identity[32];
    uint64_t cache_generation;
    int incoming_deferred;
    uint8_t *prewrite;
    size_t prewrite_length,prewrite_capacity;
};

typedef struct {
    uint8_t identity[32],pfs[64],ticket[16];
    uint64_t until_ms,used,generation;
} encryption_cache_t;
static encryption_cache_t encryption_cache[64];
static pthread_mutex_t encryption_cache_lock=PTHREAD_MUTEX_INITIALIZER;
static uint64_t encryption_cache_sequence;

static void cache_identity(const vless_config_t *config, uint8_t identity[32]) {
    blake3_hash((const uint8_t *)config,sizeof(*config),identity);
    for (size_t i=0;i<core_server_ip_count();i++) {
        struct sockaddr_storage address={0}; socklen_t length=0;
        if (!core_server_address_at(i,config->server_port,&address,&length)) {
            uint8_t material[32+sizeof(address)];
            memcpy(material,identity,32); memcpy(material+32,&address,length);
            blake3_hash(material,32+length,identity);
        }
    }
}

static uint64_t cache_load(const uint8_t identity[32], uint8_t pfs[64], uint8_t ticket[16]) {
    uint64_t generation=0,now=core_now_ms();
    pthread_mutex_lock(&encryption_cache_lock);
    for (size_t i=0;i<64;i++) {
        encryption_cache_t *entry=&encryption_cache[i];
        if (entry->until_ms && entry->until_ms <= now) OPENSSL_cleanse(entry,sizeof(*entry));
        if (entry->until_ms && !memcmp(entry->identity,identity,32)) {
            memcpy(pfs,entry->pfs,64); memcpy(ticket,entry->ticket,16);
            generation=entry->generation; entry->used=++encryption_cache_sequence; break;
        }
    }
    pthread_mutex_unlock(&encryption_cache_lock);
    return generation;
}

static void cache_store(const uint8_t identity[32], const uint8_t pfs[64], const uint8_t ticket[16], unsigned seconds) {
    if (!seconds) return;
    pthread_mutex_lock(&encryption_cache_lock);
    encryption_cache_t *chosen=&encryption_cache[0]; uint64_t now=core_now_ms();
    for (size_t i=0;i<64;i++) {
        encryption_cache_t *entry=&encryption_cache[i];
        if (entry->until_ms && entry->until_ms <= now) OPENSSL_cleanse(entry,sizeof(*entry));
        if (entry->until_ms && !memcmp(entry->identity,identity,32)) { chosen=entry; break; }
        if (!entry->until_ms || entry->used < chosen->used) chosen=entry;
    }
    OPENSSL_cleanse(chosen,sizeof(*chosen));
    memcpy(chosen->identity,identity,32); memcpy(chosen->pfs,pfs,64); memcpy(chosen->ticket,ticket,16);
    chosen->until_ms=now+(uint64_t)seconds*1000; chosen->used=chosen->generation=++encryption_cache_sequence;
    pthread_mutex_unlock(&encryption_cache_lock);
}

static void cache_invalidate(vless_encryption_conn_t *connection) {
    if (!connection->cache_generation) return;
    pthread_mutex_lock(&encryption_cache_lock);
    for (size_t i=0;i<64;i++) if (encryption_cache[i].generation == connection->cache_generation &&
        !memcmp(encryption_cache[i].identity,connection->cache_identity,32)) OPENSSL_cleanse(&encryption_cache[i],sizeof(encryption_cache[i]));
    pthread_mutex_unlock(&encryption_cache_lock);
    connection->cache_generation=0;
}

static void set_err(char *err, size_t cap, const char *msg) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
}

static void clear_free(void *memory, size_t capacity) {
    int saved=errno;
    if (memory) { OPENSSL_cleanse(memory,capacity); free(memory); }
    errno=saved;
}

static int random_range(int min, int max) {
    if (min > max) { int temporary=min; min=max; max=temporary; }
    if (min == max) return min;
    uint32_t value;
    if (min < 0 || core_random_range((uint32_t)min,(uint32_t)max-1,&value)) return -1;
    return (int)value;
}

static int padding_create(const vless_config_t *config, int lengths[14], int gaps[14], size_t *count) {
    static const vless_encryption_padding_t defaults[]={{100,111,1111},{75,0,111},{50,0,3333}};
    const vless_encryption_padding_t *parameters=config->encryption_padding_count ? config->encryption_padding : defaults;
    size_t size=config->encryption_padding_count ? config->encryption_padding_count : 3;
    if (size > VLESS_ENCRYPTION_MAX_PADDING) return -1;
    memset(lengths,0,14*sizeof(*lengths)); memset(gaps,0,14*sizeof(*gaps));
    int total=0;
    for (size_t i=0;i<size;i++) {
        int choice=random_range(0,100),selected=0;
        if (choice < 0) return -1;
        if (parameters[i].probability >= choice) selected=random_range(parameters[i].min,parameters[i].max);
        if (selected < 0) return -1;
        if (i%2) gaps[i/2]=selected;
        else { if (selected > 65553-total) return -1; lengths[i/2]=selected; total+=selected; }
    }
    *count=(size+1)/2;
    return total >= 35 ? total : -1;
}

static int padding_write(tls13_conn_t *transport, const uint8_t *hello, size_t length, size_t prefix,
                         const int lengths[14], const int gaps[14], size_t count) {
    size_t offset=0;
    for (size_t i=0;i<count;i++) {
        size_t part=(size_t)lengths[i]+(i ? 0 : prefix);
        if (part > length-offset || (part && tls13_write_app(transport,hello+offset,part))) return -1;
        offset+=part;
        if (gaps[i]) {
            if (core_poll(NULL,0,gaps[i]) < 0 || (core_deadline_active() && !core_deadline_remaining())) {
                errno=ETIMEDOUT; return -1;
            }
        }
    }
    return offset == length ? 0 : -1;
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

static int aead_seal_context(vless_aead_t *aead, EVP_CIPHER_CTX *ctx, const uint8_t *nonce_override,
                     const uint8_t *plain, size_t plain_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t *out_len) {
    *out_len=0;
    uint8_t nonce[12];
    if (nonce_override != NULL) {
        memcpy(nonce, nonce_override, sizeof(nonce));
    } else {
        increase_nonce(aead->nonce);
        memcpy(nonce, aead->nonce, sizeof(nonce));
    }

    if (ctx == NULL) {
        OPENSSL_cleanse(nonce,sizeof(nonce));
        return -1;
    }
    int n = 0;
    int total = 0;
    const EVP_CIPHER *cipher=EVP_chacha20_poly1305();
    if (EVP_CIPHER_CTX_cipher(ctx) && EVP_CIPHER_CTX_nid(ctx) != EVP_CIPHER_nid(cipher)) EVP_CIPHER_CTX_reset(ctx);
    int ok = EVP_EncryptInit_ex(ctx, EVP_CIPHER_CTX_cipher(ctx) ? NULL : cipher, NULL, NULL, NULL) == 1 &&
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
    if (!ok) EVP_CIPHER_CTX_reset(ctx);
    OPENSSL_cleanse(nonce,sizeof(nonce));
    if (!ok) {
        OPENSSL_cleanse(out,plain_len+16);
        return -1;
    }
    *out_len = (size_t)total;
    return 0;
}

static int aead_open_context(vless_aead_t *aead, EVP_CIPHER_CTX *ctx, const uint8_t *nonce_override,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t *out_len) {
    *out_len=0;
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
    if (ctx == NULL) {
        OPENSSL_cleanse(nonce,sizeof(nonce));
        OPENSSL_cleanse(out,data_len);
        return -1;
    }
    int n = 0;
    int total = 0;
    const EVP_CIPHER *cipher=EVP_chacha20_poly1305();
    if (EVP_CIPHER_CTX_cipher(ctx) && EVP_CIPHER_CTX_nid(ctx) != EVP_CIPHER_nid(cipher)) EVP_CIPHER_CTX_reset(ctx);
    int ok = EVP_DecryptInit_ex(ctx, EVP_CIPHER_CTX_cipher(ctx) ? NULL : cipher, NULL, NULL, NULL) == 1 &&
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
    if (!ok) EVP_CIPHER_CTX_reset(ctx);
    OPENSSL_cleanse(nonce,sizeof(nonce));
    if (!ok) {
        OPENSSL_cleanse(out,data_len);
        return -1;
    }
    *out_len = (size_t)total;
    return 0;
}
static int aead_seal(vless_aead_t *aead,const uint8_t *nonce,const uint8_t *plain,size_t length,
                     const uint8_t *aad,size_t aad_length,uint8_t *output,size_t *output_length) {
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new();
    int result=aead_seal_context(aead,context,nonce,plain,length,aad,aad_length,output,output_length);
    EVP_CIPHER_CTX_free(context); return result;
}
static int aead_open(vless_aead_t *aead,const uint8_t *nonce,const uint8_t *data,size_t length,
                     const uint8_t *aad,size_t aad_length,uint8_t *output,size_t *output_length) {
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new();
    int result=aead_open_context(aead,context,nonce,data,length,aad,aad_length,output,output_length);
    EVP_CIPHER_CTX_free(context); return result;
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
        OPENSSL_cleanse(derived,sizeof(derived));
        return -1;
    }
    OPENSSL_cleanse(derived,sizeof(derived));
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
    EVP_CIPHER_CTX *previous_ctr=NULL,*public_ctr=NULL;
    EVP_PKEY *private_key=NULL;
    uint8_t current_key[32]={0},hash[32]={0};
    size_t off=0; int result=-1;
    for (size_t i=0;i<cfg->encryption_relay_count;i++) {
        const vless_encryption_relay_t *relay=&cfg->encryption_relays[i];
        size_t relay_len=relay->key_len == 32 ? 32 : 1088;
        if (relay->key_len == 32) {
            if (x25519_generate(&private_key,out+off) || x25519_derive(private_key,relay->key,current_key)) goto cleanup;
            EVP_PKEY_free(private_key); private_key=NULL;
        } else if (mlkem_encapsulate_public(relay->key,out+off,current_key)) goto cleanup;
        if (cfg->encryption_xor_mode) {
            if (aes_ctr_init(&public_ctr,relay->key,relay->key_len,iv) || aes_ctr_xor(public_ctr,out+off,relay_len)) goto cleanup;
            EVP_CIPHER_CTX_free(public_ctr); public_ctr=NULL;
        }
        if (previous_ctr && aes_ctr_xor(previous_ctr,out+off,32)) goto cleanup;
        if (i+1 < cfg->encryption_relay_count) {
            blake3_hash(cfg->encryption_relays[i+1].key,cfg->encryption_relays[i+1].key_len,hash);
            memcpy(out+off+relay_len,hash,sizeof(hash));
            EVP_CIPHER_CTX_free(previous_ctr); previous_ctr=NULL;
            if (aes_ctr_init(&previous_ctr,current_key,sizeof(current_key),iv) ||
                aes_ctr_xor(previous_ctr,out+off+relay_len,sizeof(hash))) goto cleanup;
            off+=relay_len+sizeof(hash);
        } else { memcpy(nfs_key,current_key,sizeof(current_key)); off+=relay_len; }
        OPENSSL_cleanse(current_key,sizeof(current_key));
    }
    result=0;
cleanup: {
    int saved=errno;
    EVP_PKEY_free(private_key); EVP_CIPHER_CTX_free(public_ctr); EVP_CIPHER_CTX_free(previous_ctr);
    OPENSSL_cleanse(current_key,sizeof(current_key)); OPENSSL_cleanse(hash,sizeof(hash));
    errno=saved; return result;
}
}
static int transport_read_exact(tls13_conn_t *transport,
                                uint8_t *buf, size_t len) {
    return tls13_read_exact_app(transport, buf, len);
}

int vless_encryption_connect(const vless_config_t *cfg, tls13_conn_t *transport,
                             vless_encryption_conn_t **out,
                             char *err, size_t err_cap) {
    struct {
        uint8_t client_iv[16],nfs_key[32],identity[32],cached_pfs[64],cached_ticket[16],pfs_key[64],ticket[16];
        uint8_t client_pfs_public[1216],encrypted_server_pfs[1136],server_pfs_public[1120];
        uint8_t encrypted_ticket[32],encrypted_length[18],decoded_length[2];
        vless_aead_t nfs_aead;
        EVP_PKEY *mlkem_key,*x25519_key;
        vless_encryption_conn_t *connection;
        uint8_t *hello,*peer_padding,*decoded_padding;
        size_t hello_length,peer_padding_length,decoded_padding_capacity;
    } handshake={0};
    int result=-1;
    *out=NULL;
    if (!cfg->encryption_enabled || !cfg->encryption_relay_count) {
        set_err(err,err_cap,"VLESS encryption is not configured"); goto cleanup;
    }
    size_t relays_len=0;
    for (size_t i=0;i<cfg->encryption_relay_count;i++) {
        relays_len+=cfg->encryption_relays[i].key_len == 32 ? 32 : 1088;
        if (i+1 < cfg->encryption_relay_count) relays_len+=32;
    }
    int padding_lengths[14],padding_gaps[14]; size_t padding_count=0;
    int padding_len=padding_create(cfg,padding_lengths,padding_gaps,&padding_count);
    if (padding_len < 0) { set_err(err,err_cap,"invalid VLESS encryption padding"); goto cleanup; }
    const size_t pfs_exchange_len=18+1184+32+16;
    handshake.hello_length=16+relays_len+pfs_exchange_len+(size_t)padding_len;
    handshake.hello=calloc(1,handshake.hello_length);
    if (!handshake.hello || core_random_fill(handshake.hello,16)) {
        set_err(err,err_cap,"failed to allocate VLESS encryption hello"); goto cleanup;
    }
    memcpy(handshake.client_iv,handshake.hello,sizeof(handshake.client_iv));
    if (build_relays(cfg,handshake.hello,handshake.hello+16,handshake.nfs_key)) {
        set_err(err,err_cap,"failed to build VLESS encryption relay"); goto cleanup;
    }
    aead_init(&handshake.nfs_aead,handshake.hello,16,handshake.nfs_key,sizeof(handshake.nfs_key));
    cache_identity(cfg,handshake.identity);
    uint64_t generation=cfg->encryption_zero_rtt ? cache_load(handshake.identity,handshake.cached_pfs,handshake.cached_ticket) : 0;
    if (generation) {
        handshake.connection=calloc(1,sizeof(*handshake.connection));
        size_t offset=16+relays_len,written=0; uint8_t length[2]={0,32};
        if (!handshake.connection ||
            aead_seal(&handshake.nfs_aead,NULL,length,2,NULL,0,handshake.hello+offset,&written) || written != 18 ||
            aead_seal(&handshake.nfs_aead,NULL,handshake.cached_ticket,16,NULL,0,handshake.hello+offset+18,&written) || written != 32) {
            set_err(err,err_cap,"failed to resume VLESS encryption"); goto cleanup;
        }
        vless_encryption_conn_t *connection=handshake.connection;
        connection->transport=transport;
        memcpy(connection->united_key,handshake.cached_pfs,64); memcpy(connection->united_key+64,handshake.nfs_key,32);
        connection->united_key_len=96;
        memcpy(connection->cache_identity,handshake.identity,32); connection->cache_generation=generation;
        aead_init(&connection->outgoing,handshake.hello+offset+18,32,connection->united_key,96);
        connection->incoming_deferred=1;
        connection->prewrite=handshake.hello; connection->prewrite_length=offset+50;
        connection->prewrite_capacity=handshake.hello_length; handshake.hello=NULL;
        if (cfg->encryption_xor_mode == 2 && aes_ctr_init(&connection->outgoing_header_ctr,connection->united_key,96,handshake.client_iv)) {
            set_err(err,err_cap,"failed to initialize resumed VLESS encryption"); goto cleanup;
        }
        *out=connection; handshake.connection=NULL; result=0; goto cleanup;
    }
    handshake.mlkem_key=mlkem_generate(handshake.client_pfs_public);
    if (!handshake.mlkem_key || x25519_generate(&handshake.x25519_key,handshake.client_pfs_public+1184)) {
        set_err(err,err_cap,"ML-KEM-768 is unavailable"); goto cleanup;
    }
    size_t offset=16+relays_len,written=0;
    uint8_t length_bytes[2]={(uint8_t)((pfs_exchange_len-18)>>8),(uint8_t)(pfs_exchange_len-18)};
    if (aead_seal(&handshake.nfs_aead,NULL,length_bytes,sizeof(length_bytes),NULL,0,handshake.hello+offset,&written) || written != 18) goto send_failure;
    offset+=written;
    if (aead_seal(&handshake.nfs_aead,NULL,handshake.client_pfs_public,sizeof(handshake.client_pfs_public),
        NULL,0,handshake.hello+offset,&written) || written != sizeof(handshake.client_pfs_public)+16) goto send_failure;
    offset+=written;
    uint8_t padding_length_bytes[2]={(uint8_t)(((size_t)padding_len-18)>>8),(uint8_t)((size_t)padding_len-18)};
    if (aead_seal(&handshake.nfs_aead,NULL,padding_length_bytes,sizeof(padding_length_bytes),NULL,0,handshake.hello+offset,&written) || written != 18) goto send_failure;
    offset+=written;
    size_t padding_plain_len=(size_t)padding_len-34;
    if (aead_seal(&handshake.nfs_aead,NULL,handshake.hello+offset,padding_plain_len,NULL,0,handshake.hello+offset,&written) ||
        written != padding_plain_len+16) goto send_failure;
    offset+=written;
    if (offset != handshake.hello_length || padding_write(transport,handshake.hello,handshake.hello_length,
        16+relays_len+pfs_exchange_len,padding_lengths,padding_gaps,padding_count)) goto send_failure;
    clear_free(handshake.hello,handshake.hello_length); handshake.hello=NULL;
    static const uint8_t max_nonce[12]={255,255,255,255,255,255,255,255,255,255,255,255};
    size_t plain_len=0;
    if (transport_read_exact(transport,handshake.encrypted_server_pfs,sizeof(handshake.encrypted_server_pfs)) ||
        aead_open(&handshake.nfs_aead,max_nonce,handshake.encrypted_server_pfs,sizeof(handshake.encrypted_server_pfs),
            NULL,0,handshake.server_pfs_public,&plain_len) || plain_len != sizeof(handshake.server_pfs_public)) {
        set_err(err,err_cap,"invalid VLESS encryption server key"); goto cleanup;
    }
    if (mlkem_decapsulate(handshake.mlkem_key,handshake.server_pfs_public,handshake.pfs_key) ||
        x25519_derive(handshake.x25519_key,handshake.server_pfs_public+1088,handshake.pfs_key+32)) {
        set_err(err,err_cap,"VLESS encryption key exchange failed"); goto cleanup;
    }
    handshake.connection=calloc(1,sizeof(*handshake.connection));
    if (!handshake.connection) { set_err(err,err_cap,"failed to allocate VLESS encryption state"); goto cleanup; }
    vless_encryption_conn_t *connection=handshake.connection;
    connection->transport=transport;
    memcpy(connection->united_key,handshake.pfs_key,sizeof(handshake.pfs_key));
    memcpy(connection->united_key+sizeof(handshake.pfs_key),handshake.nfs_key,sizeof(handshake.nfs_key));
    connection->united_key_len=sizeof(handshake.pfs_key)+sizeof(handshake.nfs_key);
    aead_init(&connection->outgoing,handshake.client_pfs_public,sizeof(handshake.client_pfs_public),connection->united_key,connection->united_key_len);
    aead_init(&connection->incoming,handshake.server_pfs_public,sizeof(handshake.server_pfs_public),connection->united_key,connection->united_key_len);
    if (transport_read_exact(transport,handshake.encrypted_ticket,sizeof(handshake.encrypted_ticket)) ||
        aead_open(&connection->incoming,NULL,handshake.encrypted_ticket,sizeof(handshake.encrypted_ticket),NULL,0,handshake.ticket,&plain_len) ||
        plain_len != sizeof(handshake.ticket) ||
        transport_read_exact(transport,handshake.encrypted_length,sizeof(handshake.encrypted_length)) ||
        aead_open(&connection->incoming,NULL,handshake.encrypted_length,sizeof(handshake.encrypted_length),NULL,0,handshake.decoded_length,&plain_len) ||
        plain_len != sizeof(handshake.decoded_length)) {
        set_err(err,err_cap,"invalid VLESS encryption server hello"); goto cleanup;
    }
    handshake.peer_padding_length=((size_t)handshake.decoded_length[0]<<8)|handshake.decoded_length[1];
    if (handshake.peer_padding_length < 16 || handshake.peer_padding_length > 65535) {
        set_err(err,err_cap,"invalid VLESS encryption server padding"); goto cleanup;
    }
    handshake.decoded_padding_capacity=handshake.peer_padding_length-16;
    if (!handshake.decoded_padding_capacity) handshake.decoded_padding_capacity=1;
    handshake.peer_padding=malloc(handshake.peer_padding_length);
    handshake.decoded_padding=malloc(handshake.decoded_padding_capacity);
    if (!handshake.peer_padding || !handshake.decoded_padding ||
        transport_read_exact(transport,handshake.peer_padding,handshake.peer_padding_length) ||
        aead_open(&connection->incoming,NULL,handshake.peer_padding,handshake.peer_padding_length,NULL,0,handshake.decoded_padding,&plain_len)) {
        set_err(err,err_cap,"invalid VLESS encryption server padding"); goto cleanup;
    }
    if (cfg->encryption_xor_mode == 2 &&
        (aes_ctr_init(&connection->outgoing_header_ctr,connection->united_key,connection->united_key_len,handshake.client_iv) ||
         aes_ctr_init(&connection->incoming_header_ctr,connection->united_key,connection->united_key_len,handshake.ticket))) {
        set_err(err,err_cap,"failed to initialize VLESS random mode"); goto cleanup;
    }
    if (cfg->encryption_zero_rtt) cache_store(handshake.identity,handshake.pfs_key,handshake.ticket,((unsigned)handshake.ticket[0]<<8)|handshake.ticket[1]);
    *out=connection; handshake.connection=NULL; result=0; goto cleanup;
send_failure:
    set_err(err,err_cap,"failed to send VLESS encryption hello");
cleanup: {
    int saved=errno;
    clear_free(handshake.hello,handshake.hello_length);
    clear_free(handshake.peer_padding,handshake.peer_padding_length);
    clear_free(handshake.decoded_padding,handshake.decoded_padding_capacity);
    vless_encryption_close(handshake.connection);
    EVP_PKEY_free(handshake.mlkem_key); EVP_PKEY_free(handshake.x25519_key);
    OPENSSL_cleanse(&handshake,sizeof(handshake));
    errno=saved; return result;
}
}
static EVP_CIPHER_CTX *record_context(vless_encryption_conn_t *connection,int writing) {
    EVP_CIPHER_CTX **context=writing ? &connection->record_encrypt : &connection->record_decrypt;
    if (!*context) *context=EVP_CIPHER_CTX_new();
    if (!*context) errno=ENOMEM;
    return *context;
}
static void working_free(vless_encryption_conn_t *connection,uint8_t *buffer,size_t capacity) {
    if (!buffer) return;
    clear_free(buffer,capacity); core_buffer_drop(&connection->working_memory,capacity);
}
static int working_reserve(vless_encryption_conn_t *connection,uint8_t **buffer,size_t *capacity,size_t needed,size_t limit) {
    if (*buffer && (needed > *capacity || buffer == &connection->input)) OPENSSL_cleanse(*buffer,*capacity);
    if (needed <= *capacity) return 0;
    if (needed > limit) { errno=EMSGSIZE; return -1; }
    if (core_buffer_budget_init(&connection->working_memory,CORE_BUFFER_RELAY,0)) return -1;
    size_t size=*capacity ? *capacity : 1024;
    while (size < needed) size=size > limit/2 ? limit : size*2;
    if (core_buffer_hold(&connection->working_memory,size)) return -1;
    uint8_t *replacement=malloc(size);
    if (!replacement) { core_buffer_drop(&connection->working_memory,size); return -1; }
    OPENSSL_cleanse(replacement,size);
    working_free(connection,*buffer,*capacity);
    *buffer=replacement; *capacity=size; return 0;
}

void vless_encryption_close(vless_encryption_conn_t *conn) {
    if (conn == NULL) {
        return;
    }
    int saved=errno;
    working_free(conn,conn->input,conn->input_capacity);
    working_free(conn,conn->record_data,conn->record_capacity);
    working_free(conn,conn->write_buffer,conn->write_capacity);
    core_buffer_budget_clear(&conn->working_memory);
    clear_free(conn->prewrite,conn->prewrite_capacity);
    EVP_CIPHER_CTX_free(conn->outgoing_header_ctr);
    EVP_CIPHER_CTX_free(conn->incoming_header_ctr);
    EVP_CIPHER_CTX_free(conn->record_encrypt); EVP_CIPHER_CTX_free(conn->record_decrypt);
    OPENSSL_cleanse(conn->united_key, sizeof(conn->united_key));
    OPENSSL_cleanse(&conn->outgoing, sizeof(conn->outgoing));
    OPENSSL_cleanse(&conn->incoming, sizeof(conn->incoming));
    OPENSSL_cleanse(conn,sizeof(*conn));
    free(conn);
    errno=saved;
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
        if (conn->prewrite_length > SIZE_MAX-record_len) { errno=EOVERFLOW; return -1; }
        size_t packet_capacity=conn->prewrite_length+record_len;
        if (working_reserve(conn,&conn->write_buffer,&conn->write_capacity,packet_capacity,CORE_BUFFER_TOTAL_LIMIT)) return -1;
        uint8_t *packet=conn->write_buffer;
        if (conn->prewrite_length) memcpy(packet,conn->prewrite,conn->prewrite_length);
        uint8_t *record=packet+conn->prewrite_length;
        size_t encrypted_len = chunk + 16;
        record[0] = 23;
        record[1] = 3;
        record[2] = 3;
        record[3] = (uint8_t)(encrypted_len >> 8);
        record[4] = (uint8_t)encrypted_len;
        size_t written = 0;
        int ok = aead_seal_context(&conn->outgoing, record_context(conn,1), NULL, buf + off, chunk,
                           record, 5, record + 5, &written) == 0 &&
                 written == encrypted_len;
        if (ok && conn->outgoing_header_ctr != NULL) {
            ok = aes_ctr_xor(conn->outgoing_header_ctr, record, 5) == 0;
        }
        if (ok) {
            ok = tls13_write_app(conn->transport,packet,conn->prewrite_length+record_len) == 0;
        }
        OPENSSL_cleanse(packet,conn->write_capacity); clear_free(conn->prewrite,conn->prewrite_capacity);
        conn->prewrite=NULL; conn->prewrite_length=conn->prewrite_capacity=0;
        if (!ok) {
            cache_invalidate(conn);
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
    if (working_reserve(conn,&conn->write_buffer,&conn->write_capacity,len,CORE_BUFFER_TOTAL_LIMIT)) return -1;
    uint8_t *encoded=conn->write_buffer;
    memcpy(encoded, buf, len);
    int rc = xor_raw_headers(
        conn->outgoing_header_ctr, encoded, len,
        conn->outgoing_raw_header, &conn->outgoing_raw_header_len,
        &conn->outgoing_raw_skip, 0);
    if (rc == 0) {
        rc = tls13_write_app(conn->transport, encoded, len);
    }
    OPENSSL_cleanse(encoded,conn->write_capacity);
    return rc;
}

static int read_record(vless_encryption_conn_t *conn) {
    if (conn->incoming_deferred) {
        size_t received=0;
        int result=tls13_read_app(conn->transport,conn->incoming_random+conn->incoming_random_length,sizeof(conn->incoming_random)-conn->incoming_random_length,&received);
        if (result > 0) return 2;
        if (result < 0 || !received) { cache_invalidate(conn); return -1; }
        conn->incoming_random_length+=received;
        if (conn->incoming_random_length < sizeof(conn->incoming_random)) return 2;
        aead_init(&conn->incoming,conn->incoming_random,sizeof(conn->incoming_random),conn->united_key,conn->united_key_len);
        if (conn->outgoing_header_ctr && aes_ctr_init(&conn->incoming_header_ctr,conn->united_key,conn->united_key_len,conn->incoming_random)) {
            cache_invalidate(conn); return -1;
        }
        conn->incoming_deferred=0;
        OPENSSL_cleanse(conn->incoming_random,sizeof(conn->incoming_random));
        return 2;
    }
    if (conn->record_header_length < sizeof(conn->record_header)) {
        size_t received=0;
        int result=tls13_read_app(conn->transport,conn->record_header+conn->record_header_length,sizeof(conn->record_header)-conn->record_header_length,&received);
        if (result > 0) return 2;
        if (result < 0) { cache_invalidate(conn); return -1; }
        if (!received) {
            if (conn->record_header_length || conn->cache_generation) { cache_invalidate(conn); return -1; }
            conn->read_eof=1; return 1;
        }
        conn->record_header_length+=received;
        if (conn->record_header_length < sizeof(conn->record_header)) return 2;
        if (conn->incoming_header_ctr && aes_ctr_xor(conn->incoming_header_ctr,conn->record_header,sizeof(conn->record_header))) { cache_invalidate(conn); return -1; }
        conn->record_length=((size_t)conn->record_header[3]<<8)|conn->record_header[4];
        if (conn->record_header[0] != 23 || conn->record_header[1] != 3 || conn->record_header[2] != 3 || conn->record_length < 17 || conn->record_length > 16640) { cache_invalidate(conn); return -1; }
        if (working_reserve(conn,&conn->record_data,&conn->record_capacity,conn->record_length,16640) ||
            working_reserve(conn,&conn->input,&conn->input_capacity,conn->record_length-16,16640)) { cache_invalidate(conn); return -1; }
        return 2;
    }
    size_t received=0;
    int result=tls13_read_app(conn->transport,conn->record_data+conn->record_received,conn->record_length-conn->record_received,&received);
    if (result > 0) return 2;
    if (result < 0 || !received) { cache_invalidate(conn); return -1; }
    conn->record_received+=received;
    if (conn->record_received < conn->record_length) return 2;
    uint8_t *plain=conn->input;
    size_t plain_len = 0;
    int rc = aead_open_context(&conn->incoming, record_context(conn,0), NULL, conn->record_data, conn->record_length,
                       conn->record_header, sizeof(conn->record_header), plain, &plain_len);
    OPENSSL_cleanse(conn->record_data,conn->record_capacity);
    conn->record_header_length=conn->record_length=conn->record_received=0;
    if (rc != 0) {
        cache_invalidate(conn);
        OPENSSL_cleanse(plain,conn->input_capacity);
        return -1;
    }
    conn->input_len = plain_len;
    conn->input_off = 0;
    conn->cache_generation=0;
    return 0;
}

int vless_encryption_has_pending_input(const vless_encryption_conn_t *conn) {
    return conn != NULL && conn->input_off < conn->input_len;
}

int vless_encryption_read(vless_encryption_conn_t *conn,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }
    if (conn->input_off == conn->input_len) {
        if (conn->read_eof) return 0;
        int result;
        do { result=read_record(conn); } while (result == 2 && tls13_has_pending_input(conn->transport));
        if (result) return result == 2 ? 1 : result > 0 ? 0 : -1;
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
    *out_len=0;
    if (!cap) return 0;
    if (conn->input_off < conn->input_len) {
        size_t available=conn->input_len-conn->input_off;
        size_t take=available < cap ? available : cap;
        memcpy(buf,conn->input+conn->input_off,take); conn->input_off+=take; *out_len=take;
        return 0;
    }
    int rc = tls13_read_app(conn->transport, buf, cap, out_len);
    if (!rc && !*out_len && (conn->incoming_raw_header_len || conn->incoming_raw_skip)) return -1;
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
        int result=vless_encryption_read(conn,buf+off,len-off,&got);
        if (result > 0) {
            if (!tls13_has_pending_input(conn->transport) && core_wait_socket(tls13_get_fd(conn->transport),POLLIN,-1) <= 0) return -1;
            continue;
        }
        if (result < 0 || got == 0) {
            return -1;
        }
        off += got;
    }
    return 0;
}
