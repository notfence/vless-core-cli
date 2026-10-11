#include "check.h"
#include "../src/vless_encryption.c"
#include "uri.h"
static uint8_t transport_data[131072];
static size_t transport_length, transport_position;
static void *cache_worker(void *opaque) {
    unsigned index=(unsigned)(uintptr_t)opaque;
    uint8_t identity[32]={0},pfs[64],ticket[16],loaded_pfs[64],loaded_ticket[16];
    identity[0]=(uint8_t)index; memset(pfs,(int)index,sizeof(pfs)); memset(ticket,(int)index,sizeof(ticket));
    for (unsigned i=0;i<100;i++) {
        cache_store(identity,pfs,ticket,60);
        if (!cache_load(identity,loaded_pfs,loaded_ticket) || memcmp(pfs,loaded_pfs,64) || memcmp(ticket,loaded_ticket,16)) return (void *)1;
    }
    return NULL;
}
int tls13_write_app(tls13_conn_t *c, const uint8_t *data, size_t length) {
    (void)c; if (transport_length + length > sizeof(transport_data)) return -1;
    memcpy(transport_data + transport_length, data, length); transport_length += length; return 0;
}
int tls13_read_app(tls13_conn_t *c, uint8_t *data, size_t capacity, size_t *length) {
    (void)c; size_t count = transport_length - transport_position; if (count > capacity) count = capacity;
    memcpy(data, transport_data + transport_position, count); transport_position += count; *length = count; return 0;
}
int tls13_read_exact_app(tls13_conn_t *c, uint8_t *data, size_t length) {
    size_t got; return tls13_read_app(c, data, length, &got) != 0 || got != length ? -1 : 0;
}
int main(void) {
    vless_encryption_conn_t pending = {0};
    CHECK("encryption/null-readiness", !vless_encryption_has_pending_input(NULL));
    CHECK("encryption/empty-readiness", !vless_encryption_has_pending_input(&pending));
    pending.input_len = 16384; pending.input_off = 8192;
    CHECK("encryption/buffered-readiness", vless_encryption_has_pending_input(&pending));
    pending.input_off = pending.input_len;
    CHECK("encryption/drained-readiness", !vless_encryption_has_pending_input(&pending));
    uint8_t public_key[1184], ciphertext[1088], secret[32], recovered[32];
    EVP_PKEY *kem = mlkem_generate(public_key); REQUIRE("encryption/mlkem-provider", kem != NULL);
    CHECK("encryption/mlkem-roundtrip", mlkem_encapsulate_public(public_key, ciphertext, secret) == 0 && mlkem_decapsulate(kem, ciphertext, recovered) == 0 && memcmp(secret, recovered, 32) == 0);
    ciphertext[0] ^= 1;
    CHECK("encryption/mlkem-implicit-rejection", mlkem_decapsulate(kem, ciphertext, recovered) == 0 && memcmp(secret, recovered, 32) != 0); EVP_PKEY_free(kem);
    uint8_t a_public[32], b_public[32]; EVP_PKEY *a = NULL, *b = NULL;
    REQUIRE("encryption/x25519-generate", x25519_generate(&a, a_public) == 0 && x25519_generate(&b, b_public) == 0);
    CHECK("encryption/x25519-shared", x25519_derive(a, b_public, secret) == 0 && x25519_derive(b, a_public, recovered) == 0 && memcmp(secret, recovered, 32) == 0); EVP_PKEY_free(a); EVP_PKEY_free(b);
    const uint8_t context[] = "vless-core", plain[] = "vless-core encrypted record", aad[] = {23,3,3};
    uint8_t encoded[128], decoded[128]; size_t encoded_len, decoded_len; vless_aead_t sender, receiver;
    aead_init(&sender, context, sizeof(context), secret, 32); receiver = sender;
    REQUIRE("encryption/aead-seal", aead_seal(&sender, NULL, plain, sizeof(plain), aad, sizeof(aad), encoded, &encoded_len) == 0);
    CHECK("encryption/aead-open", aead_open(&receiver, NULL, encoded, encoded_len, aad, sizeof(aad), decoded, &decoded_len) == 0 && decoded_len == sizeof(plain) && memcmp(plain, decoded, decoded_len) == 0);
    CHECK("encryption/nonce-advance", sender.nonce[11] == 1 && receiver.nonce[11] == 1);
    for (size_t i = 0; i < encoded_len; i++) {
        aead_init(&receiver, context, sizeof(context), secret, 32); encoded[i] ^= 1;
        CHECK("encryption/tamper-rejected", aead_open(&receiver, NULL, encoded, encoded_len, aad, sizeof(aad), decoded, &decoded_len) != 0); encoded[i] ^= 1;
    }
    aead_init(&receiver, context, sizeof(context), secret, 32);
    CHECK("encryption/aad-rejected", aead_open(&receiver, NULL, encoded, encoded_len, NULL, 0, decoded, &decoded_len) != 0);
    CHECK("encryption/truncated-tag", aead_open(&receiver, NULL, encoded, 15, NULL, 0, decoded, &decoded_len) != 0);
    uint8_t nonce[12]; memset(nonce, 255, sizeof(nonce)); increase_nonce(nonce); uint8_t zero[12] = {0}; CHECK("encryption/nonce-carry", memcmp(nonce, zero, 12) == 0);
    uint8_t payload[24579], output[sizeof(payload)]; for (size_t i = 0; i < sizeof(payload); i++) payload[i] = i % 251;
    for (int mode = 0; mode < 3; mode++) {
        vless_encryption_conn_t *write_conn = calloc(1, sizeof(*write_conn)), *read_conn = calloc(1, sizeof(*read_conn));
        REQUIRE("encryption/record-allocate", write_conn && read_conn);
        aead_init(&write_conn->outgoing, context, sizeof(context), secret, 32); read_conn->incoming = write_conn->outgoing;
        uint8_t iv[16] = {0};
        if (mode == 2) REQUIRE("encryption/random-header-init", aes_ctr_init(&write_conn->outgoing_header_ctr, secret, 32, iv) == 0 && aes_ctr_init(&read_conn->incoming_header_ctr, secret, 32, iv) == 0);
        transport_length = transport_position = 0;
        REQUIRE("encryption/record-write", vless_encryption_write(write_conn, payload, sizeof(payload)) == 0);
        CHECK("encryption/record-size", transport_length == sizeof(payload) + 4*21);
        REQUIRE("encryption/record-read", vless_encryption_read_exact(read_conn, output, sizeof(output)) == 0);
        CHECK("encryption/record-roundtrip", memcmp(payload, output, sizeof(output)) == 0);
        CHECK("encryption/record-eof", vless_encryption_read_exact(read_conn, output, 1) != 0);
        vless_encryption_close(write_conn); vless_encryption_close(read_conn);
    }
    for (size_t split = 1; split < 12; split++) {
        uint8_t raw[] = {23,3,3,0,3,1,2,3,23,3,3,0,2,4,5}, original[sizeof(raw)], iv[16] = {0}; memcpy(original, raw, sizeof(raw));
        EVP_CIPHER_CTX *encode = NULL, *decode = NULL;
        REQUIRE("encryption/raw-ctr-init", aes_ctr_init(&encode, secret, 32, iv) == 0 && aes_ctr_init(&decode, secret, 32, iv) == 0);
        uint8_t header[5]; size_t header_len = 0, skip = 0;
        REQUIRE("encryption/raw-encode", xor_raw_headers(encode, raw, split, header, &header_len, &skip, 0) == 0 && xor_raw_headers(encode, raw+split, sizeof(raw)-split, header, &header_len, &skip, 0) == 0);
        header_len = skip = 0;
        REQUIRE("encryption/raw-decode", xor_raw_headers(decode, raw, split, header, &header_len, &skip, 1) == 0 && xor_raw_headers(decode, raw+split, sizeof(raw)-split, header, &header_len, &skip, 1) == 0);
        CHECK("encryption/raw-fragmented-roundtrip", memcmp(raw, original, sizeof(raw)) == 0); EVP_CIPHER_CTX_free(encode); EVP_CIPHER_CTX_free(decode);
    }
    vless_config_t cfg = {0}; vless_encryption_conn_t *conn = (void *)1; char error[128];
    CHECK("encryption/not-configured", vless_encryption_connect(&cfg, NULL, &conn, error, sizeof(error)) != 0 && conn == NULL);
    core_config_defaults(&cfg); cfg.encryption_enabled=1; cfg.encryption_zero_rtt=1;
    cfg.encryption_relay_count=1; cfg.encryption_relays[0].key_len=32;
    memcpy(cfg.encryption_relays[0].key,a_public,32);
    uint8_t identity[32],pfs[64],ticket[16],loaded_pfs[64],loaded_ticket[16];
    memset(pfs,7,sizeof(pfs)); memset(ticket,8,sizeof(ticket)); cache_identity(&cfg,identity);
    cache_store(identity,pfs,ticket,60);
    uint64_t generation=cache_load(identity,loaded_pfs,loaded_ticket);
    CHECK("encryption/cache-material",generation && !memcmp(pfs,loaded_pfs,64) && !memcmp(ticket,loaded_ticket,16));
    transport_length=transport_position=0;
    REQUIRE("encryption/cached-handshake-does-not-read",vless_encryption_connect(&cfg,NULL,&conn,error,sizeof(error)) == 0 && conn->incoming_deferred && conn->cache_generation == generation && !transport_length);
    REQUIRE("encryption/resume-first-write",vless_encryption_write(conn,payload,1) == 0);
    CHECK("encryption/resume-prewrite-once",transport_length == 16+32+18+32+22 && !conn->prewrite && !conn->prewrite_length);
    REQUIRE("encryption/resume-second-write",vless_encryption_write(conn,payload,1) == 0);
    CHECK("encryption/resume-second-write-no-prefix",transport_length == 16+32+18+32+44);
    cache_store(identity,pfs,ticket,60); cache_invalidate(conn);
    CHECK("encryption/rejection-does-not-delete-new-ticket",cache_load(identity,loaded_pfs,loaded_ticket) != 0);
    vless_encryption_close(conn);
    for (size_t i=0;i<64;i++) if (!memcmp(encryption_cache[i].identity,identity,32) && encryption_cache[i].until_ms) encryption_cache[i].until_ms=core_now_ms()-1;
    CHECK("encryption/cache-expiry",!cache_load(identity,loaded_pfs,loaded_ticket));
    CHECK("encryption/expired-secret-cleared",!memcmp(encryption_cache[63].pfs,(uint8_t[64]){0},64));
    cache_store(identity,pfs,ticket,60);
    REQUIRE("encryption/rejected-ticket-fixture",vless_encryption_connect(&cfg,NULL,&conn,error,sizeof(error)) == 0);
    memset(transport_data,0,21); transport_length=21; transport_position=0; size_t received=0;
    CHECK("encryption/rejected-ticket-read",vless_encryption_read(conn,output,sizeof(output),&received) < 0);
    CHECK("encryption/rejected-ticket-invalidated",!cache_load(identity,loaded_pfs,loaded_ticket));
    vless_encryption_close(conn);
    for (int random=0;random<2;random++) {
        vless_encryption_conn_t *reader=calloc(1,sizeof(*reader)),*writer=calloc(1,sizeof(*writer));
        REQUIRE("encryption/deferred-reader-fixture",reader && writer);
        memcpy(reader->united_key,pfs,64); memcpy(reader->united_key+64,secret,32); reader->united_key_len=96;
        uint8_t server_random[16]; memset(server_random,39,sizeof(server_random));
        reader->incoming_deferred=1;
        aead_init(&writer->outgoing,server_random,16,reader->united_key,96);
        writer->prewrite=malloc(16); REQUIRE("encryption/server-random-fixture",writer->prewrite != NULL);
        memcpy(writer->prewrite,server_random,16); writer->prewrite_length=16;
        if (random) {
            REQUIRE("encryption/deferred-random-mode",aes_ctr_init(&reader->outgoing_header_ctr,reader->united_key,96,server_random) == 0 &&
                aes_ctr_init(&writer->outgoing_header_ctr,reader->united_key,96,server_random) == 0);
        }
        transport_length=transport_position=0;
        REQUIRE("encryption/deferred-server-write",vless_encryption_write(writer,payload,sizeof(payload)) == 0);
        CHECK("encryption/deferred-incoming-key",vless_encryption_read_exact(reader,output,sizeof(output)) == 0 && !memcmp(output,payload,sizeof(payload)) && !reader->incoming_deferred);
        vless_encryption_close(reader); vless_encryption_close(writer);
    }
    const size_t identity_offsets[]={offsetof(vless_config_t,server_host),offsetof(vless_config_t,server_port),offsetof(vless_config_t,security),
        offsetof(vless_config_t,sni),offsetof(vless_config_t,uuid),offsetof(vless_config_t,fp_mode),offsetof(vless_config_t,encryption_xor_mode),
        offsetof(vless_config_t,encryption_relays),offsetof(vless_config_t,transport_mode),offsetof(vless_config_t,allow_insecure)};
    for (size_t i=0;i<sizeof(identity_offsets)/sizeof(*identity_offsets);i++) {
        vless_config_t other=cfg; ((uint8_t *)&other)[identity_offsets[i]]^=1;
        uint8_t different[32]; cache_identity(&other,different);
        CHECK("encryption/cache-identity-isolated",memcmp(identity,different,32) != 0);
    }
    OPENSSL_cleanse(encryption_cache,sizeof(encryption_cache));
    for (unsigned i=0;i<64;i++) { identity[0]=(uint8_t)i; cache_store(identity,pfs,ticket,60); }
    identity[0]=0; CHECK("encryption/lru-touch",cache_load(identity,loaded_pfs,loaded_ticket) != 0);
    identity[0]=64; cache_store(identity,pfs,ticket,60);
    identity[0]=1; CHECK("encryption/lru-eviction",!cache_load(identity,loaded_pfs,loaded_ticket));
    identity[0]=0; CHECK("encryption/lru-preserves-recent",cache_load(identity,loaded_pfs,loaded_ticket) != 0);
    OPENSSL_cleanse(encryption_cache,sizeof(encryption_cache));
    pthread_t workers[16];
    for (unsigned i=0;i<16;i++) REQUIRE("encryption/cache-concurrency-start",pthread_create(&workers[i],NULL,cache_worker,(void *)(uintptr_t)i) == 0);
    for (unsigned i=0;i<16;i++) { void *result=NULL; pthread_join(workers[i],&result); CHECK("encryption/cache-concurrency",result == NULL); }
    OPENSSL_cleanse(encryption_cache,sizeof(encryption_cache));
    char uri[1024];
    const char *invalid_padding[]={"bad","100-34-35","99-35-35","100-35","100--35","100-65554-65554","100-35-35.100-2147483648-1","100-35-35.100-0-0.100-65553-65553"};
    for (size_t i=0;i<sizeof(invalid_padding)/sizeof(*invalid_padding);i++) {
        snprintf(uri,sizeof(uri),"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:1?encryption=mlkem768x25519plus.native.0rtt.%s.7yEo4KXNFHjDGOeL5a-4RTYsbP9p3Tc032CBVdrluQ8",invalid_padding[i]);
        CHECK("encryption/invalid-padding-rejected",parse_core_uri(uri,&cfg,error,sizeof(error)) < 0);
    }
    return test_result();
}
