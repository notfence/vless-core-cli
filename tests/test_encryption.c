#include "check.h"
#include "../src/vless_encryption.c"
static uint8_t transport_data[131072];
static size_t transport_length, transport_position;
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
    return test_result();
}
