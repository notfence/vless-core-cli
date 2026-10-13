#include "check.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
static struct { void *pointer; size_t capacity; } observed_allocations[128];
static unsigned observing,allocation_calls,allocation_failure,cipher_calls,cipher_failure,random_calls,random_failure,fault_triggered;
static unsigned peer_mode,peer_ready,peer_cut,peer_building,peer_empty_padding,peer_corrupt;
static EVP_PKEY *peer_key;
static int prepare_peer_reply(void);
static void *observe_allocation(size_t size, int zero) {
    if (observing && ++allocation_calls == allocation_failure) { fault_triggered=1; errno=ENOMEM; return NULL; }
    void *pointer=zero ? calloc(1,size) : malloc(size);
    if (pointer && observing) {
        unsigned index=0;
        while (index < 128 && observed_allocations[index].pointer) index++;
        REQUIRE("encryption/cleanup-allocation-tracker-capacity",index < 128);
        observed_allocations[index].pointer=pointer; observed_allocations[index].capacity=size;
        if (!zero) memset(pointer,0xa5,size);
    }
    return pointer;
}
static void *observe_calloc(size_t count, size_t size) {
    if (size && count > SIZE_MAX/size) { errno=ENOMEM; return NULL; }
    return observe_allocation(count*size,1);
}
static void *observe_malloc(size_t size) { return observe_allocation(size,0); }
static void observe_free(void *pointer) {
    for (unsigned i=0;pointer && i<128;i++) if (observed_allocations[i].pointer == pointer) {
        unsigned dirty=0;
        for (size_t j=0;j<observed_allocations[i].capacity;j++) dirty|=((unsigned char *)pointer)[j];
        CHECK("encryption/allocation-cleared-before-free",!dirty);
        if (peer_mode && !peer_ready && observed_allocations[i].capacity == 1333)
            REQUIRE("encryption/cleanup-controlled-peer",!prepare_peer_reply());
        observed_allocations[i].pointer=NULL; break;
    }
    free(pointer);
}
static EVP_CIPHER_CTX *observe_cipher_new(void) {
    if (observing && !peer_building && ++cipher_calls == cipher_failure) { fault_triggered=1; errno=ENOMEM; return NULL; }
    return EVP_CIPHER_CTX_new();
}
static int observe_random(unsigned char *output, int size) {
    if (observing && !peer_building && ++random_calls == random_failure) { fault_triggered=1; errno=EIO; return 0; }
    return RAND_bytes(output,size);
}
#define calloc observe_calloc
#define malloc observe_malloc
#define free observe_free
#define EVP_CIPHER_CTX_new observe_cipher_new
#define RAND_bytes observe_random
#include "../src/vless_encryption.c"
#undef RAND_bytes
#undef EVP_CIPHER_CTX_new
#undef free
#undef malloc
#undef calloc
#include "uri.h"
static uint8_t transport_data[131072];
static size_t transport_length, transport_position;
static int transport_yielding;
static uint64_t write_times[64]; static size_t write_count;
static int prepare_peer_reply(void) {
    if (transport_length != 1333) return 0;
    peer_building=1;
    uint8_t nfs[32],client_public[1216],server_public[1120],pfs[64],united[96],packet[1206],ticket[16]={0,60},length[2]={0,20},padding[4]={0};
    uint8_t max_nonce[12]; memset(max_nonce,255,sizeof(max_nonce));
    if (peer_empty_padding) length[1]=16;
    vless_aead_t incoming,outgoing; EVP_PKEY *server_key=NULL; size_t count=0,used=0;
    if (x25519_derive(peer_key,transport_data+16,nfs)) return -1;
    aead_init(&incoming,transport_data,16,nfs,32);
    uint8_t declared[2];
    if (aead_open(&incoming,NULL,transport_data+48,18,NULL,0,declared,&count) || count != 2 ||
        aead_open(&incoming,NULL,transport_data+66,1232,NULL,0,client_public,&count) || count != sizeof(client_public) ||
        mlkem_encapsulate_public(client_public,server_public,pfs) || x25519_generate(&server_key,server_public+1088) ||
        x25519_derive(server_key,client_public+1184,pfs+32)) { EVP_PKEY_free(server_key); return -1; }
    EVP_PKEY_free(server_key);
    if (aead_seal(&incoming,max_nonce,server_public,sizeof(server_public),NULL,0,packet,&count) || count != 1136) return -1;
    used=count; memcpy(united,pfs,64); memcpy(united+64,nfs,32); aead_init(&outgoing,server_public,sizeof(server_public),united,sizeof(united));
    if (aead_seal(&outgoing,NULL,ticket,16,NULL,0,packet+used,&count)) return -1;
    used+=count;
    if (aead_seal(&outgoing,NULL,length,2,NULL,0,packet+used,&count)) return -1;
    used+=count;
    if (aead_seal(&outgoing,NULL,padding,peer_empty_padding ? 0 : 4,NULL,0,packet+used,&count)) return -1;
    used+=count;
    if (peer_corrupt) packet[peer_corrupt-1]^=1;
    memcpy(transport_data,packet,used); transport_length=peer_cut ? peer_cut : used; transport_position=0; peer_ready=1;
    OPENSSL_cleanse(nfs,sizeof(nfs)); OPENSSL_cleanse(pfs,sizeof(pfs)); OPENSSL_cleanse(united,sizeof(united));
    OPENSSL_cleanse(&incoming,sizeof(incoming)); OPENSSL_cleanse(&outgoing,sizeof(outgoing)); peer_building=0; return 0;
}
static void cleanup_checks(void) {
    vless_config_t config; core_config_defaults(&config);
    config.encryption_enabled=1; config.encryption_zero_rtt=1; config.encryption_relay_count=1;
    config.encryption_relays[0].key_len=32;
    EVP_PKEY *key=NULL; REQUIRE("encryption/cleanup-relay-key",!x25519_generate(&key,config.encryption_relays[0].key)); peer_key=key;
    uint8_t identity[32],pfs[64],ticket[16],loaded_pfs[64],loaded_ticket[16]; char error[160];
    memset(pfs,7,sizeof(pfs)); memset(ticket,8,sizeof(ticket)); cache_identity(&config,identity);
    observing=1;
    for (unsigned failure=0;failure<4;failure++) {
        cache_store(identity,pfs,ticket,60); allocation_calls=0; allocation_failure=failure; fault_triggered=0;
        vless_encryption_conn_t *connection=NULL;
        int result=vless_encryption_connect(&config,NULL,&connection,error,sizeof(error));
        CHECK("encryption/cleanup-resume-allocation-failure",fault_triggered ? result < 0 && !connection : !result && connection);
        vless_encryption_close(connection);
        CHECK("encryption/cleanup-resume-keeps-live-cache",cache_load(identity,loaded_pfs,loaded_ticket) && !memcmp(pfs,loaded_pfs,64) && !memcmp(ticket,loaded_ticket,16));
    }
    allocation_failure=0; config.encryption_zero_rtt=0;
    config.encryption_padding_count=1; config.encryption_padding[0]=(vless_encryption_padding_t){100,35,35};
    peer_mode=1;
    for (unsigned failure=0;failure<6;failure++) {
        allocation_calls=0; allocation_failure=failure; peer_ready=0; fault_triggered=0; transport_length=transport_position=0;
        vless_encryption_conn_t *connection=NULL;
        int result=vless_encryption_connect(&config,NULL,&connection,error,sizeof(error));
        CHECK("encryption/cleanup-full-allocation-failure",fault_triggered ? result < 0 && !connection : !result && connection);
        vless_encryption_close(connection);
    }
    allocation_failure=0;
    for (unsigned failure=1;failure<32;failure++) {
        cipher_calls=0; cipher_failure=failure; peer_ready=0; fault_triggered=0; transport_length=transport_position=0;
        vless_encryption_conn_t *connection=NULL;
        int result=vless_encryption_connect(&config,NULL,&connection,error,sizeof(error));
        CHECK("encryption/cleanup-full-cipher-failure",fault_triggered ? result < 0 && !connection : !result && connection);
        vless_encryption_close(connection);
        if (!fault_triggered) break;
    }
    cipher_failure=0;
    vless_encryption_conn_t *connection=NULL;
    for (unsigned failure=1;failure<8;failure++) {
        random_calls=0; random_failure=failure; peer_ready=0; fault_triggered=0; transport_length=transport_position=0;
        int result=vless_encryption_connect(&config,NULL,&connection,error,sizeof(error));
        CHECK("encryption/cleanup-random-failure",fault_triggered ? result < 0 && !connection : !result && connection);
        vless_encryption_close(connection);
        if (!fault_triggered) break;
    }
    random_failure=0;
    peer_empty_padding=1; peer_ready=0; transport_length=transport_position=0;
    CHECK("encryption/cleanup-empty-server-padding",!vless_encryption_connect(&config,NULL,&connection,error,sizeof(error)) && connection);
    vless_encryption_close(connection); peer_empty_padding=0;
    const unsigned corruptions[]={1,1136,1137,1168,1169,1186,1187,1206};
    for (unsigned i=0;i<sizeof(corruptions)/sizeof(*corruptions);i++) {
        peer_corrupt=corruptions[i]; peer_ready=0; transport_length=transport_position=0;
        CHECK("encryption/cleanup-server-authentication-failure",vless_encryption_connect(&config,NULL,&connection,error,sizeof(error)) < 0 && !connection);
    }
    peer_corrupt=0;
    const unsigned cuts[]={1,1135,1136,1167,1168,1185,1186,1205};
    for (unsigned i=0;i<sizeof(cuts)/sizeof(*cuts);i++) {
        peer_cut=cuts[i]; peer_ready=0; transport_length=transport_position=0;
        CHECK("encryption/cleanup-full-read-failure",vless_encryption_connect(&config,NULL,&connection,error,sizeof(error)) < 0 && !connection);
    }
    peer_mode=0; peer_cut=0;
    config.encryption_zero_rtt=1; config.encryption_xor_mode=2; cache_identity(&config,identity);
    for (unsigned failure=1;failure<16;failure++) {
        cache_store(identity,pfs,ticket,60); cipher_calls=0; cipher_failure=failure; fault_triggered=0;
        int result=vless_encryption_connect(&config,NULL,&connection,error,sizeof(error));
        CHECK("encryption/cleanup-resume-cipher-failure",fault_triggered ? result < 0 && !connection : !result && connection);
        vless_encryption_close(connection);
        CHECK("encryption/cleanup-resume-error-keeps-cache",cache_load(identity,loaded_pfs,loaded_ticket) != 0);
        if (!fault_triggered) break;
    }
    cipher_failure=0;
    vless_encryption_conn_t *writer=observe_calloc(1,sizeof(*writer)),*reader=observe_calloc(1,sizeof(*reader));
    REQUIRE("encryption/cleanup-record-pair",writer && reader);
    aead_init(&writer->outgoing,(const uint8_t *)"vless-core",10,pfs,64);
    aead_init(&reader->incoming,(const uint8_t *)"vless-core",10,pfs,64);
    transport_length=transport_position=0;
    REQUIRE("encryption/cleanup-record-write",!vless_encryption_write(writer,(const uint8_t *)"vless-core secret",17));
    uint8_t output[17]; REQUIRE("encryption/cleanup-record-read",!vless_encryption_read_exact(reader,output,sizeof(output)));
    errno=ENOTTY; vless_encryption_close(reader); vless_encryption_close(writer);
    CHECK("encryption/cleanup-preserves-error",errno == ENOTTY);
    for (unsigned failure=1;failure<=2;failure++) {
        writer=observe_calloc(1,sizeof(*writer)); reader=observe_calloc(1,sizeof(*reader));
        REQUIRE("encryption/cleanup-record-fault-pair",writer && reader);
        aead_init(&writer->outgoing,(const uint8_t *)"vless-core",10,pfs,64); reader->incoming=writer->outgoing;
        transport_length=transport_position=0;
        REQUIRE("encryption/cleanup-record-fault-wire",!vless_encryption_write(writer,(const uint8_t *)"vless-core secret",17));
        allocation_calls=0; allocation_failure=failure;
        CHECK("encryption/cleanup-record-allocation-failure",vless_encryption_read_exact(reader,output,sizeof(output)) < 0);
        allocation_failure=0; vless_encryption_close(reader); vless_encryption_close(writer);
    }
    writer=observe_calloc(1,sizeof(*writer)); REQUIRE("encryption/cleanup-raw-writer",writer != NULL);
    uint8_t iv[16]={0},raw[]={23,3,3,0,3,'r','a','w'};
    REQUIRE("encryption/cleanup-raw-ctr",!aes_ctr_init(&writer->outgoing_header_ctr,pfs,64,iv));
    transport_length=transport_position=0;
    CHECK("encryption/cleanup-raw-write",!vless_encryption_write_raw(writer,raw,sizeof(raw)));
    vless_encryption_close(writer);
    for (unsigned i=0;i<128;i++) CHECK("encryption/cleanup-no-live-allocations",!observed_allocations[i].pointer);
    observing=0; OPENSSL_cleanse(encryption_cache,sizeof(encryption_cache));
    EVP_PKEY_free(key); peer_key=NULL;
}
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
    if (write_count < 64) write_times[write_count++]=core_now_ms();
    (void)c; if (transport_length + length > sizeof(transport_data)) return -1;
    memcpy(transport_data + transport_length, data, length); transport_length += length; return 0;
}
int tls13_read_app(tls13_conn_t *c, uint8_t *data, size_t capacity, size_t *length) {
    (void)c; size_t count = transport_length - transport_position; if (count > capacity) count = capacity;
    memcpy(data, transport_data + transport_position, count); transport_position += count; *length = count; return !count && transport_yielding ? 1 : 0;
}
int tls13_has_pending_input(const tls13_conn_t *c) { (void)c; return !transport_yielding || transport_position < transport_length; }
int tls13_get_fd(const tls13_conn_t *c) { (void)c; return -1; }
int tls13_read_exact_app(tls13_conn_t *c, uint8_t *data, size_t length) {
    size_t got; return tls13_read_app(c, data, length, &got) != 0 || got != length ? -1 : 0;
}
int tls13_read_exact_or_eof(tls13_conn_t *c, uint8_t *data, size_t length) {
    size_t got=0;
    if (tls13_read_app(c,data,length,&got)) return -1;
    return got == length ? 0 : !got ? 1 : -1;
}
int main(void) {
    cleanup_checks();
    vless_encryption_conn_t raw_switch={0}; uint8_t tail[16]; size_t tail_length=0;
    raw_switch.input=(uint8_t *)"buffered"; raw_switch.input_len=8;
    memcpy(transport_data,"wire",4); transport_length=4; transport_position=0;
    CHECK("encryption/raw-switch-drains-decrypted-tail-first",vless_encryption_read_raw(&raw_switch,tail,3,&tail_length) == 0 && tail_length == 3 && !memcmp(tail,"buf",3) && !transport_position);
    CHECK("encryption/raw-switch-drains-complete-tail",vless_encryption_read_raw(&raw_switch,tail,sizeof(tail),&tail_length) == 0 && tail_length == 5 && !memcmp(tail,"fered",5) && !transport_position);
    CHECK("encryption/raw-switch-preserves-outer-transport",vless_encryption_read_raw(&raw_switch,tail,sizeof(tail),&tail_length) == 0 && tail_length == 4 && !memcmp(tail,"wire",4));
    transport_length=transport_position=0;
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
    uint8_t raw_record[]={23,3,3,0,3,'r','a','w'},raw_original[sizeof(raw_record)],raw_iv[16]={0};
    memcpy(raw_original,raw_record,sizeof(raw_record)); EVP_CIPHER_CTX *raw_encoder=NULL;
    vless_encryption_conn_t buffered_raw={.input=(uint8_t *)"buffered",.input_len=8};
    REQUIRE("encryption/raw-tail-ctr-initialized",aes_ctr_init(&raw_encoder,secret,32,raw_iv) == 0 && aes_ctr_init(&buffered_raw.incoming_header_ctr,secret,32,raw_iv) == 0);
    uint8_t raw_header[5]; size_t raw_header_length=0,raw_skip=0;
    REQUIRE("encryption/raw-tail-wire-masked",xor_raw_headers(raw_encoder,raw_record,sizeof(raw_record),raw_header,&raw_header_length,&raw_skip,0) == 0);
    memcpy(transport_data,raw_record,sizeof(raw_record)); transport_length=sizeof(raw_record); transport_position=0;
    CHECK("encryption/raw-tail-not-remasked",vless_encryption_read_raw(&buffered_raw,tail,sizeof(tail),&tail_length) == 0 && tail_length == 8 && !memcmp(tail,"buffered",8) && !transport_position);
    CHECK("encryption/raw-tail-keeps-next-header-ctr-aligned",vless_encryption_read_raw(&buffered_raw,tail,sizeof(tail),&tail_length) == 0 && tail_length == sizeof(raw_original) && !memcmp(tail,raw_original,sizeof(raw_original)));
    EVP_CIPHER_CTX_free(raw_encoder); EVP_CIPHER_CTX_free(buffered_raw.incoming_header_ctr); transport_length=transport_position=0;
    for (size_t i = 0; i < encoded_len; i++) {
        aead_init(&receiver, context, sizeof(context), secret, 32); encoded[i] ^= 1;
        CHECK("encryption/tamper-rejected", aead_open(&receiver, NULL, encoded, encoded_len, aad, sizeof(aad), decoded, &decoded_len) != 0); encoded[i] ^= 1;
        CHECK("encryption/tamper-clears-unverified-plaintext",!memcmp(decoded,(uint8_t[sizeof(plain)]){0},sizeof(plain)));
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
    vless_encryption_conn_t *eof_writer=calloc(1,sizeof(*eof_writer));
    REQUIRE("encryption/eof-fixture",eof_writer != NULL);
    aead_init(&eof_writer->outgoing,context,sizeof(context),secret,32);
    transport_length=transport_position=0;
    REQUIRE("encryption/eof-record",vless_encryption_write(eof_writer,payload,1) == 0);
    size_t whole=transport_length; uint8_t complete_record[64]; memcpy(complete_record,transport_data,whole);
    for (size_t cut=0;cut<=whole;cut++) {
        vless_encryption_conn_t *reader=calloc(1,sizeof(*reader)); REQUIRE("encryption/eof-reader",reader != NULL);
        aead_init(&reader->incoming,context,sizeof(context),secret,32);
        transport_length=cut; transport_position=0; size_t received=0;
        int result=vless_encryption_read(reader,output,sizeof(output),&received);
        CHECK("encryption/clean-eof-vs-truncated-record",!cut ? result == 0 && !received : cut < whole ? result < 0 : result == 0 && received == 1 && output[0] == payload[0]);
        vless_encryption_close(reader);
    }
    for (size_t cut=1;cut<whole;cut++) {
        memcpy(transport_data,complete_record,whole);
        vless_encryption_conn_t *reader=calloc(1,sizeof(*reader)); REQUIRE("encryption/fragment-reader",reader != NULL);
        aead_init(&reader->incoming,context,sizeof(context),secret,32);
        transport_length=cut; transport_position=0; transport_yielding=1; size_t received=0;
        CHECK("encryption/partial-record-yields",vless_encryption_read(reader,output,sizeof(output),&received) == 1 && !received && transport_position == cut);
        CHECK("encryption/partial-record-does-not-block-upload",vless_encryption_write(eof_writer,(const uint8_t *)"upload",6) == 0);
        memcpy(transport_data,complete_record,whole);
        transport_length=whole; transport_yielding=0;
        CHECK("encryption/fragment-tail-retained",vless_encryption_read(reader,output,sizeof(output),&received) == 0 && received == 1 && output[0] == payload[0]);
        vless_encryption_close(reader);
    }
    vless_encryption_close(eof_writer);
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
        memcpy(writer->prewrite,server_random,16); writer->prewrite_length=writer->prewrite_capacity=16;
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
    transport_length=transport_position=write_count=0;
    const int lengths[14]={4,3},gaps[14]={20,0}; const uint8_t padding_data[]={0,1,2,3,4,5,6};
    REQUIRE("encryption/padding-writes",padding_write(NULL,padding_data,sizeof(padding_data),0,lengths,gaps,2) == 0);
    CHECK("encryption/padding-boundaries",write_count == 2 && transport_length == sizeof(padding_data) && !memcmp(transport_data,padding_data,sizeof(padding_data)));
    CHECK("encryption/padding-gap-enforced",write_times[1]-write_times[0] >= 15);
    return test_result();
}
