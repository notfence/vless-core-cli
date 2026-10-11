#define _POSIX_C_SOURCE 200809L
#include "../src/vless_encryption.c"

static const uint8_t *fuzz_input;
static size_t fuzz_length,fuzz_offset;
static uint8_t fuzz_output[65536];
static size_t fuzz_output_length;
static unsigned fuzz_reads;
int tls13_has_pending_input(const tls13_conn_t *transport) { (void)transport; return 0; }
int tls13_get_fd(const tls13_conn_t *transport) { (void)transport; return -1; }

int tls13_write_app(tls13_conn_t *transport, const uint8_t *data, size_t length) {
    (void)transport;
    if (length > sizeof(fuzz_output)-fuzz_output_length) return -1;
    memcpy(fuzz_output+fuzz_output_length,data,length); fuzz_output_length+=length;
    return 0;
}

int tls13_read_app(tls13_conn_t *transport, uint8_t *data, size_t capacity, size_t *length) {
    (void)transport;
    if (++fuzz_reads%3 == 0) { *length=0; return 1; }
    size_t available=fuzz_length-fuzz_offset,take=available < capacity ? available : capacity;
    if (take > 7) take=7;
    if (take) memcpy(data,fuzz_input+fuzz_offset,take);
    fuzz_offset+=take; *length=take; return 0;
}

int tls13_read_exact_app(tls13_conn_t *transport, uint8_t *data, size_t length) {
    size_t offset=0;
    while (offset < length) {
        size_t received=0;
        if (tls13_read_app(transport,data+offset,length-offset,&received) || !received) return -1;
        offset+=received;
    }
    return 0;
}
int tls13_read_exact_or_eof(tls13_conn_t *transport, uint8_t *data, size_t length) {
    if (fuzz_offset == fuzz_length) return 1;
    return tls13_read_exact_app(transport,data,length);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length) {
    if (!length || length > 4096) return 0;
    vless_encryption_conn_t *reader=calloc(1,sizeof(*reader)),*writer=calloc(1,sizeof(*writer));
    if (!reader || !writer) abort();
    uint8_t context[16]={0},key[96]={0};
    aead_init(&reader->incoming,context,sizeof(context),key,sizeof(key));
    memcpy(reader->united_key,key,sizeof(key)); reader->united_key_len=sizeof(key);
    reader->incoming_deferred=(data[0]&1) != 0;
    if (data[0]&4) {
        if (aes_ctr_init(&reader->outgoing_header_ctr,key,sizeof(key),context)) abort();
        if (!reader->incoming_deferred && aes_ctr_init(&reader->incoming_header_ctr,key,sizeof(key),context)) abort();
    }
    fuzz_input=data; fuzz_length=length; fuzz_offset=0; fuzz_output_length=0; fuzz_reads=0;
    if (data[0]&2) {
        aead_init(&writer->outgoing,context,sizeof(context),key,sizeof(key));
        if (data[0]&4 && aes_ctr_init(&writer->outgoing_header_ctr,key,sizeof(key),context)) abort();
        if (reader->incoming_deferred) {
            writer->prewrite=calloc(1,sizeof(context)); writer->prewrite_length=sizeof(context);
            if (!writer->prewrite) abort();
        }
        if (vless_encryption_write(writer,data,length)) abort();
        if (data[0]&8) fuzz_output[length%fuzz_output_length]^=data[length-1];
        fuzz_input=fuzz_output; fuzz_length=fuzz_output_length;
    }
    uint8_t output[127];
    for (size_t i=0;i<length+32;i++) {
        size_t received=0;
        int result=vless_encryption_read(reader,output,sizeof(output),&received);
        if (result > 0) continue;
        if (result < 0 || !received) break;
        if (received > sizeof(output)) abort();
    }
    vless_encryption_close(reader); vless_encryption_close(writer);
    return 0;
}
