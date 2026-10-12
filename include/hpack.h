#ifndef CORE_HPACK_H
#define CORE_HPACK_H
#include <stddef.h>
#include <stdint.h>

#define CORE_HPACK_TABLE_LIMIT 4096
#define CORE_HPACK_HEADER_LIMIT 65536

typedef struct { char *name; char *value; size_t size, name_length, value_length; } core_hpack_entry_t;
typedef struct {
    core_hpack_entry_t entries[128];
    size_t count, size, maximum;
    int initialized;
} core_hpack_decoder_t;
typedef struct {
    int status;
    int grpc_status;
    int has_grpc_status;
    size_t decoded_size;
    unsigned regular_seen, other_pseudo, status_seen, has_content_length, has_te;
    uint64_t content_length;
} core_hpack_headers_t;

void core_hpack_init(core_hpack_decoder_t *decoder);
void core_hpack_clear(core_hpack_decoder_t *decoder);
int core_hpack_decode(core_hpack_decoder_t *decoder, const uint8_t *block, size_t length, core_hpack_headers_t *headers);
int core_hpack_status(const uint8_t *block, size_t length);
int core_hpack_decode_int(const uint8_t *, size_t, size_t *, uint8_t, uint32_t *);
int core_hpack_decode_huffman(const uint8_t *, size_t, char *, size_t, size_t *);
size_t core_hpack_huffman_bits(const uint8_t *, size_t);
int core_hpack_read_string(const uint8_t *, size_t, size_t *, char *, size_t, size_t *);
#endif
