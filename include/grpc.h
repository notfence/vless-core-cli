#ifndef CORE_GRPC_H
#define CORE_GRPC_H
#include "types.h"
#include "hpack.h"
typedef struct core_grpc_chunk core_grpc_chunk_t;
typedef struct {
    uint8_t header[5];
    unsigned header_used, phase, wire, field, shift, failed;
    uint64_t varint;
    size_t remaining, field_remaining;
    size_t reserved;
    core_grpc_chunk_t *head, *tail;
    unsigned multi, ready, depth;
    uint32_t groups[64];
} core_grpc_decoder_t;
int core_grpc_parameter(vless_config_t *, const char *, const char *, char *, size_t);
int core_grpc_decode(core_grpc_decoder_t *, const uint8_t *, size_t, size_t *, const uint8_t **, size_t *);
int core_grpc_complete(const core_grpc_decoder_t *);
int core_grpc_pending(const core_grpc_decoder_t *);
int core_grpc_read(core_grpc_decoder_t *, uint8_t *, size_t, size_t *);
void core_grpc_clear(core_grpc_decoder_t *);
int core_grpc_content_type(const char *, size_t);
int core_grpc_response_headers(const core_hpack_headers_t *, int, int, char *, size_t);
#endif
