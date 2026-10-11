#ifndef CORE_GRPC_H
#define CORE_GRPC_H
#include "types.h"
typedef struct {
    uint8_t header[5];
    unsigned header_used, phase, wire, field, shift, found, failed;
    uint64_t varint;
    size_t remaining, field_remaining;
} core_grpc_decoder_t;
int core_grpc_parameter(vless_config_t *, const char *, const char *, char *, size_t);
int core_grpc_decode(core_grpc_decoder_t *, const uint8_t *, size_t, size_t *, const uint8_t **, size_t *);
int core_grpc_complete(const core_grpc_decoder_t *);
#endif
