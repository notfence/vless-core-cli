#ifndef V2RAYIOS6_UTILS_H
#define V2RAYIOS6_UTILS_H

#include <stddef.h>
#include <stdint.h>

int parse_uuid(const char *s, uint8_t out[16]);
int hex_to_bytes(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);
int base64url_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);
int percent_decode(const char *in, char *out, size_t out_cap);

#endif
