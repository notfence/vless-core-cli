#ifndef VLESS_CORE_BLAKE3_H
#define VLESS_CORE_BLAKE3_H

#include <stddef.h>
#include <stdint.h>

void blake3_hash(const uint8_t *input, size_t input_len, uint8_t out[32]);
void blake3_derive_key(const uint8_t *context, size_t context_len,
                       const uint8_t *key_material, size_t key_material_len,
                       uint8_t out[32]);

#endif
