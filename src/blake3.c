#include "blake3.h"

#include <string.h>

#define B3_CHUNK_START 1U
#define B3_CHUNK_END 2U
#define B3_PARENT 4U
#define B3_ROOT 8U
#define B3_DERIVE_KEY_CONTEXT 32U
#define B3_DERIVE_KEY_MATERIAL 64U

static const uint32_t b3_iv[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
};

static const uint8_t b3_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

typedef struct {
    uint32_t input_cv[8];
    uint32_t block[16];
    uint64_t counter;
    uint32_t block_len;
    uint32_t flags;
} b3_output_t;

static uint32_t b3_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void b3_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t b3_rotr32(uint32_t v, unsigned n) {
    return (v >> n) | (v << (32U - n));
}

static void b3_g(uint32_t state[16], int a, int b, int c, int d,
                 uint32_t x, uint32_t y) {
    state[a] = state[a] + state[b] + x;
    state[d] = b3_rotr32(state[d] ^ state[a], 16);
    state[c] += state[d];
    state[b] = b3_rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + y;
    state[d] = b3_rotr32(state[d] ^ state[a], 8);
    state[c] += state[d];
    state[b] = b3_rotr32(state[b] ^ state[c], 7);
}

static void b3_compress(const uint32_t cv[8], const uint32_t block[16],
                        uint64_t counter, uint32_t block_len, uint32_t flags,
                        uint32_t out[16]) {
    uint32_t state[16];
    memcpy(state, cv, 8 * sizeof(uint32_t));
    memcpy(state + 8, b3_iv, 4 * sizeof(uint32_t));
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = flags;

    for (int round = 0; round < 7; round++) {
        const uint8_t *s = b3_schedule[round];
        b3_g(state, 0, 4, 8, 12, block[s[0]], block[s[1]]);
        b3_g(state, 1, 5, 9, 13, block[s[2]], block[s[3]]);
        b3_g(state, 2, 6, 10, 14, block[s[4]], block[s[5]]);
        b3_g(state, 3, 7, 11, 15, block[s[6]], block[s[7]]);
        b3_g(state, 0, 5, 10, 15, block[s[8]], block[s[9]]);
        b3_g(state, 1, 6, 11, 12, block[s[10]], block[s[11]]);
        b3_g(state, 2, 7, 8, 13, block[s[12]], block[s[13]]);
        b3_g(state, 3, 4, 9, 14, block[s[14]], block[s[15]]);
    }

    for (int i = 0; i < 8; i++) {
        out[i] = state[i] ^ state[i + 8];
        out[i + 8] = state[i + 8] ^ cv[i];
    }
}

static void b3_output_cv(const b3_output_t *output, uint32_t cv[8]) {
    uint32_t words[16];
    b3_compress(output->input_cv, output->block, output->counter,
                output->block_len, output->flags, words);
    memcpy(cv, words, 8 * sizeof(uint32_t));
}

static void b3_output_root(const b3_output_t *output, uint8_t out[32]) {
    uint32_t words[16];
    b3_compress(output->input_cv, output->block, 0, output->block_len,
                output->flags | B3_ROOT, words);
    for (int i = 0; i < 8; i++) {
        b3_store32(out + i * 4, words[i]);
    }
}

static void b3_load_block(const uint8_t *input, size_t input_len,
                          uint32_t block[16]) {
    uint8_t bytes[64] = {0};
    if (input_len > 0) {
        memcpy(bytes, input, input_len);
    }
    for (int i = 0; i < 16; i++) {
        block[i] = b3_load32(bytes + i * 4);
    }
}

static b3_output_t b3_chunk_output(const uint8_t *input, size_t input_len,
                                   uint64_t chunk_counter,
                                   const uint32_t key[8], uint32_t flags) {
    uint32_t cv[8];
    memcpy(cv, key, sizeof(cv));

    size_t blocks = input_len == 0 ? 1 : (input_len + 63) / 64;
    for (size_t i = 0; i + 1 < blocks; i++) {
        uint32_t block[16];
        uint32_t words[16];
        b3_load_block(input + i * 64, 64, block);
        b3_compress(cv, block, chunk_counter, 64,
                    flags | (i == 0 ? B3_CHUNK_START : 0), words);
        memcpy(cv, words, sizeof(cv));
    }

    size_t last_off = (blocks - 1) * 64;
    size_t last_len = input_len > last_off ? input_len - last_off : 0;
    b3_output_t output;
    memcpy(output.input_cv, cv, sizeof(cv));
    b3_load_block(input + last_off, last_len, output.block);
    output.counter = chunk_counter;
    output.block_len = (uint32_t)last_len;
    output.flags = flags | B3_CHUNK_END |
                   (blocks == 1 ? B3_CHUNK_START : 0);
    return output;
}

static b3_output_t b3_parent_output(const uint32_t left[8],
                                    const uint32_t right[8],
                                    const uint32_t key[8], uint32_t flags) {
    b3_output_t output;
    memcpy(output.input_cv, key, 8 * sizeof(uint32_t));
    memcpy(output.block, left, 8 * sizeof(uint32_t));
    memcpy(output.block + 8, right, 8 * sizeof(uint32_t));
    output.counter = 0;
    output.block_len = 64;
    output.flags = flags | B3_PARENT;
    return output;
}

static void b3_hash_internal(const uint8_t *input, size_t input_len,
                             const uint32_t key[8], uint32_t flags,
                             uint8_t out[32]) {
    uint32_t cv_stack[54][8];
    size_t stack_len = 0;
    uint64_t chunk_count = input_len == 0 ? 1 : (input_len + 1023) / 1024;

    for (uint64_t chunk = 0; chunk + 1 < chunk_count; chunk++) {
        b3_output_t chunk_out =
            b3_chunk_output(input + chunk * 1024, 1024, chunk, key, flags);
        uint32_t cv[8];
        b3_output_cv(&chunk_out, cv);
        uint64_t total_chunks = chunk + 1;
        while ((total_chunks & 1U) == 0U) {
            b3_output_t parent =
                b3_parent_output(cv_stack[--stack_len], cv, key, flags);
            b3_output_cv(&parent, cv);
            total_chunks >>= 1;
        }
        memcpy(cv_stack[stack_len++], cv, sizeof(cv));
    }

    uint64_t last_chunk = chunk_count - 1;
    size_t last_off = (size_t)last_chunk * 1024;
    size_t last_len = input_len > last_off ? input_len - last_off : 0;
    b3_output_t output =
        b3_chunk_output(input + last_off, last_len, last_chunk, key, flags);

    while (stack_len > 0) {
        uint32_t right[8];
        b3_output_cv(&output, right);
        output = b3_parent_output(cv_stack[--stack_len], right, key, flags);
    }
    b3_output_root(&output, out);
}

void blake3_hash(const uint8_t *input, size_t input_len, uint8_t out[32]) {
    b3_hash_internal(input, input_len, b3_iv, 0, out);
}

void blake3_derive_key(const uint8_t *context, size_t context_len,
                       const uint8_t *key_material, size_t key_material_len,
                       uint8_t out[32]) {
    uint8_t context_key[32];
    uint32_t context_words[8];
    b3_hash_internal(context, context_len, b3_iv, B3_DERIVE_KEY_CONTEXT,
                     context_key);
    for (int i = 0; i < 8; i++) {
        context_words[i] = b3_load32(context_key + i * 4);
    }
    b3_hash_internal(key_material, key_material_len, context_words,
                     B3_DERIVE_KEY_MATERIAL, out);
}
