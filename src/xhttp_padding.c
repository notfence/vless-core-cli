#include "xhttp_padding.h"
#include "core_random.h"
#include "hpack.h"
#include <errno.h>
#include <string.h>

int core_xhttp_padding(core_range_t range, const char *method, char *output, size_t capacity) {
    if (!output || !capacity || !method || range.min < 0 || range.max < range.min || range.max > 8192) return -1;
    output[0]=0;
    if (!range.max) range=(core_range_t){100,1000};
    uint32_t value;
    if (core_random_range((uint32_t)range.min,(uint32_t)range.max,&value)) return -1;
    size_t target=value;
    if (!strcmp(method,"repeat-x") || !method[0]) {
        if (target >= capacity) return -1;
        memset(output,'X',target); output[target]=0; return 0;
    }
    if (strcmp(method,"tokenish")) return -1;
    const char *alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    size_t written=0,bits=0; unsigned attempts=0;
    while ((bits+7)/8 < target) {
        unsigned char random[128];
        if (core_random_fill(random,sizeof(random))) { output[0]=0; return -1; }
        size_t previous=written;
        for (size_t i=0;i<sizeof(random) && (bits+7)/8 < target;i++) {
            if (random[i] >= 248) continue;
            if (written+1 >= capacity) { output[0]=0; return -1; }
            uint8_t character=(uint8_t)alphabet[random[i]%62]; output[written++]=(char)character;
            bits+=core_hpack_huffman_bits(&character,1);
        }
        if (written != previous) attempts=0;
        else if (++attempts == CORE_RANDOM_MAX_ATTEMPTS) { output[0]=0; errno=EIO; return -1; }
    }
    output[written]=0; return 0;
}
