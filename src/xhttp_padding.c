#include "xhttp_padding.h"
#include "hpack.h"
#include <openssl/rand.h>
#include <string.h>

int core_xhttp_padding(core_range_t range, const char *method, char *output, size_t capacity) {
    if (!output || !capacity || !method || range.min < 0 || range.max < range.min || range.max > 8192) return -1;
    output[0]=0;
    if (!range.max) range=(core_range_t){100,1000};
    uint32_t span=(uint32_t)(range.max-range.min)+1,threshold=(uint32_t)(-span)%span,value;
    do { if (RAND_bytes((unsigned char *)&value,sizeof(value)) != 1) return -1; } while (value < threshold);
    size_t target=(size_t)range.min+value%span;
    if (!strcmp(method,"repeat-x") || !method[0]) {
        if (target >= capacity) return -1;
        memset(output,'X',target); output[target]=0; return 0;
    }
    if (strcmp(method,"tokenish")) return -1;
    const char *alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    size_t written=0,bits=0;
    while ((bits+7)/8 < target) {
        unsigned char random[128];
        if (RAND_bytes(random,sizeof(random)) != 1) { output[0]=0; return -1; }
        for (size_t i=0;i<sizeof(random) && (bits+7)/8 < target;i++) {
            if (random[i] >= 248) continue;
            if (written+1 >= capacity) { output[0]=0; return -1; }
            uint8_t character=(uint8_t)alphabet[random[i]%62]; output[written++]=(char)character;
            bits+=core_hpack_huffman_bits(&character,1);
        }
    }
    output[written]=0; return 0;
}
