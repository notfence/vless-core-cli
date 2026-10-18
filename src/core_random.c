#include "core_random.h"
#include "deadline.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

int core_random_fill(void *output,size_t length) {
    if (!length) return 0;
    if (!output || length > INT_MAX) { errno=EINVAL; return -1; }
    if (core_deadline_active() && !core_deadline_remaining()) return -1;
    if (RAND_bytes(output,(int)length) == 1) return 0;
    OPENSSL_cleanse(output,length); errno=EIO; return -1;
}

int core_random_range(uint32_t min,uint32_t max,uint32_t *sampled) {
    if (!sampled || max < min) { errno=EINVAL; return -1; }
    uint32_t span=max-min+1,threshold=span ? (uint32_t)(-span)%span : 0,value=0;
    for (unsigned attempt=0;attempt<CORE_RANDOM_MAX_ATTEMPTS;attempt++) {
        if (core_random_fill(&value,sizeof(value))) { int cause=errno; OPENSSL_cleanse(&value,sizeof(value)); errno=cause; return -1; }
        if (value < threshold) continue;
        *sampled=min+(span ? value%span : value); OPENSSL_cleanse(&value,sizeof(value)); return 0;
    }
    OPENSSL_cleanse(&value,sizeof(value)); errno=EIO; return -1;
}
