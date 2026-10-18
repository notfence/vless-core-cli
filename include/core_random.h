#ifndef CORE_RANDOM_H
#define CORE_RANDOM_H
#include <stddef.h>
#include <stdint.h>

#define CORE_RANDOM_MAX_ATTEMPTS 128U

int core_random_fill(void *,size_t);
int core_random_range(uint32_t,uint32_t,uint32_t *);
#endif
