#ifndef CORE_RELAY_MEMORY_H
#define CORE_RELAY_MEMORY_H
#include "buffer_budget.h"
#include <stdint.h>

#define CORE_RELAY_MINIMUM 8192U
#define CORE_RELAY_OUTPUT_LIMIT (256U*1024U)
enum { CORE_RELAY_INPUT_WAIT=1, CORE_RELAY_OUTPUT_WAIT=2 };
typedef struct {
    uint8_t *data;
    size_t length,capacity,minimum,limit;
    core_buffer_budget_t *memory;
} core_relay_buffer_t;
typedef struct core_relay_memory {
    core_buffer_budget_t upload,download,temporary;
    core_relay_buffer_t input,output,wrapped,plain,packet;
    int notify[2],initialized,registered,notified;
    unsigned waiting;
    struct core_relay_memory *next;
} core_relay_memory_t;
size_t core_relay_capacity(size_t);
int core_relay_buffer_reserve(core_relay_buffer_t *,size_t);
int core_relay_buffer_append(core_relay_buffer_t *,const void *,size_t);
void core_relay_buffer_consume(core_relay_buffer_t *,size_t);
int core_relay_buffer_trim(core_relay_buffer_t *);
void core_relay_buffer_clear(core_relay_buffer_t *);
int core_relay_memory_init(core_relay_memory_t *,size_t);
void core_relay_memory_clear(core_relay_memory_t *);
int core_relay_memory_credit(core_relay_memory_t *,size_t);
int core_relay_memory_watch(core_relay_memory_t *,unsigned);
void core_relay_memory_unwatch(core_relay_memory_t *,unsigned);
unsigned core_relay_memory_ack(core_relay_memory_t *);
int core_relay_memory_fd(const core_relay_memory_t *);
void core_relay_memory_released(void);
#endif
