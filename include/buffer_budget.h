#ifndef CORE_BUFFER_BUDGET_H
#define CORE_BUFFER_BUDGET_H
#include <stddef.h>

#define CORE_BUFFER_TOTAL_LIMIT (16U*1024U*1024U)
#define CORE_BUFFER_PROTOCOL_RESERVE (192U*1024U)
#define CORE_BUFFER_OUTPUT_RESERVE (256U*1024U)
#define CORE_BUFFER_REQUEST_RESERVE (512U*1024U)
enum { CORE_BUFFER_UPLOAD, CORE_BUFFER_DOWNLOAD, CORE_BUFFER_RELAY, CORE_BUFFER_DIRECTIONS };
typedef struct {
    size_t minimum, allocated, charged;
    unsigned direction;
} core_buffer_budget_t;
typedef struct core_buffer_waiter {
    struct core_buffer_waiter *next;
    int fd,registered;
    unsigned directions;
} core_buffer_waiter_t;
void core_buffer_watch(core_buffer_waiter_t *,int,unsigned);
void core_buffer_unwatch(core_buffer_waiter_t *);
int core_buffer_budget_init(core_buffer_budget_t *, unsigned, size_t);
int core_buffer_budget_clear(core_buffer_budget_t *);
int core_buffer_hold(core_buffer_budget_t *, size_t);
void core_buffer_drop(core_buffer_budget_t *, size_t);
void *core_buffer_alloc(core_buffer_budget_t *, size_t);
void *core_buffer_realloc(core_buffer_budget_t *, void *, size_t, size_t);
void core_buffer_free(core_buffer_budget_t *, void *, size_t);
int core_buffer_transfer(core_buffer_budget_t *, core_buffer_budget_t *, size_t);
void core_buffer_snapshot(unsigned, size_t *, size_t *);
size_t core_buffer_available(unsigned);
#endif
