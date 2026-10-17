#include "buffer_budget.h"
#include "relay_memory.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

static pthread_mutex_t buffer_lock=PTHREAD_MUTEX_INITIALIZER;
static size_t charged[CORE_BUFFER_DIRECTIONS], allocated[CORE_BUFFER_DIRECTIONS];

static int claim(core_buffer_budget_t *budget, size_t size) {
    if (!budget || budget->direction >= CORE_BUFFER_DIRECTIONS) { errno=EINVAL; return -1; }
    pthread_mutex_lock(&buffer_lock);
    if (size > SIZE_MAX-budget->allocated) { pthread_mutex_unlock(&buffer_lock); errno=EOVERFLOW; return -1; }
    size_t total=budget->allocated+size;
    size_t increase=total > budget->charged ? total-budget->charged : 0;
    if (increase > CORE_BUFFER_TOTAL_LIMIT-charged[budget->direction]) { pthread_mutex_unlock(&buffer_lock); errno=ENOBUFS; return -1; }
    charged[budget->direction]+=increase; budget->charged+=increase;
    allocated[budget->direction]+=size; budget->allocated=total;
    pthread_mutex_unlock(&buffer_lock); return 0;
}

static void release(core_buffer_budget_t *budget, size_t size) {
    pthread_mutex_lock(&buffer_lock);
    budget->allocated-=size; allocated[budget->direction]-=size;
    size_t remaining=budget->allocated > budget->minimum ? budget->allocated : budget->minimum;
    size_t released=budget->charged-remaining;
    charged[budget->direction]-=budget->charged-remaining; budget->charged=remaining;
    pthread_mutex_unlock(&buffer_lock);
    if (released && budget->direction == CORE_BUFFER_RELAY) core_relay_memory_released();
}

int core_buffer_budget_init(core_buffer_budget_t *budget, unsigned direction, size_t minimum) {
    if (!budget || direction >= CORE_BUFFER_DIRECTIONS || minimum > CORE_BUFFER_TOTAL_LIMIT ||
        ((budget->charged || budget->allocated) && budget->direction != direction)) { errno=EINVAL; return -1; }
    pthread_mutex_lock(&buffer_lock);
    size_t required=minimum > budget->allocated ? minimum : budget->allocated;
    size_t released=required < budget->charged ? budget->charged-required : 0;
    size_t increase=required > budget->charged ? required-budget->charged : 0;
    if (increase > CORE_BUFFER_TOTAL_LIMIT-charged[direction]) { pthread_mutex_unlock(&buffer_lock); errno=ENOBUFS; return -1; }
    charged[direction]+=increase;
    if (required < budget->charged) charged[direction]-=budget->charged-required;
    budget->direction=direction; budget->minimum=minimum; budget->charged=required;
    pthread_mutex_unlock(&buffer_lock);
    if (released && direction == CORE_BUFFER_RELAY) core_relay_memory_released();
    return 0;
}

int core_buffer_budget_clear(core_buffer_budget_t *budget) {
    if (!budget || budget->allocated) { errno=EINVAL; return -1; }
    return core_buffer_budget_init(budget,budget->direction,0);
}

int core_buffer_hold(core_buffer_budget_t *budget, size_t size) { return claim(budget,size); }
void core_buffer_drop(core_buffer_budget_t *budget, size_t size) { release(budget,size); }

void *core_buffer_alloc(core_buffer_budget_t *budget, size_t size) {
    if (!size || claim(budget,size)) return NULL;
    void *data=malloc(size);
    if (!data) release(budget,size);
    return data;
}

void *core_buffer_realloc(core_buffer_budget_t *budget, void *data, size_t previous, size_t size) {
    if (!size) { core_buffer_free(budget,data,previous); return NULL; }
    if (claim(budget,size)) return NULL;
    void *replacement=realloc(data,size);
    if (!replacement) { release(budget,size); return NULL; }
    if (previous) release(budget,previous);
    return replacement;
}

void core_buffer_free(core_buffer_budget_t *budget, void *data, size_t size) {
    if (!data) return;
    free(data); release(budget,size);
}

int core_buffer_transfer(core_buffer_budget_t *from, core_buffer_budget_t *to, size_t size) {
    if (!from || !to || from->direction >= CORE_BUFFER_DIRECTIONS || from->direction != to->direction) { errno=EINVAL; return -1; }
    if (from == to) return 0;
    pthread_mutex_lock(&buffer_lock);
    if (size > from->allocated || size > SIZE_MAX-to->allocated) { pthread_mutex_unlock(&buffer_lock); errno=EINVAL; return -1; }
    size_t source=from->allocated-size;
    if (source < from->minimum) source=from->minimum;
    size_t destination=to->allocated+size;
    if (destination < to->minimum) destination=to->minimum;
    size_t current=from->charged+to->charged;
    size_t future=source+destination;
    if (future > current && future-current > CORE_BUFFER_TOTAL_LIMIT-charged[from->direction]) {
        pthread_mutex_unlock(&buffer_lock); errno=ENOBUFS; return -1;
    }
    charged[from->direction]-=current; charged[from->direction]+=future;
    from->allocated-=size; to->allocated+=size; from->charged=source; to->charged=destination;
    pthread_mutex_unlock(&buffer_lock); return 0;
}

void core_buffer_snapshot(unsigned direction, size_t *bytes, size_t *reserved) {
    pthread_mutex_lock(&buffer_lock);
    if (bytes) *bytes=direction < CORE_BUFFER_DIRECTIONS ? allocated[direction] : 0;
    if (reserved) *reserved=direction < CORE_BUFFER_DIRECTIONS ? charged[direction]-allocated[direction] : 0;
    pthread_mutex_unlock(&buffer_lock);
}

size_t core_buffer_available(unsigned direction) {
    pthread_mutex_lock(&buffer_lock);
    size_t available=direction < CORE_BUFFER_DIRECTIONS ? CORE_BUFFER_TOTAL_LIMIT-charged[direction] : 0;
    pthread_mutex_unlock(&buffer_lock); return available;
}
