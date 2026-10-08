#ifndef CORE_DEADLINE_H
#define CORE_DEADLINE_H
#include <stdint.h>

typedef struct {
    uint64_t until_ms;
    uint64_t paused_ms;
    uint64_t (*now_ms)(void);
    int active;
} core_deadline_t;

typedef struct {
    core_deadline_t temporary;
    core_deadline_t *previous;
} core_deadline_scope_t;

int core_deadline_attach(core_deadline_t *deadline);
void core_deadline_detach(void);
void core_deadline_begin(int timeout_ms);
void core_deadline_end(void);
int core_deadline_active(void);
int core_deadline_remaining(void);
int core_deadline_limit(int timeout_ms);
void core_deadline_pause(void);
void core_deadline_resume(void);
int core_deadline_scope_begin(core_deadline_scope_t *, int);
void core_deadline_scope_end(core_deadline_scope_t *);
#endif
