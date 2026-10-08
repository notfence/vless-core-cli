#define _POSIX_C_SOURCE 200809L
#include "deadline.h"
#include "socket_util.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>

static pthread_once_t deadline_once = PTHREAD_ONCE_INIT;
static pthread_key_t deadline_key;
static int deadline_ready;

static void deadline_init(void) { deadline_ready = pthread_key_create(&deadline_key, NULL) == 0; }

static core_deadline_t *deadline_current(void) {
    pthread_once(&deadline_once, deadline_init);
    return deadline_ready ? pthread_getspecific(deadline_key) : NULL;
}

int core_deadline_attach(core_deadline_t *deadline) {
    if (!deadline) return -1;
    pthread_once(&deadline_once, deadline_init);
    if (!deadline_ready) return -1;
    memset(deadline, 0, sizeof(*deadline));
    deadline->now_ms = core_now_ms;
    return pthread_setspecific(deadline_key, deadline) == 0 ? 0 : -1;
}

void core_deadline_detach(void) { if (deadline_ready) pthread_setspecific(deadline_key, NULL); }

void core_deadline_begin(int timeout_ms) {
    core_deadline_t *deadline = deadline_current();
    if (!deadline) return;
    deadline->until_ms = deadline->now_ms() + (unsigned)(timeout_ms > 0 ? timeout_ms : 1);
    deadline->paused_ms = 0;
    deadline->active = 1;
}

void core_deadline_end(void) {
    core_deadline_t *deadline = deadline_current();
    if (deadline) { deadline->active = 0; deadline->paused_ms = 0; }
}

int core_deadline_active(void) { core_deadline_t *deadline = deadline_current(); return deadline && deadline->active; }

int core_deadline_remaining(void) {
    core_deadline_t *deadline = deadline_current();
    if (!deadline || !deadline->active) return INT_MAX;
    uint64_t now = deadline->now_ms();
    if (now >= deadline->until_ms) { errno = ETIMEDOUT; return 0; }
    uint64_t left = deadline->until_ms - now;
    return left > INT_MAX ? INT_MAX : (int)left;
}

int core_deadline_limit(int timeout_ms) {
    if (!core_deadline_active()) return timeout_ms;
    int left = core_deadline_remaining();
    return timeout_ms < 0 || timeout_ms > left ? left : timeout_ms;
}

void core_deadline_pause(void) {
    core_deadline_t *deadline = deadline_current();
    if (deadline && deadline->active) {
        deadline->paused_ms = (uint64_t)core_deadline_remaining() + 1;
        deadline->active = 0;
    }
}

void core_deadline_resume(void) {
    core_deadline_t *deadline = deadline_current();
    if (deadline && deadline->paused_ms) {
        deadline->until_ms = deadline->now_ms() + deadline->paused_ms - 1;
        deadline->paused_ms = 0;
        deadline->active = 1;
    }
}

int core_deadline_scope_begin(core_deadline_scope_t *scope, int timeout_ms) {
    if (!scope) return -1;
    scope->previous=deadline_current();
    if (core_deadline_attach(&scope->temporary) != 0) return -1;
    core_deadline_begin(timeout_ms); return 0;
}

void core_deadline_scope_end(core_deadline_scope_t *scope) {
    if (scope && deadline_ready) pthread_setspecific(deadline_key,scope->previous);
}
