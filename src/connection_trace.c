#define _POSIX_C_SOURCE 200809L
#include "connection_trace.h"
#include "core_log.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

static pthread_once_t trace_once = PTHREAD_ONCE_INIT;
static pthread_key_t trace_key;
static int trace_key_ready;
static pthread_mutex_t trace_id_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t trace_next_id;

static void trace_key_init(void) {
    trace_key_ready = pthread_key_create(&trace_key, NULL) == 0;
}

static core_connection_trace_t *trace_current(void) {
    pthread_once(&trace_once, trace_key_init);
    return trace_key_ready ? pthread_getspecific(trace_key) : NULL;
}

static uint64_t trace_now_ms(void) {
#ifdef __APPLE__
    mach_timebase_info_data_t scale;
    if (mach_timebase_info(&scale) != KERN_SUCCESS || scale.denom == 0) return 0;
    return (uint64_t)((double)mach_absolute_time() * scale.numer / scale.denom / 1000000.0);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

int core_trace_attach(core_connection_trace_t *trace) {
    if (!trace) return -1;
    int saved_errno = errno;
    pthread_once(&trace_once, trace_key_init);
    if (!trace_key_ready) return -1;
    memset(trace, 0, sizeof(*trace));
    trace->stage = CORE_TRACE_NONE;
    trace->failed_stage = CORE_TRACE_NONE;
    trace->now_ms = trace_now_ms;
    for (size_t i = 0; i < CORE_TRACE_STAGE_COUNT; i++) trace->durations[i] = -1;
    pthread_mutex_lock(&trace_id_lock);
    trace->id = ++trace_next_id;
    pthread_mutex_unlock(&trace_id_lock);
    int result = pthread_setspecific(trace_key, trace);
    errno = saved_errno;
    return result == 0 ? 0 : -1;
}

void core_trace_detach(void) {
    int saved_errno = errno;
    if (trace_current()) pthread_setspecific(trace_key, NULL);
    errno = saved_errno;
}

int core_trace_snapshot(core_connection_trace_t *trace) {
    core_connection_trace_t *current=trace_current();
    if (!current || !trace) return 0;
    *trace=*current; return 1;
}

int core_trace_bind(core_connection_trace_t *trace) {
    pthread_once(&trace_once,trace_key_init);
    return trace_key_ready && trace && pthread_setspecific(trace_key,trace) == 0 ? 0 : -1;
}

void core_trace_restore(const core_connection_trace_t *trace) {
    core_connection_trace_t *current=trace_current();
    if (current && trace) {
        void (*observer)(core_trace_stage_t,void *)=current->stage_observer;
        void *context=current->observer_context;
        *current=*trace; current->stage_observer=observer; current->observer_context=context;
    }
}

void core_trace_observe(void (*observer)(core_trace_stage_t, void *), void *context) {
    int saved=errno; core_connection_trace_t *trace=trace_current();
    if (trace) { trace->stage_observer=observer; trace->observer_context=context; }
    errno=saved;
}

static void trace_charge(core_connection_trace_t *trace, uint64_t now) {
    if (trace->started && trace->stage >= 0 && trace->stage < CORE_TRACE_STAGE_COUNT) {
        uint64_t elapsed = now >= trace->entered_ms ? now - trace->entered_ms : 0;
        if (elapsed > INT64_MAX - (uint64_t)trace->durations[trace->stage])
            trace->durations[trace->stage] = INT64_MAX;
        else trace->durations[trace->stage] += (int64_t)elapsed;
    }
}

void core_trace_stage(core_trace_stage_t stage) {
    int saved_errno = errno;
    core_connection_trace_t *trace = trace_current();
    if (trace && !trace->finished && stage >= 0 && stage < CORE_TRACE_STAGE_COUNT && trace->stage != stage) {
        uint64_t now = trace->now_ms();
        trace_charge(trace, now);
        if (!trace->started) {
            trace->started = 1;
            trace->started_ms = now;
        }
        trace->stage = stage;
        trace->entered_ms = now;
        if (trace->durations[stage] < 0) trace->durations[stage] = 0;
        if (trace->stage_observer) trace->stage_observer(stage,trace->observer_context);
    }
    errno = saved_errno;
}

void core_trace_failure(core_trace_stage_t stage) {
    int saved_errno = errno;
    core_connection_trace_t *trace = trace_current();
    if (trace && !trace->finished && stage >= 0 && stage < CORE_TRACE_STAGE_COUNT) {
        trace->failed_stage = trace->error.kind ? trace->error.stage : stage;
        if (trace->stage_observer) trace->stage_observer(stage,trace->observer_context);
    }
    errno = saved_errno;
}

core_connection_error_t core_connection_error(core_trace_stage_t stage, core_failure_kind_t kind, int system_error) {
    if (system_error == ETIMEDOUT) kind=CORE_FAILURE_DEADLINE;
    else if (system_error == ENOMEM || system_error == ENOBUFS || system_error == EMFILE || system_error == ENFILE) kind=CORE_FAILURE_RESOURCE;
    return (core_connection_error_t){stage,kind,system_error};
}

void core_trace_error_set(core_connection_error_t error) {
    int saved=errno; core_connection_trace_t *trace=trace_current();
    if (trace && !trace->finished && error.kind && error.stage >= 0 && error.stage < CORE_TRACE_STAGE_COUNT) {
        trace->error=error; trace->failed_stage=error.stage;
        if (trace->stage_observer) trace->stage_observer(error.stage,trace->observer_context);
    }
    errno=saved;
}

int core_trace_error_get(core_connection_error_t *error) {
    int saved=errno; core_connection_trace_t *trace=trace_current();
    if (error) *error=trace ? trace->error : (core_connection_error_t){.stage=CORE_TRACE_NONE};
    errno=saved; return error && error->kind;
}

void core_trace_error_clear(void) {
    int saved=errno; core_connection_trace_t *trace=trace_current();
    if (trace && !trace->finished) { trace->error=(core_connection_error_t){.stage=CORE_TRACE_NONE}; trace->failed_stage=CORE_TRACE_NONE; }
    errno=saved;
}

uint64_t core_trace_id(void) {
    int saved=errno; core_connection_trace_t *trace=trace_current(); uint64_t id=trace ? trace->id : 0;
    errno=saved; return id;
}

const char *core_failure_name(core_failure_kind_t kind) {
    static const char *const names[]={"none","system","tls","protocol","eof","deadline","resource"};
    return kind >= CORE_FAILURE_NONE && kind <= CORE_FAILURE_RESOURCE ? names[kind] : "none";
}

const char *core_trace_stage_name(core_trace_stage_t stage) {
    static const char *const names[] = {"dns", "tcp", "transport", "protocol", "carry"};
    return stage >= 0 && stage < CORE_TRACE_STAGE_COUNT ? names[stage] : "none";
}

int core_trace_format(const core_connection_trace_t *trace, char *out, size_t capacity) {
    if (!trace || !trace->finished || !out || capacity == 0) return -1;
    int length = snprintf(out, capacity,
        "v=1 id=%llu success=%d stage=%s dns_ms=%lld tcp_ms=%lld transport_ms=%lld protocol_ms=%lld carry_ms=%lld total_ms=%llu",
        (unsigned long long)trace->id, trace->success, core_trace_stage_name(trace->failed_stage),
        (long long)trace->durations[0], (long long)trace->durations[1], (long long)trace->durations[2],
        (long long)trace->durations[3], (long long)trace->durations[4], (unsigned long long)trace->total_ms);
    return length >= 0 && (size_t)length < capacity ? length : -1;
}

void core_trace_complete(int success) {
    int saved_errno = errno;
    core_connection_trace_t *trace = trace_current();
    if (trace && trace->started && !trace->finished) {
        uint64_t now = trace->now_ms();
        trace_charge(trace, now);
        trace->total_ms = now >= trace->started_ms ? now - trace->started_ms : 0;
        trace->success = success != 0;
        trace->finished = 1;
        if (success) { trace->failed_stage = CORE_TRACE_NONE; trace->error=(core_connection_error_t){.stage=CORE_TRACE_NONE}; }
        else if (trace->failed_stage == CORE_TRACE_NONE) trace->failed_stage = trace->stage;
        char text[384];
        if (core_trace_format(trace, text, sizeof(text)) >= 0) {
            if (success) vc_log_info("probe", "%s", text);
            else vc_log_warning("probe", "%s", text);
        }
    }
    errno = saved_errno;
}
