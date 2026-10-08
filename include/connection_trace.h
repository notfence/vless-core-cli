#ifndef CORE_CONNECTION_TRACE_H
#define CORE_CONNECTION_TRACE_H
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CORE_TRACE_NONE = -1,
    CORE_TRACE_DNS,
    CORE_TRACE_TCP,
    CORE_TRACE_TRANSPORT,
    CORE_TRACE_PROTOCOL,
    CORE_TRACE_CARRY,
    CORE_TRACE_STAGE_COUNT
} core_trace_stage_t;

typedef struct {
    uint64_t id;
    uint64_t started_ms;
    uint64_t entered_ms;
    uint64_t total_ms;
    int64_t durations[CORE_TRACE_STAGE_COUNT];
    core_trace_stage_t stage;
    core_trace_stage_t failed_stage;
    uint64_t (*now_ms)(void);
    void (*stage_observer)(core_trace_stage_t, void *);
    void *observer_context;
    int started;
    int finished;
    int success;
} core_connection_trace_t;

int core_trace_attach(core_connection_trace_t *trace);
int core_trace_snapshot(core_connection_trace_t *trace);
int core_trace_bind(core_connection_trace_t *trace);
void core_trace_restore(const core_connection_trace_t *trace);
void core_trace_observe(void (*observer)(core_trace_stage_t, void *), void *context);
void core_trace_detach(void);
void core_trace_stage(core_trace_stage_t stage);
void core_trace_failure(core_trace_stage_t stage);
void core_trace_complete(int success);
const char *core_trace_stage_name(core_trace_stage_t stage);
int core_trace_format(const core_connection_trace_t *trace, char *out, size_t capacity);
#endif
