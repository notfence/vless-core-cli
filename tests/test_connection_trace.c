#include "connection_trace.h"
#include "check.h"
#include <errno.h>
#include <pthread.h>

static uint64_t ticks;
static uint64_t fake_clock(void) { return ticks; }

static void *parallel_trace(void *opaque) {
    core_connection_trace_t *trace = opaque;
    if (core_trace_attach(trace) != 0) return (void *)1;
    core_trace_stage(CORE_TRACE_TCP);
    core_trace_stage(CORE_TRACE_TRANSPORT);
    core_trace_stage(CORE_TRACE_PROTOCOL);
    core_trace_stage(CORE_TRACE_CARRY);
    core_trace_complete(1);
    core_trace_detach();
    return NULL;
}

int main(void) {
    core_connection_trace_t trace;
    char text[384];
    errno = ENOTTY;
    REQUIRE("trace/attach", core_trace_attach(&trace) == 0);
    CHECK("trace/attach-preserves-errno", errno == ENOTTY);
    trace.now_ms = fake_clock;
    ticks = 100;
    core_trace_stage(CORE_TRACE_DNS);
    ticks = 130; core_trace_stage(CORE_TRACE_TCP);
    ticks = 170; core_trace_stage(CORE_TRACE_TRANSPORT);
    ticks = 220; core_trace_stage(CORE_TRACE_PROTOCOL);
    ticks = 280; core_trace_stage(CORE_TRACE_CARRY);
    ticks = 350; core_trace_complete(1);
    CHECK("trace/real-stage-durations", trace.durations[0] == 30 && trace.durations[1] == 40 && trace.durations[2] == 50 && trace.durations[3] == 60 && trace.durations[4] == 70 && trace.total_ms == 250);
    CHECK("trace/success-has-no-failed-stage", trace.success && trace.finished && trace.failed_stage == CORE_TRACE_NONE);
    CHECK("trace/operations-preserve-errno", errno == ENOTTY);
    REQUIRE("trace/format", core_trace_format(&trace,text,sizeof(text)) > 0);
    CHECK("trace/stable-machine-report", strstr(text,"v=1 id=") == text && strstr(text,"success=1 stage=none dns_ms=30 tcp_ms=40 transport_ms=50 protocol_ms=60 carry_ms=70 total_ms=250"));
    ticks = 1000; core_trace_stage(CORE_TRACE_DNS); core_trace_failure(CORE_TRACE_TCP); core_trace_complete(0);
    CHECK("trace/completion-is-once", trace.total_ms == 250 && trace.success && trace.failed_stage == CORE_TRACE_NONE);
    CHECK("trace/short-report-buffer", core_trace_format(&trace,text,2) < 0 && text[1] == '\0');
    CHECK("trace/null-report-rejected", core_trace_format(NULL,text,sizeof(text)) < 0 && core_trace_format(&trace,NULL,0) < 0);
    core_trace_detach();
    for (int stage = 0; stage < CORE_TRACE_STAGE_COUNT; stage++) {
        REQUIRE("trace/failure-attach", core_trace_attach(&trace) == 0);
        trace.now_ms = fake_clock;
        ticks = 100; core_trace_stage((core_trace_stage_t)stage);
        ticks = 150; core_trace_complete(0);
        CHECK("trace/failure-reports-current-stage", !trace.success && trace.failed_stage == stage && trace.durations[stage] == 50);
        for (int other = 0; other < CORE_TRACE_STAGE_COUNT; other++)
            if (other != stage) CHECK("trace/unattempted-stage-is-not-measured", trace.durations[other] == -1);
        core_trace_detach();
    }
    REQUIRE("trace/retry-attach", core_trace_attach(&trace) == 0);
    trace.now_ms = fake_clock;
    ticks = 0; core_trace_stage(CORE_TRACE_TCP);
    ticks = 10; core_trace_stage(CORE_TRACE_TRANSPORT);
    ticks = 30; core_trace_stage(CORE_TRACE_TCP);
    ticks = 45; core_trace_stage(CORE_TRACE_TRANSPORT);
    ticks = 70; core_trace_failure(CORE_TRACE_TRANSPORT); core_trace_complete(0);
    CHECK("trace/retries-accumulate-without-reset", trace.durations[CORE_TRACE_TCP] == 25 && trace.durations[CORE_TRACE_TRANSPORT] == 45 && trace.total_ms == 70);
    core_trace_detach();
    REQUIRE("trace/idle-attach", core_trace_attach(&trace) == 0);
    core_trace_complete(0);
    CHECK("trace/listener-check-is-not-a-probe", !trace.started && !trace.finished && core_trace_format(&trace,text,sizeof(text)) < 0);
    core_trace_detach();
    core_connection_trace_t parallel[8];
    pthread_t threads[8];
    for (size_t i = 0; i < 8; i++) REQUIRE("trace/parallel-start", pthread_create(&threads[i],NULL,parallel_trace,&parallel[i]) == 0);
    for (size_t i = 0; i < 8; i++) {
        void *result = (void *)1;
        REQUIRE("trace/parallel-join", pthread_join(threads[i],&result) == 0 && result == NULL);
        CHECK("trace/parallel-states-are-independent", parallel[i].success && parallel[i].finished && parallel[i].durations[CORE_TRACE_DNS] == -1);
        for (size_t other = 0; other < i; other++) CHECK("trace/unique-connection-identifiers", parallel[i].id != parallel[other].id);
    }
    return test_result();
}
