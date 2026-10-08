#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "deadline.h"
#include "socket_util.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>

static uint64_t now;
static uint64_t fake_now(void) { return now; }

static void *drip(void *argument) {
    int fd = *(int *)argument;
    for (int i = 0; i < 8; i++) {
        (void)core_poll(NULL, 0, 20);
        if (core_send(fd, "v", 1, 0) != 1) break;
    }
    return NULL;
}

int main(void) {
    core_deadline_t deadline;
    REQUIRE("deadline/attach", core_deadline_attach(&deadline) == 0);
    deadline.now_ms = fake_now; now = 1000;
    CHECK("deadline/inactive", !core_deadline_active() && core_deadline_limit(-1) == -1);
    core_deadline_begin(100);
    CHECK("deadline/begin", core_deadline_remaining() == 100 && core_deadline_limit(50) == 50);
    now += 40;
    CHECK("deadline/shared-budget", core_deadline_remaining() == 60 && core_deadline_limit(-1) == 60);
    core_deadline_pause(); now += 10000;
    CHECK("deadline/client-wait-paused", !core_deadline_active());
    core_deadline_resume();
    CHECK("deadline/resume-not-reset", core_deadline_remaining() == 60);
    now += 60;
    CHECK("deadline/expired", core_deadline_remaining() == 0 && errno == ETIMEDOUT);
    core_deadline_pause(); now += 1000; core_deadline_resume();
    CHECK("deadline/expired-stays-expired", core_deadline_remaining() == 0);
    core_deadline_scope_t scope;
    REQUIRE("deadline/cleanup-scope", core_deadline_scope_begin(&scope,100) == 0);
    CHECK("deadline/cleanup-has-independent-budget", core_deadline_active() && core_deadline_remaining() > 0 && scope.temporary.now_ms == core_now_ms);
    core_deadline_scope_end(&scope);
    CHECK("deadline/cleanup-does-not-renew-connection", core_deadline_active() && !core_deadline_remaining() && deadline.now_ms == fake_now);
    core_deadline_end(); CHECK("deadline/end", core_deadline_remaining() == INT_MAX);
    deadline.now_ms = core_now_ms;
    int pair[2]; REQUIRE("deadline/drip-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pthread_t thread; REQUIRE("deadline/drip-thread", pthread_create(&thread, NULL, drip, &pair[1]) == 0);
    core_deadline_begin(65); uint64_t started = core_now_ms(); int bytes = 0;
    char byte;
    while (core_recv(pair[0], &byte, 1, 0) == 1) bytes++;
    CHECK("deadline/drip-does-not-renew", errno == ETIMEDOUT && bytes >= 2 && bytes <= 4 && core_now_ms() - started < 150);
    core_deadline_end();
    pthread_join(thread, NULL);
    CHECK("deadline/idle-still-usable", core_recv(pair[0], &byte, 1, 0) == 1);
    close(pair[0]); close(pair[1]); core_deadline_detach();
    REQUIRE("deadline/cleanup-without-connection", core_deadline_scope_begin(&scope,100) == 0);
    CHECK("deadline/temporary-attachment", core_deadline_active()); core_deadline_scope_end(&scope);
    CHECK("deadline/original-attachment-restored", !core_deadline_active());
    return test_result();
}
