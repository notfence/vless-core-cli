#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "deadline.h"
#include "socket_util.h"
#include <errno.h>
#include <limits.h>
#include <unistd.h>

static uint64_t now;
static uint64_t fake_now(void) { return now; }

static int drip_fd=-1,interrupts;
static uint64_t ready_at;
int __real_poll(struct pollfd *,nfds_t,int);
ssize_t __real_recv(int,void *,size_t,int);
int __wrap_poll(struct pollfd *fds,nfds_t count,int timeout) {
    if (count != 1 || fds[0].fd != drip_fd) return __real_poll(fds,count,timeout);
    CHECK("deadline/poll-keeps-remaining-budget",timeout >= 0 && timeout <= core_deadline_remaining());
    if (interrupts) { interrupts--; now+=5; errno=EINTR; return -1; }
    fds[0].revents=0;
    if ((uint64_t)timeout < ready_at-now) { now+=(unsigned)timeout; return 0; }
    now=ready_at; fds[0].revents=POLLIN; return 1;
}
ssize_t __wrap_recv(int fd,void *data,size_t length,int flags) {
    if (fd != drip_fd) return __real_recv(fd,data,length,flags);
    if (!length) return 0;
    if (now < ready_at) {
        if (flags&MSG_DONTWAIT) { errno=EAGAIN; return -1; }
        now=ready_at;
    }
    ((char *)data)[0]='v'; ready_at+=20; return 1;
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
    for (unsigned late=0;late<2;late++) for (unsigned interrupted=0;interrupted<2;interrupted++) {
        int pair[2]; REQUIRE("deadline/drip-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        now=1000; ready_at=now+(late ? 100 : 20); drip_fd=pair[0]; interrupts=interrupted ? 2 : 0;
        core_deadline_begin(65); int bytes=0; char byte;
        while (bytes < 8 && core_recv(pair[0],&byte,1,0) == 1) bytes++;
        CHECK("deadline/drip-does-not-renew",errno == ETIMEDOUT && bytes == (late ? 0 : 3) && now == 1065);
        core_deadline_end();
        CHECK("deadline/idle-still-usable",core_recv(pair[0],&byte,1,0) == 1 && byte == 'v');
        drip_fd=-1; close(pair[0]); close(pair[1]);
    }
    core_deadline_detach();
    REQUIRE("deadline/cleanup-without-connection", core_deadline_scope_begin(&scope,100) == 0);
    CHECK("deadline/temporary-attachment", core_deadline_active()); core_deadline_scope_end(&scope);
    CHECK("deadline/original-attachment-restored", !core_deadline_active());
    return test_result();
}
