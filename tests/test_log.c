#include "check.h"
#include "../src/core_log.c"
#include "deadline.h"
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
static void *log_worker(void *arg) { vc_log_info("thread", "vless-core thread=%ld", (long)arg); return NULL; }
static int fail_log_thread,write_step;
int __real_pthread_create(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
ssize_t __real_write(int,const void *,size_t);
int __wrap_pthread_create(pthread_t *thread,const pthread_attr_t *attributes,void *(*function)(void *),void *argument) {
    if (fail_log_thread && function == log_output_worker) { fail_log_thread=0; return EAGAIN; }
    return __real_pthread_create(thread,attributes,function,argument);
}
ssize_t __wrap_write(int fd,const void *data,size_t length) {
    if (fd == 2 && write_step) {
        int step=write_step++;
        if (step == 1) { errno=EINTR; return -1; }
        if (step == 2) return __real_write(fd,data,length > 3 ? 3 : length);
        if (step == 3) { errno=EAGAIN; return -1; }
        write_step=0;
    }
    return __real_write(fd,data,length);
}
static void blocked_output(void) {
    int output[2],done[2];
    REQUIRE("logging/pressure-pipes",pipe(output) == 0 && pipe(done) == 0);
    int flags=fcntl(output[1],F_GETFL);
    REQUIRE("logging/pressure-nonblocking-fill",flags >= 0 && fcntl(output[1],F_SETFL,flags|O_NONBLOCK) == 0);
    char fill[1024]; memset(fill,'x',sizeof(fill));
    size_t filled=0; ssize_t sent;
    while ((sent=write(output[1],fill,sizeof(fill))) > 0) filled+=(size_t)sent;
    REQUIRE("logging/pressure-filled",errno == EAGAIN && fcntl(output[1],F_SETFL,flags) == 0);
    fflush(stdout);
    pid_t child=fork(); REQUIRE("logging/pressure-child",child >= 0);
    if (!child) {
        close(output[0]); close(done[0]);
        if (dup2(output[1],2) != 2) _exit(2);
        close(output[1]);
        core_deadline_t deadline;
        if (core_deadline_attach(&deadline)) _exit(2);
        core_deadline_begin(1); deadline.until_ms=core_now_ms()-1;
        for (unsigned i=0;i<400;i++) vc_log_debug("pressure","vless-core record=%u",i);
        vc_log_error("pressure","vless-core priority error");
        vc_log_probe(1,"v=1 id=42 success=1 stage=none dns_ms=0 tcp_ms=0 transport_ms=0 protocol_ms=0 carry_ms=0 total_ms=0");
        for (unsigned i=0;i<100;i++) vc_log_error("pressure","vless-core overload=%u",i);
        int bounded=vc_log_flush() < 0;
        pthread_mutex_lock(&g_log_mutex);
        int valid=logger.started && logger.count <= 54 && logger.ordinary <= 39 && logger.dropped[0] && logger.dropped[3];
        pthread_mutex_unlock(&g_log_mutex);
        char ready=bounded && valid && fcntl(2,F_GETFL) == flags ? 1 : 2;
        if (write(done[1],&ready,1) != 1) _exit(2);
        core_deadline_detach(); exit(0);
    }
    close(output[1]); close(done[1]);
    struct pollfd notification={.fd=done[0],.events=POLLIN};
    int progressed=poll(&notification,1,700) == 1 && (notification.revents&POLLIN);
    CHECK("logging/blocked-output-does-not-block-producer",progressed);
    char ready=0;
    if (progressed) REQUIRE("logging/producer-ready",read(done[0],&ready,1) == 1);
    CHECK("logging/queue-reserve-and-bounded-flush",ready == 1);
    if (!progressed) kill(child,SIGKILL);
    REQUIRE("logging/pressure-reader-nonblocking",fcntl(output[0],F_SETFL,O_NONBLOCK) == 0);
    char captured[32768]; size_t used=0; uint64_t until=core_now_ms()+1000;
    while (progressed && used+1 < sizeof(captured)) {
        char block[4096]; ssize_t length=read(output[0],block,sizeof(block));
        if (length > 0) {
            size_t skip=filled < (size_t)length ? filled : (size_t)length; filled-=skip;
            size_t take=(size_t)length-skip;
            if (take > sizeof(captured)-used-1) take=sizeof(captured)-used-1;
            memcpy(captured+used,block+skip,take); used+=take; continue;
        }
        if (!length) break;
        if (errno != EAGAIN && errno != EINTR) break;
        if (core_now_ms() >= until) { kill(child,SIGKILL); break; }
        struct pollfd fd={.fd=output[0],.events=POLLIN}; (void)poll(&fd,1,20);
    }
    captured[used]=0;
    int status; REQUIRE("logging/pressure-reaped",waitpid(child,&status,0) == child);
    CHECK("logging/pressure-priority-error-preserved",strstr(captured,"E [pressure] vless-core priority error\n") != NULL);
    CHECK("logging/pressure-diagnostic-preserved",strstr(captured,"I [probe] v=1 id=42 success=1 stage=none ") != NULL);
    CHECK("logging/recovery-reports-dropped-records",strstr(captured,"W [log] dropped debug=") && strstr(captured," diagnostic=0\n"));
    CHECK("logging/pressure-clean-exit",WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(output[0]); close(done[0]);
}
static void worker_failure(void) {
    fflush(stdout);
    pid_t child=fork(); REQUIRE("logging/failure-child",child >= 0);
    if (!child) {
        int fd=open("/dev/null",O_WRONLY); if (fd < 0 || dup2(fd,2) != 2) _exit(2); close(fd);
        fail_log_thread=1; errno=ENOENT; vc_log_info("failure","vless-core unavailable worker");
        int valid=!logger.started && logger.dropped[1] == 1 && errno == ENOENT;
        logger.retry_ms=0; vc_log_error("failure","vless-core recovered worker");
        valid=valid && !vc_log_flush() && logger.started && !logger.count;
        exit(valid ? 0 : 1);
    }
    int status; REQUIRE("logging/failure-reaped",waitpid(child,&status,0) == child);
    CHECK("logging/worker-failure-and-recovery",WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void closed_output(void) {
    int pair[2]; REQUIRE("logging/closed-pipe",pipe(pair) == 0); close(pair[0]);
    fflush(stdout);
    pid_t child=fork(); REQUIRE("logging/closed-output-child",child >= 0);
    if (!child) {
        if (dup2(pair[1],2) != 2) _exit(2);
        close(pair[1]); vc_log_error("closed","vless-core closed receiver");
        int valid=!vc_log_flush() && logger.dropped[3] == 1;
        exit(valid ? 0 : 1);
    }
    close(pair[1]); int status; REQUIRE("logging/closed-output-reaped",waitpid(child,&status,0) == child);
    CHECK("logging/closed-receiver-does-not-raise-sigpipe",WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(void) {
    blocked_output(); worker_failure(); closed_output();
    int pair[2]; REQUIRE("logging/pipe", pipe(pair) == 0); int saved = dup(2); REQUIRE("logging/capture", dup2(pair[1], 2) == 2); close(pair[1]);
    write_step=1; errno = ENOENT; vc_log_debug("a\nb", "one\ntwo\tthree"); CHECK("logging/preserve-errno", errno == ENOENT);
    vc_log_warning(NULL, "warning"); vc_log_error("error", "failure");
    pthread_t threads[8]; for (long i = 0; i < 8; i++) REQUIRE("logging/thread", pthread_create(threads+i, NULL, log_worker, (void *)i) == 0);
    for (int i = 0; i < 8; i++) pthread_join(threads[i], NULL);
    char large[2200]; memset(large, 'x', sizeof(large)-1); large[sizeof(large)-1] = 0; vc_log_info("large", "%s", large);
    REQUIRE("logging/flush",vc_log_flush() == 0);
    CHECK("logging/partial-write-eintr-and-eagain",write_step == 0);
    dup2(saved, 2); close(saved); char buffer[8192]; ssize_t length = read(pair[0], buffer, sizeof(buffer)-1); close(pair[0]); REQUIRE("logging/read", length > 0); buffer[length] = 0;
    CHECK("logging/sanitize", strstr(buffer, "D [a b] one two three\n") != NULL);
    CHECK("logging/levels", strstr(buffer, "W [core] warning\n") && strstr(buffer, "E [error] failure\n"));
    CHECK("logging/truncate", strstr(buffer, "...\n") != NULL);
    int lines = 0; for (ssize_t i = 0; i < length; i++) if (buffer[i] == '\n') lines++;
    CHECK("logging/serialized-records", lines == 12);
    for (int i = 0; i < 8; i++) { char expected[80]; snprintf(expected, sizeof(expected), "I [thread] vless-core thread=%d\n", i); CHECK("logging/thread-record", strstr(buffer, expected) != NULL); }
    worker_failure(); closed_output();
    return test_result();
}
