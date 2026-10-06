#include <gcov.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static sigset_t stop_signals;
int __real_main(int argc, char **argv);

static void *stop_and_dump(void *unused) {
    (void)unused;
    int received = 0;
    if (sigwait(&stop_signals, &received) != 0) _Exit(70);
    __gcov_dump();
    fputs("PASS coverage/cli-flush\n", stderr);
    fflush(stderr);
    _Exit(128+received);
}

int __wrap_main(int argc, char **argv) {
    sigemptyset(&stop_signals);
    sigaddset(&stop_signals, SIGTERM);
    pthread_t thread;
    if (pthread_sigmask(SIG_BLOCK, &stop_signals, NULL) != 0 || pthread_create(&thread, NULL, stop_and_dump, NULL) != 0) {
        fputs("FAIL coverage/cli-flush: cannot start signal waiter\n", stderr);
        return 70;
    }
    return __real_main(argc, argv);
}
