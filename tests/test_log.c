#include "check.h"
#include "core_log.h"
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
static void *log_worker(void *arg) { vc_log_info("thread", "vless-core thread=%ld", (long)arg); return NULL; }
int main(void) {
    int pair[2]; REQUIRE("logging/pipe", pipe(pair) == 0); int saved = dup(2); REQUIRE("logging/capture", dup2(pair[1], 2) == 2); close(pair[1]);
    errno = ENOENT; vc_log_debug("a\nb", "one\ntwo\tthree"); CHECK("logging/preserve-errno", errno == ENOENT);
    vc_log_warning(NULL, "warning"); vc_log_error("error", "failure");
    pthread_t threads[8]; for (long i = 0; i < 8; i++) REQUIRE("logging/thread", pthread_create(threads+i, NULL, log_worker, (void *)i) == 0);
    for (int i = 0; i < 8; i++) pthread_join(threads[i], NULL);
    char large[2200]; memset(large, 'x', sizeof(large)-1); large[sizeof(large)-1] = 0; vc_log_info("large", "%s", large);
    dup2(saved, 2); close(saved); char buffer[8192]; ssize_t length = read(pair[0], buffer, sizeof(buffer)-1); close(pair[0]); REQUIRE("logging/read", length > 0); buffer[length] = 0;
    CHECK("logging/sanitize", strstr(buffer, "D [a b] one two three\n") != NULL);
    CHECK("logging/levels", strstr(buffer, "W [core] warning\n") && strstr(buffer, "E [error] failure\n"));
    CHECK("logging/truncate", strstr(buffer, "...\n") != NULL);
    int lines = 0; for (ssize_t i = 0; i < length; i++) if (buffer[i] == '\n') lines++;
    CHECK("logging/serialized-records", lines == 12);
    for (int i = 0; i < 8; i++) { char expected[80]; snprintf(expected, sizeof(expected), "I [thread] vless-core thread=%d\n", i); CHECK("logging/thread-record", strstr(buffer, expected) != NULL); }
    return test_result();
}
