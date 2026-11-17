#include "check.h"
#include "fingerprint.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static uint32_t random_value;
static int random_failure,random_calls;

int __wrap_RAND_bytes(unsigned char *output,int length) {
    random_calls++;
    if (random_failure || length != 4) return 0;
    memcpy(output,&random_value,4); return 1;
}

static void *resolve_thread(void *argument) {
    fingerprint_mode_t expected=*(fingerprint_mode_t *)argument,effective;
    for (unsigned i=0;i<100;i++) if (core_fingerprint_resolve(FP_RANDOM,&effective) || effective != expected) return (void *)1;
    return NULL;
}

static int child_choice(unsigned index,int failure) {
    random_value=11+index; random_failure=failure;
    fingerprint_mode_t effective=FP_COUNT;
    if (failure) {
        if (!core_fingerprint_resolve(FP_RANDOM,&effective) || errno != EIO || effective != FP_COUNT) return 1;
        random_failure=0;
        return !core_fingerprint_resolve(FP_RANDOM,&effective) || random_calls != 1;
    }
    if (core_fingerprint_resolve(FP_RANDOM,&effective) || effective != core_fingerprint_modern[index] || random_calls != 1) return 1;
    pthread_t workers[16];
    for (unsigned i=0;i<16;i++) if (pthread_create(workers+i,NULL,resolve_thread,&effective)) return 1;
    for (unsigned i=0;i<16;i++) { void *result=NULL; if (pthread_join(workers[i],&result) || result) return 1; }
    return random_calls != 1;
}

int main(void) {
    const struct { const char *name; fingerprint_mode_t mode; } cases[]={
        {"chrome",FP_CHROME},{"HELLOCHROME_AUTO",FP_CHROME},{"hellochrome_133",FP_CHROME},
        {"firefox",FP_FIREFOX},{"hellofirefox_148",FP_FIREFOX},{"hellofirefox_120",FP_FIREFOX_120},
        {"edge",FP_EDGE},{"helloedge_auto",FP_EDGE},{"helloedge_106",FP_EDGE_106},
        {"ios",FP_IOS_14},{"helloios_auto",FP_IOS_14},{"helloios_13",FP_IOS_13},
        {"safari",FP_SAFARI_26_3},{"hellosafari_auto",FP_SAFARI_26_3},
        {"360",FP_360_7_5},{"hello360_auto",FP_360_7_5},{"hello360_11_0",FP_360_11_0},
        {"qq",FP_QQ},{"helloqq_auto",FP_QQ},{"random",FP_RANDOM},{"randomized",FP_RANDOMIZED}
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(*cases);i++) {
        fingerprint_mode_t mode=FP_COUNT;
        CHECK("fingerprint/alias",!core_fingerprint_parse(cases[i].name,&mode) && mode == cases[i].mode);
    }
    for (unsigned i=0;i<CORE_FINGERPRINT_MODERN_COUNT;i++) {
        CHECK("fingerprint/modern-tls13",core_fingerprint_tls13(core_fingerprint_modern[i]));
        pid_t child=fork(); REQUIRE("fingerprint/fork",child >= 0);
        if (!child) _exit(child_choice(i,0));
        int status; REQUIRE("fingerprint/wait",waitpid(child,&status,0) == child);
        CHECK("fingerprint/random-each-choice-stable-parallel",WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    pid_t child=fork(); REQUIRE("fingerprint/failure-fork",child >= 0);
    if (!child) _exit(child_choice(0,1));
    int status; REQUIRE("fingerprint/failure-wait",waitpid(child,&status,0) == child);
    CHECK("fingerprint/random-failure-is-sticky",WIFEXITED(status) && WEXITSTATUS(status) == 0);
    fingerprint_mode_t mode=FP_CHROME;
    CHECK("fingerprint/null",core_fingerprint_parse(NULL,&mode) && core_fingerprint_parse("chrome",NULL));
    CHECK("fingerprint/unknown-preserves-output",core_fingerprint_parse("hellofirefox_55",&mode) && mode == FP_CHROME);
    CHECK("fingerprint/invalid-mode",core_fingerprint_resolve(FP_COUNT,&mode));
    CHECK("fingerprint/360-auto-tls12-only",!core_fingerprint_tls13(FP_360_7_5));
    return test_result();
}
