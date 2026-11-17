#include "fingerprint.h"
#include "core_random.h"
#include <errno.h>
#include <pthread.h>

static pthread_once_t random_once=PTHREAD_ONCE_INIT;
static fingerprint_mode_t random_profile;
static int random_error;

static void choose_random_profile(void) {
    uint32_t index;
    if (core_random_range(0,CORE_FINGERPRINT_MODERN_COUNT-1,&index)) random_error=errno ? errno : EIO;
    else random_profile=core_fingerprint_modern[index];
}

int core_fingerprint_resolve(fingerprint_mode_t mode, fingerprint_mode_t *effective) {
    if (!effective || (unsigned)mode >= FP_COUNT) { errno=EINVAL; return -1; }
    if (mode != FP_RANDOM) { *effective=mode; return 0; }
    int error=pthread_once(&random_once,choose_random_profile);
    if (error || random_error) { errno=error ? error : random_error; return -1; }
    *effective=random_profile; return 0;
}
