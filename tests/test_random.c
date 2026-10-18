#include "check.h"
#include "core_random.h"
#include "deadline.h"
#include "xhttp_config.h"
#include "uri.h"
#include <errno.h>
#include <limits.h>

int __real_RAND_bytes(unsigned char *,int);
static unsigned mode,calls;
static uint32_t value;
static uint64_t clock_ms,clock_step;
static uint64_t now_ms(void) { return clock_ms; }
int __wrap_RAND_bytes(unsigned char *output,int length) {
    if (!mode) return __real_RAND_bytes(output,length);
    calls++; clock_ms+=clock_step;
    if (mode == 1) { memset(output,0xa5,(size_t)length); return 0; }
    if (length != (int)sizeof(value)) return 0;
    uint32_t chosen=mode == 3 ? value++ : value;
    memcpy(output,&chosen,sizeof(chosen)); return 1;
}

int main(void) {
    uint32_t result=777;
    CHECK("random/invalid-range",core_random_range(2,1,&result) < 0 && errno == EINVAL && result == 777);
    CHECK("random/null-result",core_random_range(0,1,NULL) < 0 && errno == EINVAL);
    CHECK("random/empty-fill",!core_random_fill(NULL,0));
    CHECK("random/invalid-fill",core_random_fill(NULL,1) < 0 && core_random_fill(&result,(size_t)INT_MAX+1) < 0 && errno == EINVAL);
    mode=1; calls=0;
    CHECK("random/failed-range-keeps-output",core_random_range(1,3,&result) < 0 && errno == EIO && result == 777 && calls == 1);
    unsigned char bytes[8]; memset(bytes,0x5a,sizeof(bytes));
    CHECK("random/failed-fill-cleans-buffer",core_random_fill(bytes,sizeof(bytes)) < 0 && !memcmp(bytes,(unsigned char[8]){0},sizeof(bytes)));
    mode=2; value=0; calls=0;
    CHECK("random/rejection-bound",core_random_range(1,3,&result) < 0 && errno == EIO && calls == CORE_RANDOM_MAX_ATTEMPTS && result == 777);
    value=1; calls=0;
    CHECK("random/constant-accepted",!core_random_range(1,3,&result) && result == 2 && calls == 1);
    value=3;
    CHECK("random/minimum",!core_random_range(1,3,&result) && result == 1);
    value=2;
    CHECK("random/maximum",!core_random_range(1,3,&result) && result == 3);
    value=UINT32_MAX;
    CHECK("random/full-range",!core_random_range(0,UINT32_MAX,&result) && result == UINT32_MAX);
    CHECK("random/fixed-range",!core_random_range(123,123,&result) && result == 123);
    mode=3; value=0; calls=0;
    CHECK("random/accepted-last-attempt",!core_random_range(0,129,&result) && calls == 127 && result == 126);
    core_deadline_t deadline={.now_ms=now_ms};
    REQUIRE("random/deadline-attach",!core_deadline_attach(&deadline));
    deadline.now_ms=now_ms;
    clock_ms=100; clock_step=1; core_deadline_begin(3); mode=2; value=0; calls=0; result=777;
    CHECK("random/deadline-between-attempts",core_random_range(1,3,&result) < 0 && errno == ETIMEDOUT && calls == 3 && result == 777 && deadline.until_ms == 103);
    CHECK("random/expired-does-not-call-generator",core_random_range(1,3,&result) < 0 && calls == 3);
    core_deadline_end(); core_deadline_detach(); clock_step=0;
    vless_config_t config; core_config_defaults(&config);
    strcpy(config.xhttp_session_id_table,"AAAB"); config.xhttp_session_id_length_min=config.xhttp_session_id_length_max=31;
    char session[256]; mode=3; value=0;
    REQUIRE("random/session-preserves-weighted-table",!core_xhttp_session(&config,session,sizeof(session)) && strlen(session) == 31);
    for (unsigned i=0;i<31;i++) CHECK("random/session-weighted-symbol",session[i] == "AAAB"[(i+1)%4]);
    mode=1;
    CHECK("random/session-propagates-failure",core_xhttp_session(&config,session,sizeof(session)) < 0);
    mode=0;
    CHECK("random/recovery-with-real-generator",!core_random_range(1,3,&result) && result >= 1 && result <= 3 && !core_xhttp_session(&config,session,sizeof(session)));
    return test_result();
}
