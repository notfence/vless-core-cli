#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int64_t __real_core_vmess_time(void);
int64_t __wrap_core_vmess_time(void) {
    int64_t value=__real_core_vmess_time();
    const char *shift=getenv("VC_TEST_VMESS_CLOCK");
    if (shift && !strcmp(shift,"past")) value-=3600;
    if (shift && !strcmp(shift,"future")) value+=3600;
    return value;
}
