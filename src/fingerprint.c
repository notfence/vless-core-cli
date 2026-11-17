#include "fingerprint.h"
#include <strings.h>

static const struct { const char *name; fingerprint_mode_t mode; } names[] = {
    {"chrome",FP_CHROME},{"firefox",FP_FIREFOX},{"edge",FP_EDGE},{"qq",FP_QQ},
    {"random",FP_RANDOM},{"randomized",FP_RANDOMIZED},
    {"ios",FP_IOS_14},{"safari",FP_SAFARI_26_3},{"360",FP_360_7_5},
    {"hellochrome_auto",FP_CHROME},{"hellofirefox_auto",FP_FIREFOX},
    {"helloedge_auto",FP_EDGE},{"helloqq_auto",FP_QQ},{"helloios_auto",FP_IOS_14},
    {"hellosafari_auto",FP_SAFARI_26_3},{"hello360_auto",FP_360_7_5},
    {"hellochrome_120",FP_CHROME_120},{"hellochrome_131",FP_CHROME_131},
    {"hellochrome_133",FP_CHROME},{"hellofirefox_120",FP_FIREFOX_120},
    {"hellofirefox_148",FP_FIREFOX},{"helloios_13",FP_IOS_13},{"helloios_14",FP_IOS_14},
    {"helloedge_106",FP_EDGE_106},{"hellosafari_26_3",FP_SAFARI_26_3},
    {"hello360_11_0",FP_360_11_0},{"helloqq_11_1",FP_QQ}
};

const fingerprint_mode_t core_fingerprint_modern[CORE_FINGERPRINT_MODERN_COUNT] = {
    FP_FIREFOX_120, FP_FIREFOX, FP_CHROME_120, FP_CHROME_131, FP_CHROME,
    FP_IOS_13, FP_IOS_14, FP_EDGE_106, FP_SAFARI_26_3, FP_360_11_0, FP_QQ
};

int core_fingerprint_parse(const char *text, fingerprint_mode_t *mode) {
    if (!text || !mode) return -1;
    for (size_t i=0;i<sizeof(names)/sizeof(*names);i++)
        if (!strcasecmp(text,names[i].name)) { *mode=names[i].mode; return 0; }
    return -1;
}

int core_fingerprint_tls13(fingerprint_mode_t mode) {
    return (unsigned)mode < FP_COUNT && mode != FP_360_7_5;
}

int core_fingerprint_hybrid(fingerprint_mode_t mode) {
    return mode == FP_CHROME || mode == FP_CHROME_131 || mode == FP_FIREFOX || mode == FP_SAFARI_26_3;
}
