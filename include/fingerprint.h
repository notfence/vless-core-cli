#ifndef CORE_FINGERPRINT_H
#define CORE_FINGERPRINT_H
#include <stddef.h>

typedef enum {
    FP_CHROME = 0,
    FP_RANDOM = 1,
    FP_QQ = 2,
    FP_RANDOMIZED = 3,
    FP_FIREFOX = 4,
    FP_EDGE = 5,
    FP_CHROME_120,
    FP_CHROME_131,
    FP_FIREFOX_120,
    FP_IOS_13,
    FP_IOS_14,
    FP_EDGE_106,
    FP_SAFARI_26_3,
    FP_360_11_0,
    FP_360_7_5,
    FP_COUNT
} fingerprint_mode_t;

#define CORE_FINGERPRINT_MODERN_COUNT 11
extern const fingerprint_mode_t core_fingerprint_modern[CORE_FINGERPRINT_MODERN_COUNT];
int core_fingerprint_parse(const char *, fingerprint_mode_t *);
int core_fingerprint_tls13(fingerprint_mode_t);
int core_fingerprint_hybrid(fingerprint_mode_t);
int core_fingerprint_resolve(fingerprint_mode_t, fingerprint_mode_t *);

#endif
