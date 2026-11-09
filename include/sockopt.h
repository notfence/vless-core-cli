#ifndef CORE_SOCKOPT_H
#define CORE_SOCKOPT_H
#include "json.h"
#include <stdint.h>

enum { CORE_SOCKOPT_TIMEOUT=1, CORE_SOCKOPT_IDLE=2, CORE_SOCKOPT_INTERVAL=4 };
typedef struct {
    int32_t user_timeout, keepalive_idle, keepalive_interval;
    unsigned present;
} core_sockopt_t;
typedef struct {
    unsigned applied, adapted, unavailable;
    int errors[3];
} core_sockopt_result_t;
int core_sockopt_parse(const core_json_t *, core_sockopt_t *, char *, size_t);
int core_sockopt_json(const char *, core_sockopt_t *, char *, size_t);
core_sockopt_result_t core_sockopt_apply(int, const core_sockopt_t *);
core_sockopt_result_t core_sockopt_check(const core_sockopt_t *);
const char *core_sockopt_field(unsigned);
int core_sockopt_notice(unsigned, int, int, char *, size_t);
#endif
