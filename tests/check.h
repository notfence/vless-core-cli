#ifndef VC_TEST_CHECK_H
#define VC_TEST_CHECK_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned test_checks, test_failures;
static char test_seen[512][160];
static unsigned test_seen_count;
static void test_check(const char *name, int result, const char *expression, int line) {
    const char *forced = getenv("VC_TEST_FAIL_SCENARIO");
    if (forced && strcmp(forced, name) == 0) result = 0;
    test_checks++;
    if (result) {
        unsigned index = 0;
        while (index < test_seen_count && strcmp(test_seen[index], name) != 0) index++;
        if (index == test_seen_count && test_seen_count < 512) {
            snprintf(test_seen[test_seen_count++], 160, "%s", name);
            printf("PASS %s\n", name);
        }
    }
    else {
        test_failures++;
        fprintf(stderr, "FAIL %s: expected true, actual false: %s (line %d)\n", name, expression, line);
    }
}
#define CHECK(name, value) test_check(name, !!(value), #value, __LINE__)
#define REQUIRE(name, value) do { int test_ok = !!(value); CHECK(name, test_ok); if (!test_ok) exit(2); } while (0)
static int test_result(void) {
    printf("RESULT %u checks, %u failures\n", test_checks, test_failures);
    return test_failures ? 1 : 0;
}
#endif
