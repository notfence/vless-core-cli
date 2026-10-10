#ifndef CORE_JSON_H
#define CORE_JSON_H
#include <stddef.h>

typedef enum { CORE_JSON_OBJECT, CORE_JSON_ARRAY, CORE_JSON_STRING, CORE_JSON_NUMBER, CORE_JSON_BOOL, CORE_JSON_NULL } core_json_type_t;
typedef struct core_json {
    core_json_type_t type;
    char *key, *text;
    const char *source;
    size_t source_length;
    struct core_json *child, *next;
} core_json_t;

core_json_t *core_json_parse(const char *text, char *error, size_t capacity);
const core_json_t *core_json_get(const core_json_t *object, const char *key);
int core_json_equal(const core_json_t *first, const core_json_t *second);
void core_json_free(core_json_t *value);
#endif
