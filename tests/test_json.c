#include "json.h"
#include "check.h"

int main(void) {
    char error[160];
    core_json_t *value=core_json_parse(" {\"escaped\":\"a\\\"b\\\\c\\u0410\\ud83d\\ude80\",\"nested\":{\"n\":12,\"a\":[true,false,null,-1.5e+2]},\"same\":1,\"same\":1} ",error,sizeof(error));
    REQUIRE("json/nested-and-escaped", value && value->type == CORE_JSON_OBJECT);
    CHECK("json/unicode-and-escapes", !strcmp(core_json_get(value,"escaped")->text,"a\"b\\cА🚀"));
    CHECK("json/scoped-field-lookup", !core_json_get(value,"n") && !strcmp(core_json_get(core_json_get(value,"nested"),"n")->text,"12"));
    const core_json_t *nested=core_json_get(value,"nested");
    CHECK("json/exact-container-source-span",nested->source_length > 1 && nested->source[0] == '{' && nested->source[nested->source_length-1] == '}');
    CHECK("json/scalar-source-preserves-escaping",core_json_get(value,"escaped")->source[0] == '"' && strstr(core_json_get(value,"escaped")->source,"\\u0410"));
    const core_json_t *array=core_json_get(core_json_get(value,"nested"),"a");
    CHECK("json/typed-values", array->type == CORE_JSON_ARRAY && array->child->type == CORE_JSON_BOOL && array->child->next->next->type == CORE_JSON_NULL && array->child->next->next->next->type == CORE_JSON_NUMBER);
    core_json_free(value);
    const char *invalid[]={"", "{", "{\"a\":1", "{\"a\":1,}", "[1,]", "truefalse", "00", "01", "+1", "1.", "1e", "{\"a\":1,\"a\":2}", "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800\\u0041\"", "\"\\u0000\"", "\"\\x11\"", "\"a\n\"", "\"\xc0\x80\"", "{}[]"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) CHECK("json/malformed-rejected", !core_json_parse(invalid[i],error,sizeof(error)) && error[0]);
    value=core_json_parse("{\"x\":{\"a\":1,\"b\":2},\"x\":{\"b\":2,\"a\":1}}",error,sizeof(error));
    CHECK("json/equivalent-duplicate-object", value != NULL); core_json_free(value);
    for (const char *input="{\"a\":[1,\"b\",{}]}";*input;input++) { value=core_json_parse(input,error,sizeof(error)); core_json_free(value); }
    return test_result();
}
