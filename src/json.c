#define _POSIX_C_SOURCE 200809L
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct { const char *start, *cursor, *end; size_t nodes; char *error; size_t capacity; } json_reader_t;

static void fail(json_reader_t *reader, const char *reason) {
    if (reader->error && reader->capacity && !reader->error[0])
        snprintf(reader->error,reader->capacity,"invalid extra JSON: %s at byte %zu",reason,(size_t)(reader->cursor-reader->start));
}

void core_json_free(core_json_t *value) {
    while (value) {
        core_json_t *next=value->next;
        core_json_free(value->child); free(value->key); free(value->text); free(value); value=next;
    }
}

const core_json_t *core_json_get(const core_json_t *object, const char *key) {
    if (!object || object->type != CORE_JSON_OBJECT || !key) return NULL;
    for (const core_json_t *entry=object->child;entry;entry=entry->next)
        if (!strcmp(entry->key,key)) return entry;
    return NULL;
}

int core_json_equal(const core_json_t *first, const core_json_t *second) {
    if (!first || !second || first->type != second->type) return first == second;
    if (first->text || second->text) return first->text && second->text && !strcmp(first->text,second->text);
    const core_json_t *a=first->child, *b=second->child;
    if (first->type == CORE_JSON_OBJECT) {
        size_t ac=0,bc=0;
        for (;a;a=a->next) { ac++; if (!core_json_equal(a,core_json_get(second,a->key))) return 0; }
        for (;b;b=b->next) bc++;
        return ac == bc;
    }
    for (;a && b;a=a->next,b=b->next) if (!core_json_equal(a,b)) return 0;
    return !a && !b;
}

static void whitespace(json_reader_t *reader) {
    while (reader->cursor < reader->end && strchr(" \t\r\n",*reader->cursor)) reader->cursor++;
}

static int hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch-'0';
    if (ch >= 'a' && ch <= 'f') return ch-'a'+10;
    if (ch >= 'A' && ch <= 'F') return ch-'A'+10;
    return -1;
}

static int unicode_unit(json_reader_t *reader, uint32_t *unit) {
    if (reader->end-reader->cursor < 4) return -1;
    *unit=0;
    for (int i=0;i<4;i++) { int digit=hex_digit(*reader->cursor++); if (digit < 0) return -1; *unit=(*unit<<4)|(unsigned)digit; }
    return 0;
}

static char *read_string(json_reader_t *reader) {
    if (reader->cursor == reader->end || *reader->cursor++ != '"') { fail(reader,"expected string"); return NULL; }
    char *text=malloc((size_t)(reader->end-reader->cursor)+1); size_t used=0;
    if (!text) { fail(reader,"allocation failed"); return NULL; }
    while (reader->cursor < reader->end) {
        unsigned char ch=(unsigned char)*reader->cursor++;
        if (ch == '"') { text[used]=0; return text; }
        if (ch < 0x20) { fail(reader,"unescaped control character"); break; }
        if (ch == '\\') {
            if (reader->cursor == reader->end) break;
            ch=(unsigned char)*reader->cursor++;
            if (ch == '"' || ch == '\\' || ch == '/') text[used++]=(char)ch;
            else if (ch == 'b') text[used++]='\b';
            else if (ch == 'f') text[used++]='\f';
            else if (ch == 'n') text[used++]='\n';
            else if (ch == 'r') text[used++]='\r';
            else if (ch == 't') text[used++]='\t';
            else if (ch == 'u') {
                uint32_t code;
                if (unicode_unit(reader,&code) != 0) { fail(reader,"invalid Unicode escape"); break; }
                if (code >= 0xd800 && code <= 0xdbff) {
                    uint32_t low;
                    if (reader->end-reader->cursor < 6 || reader->cursor[0] != '\\' || reader->cursor[1] != 'u') { fail(reader,"missing low surrogate"); break; }
                    reader->cursor+=2;
                    if (unicode_unit(reader,&low) != 0 || low < 0xdc00 || low > 0xdfff) { fail(reader,"invalid low surrogate"); break; }
                    code=0x10000+((code-0xd800)<<10)+(low-0xdc00);
                } else if (code >= 0xdc00 && code <= 0xdfff) { fail(reader,"unexpected low surrogate"); break; }
                if (!code) { fail(reader,"NUL is not supported"); break; }
                if (code < 0x80) text[used++]=(char)code;
                else if (code < 0x800) { text[used++]=(char)(0xc0|(code>>6)); text[used++]=(char)(0x80|(code&63)); }
                else if (code < 0x10000) { text[used++]=(char)(0xe0|(code>>12)); text[used++]=(char)(0x80|((code>>6)&63)); text[used++]=(char)(0x80|(code&63)); }
                else { text[used++]=(char)(0xf0|(code>>18)); text[used++]=(char)(0x80|((code>>12)&63)); text[used++]=(char)(0x80|((code>>6)&63)); text[used++]=(char)(0x80|(code&63)); }
            } else { fail(reader,"invalid escape"); break; }
        } else if (ch >= 0x80) {
            unsigned bytes=ch >= 0xc2 && ch <= 0xdf ? 1 : ch >= 0xe0 && ch <= 0xef ? 2 : ch >= 0xf0 && ch <= 0xf4 ? 3 : 0;
            if (!bytes || (size_t)(reader->end-reader->cursor) < bytes) { fail(reader,"invalid UTF-8"); break; }
            unsigned char next=(unsigned char)reader->cursor[0];
            if ((ch == 0xe0 && next < 0xa0) || (ch == 0xed && next >= 0xa0) || (ch == 0xf0 && next < 0x90) || (ch == 0xf4 && next >= 0x90)) { fail(reader,"invalid UTF-8"); break; }
            unsigned i;
            for (i=0;i<bytes;i++) if (((unsigned char)reader->cursor[i]&0xc0) != 0x80) break;
            if (i != bytes) { fail(reader,"invalid UTF-8"); break; }
            text[used++]=(char)ch; memcpy(text+used,reader->cursor,bytes); used+=bytes; reader->cursor+=bytes;
        } else text[used++]=(char)ch;
    }
    fail(reader,"unterminated string"); free(text); return NULL;
}

static core_json_t *read_value(json_reader_t *reader, unsigned depth) {
    whitespace(reader);
    if (reader->cursor == reader->end || depth > 16 || reader->nodes++ >= 1024) { fail(reader,"missing value or capacity exceeded"); return NULL; }
    core_json_t *value=calloc(1,sizeof(*value));
    if (!value) { fail(reader,"allocation failed"); return NULL; }
    char ch=*reader->cursor;
    if (ch == '{' || ch == '[') {
        value->type=ch == '{' ? CORE_JSON_OBJECT : CORE_JSON_ARRAY;
        char close=ch == '{' ? '}' : ']'; reader->cursor++; whitespace(reader);
        if (reader->cursor < reader->end && *reader->cursor == close) { reader->cursor++; return value; }
        core_json_t **tail=&value->child;
        for (;;) {
            char *key=NULL;
            if (ch == '{') {
                key=read_string(reader); if (!key) goto failure;
                whitespace(reader);
                if (reader->cursor == reader->end || *reader->cursor++ != ':') { free(key); fail(reader,"expected colon"); goto failure; }
            }
            core_json_t *entry=read_value(reader,depth+1);
            if (!entry) { free(key); goto failure; }
            entry->key=key;
            const core_json_t *duplicate=key ? core_json_get(value,key) : NULL;
            if (duplicate) {
                if (!core_json_equal(duplicate,entry)) { core_json_free(entry); fail(reader,"conflicting duplicate field"); goto failure; }
                core_json_free(entry);
            } else { *tail=entry; tail=&entry->next; }
            whitespace(reader);
            if (reader->cursor == reader->end) { fail(reader,"unterminated container"); goto failure; }
            if (*reader->cursor == close) { reader->cursor++; return value; }
            if (*reader->cursor++ != ',') { fail(reader,"expected comma"); goto failure; }
            whitespace(reader);
        }
    }
    if (ch == '"') {
        value->type=CORE_JSON_STRING; value->text=read_string(reader);
        if (!value->text) goto failure;
        return value;
    }
    const char *start=reader->cursor;
    if (ch == '-' || (ch >= '0' && ch <= '9')) {
        value->type=CORE_JSON_NUMBER;
        if (ch == '-') reader->cursor++;
        if (reader->cursor == reader->end) goto invalid_number;
        if (*reader->cursor == '0') reader->cursor++;
        else {
            if (*reader->cursor < '1' || *reader->cursor > '9') goto invalid_number;
            do { reader->cursor++; } while (reader->cursor < reader->end && *reader->cursor >= '0' && *reader->cursor <= '9');
        }
        if (reader->cursor < reader->end && *reader->cursor == '.') {
            reader->cursor++;
            if (reader->cursor == reader->end || *reader->cursor < '0' || *reader->cursor > '9') goto invalid_number;
            do { reader->cursor++; } while (reader->cursor < reader->end && *reader->cursor >= '0' && *reader->cursor <= '9');
        }
        if (reader->cursor < reader->end && (*reader->cursor == 'e' || *reader->cursor == 'E')) {
            reader->cursor++;
            if (reader->cursor < reader->end && (*reader->cursor == '+' || *reader->cursor == '-')) reader->cursor++;
            if (reader->cursor == reader->end || *reader->cursor < '0' || *reader->cursor > '9') goto invalid_number;
            do { reader->cursor++; } while (reader->cursor < reader->end && *reader->cursor >= '0' && *reader->cursor <= '9');
        }
    } else {
        const char *literal=ch == 't' ? "true" : ch == 'f' ? "false" : ch == 'n' ? "null" : NULL;
        if (!literal || (size_t)(reader->end-reader->cursor) < strlen(literal) || strncmp(reader->cursor,literal,strlen(literal))) { fail(reader,"invalid literal"); goto failure; }
        value->type=ch == 'n' ? CORE_JSON_NULL : CORE_JSON_BOOL; reader->cursor+=strlen(literal);
    }
    value->text=malloc((size_t)(reader->cursor-start)+1);
    if (!value->text) { fail(reader,"allocation failed"); goto failure; }
    memcpy(value->text,start,(size_t)(reader->cursor-start)); value->text[reader->cursor-start]=0;
    return value;
invalid_number:
    fail(reader,"invalid number");
failure:
    core_json_free(value); return NULL;
}

core_json_t *core_json_parse(const char *text, char *error, size_t capacity) {
    if (error && capacity) error[0]=0;
    if (!text || strlen(text) > 4095) { if (error && capacity) snprintf(error,capacity,"extra JSON exceeds size limit"); return NULL; }
    json_reader_t reader={.start=text,.cursor=text,.end=text+strlen(text),.error=error,.capacity=capacity};
    core_json_t *value=read_value(&reader,0); whitespace(&reader);
    if (value && reader.cursor != reader.end) { fail(&reader,"trailing data"); core_json_free(value); value=NULL; }
    return value;
}
