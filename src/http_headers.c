#include "http_headers.h"
#include "xhttp_payload.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

static int failure(char *error, size_t capacity, const char *name) {
    char path[160]; size_t used=0;
    if (!name) name="headers";
    for (;*name && used+1<sizeof(path);name++) path[used++]=(unsigned char)*name >= 0x21 && (unsigned char)*name < 0x7f ? *name : '?';
    path[used]=0;
    if (error && capacity) snprintf(error,capacity,"invalid XHTTP headers field %s",path);
    return -1;
}

static int valid_value(const char *value) {
    for (const unsigned char *cursor=(const unsigned char *)value;*cursor;cursor++) if ((*cursor < 0x20 && *cursor != '\t') || *cursor == 0x7f) return 0;
    return 1;
}

int core_http_header_allowed(const char *name) {
    if (!core_http_token(name) || strlen(name) >= 128) return 0;
    const char *reserved[]={"host","content-length","transfer-encoding","connection","keep-alive","proxy-connection","upgrade","trailer","te"};
    for (size_t i=0;i<sizeof(reserved)/sizeof(*reserved);i++) if (!strcasecmp(name,reserved[i])) return 0;
    return 1;
}

const char *core_http_header_get(const char *headers, const char *name, size_t *length) {
    if (!headers || !name) return NULL;
    for (const char *line=headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!end || !colon) return NULL;
        if ((size_t)(colon-line) == strlen(name) && !strncasecmp(line,name,strlen(name))) {
            const char *value=colon+1;
            while (value < end && (*value == ' ' || *value == '\t')) value++;
            const char *last=end; while (last > value && (last[-1] == ' ' || last[-1] == '\t')) last--;
            if (length) *length=(size_t)(last-value);
            return value;
        }
        line=end+2;
    }
    return NULL;
}

int core_http_header_set(char *headers, size_t capacity, const char *name, const char *value) {
    if (!headers || !name || !value || !core_http_token(name) || !valid_value(value)) return -1;
    size_t used=strlen(headers),replacement=strlen(name)+strlen(value)+4,removed=0;
    if (used >= capacity) return -1;
    for (const char *line=headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!end || !colon) return -1;
        if ((size_t)(colon-line) == strlen(name) && !strncasecmp(line,name,strlen(name))) removed+=(size_t)(end+2-line);
        line=end+2;
    }
    if (replacement >= capacity || used-removed >= capacity-replacement) return -1;
    for (char *line=headers;*line;) {
        char *end=strstr(line,"\r\n"),*colon=memchr(line,':',(size_t)(end-line));
        if ((size_t)(colon-line) == strlen(name) && !strncasecmp(line,name,strlen(name))) {
            size_t length=(size_t)(end+2-line); memmove(line,end+2,strlen(end+2)+1); used-=length;
        } else line=end+2;
    }
    int size=snprintf(headers+used,capacity-used,"%s: %s\r\n",name,value);
    return size < 0 || (size_t)size >= capacity-used ? -1 : 0;
}

int core_http_header_append_cookie(char *headers, size_t capacity, const char *cookie) {
    size_t length=0; const char *existing=core_http_header_get(headers,"Cookie",&length);
    if (!existing || !length) return core_http_header_set(headers,capacity,"Cookie",cookie);
    size_t added=strlen(cookie);
    if (length > capacity || added > capacity-length || length+added+3 > capacity) return -1;
    char *combined=malloc(length+added+3);
    if (!combined) return -1;
    memcpy(combined,existing,length); memcpy(combined+length,"; ",2); memcpy(combined+length+2,cookie,added+1);
    int result=core_http_header_set(headers,capacity,"Cookie",combined); free(combined); return result;
}

static int compare(const void *left, const void *right) {
    const core_json_t *a=*(const core_json_t *const *)left,*b=*(const core_json_t *const *)right;
    return strcasecmp(a->key,b->key);
}

int core_http_headers_parse(const core_json_t *value, char *output, size_t capacity, char *error, size_t error_capacity) {
    if (!value || value->type != CORE_JSON_OBJECT || !capacity) return failure(error,error_capacity,NULL);
    const core_json_t *entries[512]; size_t count=0;
    for (const core_json_t *entry=value->child;entry;entry=entry->next) {
        if (count == sizeof(entries)/sizeof(*entries) || !core_http_header_allowed(entry->key) || entry->type != CORE_JSON_STRING || !valid_value(entry->text)) return failure(error,error_capacity,entry->key);
        entries[count++]=entry;
    }
    qsort(entries,count,sizeof(*entries),compare); memset(output,0,capacity);
    for (size_t i=0;i<count;i++) {
        if (i && !strcasecmp(entries[i]->key,entries[i-1]->key)) {
            if (strcmp(entries[i]->text,entries[i-1]->text)) return failure(error,error_capacity,entries[i]->key);
            continue;
        }
        char name[128]; size_t length=strlen(entries[i]->key);
        for (size_t byte=0;byte<=length;byte++) name[byte]=(char)(entries[i]->key[byte] >= 'A' && entries[i]->key[byte] <= 'Z' ? entries[i]->key[byte]+('a'-'A') : entries[i]->key[byte]);
        if (core_http_header_set(output,capacity,name,entries[i]->text) != 0) return failure(error,error_capacity,"capacity");
    }
    return 0;
}
