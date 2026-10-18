#include "xhttp_payload.h"
#include "core_random.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

int core_http_token(const char *text) {
    if (!text || !*text) return 0;
    for (const unsigned char *cursor=(const unsigned char *)text;*cursor;cursor++) {
        unsigned ch=*cursor;
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || strchr("!#$%&'*+-.^_`|~",(int)ch))) return 0;
    }
    return 1;
}

static int fail(char *error, size_t capacity, const char *text) {
    if (error && capacity) snprintf(error,capacity,"%s",text);
    return -1;
}

static size_t digits(size_t number) { size_t count=1; while (number >= 10) { number/=10; count++; } return count; }
static size_t encoded_size(size_t bytes) { return bytes/3*4+(bytes%3 ? bytes%3+1 : 0); }

static void *payload_alloc(core_buffer_budget_t *memory, size_t length) {
    return memory ? core_buffer_alloc(memory,length) : malloc(length);
}

static void payload_free(core_buffer_budget_t *memory, void *data, size_t length) {
    if (memory) core_buffer_free(memory,data,length);
    else free(data);
}

void core_xhttp_payload_clear(core_xhttp_payload_t *packet) {
    payload_free(packet->memory,packet->headers,packet->header_capacity);
    memset(packet,0,sizeof(*packet));
}

static size_t payload_cost(size_t bytes, const size_t *chunks, size_t count, size_t key_size, int cookie) {
    size_t encoded=encoded_size(bytes),offset=0,index=0;
    size_t cost=encoded+(cookie ? 38 : 0);
    while (offset < encoded) {
        if (index >= count) return SIZE_MAX;
        offset+=chunks[index]; cost+=key_size+digits(index)+(cookie ? 4 : 33); index++;
    }
    if (cookie && index) cost-=2;
    return cost;
}

static int prefix_cost(const char *headers, size_t *cost) {
    *cost=0;
    for (const char *line=headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!colon || colon == line || colon-line >= 128) return -1;
        char name[128]; memcpy(name,line,(size_t)(colon-line)); name[colon-line]=0;
        if (!core_http_token(name)) return -1;
        const char *value=colon+1;
        while (value < end && (*value == ' ' || *value == '\t')) value++;
        const char *last=end;
        while (last > value && (last[-1] == ' ' || last[-1] == '\t')) last--;
        for (const unsigned char *cursor=(const unsigned char *)value;cursor<(const unsigned char *)last;cursor++) if ((*cursor < 0x20 && *cursor != '\t') || *cursor == 0x7f) return -1;
        *cost+=(size_t)(colon-line)+(size_t)(last-value)+32;
        line=end+2;
    }
    return 0;
}

int core_xhttp_payload_build(const core_xhttp_payload_options_t *options, const uint8_t *data, size_t length, const char *prefix, size_t budget, core_xhttp_payload_t *result, char *error, size_t capacity) {
    if (!result) return fail(error,capacity,"missing XHTTP packet output");
    memset(result,0,sizeof(*result));
    if (!options || !options->placement || !prefix || length > 16U*1024U*1024U || (length && !data)) return fail(error,capacity,"invalid XHTTP packet input");
    result->memory=options->memory;
    size_t initial;
    if (prefix_cost(prefix,&initial) != 0) return fail(error,capacity,"invalid XHTTP packet headers");
    if (budget > 65536) budget=65536;
    if (initial >= budget || strlen(prefix) >= budget) return fail(error,capacity,"XHTTP metadata exceeds the request header limit");
    int body=!strcmp(options->placement,"body") || !strcmp(options->placement,"auto") || !options->placement[0];
    if (body) {
        result->header_capacity=strlen(prefix)+1;
        result->headers=payload_alloc(options->memory,result->header_capacity);
        if (!result->headers) return fail(error,capacity,"XHTTP packet allocation failed");
        memcpy(result->headers,prefix,strlen(prefix)+1); result->consumed=result->body_size=length; return 0;
    }
    int cookie=!strcmp(options->placement,"cookie");
    if (!cookie && strcmp(options->placement,"header")) return fail(error,capacity,"invalid XHTTP uplinkDataPlacement");
    const char *key=options->key && options->key[0] ? options->key : cookie ? "x_data" : "X-Data";
    if (!core_http_token(key) || strlen(key) > 63) return fail(error,capacity,"invalid XHTTP uplinkDataKey");
    core_range_t range=options->chunks;
    if (!range.max) range=cookie ? (core_range_t){2048,3072} : (core_range_t){3000,4000};
    if (range.min < 0 || range.max < range.min) return fail(error,capacity,"invalid XHTTP uplinkChunkSize");
    if (range.min < 64) range.min=64;
    if (range.max < 64) range.max=64;
    size_t chunks[1024],count=0,covered=0,wanted=encoded_size(length);
    if (wanted > budget-initial) wanted=budget-initial;
    uint32_t value;
    while (covered < wanted) {
        if (count == sizeof(chunks)/sizeof(*chunks)) return fail(error,capacity,"XHTTP packet has too many chunks");
        if (core_random_range((uint32_t)range.min,(uint32_t)range.max,&value)) return fail(error,capacity,"XHTTP chunk sampling failed");
        chunks[count]=value; covered+=chunks[count++];
    }
    size_t low=0,high=length;
    while (low < high) {
        size_t middle=low+(high-low+1)/2;
        if (payload_cost(middle,chunks,count,strlen(key),cookie) <= budget-initial) low=middle;
        else high=middle-1;
    }
    if (length && !low) return fail(error,capacity,"XHTTP uplinkDataKey/chunk size cannot fit the request header limit");
    size_t encoded_capacity=4*((low+2)/3)+1,header_capacity=budget+1;
    char *encoded=payload_alloc(options->memory,encoded_capacity),*headers=payload_alloc(options->memory,header_capacity);
    if (!encoded || !headers) { payload_free(options->memory,encoded,encoded_capacity); payload_free(options->memory,headers,header_capacity); return fail(error,capacity,"XHTTP packet allocation failed"); }
    int encoded_length=low ? EVP_EncodeBlock((unsigned char *)encoded,data,(int)low) : 0;
    if (encoded_length < 0) { payload_free(options->memory,encoded,encoded_capacity); payload_free(options->memory,headers,header_capacity); return fail(error,capacity,"XHTTP packet encoding failed"); }
    for (int index=0;index<encoded_length;index++) {
        if (encoded[index] == '+') encoded[index]='-';
        else if (encoded[index] == '/') encoded[index]='_';
    }
    while (encoded_length && encoded[encoded_length-1] == '=') encoded_length--;
    encoded[encoded_length]=0;
    size_t used=strlen(prefix); memcpy(headers,prefix,used);
    if (cookie && encoded_length) { memcpy(headers+used,"Cookie: ",8); used+=8; }
    for (size_t offset=0,index=0;offset<(size_t)encoded_length;index++) {
        size_t take=(size_t)encoded_length-offset; if (take > chunks[index]) take=chunks[index];
        int added=cookie ? snprintf(headers+used,budget+1-used,"%s%s_%zu=%.*s",index ? "; " : "",key,index,(int)take,encoded+offset)
                         : snprintf(headers+used,budget+1-used,"%s-%zu: %.*s\r\n",key,index,(int)take,encoded+offset);
        if (added < 0 || (size_t)added > budget-used) { payload_free(options->memory,encoded,encoded_capacity); payload_free(options->memory,headers,header_capacity); return fail(error,capacity,"XHTTP packet headers exceed capacity"); }
        used+=(size_t)added; offset+=take;
    }
    if (cookie && encoded_length) { if (used+2 > budget) { payload_free(options->memory,encoded,encoded_capacity); payload_free(options->memory,headers,header_capacity); return fail(error,capacity,"XHTTP cookie headers exceed capacity"); } memcpy(headers+used,"\r\n",2); used+=2; }
    headers[used]=0; payload_free(options->memory,encoded,encoded_capacity);
    result->headers=headers; result->header_capacity=header_capacity; result->consumed=low; return 0;
}
