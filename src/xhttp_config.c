#define _POSIX_C_SOURCE 200809L
#include "xhttp_config.h"
#include "core_log.h"
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

typedef enum { FIELD_STRING, FIELD_LOWER, FIELD_UPPER, FIELD_BOOL, FIELD_RANGE } field_kind_t;
typedef struct { const char *key; size_t offset, size; field_kind_t kind; int maximum; } config_field_t;
#define STRING_FIELD(key,member,kind) {key,offsetof(vless_config_t,member),sizeof(((vless_config_t *)0)->member),kind,0}
#define RANGE_FIELD(key,member,maximum) {key,offsetof(vless_config_t,member),sizeof(int)*2,FIELD_RANGE,maximum}
static const config_field_t fields[] = {
    STRING_FIELD("mode",xhttp_mode,FIELD_LOWER), STRING_FIELD("path",xhttp_path,FIELD_STRING), STRING_FIELD("host",xhttp_host,FIELD_STRING),
    STRING_FIELD("sessionPlacement",xhttp_session_placement,FIELD_LOWER), STRING_FIELD("sessionIDPlacement",xhttp_session_placement,FIELD_LOWER),
    STRING_FIELD("sessionKey",xhttp_session_key,FIELD_STRING), STRING_FIELD("sessionIDKey",xhttp_session_key,FIELD_STRING),
    STRING_FIELD("seqPlacement",xhttp_seq_placement,FIELD_LOWER), STRING_FIELD("seqKey",xhttp_seq_key,FIELD_STRING),
    STRING_FIELD("uplinkHTTPMethod",xhttp_uplink_method,FIELD_UPPER), STRING_FIELD("uplinkDataPlacement",xhttp_uplink_data_placement,FIELD_LOWER),
    STRING_FIELD("xPaddingPlacement",xhttp_padding_placement,FIELD_LOWER), STRING_FIELD("xPaddingKey",xhttp_padding_key,FIELD_STRING),
    STRING_FIELD("xPaddingHeader",xhttp_padding_header,FIELD_STRING), STRING_FIELD("xPaddingMethod",xhttp_padding_method,FIELD_LOWER),
    STRING_FIELD("xPaddingObfsMode",xhttp_padding_obfs,FIELD_BOOL),
    RANGE_FIELD("xPaddingBytes",xhttp_padding_min,8192), RANGE_FIELD("scMaxEachPostBytes",xhttp_max_each_post_min,16*1024*1024),
};

static int invalid(const char *path, char *error, size_t capacity) {
    if (error && capacity) snprintf(error,capacity,"invalid XHTTP field %s",path);
    return -1;
}

static int decimal(const char *text, const char **end, int maximum, int *result) {
    if (!text || *text < '0' || *text > '9') return -1;
    unsigned value=0;
    do {
        unsigned digit=(unsigned)(*text-'0');
        if (value > ((unsigned)maximum-digit)/10 || digit > (unsigned)maximum) return -1;
        value=value*10+digit; text++;
    } while (*text >= '0' && *text <= '9');
    *end=text; *result=(int)value; return 0;
}

int core_xhttp_range(const core_json_t *value, core_range_t *range, int maximum) {
    if (!value || !range || maximum < 0 || (value->type != CORE_JSON_STRING && value->type != CORE_JSON_NUMBER)) return -1;
    const char *end;
    if (decimal(value->text,&end,maximum,&range->min) != 0) return -1;
    range->max=range->min;
    if (*end == '-') { if (decimal(end+1,&end,maximum,&range->max) != 0) return -1; }
    if (*end || range->min > range->max) return -1;
    return 0;
}

static const config_field_t *find_field(const char *key) {
    for (size_t i=0;i<sizeof(fields)/sizeof(*fields);i++) if (!strcasecmp(key,fields[i].key)) return &fields[i];
    return NULL;
}

static int apply_field(vless_config_t *config, const config_field_t *field, const core_json_t *value, int query, const char *path, char *error, size_t capacity) {
    unsigned char *destination=(unsigned char *)config+field->offset;
    if (field->kind == FIELD_RANGE) {
        core_range_t range;
        if (core_xhttp_range(value,&range,field->maximum) != 0 || (field->maximum == 16*1024*1024 && !range.min)) return invalid(path,error,capacity);
        memcpy(destination,&range,sizeof(range)); return 0;
    }
    if (field->kind == FIELD_BOOL) {
        if (value->type != CORE_JSON_BOOL && (!query || value->type != CORE_JSON_STRING)) return invalid(path,error,capacity);
        int enabled;
        if (!strcmp(value->text,"true") || (query && !strcmp(value->text,"1"))) enabled=1;
        else if (!strcmp(value->text,"false") || (query && !strcmp(value->text,"0"))) enabled=0;
        else return invalid(path,error,capacity);
        memcpy(destination,&enabled,sizeof(enabled)); return 0;
    }
    if (value->type != CORE_JSON_STRING || strlen(value->text) >= field->size) return invalid(path,error,capacity);
    for (size_t i=0;i<=strlen(value->text);i++) {
        unsigned char ch=(unsigned char)value->text[i];
        if (ch < 0x20 && ch) return invalid(path,error,capacity);
        destination[i]=(unsigned char)(field->kind == FIELD_LOWER ? tolower(ch) : field->kind == FIELD_UPPER ? toupper(ch) : ch);
    }
    return 0;
}

static void warning(const char *prefix, const char *key, int server) {
    char path[160]; size_t length=(size_t)snprintf(path,sizeof(path),"%s.",prefix);
    for (;*key && length+1<sizeof(path);key++) path[length++]=(unsigned char)*key >= 0x21 && (unsigned char)*key < 0x7f ? *key : '?';
    path[length]=0;
    if (server) vc_log_info("xhttp","server-only field %s is not applied by the client",path);
    else vc_log_warning("xhttp","unknown field %s ignored",path);
}

static int parse_xmux(vless_config_t *config, const core_json_t *value, char *error, size_t capacity) {
    if (value->type != CORE_JSON_OBJECT) return invalid("extra.xmux",error,capacity);
    core_xmux_config_t parsed={.present=1};
    for (const core_json_t *entry=value->child;entry;entry=entry->next) {
        core_range_t *range=NULL;
        if (!strcasecmp(entry->key,"maxConcurrency")) range=&parsed.max_concurrency;
        else if (!strcasecmp(entry->key,"maxConnections")) range=&parsed.max_connections;
        else if (!strcasecmp(entry->key,"cMaxReuseTimes")) range=&parsed.reuse_times;
        else if (!strcasecmp(entry->key,"hMaxRequestTimes")) range=&parsed.request_times;
        else if (!strcasecmp(entry->key,"hMaxReusableSecs")) range=&parsed.reusable_secs;
        else if (!strcasecmp(entry->key,"hKeepAlivePeriod")) {
            core_range_t keep;
            if (entry->type == CORE_JSON_NUMBER && !strcmp(entry->text,"-1")) { parsed.keep_alive_period=-1; continue; }
            if (core_xhttp_range(entry,&keep,INT_MAX) != 0 || keep.min != keep.max || entry->type != CORE_JSON_NUMBER) return invalid("extra.xmux.hKeepAlivePeriod",error,capacity);
            parsed.keep_alive_period=keep.min; continue;
        } else { warning("extra.xmux",entry->key,0); continue; }
        char path[160]; snprintf(path,sizeof(path),"extra.xmux.%s",entry->key);
        if (core_xhttp_range(entry,range,INT_MAX) != 0) return invalid(path,error,capacity);
    }
    if (parsed.max_connections.max && parsed.max_concurrency.max) return invalid("extra.xmux.maxConnections/maxConcurrency",error,capacity);
    if (!parsed.max_connections.max && !parsed.max_concurrency.max && !parsed.reuse_times.max && !parsed.request_times.max && !parsed.reusable_secs.max && !parsed.keep_alive_period) {
        parsed.max_connections=(core_range_t){6,6}; parsed.request_times=(core_range_t){600,900}; parsed.reusable_secs=(core_range_t){1800,3000};
    }
    config->xmux=parsed; return 0;
}

int core_xhttp_extra(vless_config_t *config, const char *json, char *error, size_t capacity) {
    core_json_t *root=core_json_parse(json,error,capacity);
    if (!root) return -1;
    if (root->type != CORE_JSON_OBJECT) { core_json_free(root); return invalid("extra",error,capacity); }
    size_t applied[sizeof(fields)/sizeof(*fields)],count=0; int result=0, xmux_seen=0;
    for (const core_json_t *entry=root->child;entry;entry=entry->next) {
        char path[160]; snprintf(path,sizeof(path),"extra.%s",entry->key);
        if (!strcasecmp(entry->key,"xmux")) {
            core_xmux_config_t previous=config->xmux;
            result=parse_xmux(config,entry,error,capacity);
            if (!result && xmux_seen && memcmp(&previous,&config->xmux,sizeof(previous))) result=invalid("extra.xmux duplicate",error,capacity);
            if (result) break;
            xmux_seen=1; continue;
        }
        const config_field_t *field=find_field(entry->key);
        if (!field) { warning("extra",entry->key,0); continue; }
        vless_config_t candidate=*config;
        result=apply_field(&candidate,field,entry,0,path,error,capacity);
        if (result) break;
        int duplicate=0;
        for (size_t i=0;i<count;i++) if (applied[i] == field->offset) duplicate=1;
        if (duplicate && memcmp((unsigned char *)&candidate+field->offset,(unsigned char *)config+field->offset,field->size)) { result=invalid(path,error,capacity); break; }
        if (!duplicate) applied[count++]=field->offset;
        *config=candidate;
    }
    core_json_free(root); return result;
}

int core_xhttp_parameter(vless_config_t *config, const char *key, const char *text, char *error, size_t capacity) {
    const config_field_t *field=find_field(key);
    if (!field) return 0;
    core_json_t value={.type=CORE_JSON_STRING,.text=(char *)text};
    return apply_field(config,field,&value,1,key,error,capacity) == 0 ? 1 : -1;
}
