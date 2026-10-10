#define _POSIX_C_SOURCE 200809L
#include "xhttp_config.h"
#include "core_log.h"
#include "xhttp_payload.h"
#include "http_headers.h"
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <openssl/rand.h>

typedef enum { FIELD_STRING, FIELD_LOWER, FIELD_UPPER, FIELD_BOOL, FIELD_RANGE, FIELD_HEADERS } field_kind_t;
typedef struct { const char *key; size_t offset, size; field_kind_t kind; int maximum; } config_field_t;
#define STRING_FIELD(key,member,kind) {key,offsetof(vless_config_t,member),sizeof(((vless_config_t *)0)->member),kind,0}
#define RANGE_FIELD(key,member,maximum) {key,offsetof(vless_config_t,member),sizeof(int)*2,FIELD_RANGE,maximum}
static const config_field_t fields[] = {
    STRING_FIELD("mode",xhttp_mode,FIELD_LOWER), STRING_FIELD("path",xhttp_path,FIELD_STRING), STRING_FIELD("host",xhttp_host,FIELD_STRING),
    STRING_FIELD("sessionPlacement",xhttp_session_placement,FIELD_LOWER), STRING_FIELD("sessionIDPlacement",xhttp_session_placement,FIELD_LOWER),
    STRING_FIELD("sessionKey",xhttp_session_key,FIELD_STRING), STRING_FIELD("sessionIDKey",xhttp_session_key,FIELD_STRING),
    STRING_FIELD("sessionIDTable",xhttp_session_id_table,FIELD_STRING), RANGE_FIELD("sessionIDLength",xhttp_session_id_length_min,255),
    STRING_FIELD("seqPlacement",xhttp_seq_placement,FIELD_LOWER), STRING_FIELD("seqKey",xhttp_seq_key,FIELD_STRING),
    STRING_FIELD("uplinkHTTPMethod",xhttp_uplink_method,FIELD_UPPER), STRING_FIELD("uplinkDataPlacement",xhttp_uplink_data_placement,FIELD_LOWER),
    STRING_FIELD("uplinkDataKey",xhttp_uplink_data_key,FIELD_STRING), RANGE_FIELD("uplinkChunkSize",xhttp_uplink_chunk_min,INT_MAX),
    STRING_FIELD("headers",xhttp_headers,FIELD_HEADERS), STRING_FIELD("noGRPCHeader",xhttp_no_grpc_header,FIELD_BOOL),
    STRING_FIELD("xPaddingPlacement",xhttp_padding_placement,FIELD_LOWER), STRING_FIELD("xPaddingKey",xhttp_padding_key,FIELD_STRING),
    STRING_FIELD("xPaddingHeader",xhttp_padding_header,FIELD_STRING), STRING_FIELD("xPaddingMethod",xhttp_padding_method,FIELD_LOWER),
    STRING_FIELD("xPaddingObfsMode",xhttp_padding_obfs,FIELD_BOOL),
    RANGE_FIELD("xPaddingBytes",xhttp_padding_min,8192), RANGE_FIELD("scMaxEachPostBytes",xhttp_max_each_post_min,16*1024*1024),
    RANGE_FIELD("scMinPostsIntervalMs",xhttp_min_posts_interval_min,INT_MAX),
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
    if (field->kind == FIELD_HEADERS) {
        if (query && value->type == CORE_JSON_STRING) {
            core_json_t *object=core_json_parse(value->text,error,capacity);
            if (!object) return -1;
            int result=core_http_headers_parse(object,(char *)destination,field->size,error,capacity);
            core_json_free(object); return result;
        }
        return core_http_headers_parse(value,(char *)destination,field->size,error,capacity);
    }
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
        if ((ch < 0x20 && ch) || ch == 0x7f) return invalid(path,error,capacity);
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

static int server_field(const core_json_t *entry, int query, int *index, int64_t values[2], char *error, size_t capacity) {
    const char *names[]={"noSSEHeader","scMaxBufferedPosts","scStreamUpServerSecs","serverMaxHeaderBytes"};
    for (*index=0;*index<4;(*index)++) if (!strcasecmp(entry->key,names[*index])) break;
    if (*index == 4) return 0;
    char path[80]; snprintf(path,sizeof(path),"extra.%s",names[*index]);
    if (*index == 0) {
        if (entry->type != CORE_JSON_BOOL && (!query || entry->type != CORE_JSON_STRING)) return invalid(path,error,capacity);
        if (!strcmp(entry->text,"true") || (query && !strcmp(entry->text,"1"))) values[0]=values[1]=1;
        else if (!strcmp(entry->text,"false") || (query && !strcmp(entry->text,"0"))) values[0]=values[1]=0;
        else return invalid(path,error,capacity);
    } else if (*index == 2) {
        core_range_t range;
        if (core_xhttp_range(entry,&range,INT_MAX) != 0) return invalid(path,error,capacity);
        values[0]=range.min; values[1]=range.max;
    } else {
        if ((entry->type != CORE_JSON_NUMBER && (!query || entry->type != CORE_JSON_STRING)) || !entry->text[0]) return invalid(path,error,capacity);
        uint64_t number=0,limit=*index == 1 ? INT64_MAX : INT_MAX;
        for (const unsigned char *p=(const unsigned char *)entry->text;*p;p++) {
            if (*p < '0' || *p > '9' || number > (limit-(*p-'0'))/10) return invalid(path,error,capacity);
            number=number*10+(*p-'0');
        }
        values[0]=values[1]=(int64_t)number;
    }
    return 1;
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
    int server_seen[4]={0}; int64_t server_values[4][2];
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
        if (!field) {
            int index; int64_t values[2]; int server=server_field(entry,0,&index,values,error,capacity);
            if (server < 0) { result=-1; break; }
            if (server) {
                if (server_seen[index] && memcmp(server_values[index],values,sizeof(values))) { result=invalid(path,error,capacity); break; }
                server_seen[index]=1; memcpy(server_values[index],values,sizeof(values));
            }
            warning("extra",entry->key,server); continue;
        }
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
    core_json_t value={.type=CORE_JSON_STRING,.text=(char *)text};
    if (!field) {
        value.key=(char *)key; int index; int64_t values[2]; int result=server_field(&value,1,&index,values,error,capacity);
        if (result > 0) warning("query",key,1);
        return result;
    }
    return apply_field(config,field,&value,1,key,error,capacity) == 0 ? 1 : -1;
}

static const char *session_table(const char *name) {
    static const struct { const char *name,*table; } tables[]={
        {"ALPHABET","ABCDEFGHIJKLMNOPQRSTUVWXYZ"},{"Alphabet","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
        {"BASE36","0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"},{"Base62","0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
        {"HEX","0123456789ABCDEF"},{"alphabet","abcdefghijklmnopqrstuvwxyz"},{"base36","0123456789abcdefghijklmnopqrstuvwxyz"},
        {"hex","0123456789abcdef"},{"number","0123456789"},
    };
    for (size_t i=0;i<sizeof(tables)/sizeof(*tables);i++) if (!strcmp(name,tables[i].name)) return tables[i].table;
    return name;
}

static int indexed_name(const char *name, size_t size, const char *key, int cookie) {
    size_t length=strlen(key);
    if (size <= length+1 || (cookie ? memcmp(name,key,length) : strncasecmp(name,key,length)) || name[length] != (cookie ? '_' : '-')) return 0;
    const char *index=name+length+1,*end=name+size;
    while (index < end && *index >= '0' && *index <= '9') index++;
    return index == end;
}

static int payload_header_collision(const vless_config_t *config) {
    if (strcmp(config->xhttp_uplink_data_placement,"header")) return 0;
    const char *key=config->xhttp_uplink_data_key[0] ? config->xhttp_uplink_data_key : "X-Data";
    for (const char *line=config->xhttp_headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!colon) return 1;
        if (indexed_name(line,(size_t)(colon-line),key,0)) return 1;
        line=end+2;
    }
    return 0;
}

static int cookie_collision(const vless_config_t *config, const char *name, int indexed) {
    size_t length=0; const char *cookie=core_http_header_get(config->xhttp_headers,"Cookie",&length);
    if (!cookie) return 0;
    const char *last=cookie+length; size_t name_size=strlen(name);
    while (cookie < last) {
        const char *end=memchr(cookie,';',(size_t)(last-cookie)); if (!end) end=last;
        while (cookie < end && (*cookie == ' ' || *cookie == '\t')) cookie++;
        const char *equals=memchr(cookie,'=',(size_t)(end-cookie));
        if (equals) {
            const char *key_end=equals;
            while (key_end > cookie && (key_end[-1] == ' ' || key_end[-1] == '\t')) key_end--;
            size_t key_size=(size_t)(key_end-cookie);
            if ((!indexed && key_size == name_size && !memcmp(cookie,name,name_size)) || (indexed && indexed_name(cookie,key_size,name,1))) return 1;
        }
        cookie=end == last ? last : end+1;
    }
    return 0;
}

int core_xhttp_validate(const vless_config_t *config, char *error, size_t capacity) {
    if (config->xhttp_uplink_method[0] && (!core_http_token(config->xhttp_uplink_method) || !strcmp(config->xhttp_uplink_method,"OPTIONS"))) return invalid("uplinkHTTPMethod",error,capacity);
    if (!strcmp(config->xhttp_uplink_method,"HEAD") && !strcmp(config->xhttp_mode,"stream-one")) return invalid("uplinkHTTPMethod HEAD cannot carry a stream-one response",error,capacity);
    const char *placements[]={config->xhttp_session_placement,config->xhttp_seq_placement};
    const char *keys[]={config->xhttp_session_key,config->xhttp_seq_key};
    const char *paths[]={"sessionIDPlacement/sessionIDKey","seqPlacement/seqKey"};
    const char *effective[2];
    for (size_t i=0;i<2;i++) {
        const char *placement=placements[i];
        if (placement[0] && strcmp(placement,"path") && strcmp(placement,"header") && strcmp(placement,"query") && strcmp(placement,"cookie")) return invalid(paths[i],error,capacity);
        effective[i]=keys[i][0] ? keys[i] : !strcmp(placement,"header") ? (i ? "X-Seq" : "X-Session") : (i ? "x_seq" : "x_session");
        if ((!strcmp(placement,"header") && !core_http_header_allowed(effective[i])) || (!strcmp(placement,"cookie") && !core_http_token(effective[i]))) return invalid(paths[i],error,capacity);
    }
    if (!strcmp(config->xhttp_mode,"packet-up") && placements[0][0] && strcmp(placements[0],"path") && !strcmp(placements[0],placements[1]) &&
        (!strcmp(placements[0],"header") ? !strcasecmp(effective[0],effective[1]) : !strcmp(effective[0],effective[1]))) return invalid("sessionIDKey/seqKey collision",error,capacity);
    const char *padding=config->xhttp_padding_placement,*method=config->xhttp_padding_method;
    if (padding[0] && strcmp(padding,"queryinheader") && strcmp(padding,"header") && strcmp(padding,"query") && strcmp(padding,"cookie")) return invalid("xPaddingPlacement",error,capacity);
    if (method[0] && strcmp(method,"repeat-x") && strcmp(method,"tokenish")) return invalid("xPaddingMethod",error,capacity);
    if (config->xhttp_padding_header[0] && !core_http_header_allowed(config->xhttp_padding_header)) return invalid("xPaddingHeader",error,capacity);
    if (!strcmp(padding,"cookie") && config->xhttp_padding_key[0] && !core_http_token(config->xhttp_padding_key)) return invalid("xPaddingKey",error,capacity);
    int cookies=!strcmp(config->xhttp_session_placement,"cookie") || !strcmp(config->xhttp_seq_placement,"cookie") || !strcmp(config->xhttp_uplink_data_placement,"cookie") ||
        (config->xhttp_padding_obfs && !strcmp(padding,"cookie")) || core_http_header_get(config->xhttp_headers,"Cookie",NULL);
    for (size_t i=0;i<2;i++) if (cookies && !strcmp(placements[i],"header") && !strcasecmp(effective[i],"Cookie")) return invalid("metadata Cookie header collision",error,capacity);
    if (payload_header_collision(config)) return invalid("headers/uplinkDataKey collision",error,capacity);
    const char *pad_place=config->xhttp_padding_obfs && padding[0] ? padding : "queryinheader";
    const char *pad_name=config->xhttp_padding_obfs ? ((!strcmp(pad_place,"header") || !strcmp(pad_place,"queryinheader")) ?
        (config->xhttp_padding_header[0] ? config->xhttp_padding_header : "X-Padding") : (config->xhttp_padding_key[0] ? config->xhttp_padding_key : "x_padding")) : "Referer";
    if (!strcmp(pad_place,"queryinheader")) pad_place="header";
    const char *data_place=config->xhttp_uplink_data_placement;
    int data_cookie=!strcmp(data_place,"cookie"),indexed_data=data_cookie || !strcmp(data_place,"header");
    const char *data_key=config->xhttp_uplink_data_key[0] ? config->xhttp_uplink_data_key : data_cookie ? "x_data" : "X-Data";
    for (size_t i=0;i<2;i++) {
        int active=i ? !strcmp(config->xhttp_mode,"packet-up") : strcmp(config->xhttp_mode,"stream-one");
        if (!active) continue;
        if (!strcmp(placements[i],"cookie") && cookie_collision(config,effective[i],0)) return invalid("headers.Cookie/metadata key collision",error,capacity);
        if (!strcmp(placements[i],pad_place) && (!strcmp(pad_place,"header") ? !strcasecmp(effective[i],pad_name) : !strcmp(effective[i],pad_name))) return invalid("padding/metadata key collision",error,capacity);
        if (indexed_data && !strcmp(placements[i],data_place) && indexed_name(effective[i],strlen(effective[i]),data_key,data_cookie)) return invalid("uplinkDataKey/metadata key collision",error,capacity);
    }
    if (indexed_data && !strcmp(pad_place,data_place) && indexed_name(pad_name,strlen(pad_name),data_key,data_cookie)) return invalid("uplinkDataKey/padding key collision",error,capacity);
    if (!strcmp(config->xhttp_uplink_data_placement,"cookie") && cookie_collision(config,config->xhttp_uplink_data_key[0] ? config->xhttp_uplink_data_key : "x_data",1)) return invalid("headers.Cookie/uplinkDataKey collision",error,capacity);
    if (!strcmp(pad_place,"cookie") && cookie_collision(config,pad_name,0)) return invalid("headers.Cookie/padding key collision",error,capacity);
    if (config->xhttp_session_id_table[0]) {
        const char *table=session_table(config->xhttp_session_id_table);
        size_t count=strlen(table);
        int min=config->xhttp_session_id_length_min,max=config->xhttp_session_id_length_max;
        if (!count || min <= 0 || max < min || max > 255) return invalid("sessionIDLength",error,capacity);
        uint64_t term=1,room=0,limit=UINT64_C(1)<<31;
        for (int length=1;length<=max && room<limit;length++) {
            term=term > limit/count ? limit : term*count;
            if (length >= min) room=room > limit-term ? limit : room+term;
        }
        if (room < limit) return invalid("sessionIDTable/sessionIDLength space",error,capacity);
        for (size_t i=0;i<count;i++) {
            unsigned char ch=(unsigned char)table[i];
            if (ch < 0x21 || ch >= 0x7f || ((!config->xhttp_session_placement[0] || !strcmp(config->xhttp_session_placement,"path")) && ch == '/') ||
                (!strcmp(config->xhttp_session_placement,"cookie") && (ch == '"' || ch == ',' || ch == ';' || ch == '\\'))) return invalid("sessionIDTable for sessionIDPlacement",error,capacity);
        }
    }
    const char *placement=config->xhttp_uplink_data_placement;
    if (config->xhttp_uplink_data_key[0] && !core_http_token(config->xhttp_uplink_data_key)) return invalid("uplinkDataKey",error,capacity);
    if (!placement[0] || !strcmp(placement,"body") || !strcmp(placement,"auto")) return 0;
    if (strcmp(placement,"header") && strcmp(placement,"cookie")) return invalid("uplinkDataPlacement",error,capacity);
    if (strcmp(config->xhttp_mode,"packet-up")) return invalid("uplinkDataPlacement requires packet-up",error,capacity);
    return 0;
}

static int sample(unsigned min, unsigned max, unsigned *sampled) {
    if (max < min) return -1;
    uint32_t span=max-min+1,threshold=(uint32_t)(-span)%span,value;
    do { if (RAND_bytes((unsigned char *)&value,sizeof(value)) != 1) return -1; } while (value < threshold);
    *sampled=min+value%span; return 0;
}

int core_xhttp_post_due(core_range_t range, uint64_t previous, uint64_t now, uint64_t *due) {
    if (!due || range.min < 0 || range.max < range.min) return -1;
    if (!previous) { *due=now; return 0; }
    if (!range.max) range=(core_range_t){30,30};
    unsigned interval=0;
    if (range.min && sample((unsigned)range.min,(unsigned)range.max,&interval) != 0) return -1;
    if (previous > UINT64_MAX-interval) return -1;
    *due=previous+interval > now ? previous+interval : now; return 0;
}

int core_xhttp_post_limit(const vless_config_t *config) {
    int min=config->xhttp_max_each_post_min,max=config->xhttp_max_each_post_max; unsigned chosen;
    if (!max) min=max=1000000;
    if (min <= 0 || max < min || sample((unsigned)min,(unsigned)max,&chosen) != 0) return -1;
    return (int)chosen;
}

int core_xhttp_session(const vless_config_t *config, char *output, size_t capacity) {
    if (!capacity) return -1;
    output[0]=0;
    if (!strcmp(config->xhttp_mode,"stream-one")) return 0;
    if (core_xhttp_validate(config,NULL,0) != 0) return -1;
    if (config->xhttp_session_id_table[0]) {
        const char *table=session_table(config->xhttp_session_id_table); unsigned length;
        if (sample((unsigned)config->xhttp_session_id_length_min,(unsigned)config->xhttp_session_id_length_max,&length) != 0 || length >= capacity) return -1;
        for (size_t i=0;i<length;i++) { unsigned index; if (sample(0,(unsigned)strlen(table)-1,&index) != 0) return -1; output[i]=table[index]; }
        output[length]=0; return 0;
    }
    if (capacity < 37) return -1;
    uint8_t bytes[16]; if (RAND_bytes(bytes,sizeof(bytes)) != 1) return -1;
    bytes[6]=(uint8_t)((bytes[6]&15)|64); bytes[8]=(uint8_t)((bytes[8]&63)|128);
    size_t offset=0; const char *hex="0123456789abcdef";
    for (size_t i=0;i<sizeof(bytes);i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) output[offset++]='-';
        output[offset++]=hex[bytes[i]>>4]; output[offset++]=hex[bytes[i]&15];
    }
    output[offset]=0; return 0;
}
