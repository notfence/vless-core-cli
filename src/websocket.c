#include "websocket.h"
#include "json.h"
#include "http_headers.h"
#include "utils.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int upgrade_token(const uint8_t *data, size_t length) {
    if (!length) return 0;
    for (size_t i=0;i<length;i++) {
        unsigned byte=data[i];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') ||
              (byte && strchr("!#$%&'*+-.^_`|~",(int)byte)))) return 0;
    }
    return 1;
}

static int upgrade_tokens(const uint8_t *data, size_t length, const char *expected) {
    if (!length) return -1;
    int found=0;
    for (size_t offset=0;offset<length;) {
        while (offset < length && (data[offset] == ' ' || data[offset] == '\t')) offset++;
        size_t start=offset;
        while (offset < length && data[offset] != ',') offset++;
        size_t end=offset;
        while (end > start && (data[end-1] == ' ' || data[end-1] == '\t')) end--;
        if (!upgrade_token(data+start,end-start)) return -1;
        if (end-start == strlen(expected) && !strncasecmp((const char *)data+start,expected,end-start)) found=1;
        if (offset < length && ++offset == length) return -1;
    }
    return found;
}

int core_ws_validate_upgrade(const uint8_t *data, size_t length, const char *accept, const char *protocol) {
    if (!data || !accept || length > 32768 || length < 17 || memcmp(data,"HTTP/1.1 101 ",13)) return -1;
    size_t offset=0;
    while (offset+1 < length && !(data[offset] == '\r' && data[offset+1] == '\n')) {
        if ((data[offset] < 0x20 && data[offset] != '\t') || data[offset] == 0x7f) return -1;
        offset++;
    }
    if (offset+1 >= length) return -1;
    offset+=2;
    int has_upgrade=0,has_connection=0,has_accept=0,has_protocol=0;
    while (offset+1 < length) {
        size_t start=offset;
        while (offset+1 < length && !(data[offset] == '\r' && data[offset+1] == '\n')) offset++;
        if (offset+1 >= length) return -1;
        size_t end=offset; offset+=2;
        if (end == start) return offset == length && has_upgrade && has_connection && has_accept ? 0 : -1;
        const uint8_t *colon=memchr(data+start,':',end-start);
        if (!colon || !upgrade_token(data+start,(size_t)(colon-data-start))) return -1;
        size_t name=(size_t)(colon-data-start),value_start=(size_t)(colon-data)+1;
        while (value_start < end && (data[value_start] == ' ' || data[value_start] == '\t')) value_start++;
        for (size_t i=value_start;i<end;i++) if ((data[i] < 0x20 && data[i] != '\t') || data[i] == 0x7f) return -1;
        while (end > value_start && (data[end-1] == ' ' || data[end-1] == '\t')) end--;
        const uint8_t *value=data+value_start; size_t value_length=end-value_start;
        if (name == 7 && !strncasecmp((const char *)data+start,"Upgrade",name)) {
            int result=upgrade_tokens(value,value_length,"websocket");
            if (result < 0) return -1;
            has_upgrade|=result;
        } else if (name == 10 && !strncasecmp((const char *)data+start,"Connection",name)) {
            int result=upgrade_tokens(value,value_length,"upgrade");
            if (result < 0) return -1;
            has_connection|=result;
        } else if (name == 20 && !strncasecmp((const char *)data+start,"Sec-WebSocket-Accept",name)) {
            if (has_accept++ || value_length != strlen(accept) || memcmp(value,accept,value_length)) return -1;
        } else if (name == 22 && !strncasecmp((const char *)data+start,"Sec-WebSocket-Protocol",name)) {
            if (has_protocol++ || !protocol || !*protocol || value_length != strlen(protocol) || memcmp(value,protocol,value_length)) return -1;
        } else if (name == 24 && !strncasecmp((const char *)data+start,"Sec-WebSocket-Extensions",name)) return -1;
    }
    return -1;
}

static int utf8(core_ws_decoder_t *state, const uint8_t *input, size_t length) {
    for (size_t i=0;i<length;i++) {
        unsigned byte=input[i];
        if (state->utf_left) {
            if (byte < state->utf_min || byte > state->utf_max) return -1;
            state->utf_left--; state->utf_min=0x80; state->utf_max=0xbf;
        } else if (byte >= 0x80) {
            state->utf_min=0x80; state->utf_max=0xbf;
            if (byte >= 0xc2 && byte <= 0xdf) state->utf_left=1;
            else if (byte >= 0xe0 && byte <= 0xef) {
                state->utf_left=2;
                if (byte == 0xe0) state->utf_min=0xa0;
                if (byte == 0xed) state->utf_max=0x9f;
            } else if (byte >= 0xf0 && byte <= 0xf4) {
                state->utf_left=3;
                if (byte == 0xf0) state->utf_min=0x90;
                if (byte == 0xf4) state->utf_max=0x8f;
            } else return -1;
        }
    }
    return 0;
}

static int frame_header(core_ws_decoder_t *state) {
    const uint8_t *header=state->header;
    state->fin=header[0]>>7; state->opcode=header[0]&15;
    if ((header[0]&0x70) || (header[1]&0x80)) return -1;
    unsigned opcode=state->opcode,code=header[1]&127;
    if (opcode != 0 && opcode != 1 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10) return -1;
    uint64_t size=code;
    if (code >= 126) {
        size=0;
        for (size_t i=2;i<state->header_used;i++) size=(size<<8)|header[i];
        if ((code == 126 && size < 126) || (code == 127 && (size <= 65535 || (header[2]&128)))) return -1;
    }
    if (opcode >= 8) {
        if (!state->fin || size > 125 || (opcode == 8 && size == 1)) return -1;
        state->control_used=0;
    } else {
        if ((!opcode && !state->fragmented) || (opcode && state->fragmented)) return -1;
        if (opcode) {
            state->text=opcode == 1; state->message_length=0; state->utf_left=0;
            state->fragmented=!state->fin;
        }
        if (size > CORE_WS_MESSAGE_LIMIT-state->message_length) return -1;
        state->message_length+=size;
    }
    state->remaining=size; state->active=1;
    return 0;
}

static int frame_end(core_ws_decoder_t *state, core_ws_event_t *event) {
    unsigned opcode=state->opcode;
    if (opcode < 8 && state->fin) {
        if (state->text && state->utf_left) return -1;
        state->fragmented=0; state->message_length=0;
    }
    if (opcode == 8) {
        if (state->control_used >= 2) {
            unsigned code=((unsigned)state->control[0]<<8)|state->control[1];
            if (!((code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006) || (code >= 3000 && code <= 4999))) return -1;
            core_ws_decoder_t text={0};
            if (utf8(&text,state->control+2,state->control_used-2) || text.utf_left) return -1;
        }
        state->closed=1;
    }
    state->active=0; state->header_used=0;
    if (opcode >= 8) {
        *event=(core_ws_event_t){opcode,state->control,state->control_used};
        return 1;
    }
    return 0;
}

int core_ws_decode(core_ws_decoder_t *state, const uint8_t *input, size_t length, size_t *consumed, core_ws_event_t *event) {
    if (!state || !consumed || !event || (!input && length)) return -1;
    *consumed=0; *event=(core_ws_event_t){0};
    if (state->failed || (state->closed && length)) return -1;
    while (*consumed < length) {
        if (!state->active) {
            size_t needed=state->header_used < 2 ? 2 : (state->header[1]&127) == 126 ? 4 : (state->header[1]&127) == 127 ? 10 : 2;
            size_t take=needed-state->header_used;
            if (take > length-*consumed) take=length-*consumed;
            memcpy(state->header+state->header_used,input+*consumed,take);
            state->header_used+=take; *consumed+=take;
            if (state->header_used < 2) continue;
            needed=(state->header[1]&127) == 126 ? 4 : (state->header[1]&127) == 127 ? 10 : 2;
            if (state->header_used < needed) continue;
            if (frame_header(state)) goto invalid;
            if (!state->remaining) {
                int result=frame_end(state,event);
                if (result < 0) goto invalid;
                if (result) return result;
                continue;
            }
        }
        size_t take=length-*consumed;
        if ((uint64_t)take > state->remaining) take=(size_t)state->remaining;
        if (!take) break;
        const uint8_t *data=input+*consumed;
        if (state->opcode < 8) {
            if (state->text && utf8(state,data,take)) goto invalid;
            *event=(core_ws_event_t){state->text ? 1U : 2U,data,take};
        } else {
            memcpy(state->control+state->control_used,data,take); state->control_used+=take;
        }
        state->remaining-=take; *consumed+=take;
        if (!state->remaining) {
            core_ws_event_t control;
            int result=frame_end(state,&control);
            if (result < 0) goto invalid;
            if (result) { *event=control; return 1; }
        }
        if (event->length) return 1;
    }
    return 0;
invalid:
    state->failed=1; *event=(core_ws_event_t){0}; return -1;
}

static int error_field(char *error, size_t capacity, const char *field) {
    if (error && capacity) snprintf(error,capacity,"invalid WebSocket field %s",field);
    return -1;
}

static int integer(const char *text, unsigned maximum, unsigned *output) {
    if (!text || !*text) return -1;
    unsigned result=0;
    for (;*text;text++) {
        if (*text < '0' || *text > '9' || result > maximum/10) return -1;
        result=result*10+(unsigned)(*text-'0');
        if (result > maximum) return -1;
    }
    *output=result; return 0;
}

int core_ws_parameter(vless_config_t *config, const char *key, const char *value, char *error, size_t capacity) {
    if (!strcmp(key,"ed") || !strcmp(key,"maxearlydata")) {
        unsigned result;
        if (integer(value,16384,&result)) return error_field(error,capacity,"ed");
        config->ws_early_data=(int)result; config->ws_early_explicit=1; return 1;
    }
    if (!strcmp(key,"heartbeatperiod")) {
        unsigned result;
        if (integer(value,INT_MAX,&result)) return error_field(error,capacity,"heartbeatPeriod");
        config->ws_heartbeat_period=(int)result; return 1;
    }
    if (strcmp(key,"headers")) return 0;
    core_json_t *json=core_json_parse(value,error,capacity);
    if (!json) return error_field(error,capacity,"headers");
    int result=core_http_headers_parse(json,config->ws_headers,sizeof(config->ws_headers),error,capacity);
    for (const core_json_t *entry=json->child;!result && entry;entry=entry->next)
        if (!strncasecmp(entry->key,"sec-websocket-",14)) result=error_field(error,capacity,"headers");
    core_json_free(json);
    return result ? -1 : 1;
}

int core_ws_configure(vless_config_t *config, char *error, size_t capacity) {
    char *query=strchr(config->xhttp_path,'?');
    if (!query) return 0;
    char result[sizeof(config->xhttp_path)];
    size_t used=(size_t)(query-config->xhttp_path);
    memcpy(result,config->xhttp_path,used); result[used]=0;
    unsigned seen=0,embedded=0;
    for (const char *item=query+1;*item;) {
        const char *next=strchr(item,'&'),*end=next ? next : item+strlen(item);
        const char *equal=memchr(item,'=',(size_t)(end-item));
        char key[256]={0},value[256]={0};
        size_t key_length=equal ? (size_t)(equal-item) : (size_t)(end-item);
        memcpy(key,item,key_length); key[key_length]=0;
        char decoded[256];
        if (percent_decode(key,decoded,sizeof(decoded))) return error_field(error,capacity,"path");
        if (!strcmp(decoded,"ed")) {
            if (seen++ || !equal) return error_field(error,capacity,"path.ed");
            memcpy(value,equal+1,(size_t)(end-equal-1));
            if (percent_decode(value,decoded,sizeof(decoded)) || integer(decoded,16384,&embedded)) return error_field(error,capacity,"path.ed");
        } else {
            result[used++]=strchr(result,'?') ? '&' : '?';
            memcpy(result+used,item,(size_t)(end-item)); used+=(size_t)(end-item); result[used]=0;
        }
        if (!next) break;
        item=next+1;
    }
    if (seen && !config->ws_early_explicit) config->ws_early_data=(int)embedded;
    memcpy(config->xhttp_path,result,used+1);
    return 0;
}
