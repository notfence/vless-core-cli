#include "grpc.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static int parameter_error(char *error, size_t capacity, const char *key) {
    if (error && capacity) snprintf(error,capacity,"invalid gRPC field %s",key);
    return -1;
}

int core_grpc_parameter(vless_config_t *config, const char *key, const char *value, char *error, size_t capacity) {
    if (!strcmp(key,"useragent")) {
        if (!*value || strlen(value) >= sizeof(config->grpc_user_agent)) return parameter_error(error,capacity,key);
        for (const unsigned char *byte=(const unsigned char *)value;*byte;byte++) if (*byte < 0x20 || *byte == 0x7f) return parameter_error(error,capacity,key);
        memcpy(config->grpc_user_agent,value,strlen(value)+1); return 1;
    }
    if (!strcmp(key,"permitwithoutstream")) {
        if (strcmp(value,"0") && strcmp(value,"1") && strcasecmp(value,"true") && strcasecmp(value,"false")) return parameter_error(error,capacity,key);
        config->grpc_permit_without_stream=!strcmp(value,"1") || !strcasecmp(value,"true"); return 1;
    }
    int *output=NULL; unsigned maximum=INT_MAX,minimum=0;
    if (!strcmp(key,"idletimeout")) output=&config->grpc_idle_timeout;
    else if (!strcmp(key,"healthchecktimeout")) output=&config->grpc_health_timeout;
    else if (!strcmp(key,"initialwindowssize")) { output=&config->grpc_initial_window; maximum=256U*1024U; minimum=1; }
    if (!output) return 0;
    unsigned result=0;
    if (!*value) return parameter_error(error,capacity,key);
    for (const char *byte=value;*byte;byte++) {
        if (*byte < '0' || *byte > '9' || result > maximum/10) return parameter_error(error,capacity,key);
        result=result*10+(unsigned)(*byte-'0');
        if (result > maximum) return parameter_error(error,capacity,key);
    }
    if (result < minimum) return parameter_error(error,capacity,key);
    *output=(int)result; return 1;
}

int core_grpc_complete(const core_grpc_decoder_t *state) {
    return state && !state->failed && !state->header_used;
}

int core_grpc_decode(core_grpc_decoder_t *state, const uint8_t *input, size_t length, size_t *consumed, const uint8_t **payload, size_t *payload_length) {
    if (!state || !consumed || !payload || !payload_length || (!input && length)) return -1;
    *consumed=0; *payload=NULL; *payload_length=0;
    if (state->failed) return -1;
    while (*consumed < length) {
        if (state->header_used < 5) {
            size_t take=5-state->header_used;
            if (take > length-*consumed) take=length-*consumed;
            memcpy(state->header+state->header_used,input+*consumed,take);
            state->header_used+=(unsigned)take; *consumed+=take;
            if (state->header_used < 5) continue;
            state->remaining=((size_t)state->header[1]<<24)|((size_t)state->header[2]<<16)|((size_t)state->header[3]<<8)|state->header[4];
            if (state->header[0] || state->remaining > 16U*1024U*1024U) goto invalid;
            state->phase=0; state->found=0; state->shift=0; state->varint=0;
            if (!state->remaining) { state->header_used=0; continue; }
            if (*consumed == length) break;
        }
        if (state->phase == 2) {
            size_t take=state->field_remaining;
            if (take > length-*consumed) take=length-*consumed;
            if (state->field == 1 && state->wire == 2) { *payload=input+*consumed; *payload_length=take; }
            state->field_remaining-=take; state->remaining-=take; *consumed+=take;
            if (!state->field_remaining) state->phase=0;
        } else {
            unsigned byte=input[(*consumed)++]; state->remaining--;
            if (state->shift > 63 || (state->shift == 63 && (byte&0xfe))) goto invalid;
            state->varint|=(uint64_t)(byte&127)<<state->shift;
            if (byte&128) state->shift+=7;
            else {
                uint64_t value=state->varint; state->varint=0; state->shift=0;
                if (state->phase == 0) {
                    if (!(value>>3) || value>>3 > 0x1fffffff) goto invalid;
                    state->field=(unsigned)(value>>3); state->wire=(unsigned)(value&7);
                    if (!state->wire) state->phase=3;
                    else if (state->wire == 2) state->phase=1;
                    else if (state->wire == 1 || state->wire == 5) {
                        state->field_remaining=state->wire == 1 ? 8 : 4;
                        if (state->field_remaining > state->remaining) goto invalid;
                        state->phase=2;
                    } else goto invalid;
                } else if (state->phase == 1) {
                    if (value > state->remaining) goto invalid;
                    if (state->field == 1) state->found=1;
                    state->field_remaining=(size_t)value; state->phase=value ? 2 : 0;
                } else state->phase=0;
            }
        }
        if (!state->remaining) {
            if (state->phase || state->shift || !state->found) goto invalid;
            state->header_used=0;
        }
        if (*payload_length) return 1;
    }
    return 0;
invalid:
    state->failed=1; *payload=NULL; *payload_length=0; return -1;
}
