#include "grpc.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/crypto.h>

#define GRPC_BUFFER_LIMIT (16U*1024U*1024U)
struct core_grpc_chunk { core_grpc_chunk_t *next; size_t start, length, capacity; uint8_t data[]; };
static pthread_mutex_t grpc_buffer_lock=PTHREAD_MUTEX_INITIALIZER;
static size_t grpc_reserved;

static void clear_chunks(core_grpc_decoder_t *state) {
    while (state->head) {
        core_grpc_chunk_t *chunk=state->head; state->head=chunk->next;
        OPENSSL_cleanse(chunk->data,chunk->capacity); free(chunk);
    }
    state->tail=NULL;
}

static void release_message(core_grpc_decoder_t *state) {
    clear_chunks(state);
    pthread_mutex_lock(&grpc_buffer_lock); grpc_reserved-=state->reserved; state->reserved=0; pthread_mutex_unlock(&grpc_buffer_lock);
    state->ready=0;
}

void core_grpc_clear(core_grpc_decoder_t *state) {
    if (!state) return;
    release_message(state); OPENSSL_cleanse(state,sizeof(*state));
}

int core_grpc_pending(const core_grpc_decoder_t *state) { return state && state->ready; }

int core_grpc_read(core_grpc_decoder_t *state, uint8_t *output, size_t capacity, size_t *length) {
    if (!state || !length || (!output && capacity)) return -1;
    *length=0;
    if (state->failed) return -1;
    if (!state->ready) return 0;
    while (state->head && *length < capacity) {
        core_grpc_chunk_t *chunk=state->head; size_t take=chunk->length-chunk->start;
        if (take > capacity-*length) take=capacity-*length;
        memcpy(output+*length,chunk->data+chunk->start,take); OPENSSL_cleanse(chunk->data+chunk->start,take);
        *length+=take; chunk->start+=take;
        if (chunk->start == chunk->length) {
            state->head=chunk->next; if (!state->head) state->tail=NULL;
            OPENSSL_cleanse(chunk->data,chunk->capacity); free(chunk);
        }
    }
    if (!state->head) release_message(state);
    return 0;
}

static int append_data(core_grpc_decoder_t *state, const uint8_t *data, size_t length) {
    size_t remaining=state->field_remaining;
    while (length) {
        if (!state->tail || state->tail->length == state->tail->capacity) {
            size_t capacity=remaining > 8192 ? 8192 : remaining;
            core_grpc_chunk_t *chunk=malloc(sizeof(*chunk)+capacity);
            if (!chunk) return -1;
            *chunk=(core_grpc_chunk_t){.capacity=capacity};
            if (state->tail) state->tail->next=chunk; else state->head=chunk;
            state->tail=chunk;
        }
        size_t take=state->tail->capacity-state->tail->length;
        if (take > length) take=length;
        memcpy(state->tail->data+state->tail->length,data,take); state->tail->length+=take;
        length-=take; remaining-=take; data+=take;
    }
    return 0;
}

static int media_token(unsigned char value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || (value && strchr("!#$%&'*+-.^_`|~",value));
}

int core_grpc_content_type(const char *value, size_t length) {
    if (!value || length < 16 || strncasecmp(value,"application/grpc",16)) return 0;
    size_t offset=16;
    if (offset < length && value[offset] == '+') {
        size_t start=++offset;
        while (offset < length && media_token((unsigned char)value[offset])) offset++;
        if (offset == start) return 0;
    }
    while (offset < length) {
        while (offset < length && (value[offset] == ' ' || value[offset] == '\t')) offset++;
        if (offset == length || value[offset++] != ';') return 0;
        while (offset < length && (value[offset] == ' ' || value[offset] == '\t')) offset++;
        size_t start=offset;
        while (offset < length && media_token((unsigned char)value[offset])) offset++;
        if (start == offset || offset == length || value[offset++] != '=') return 0;
        if (offset < length && value[offset] == '"') {
            offset++; int closed=0;
            while (offset < length) {
                unsigned char byte=(unsigned char)value[offset++];
                if (byte == '"') { closed=1; break; }
                if (byte == '\\') { if (offset == length) return 0; byte=(unsigned char)value[offset++]; }
                if ((byte < 0x20 && byte != '\t') || byte == 0x7f) return 0;
            }
            if (!closed) return 0;
        } else {
            start=offset; while (offset < length && media_token((unsigned char)value[offset])) offset++;
            if (start == offset) return 0;
        }
    }
    return 1;
}

int core_grpc_response_headers(const core_hpack_headers_t *headers, int initial, int end, char *error, size_t capacity) {
    const char *reason=NULL; int status=0;
    if (initial && headers->status != 200) {
        status=headers->status == 400 ? 13 : headers->status == 401 ? 16 : headers->status == 403 ? 7 : headers->status == 404 ? 12 :
            headers->status == 429 || headers->status == 502 || headers->status == 503 || headers->status == 504 ? 14 : 2;
        if (end && headers->has_grpc_status) status=headers->grpc_status;
        if (!status) status=2;
    } else if (initial && (headers->content_type_seen != 1 || !headers->grpc_content_type)) reason="gRPC response has invalid content-type";
    else if (!initial && headers->content_type_seen) reason="gRPC content-type is not permitted in trailers";
    else if (headers->has_grpc_status && !end) reason="gRPC status is not terminal";
    else if (end && !headers->has_grpc_status) reason="gRPC response ended without grpc-status";
    else if (end) status=headers->grpc_status;
    if (reason) { if (error && capacity) snprintf(error,capacity,"%s",reason); return -1; }
    if (status) {
        if (error && capacity) {
            if (initial && headers->status != 200) snprintf(error,capacity,"grpc h2 non-200: %d mapped to gRPC grpc-status=%d",headers->status,status);
            else snprintf(error,capacity,"gRPC peer returned grpc-status=%d",status < 0 || status > 16 ? 2 : status);
        }
        return -1;
    }
    return 0;
}

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
    if (state->ready) return 1;
    while (*consumed < length) {
        if (state->header_used < 5) {
            size_t take=5-state->header_used;
            if (take > length-*consumed) take=length-*consumed;
            memcpy(state->header+state->header_used,input+*consumed,take);
            state->header_used+=(unsigned)take; *consumed+=take;
            if (state->header_used < 5) continue;
            state->remaining=((size_t)state->header[1]<<24)|((size_t)state->header[2]<<16)|((size_t)state->header[3]<<8)|state->header[4];
            if (state->header[0] || state->remaining > 16U*1024U*1024U) goto invalid;
            state->phase=0; state->shift=0; state->varint=0; state->depth=0;
            if (!state->multi && state->remaining) {
                pthread_mutex_lock(&grpc_buffer_lock);
                if (state->remaining > GRPC_BUFFER_LIMIT-grpc_reserved) {
                    pthread_mutex_unlock(&grpc_buffer_lock); state->failed=2; errno=ENOBUFS; return -1;
                }
                state->reserved=state->remaining; grpc_reserved+=state->reserved; pthread_mutex_unlock(&grpc_buffer_lock);
            }
            if (!state->remaining) {
                state->header_used=0;
                if (!state->multi) { state->ready=1; return 1; }
                continue;
            }
            if (*consumed == length) break;
        }
        if (state->phase == 2) {
            size_t take=state->field_remaining;
            if (take > length-*consumed) take=length-*consumed;
            if (!state->depth && state->field == 1 && state->wire == 2) {
                if (state->multi) { *payload=input+*consumed; *payload_length=take; }
                else if (append_data(state,input+*consumed,take)) { state->failed=3; release_message(state); errno=ENOMEM; return -1; }
            }
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
                    } else if (state->wire == 3) {
                        if (state->depth == sizeof(state->groups)/sizeof(*state->groups)) goto invalid;
                        state->groups[state->depth++]=state->field;
                    } else if (state->wire == 4) {
                        if (!state->depth || state->groups[state->depth-1] != state->field) goto invalid;
                        state->depth--;
                    } else goto invalid;
                } else if (state->phase == 1) {
                    if (value > state->remaining) goto invalid;
                    if (!state->depth && state->field == 1 && !state->multi) clear_chunks(state);
                    state->field_remaining=(size_t)value; state->phase=value ? 2 : 0;
                } else state->phase=0;
            }
        }
        if (!state->remaining) {
            if (state->phase || state->shift || state->depth) goto invalid;
            state->header_used=0;
            if (!state->multi) { state->ready=1; return 1; }
        }
        if (*payload_length) return 1;
    }
    return 0;
invalid:
    state->failed=1; release_message(state); *payload=NULL; *payload_length=0; return -1;
}
