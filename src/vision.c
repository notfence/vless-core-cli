#include "vision.h"
#include "core_random.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define CMD_CONTINUE 0
#define CMD_END 1
#define CMD_DIRECT 2

#define VISION_DEFAULT_PAD_PACKETS 8
#define VISION_MAX_PAD_PACKETS 32

// Follow xray's long/short padding profile for early Vision packets.
#define VISION_LONG_PAD_THRESHOLD 900
#define VISION_LONG_PAD_RANDOM 500
#define VISION_LONG_PAD_BASE 900
#define VISION_SHORT_PAD_RANDOM 256

static int append_stash(vision_unpad_t *ctx,const uint8_t *data,size_t length) {
    core_relay_buffer_t stash={.data=ctx->stash,.length=ctx->stash_len,.capacity=ctx->stash_cap,.memory=ctx->memory};
    int result=core_relay_buffer_append(&stash,data,length);
    ctx->stash=stash.data; ctx->stash_len=stash.length; ctx->stash_cap=stash.capacity;
    return result;
}

static int read_pad_packets_env(void) {
    const char *raw = getenv("VLESS_VISION_PAD_PACKETS");
    if (raw == NULL || raw[0] == '\0') {
        return VISION_DEFAULT_PAD_PACKETS;
    }

    char *end = NULL;
    errno = 0;
    long parsed = strtol(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0') {
        return VISION_DEFAULT_PAD_PACKETS;
    }
    if (parsed < 1) {
        return 1;
    }
    if (parsed > VISION_MAX_PAD_PACKETS) {
        return VISION_MAX_PAD_PACKETS;
    }
    return (int)parsed;
}

static int rand_u16_mod(uint16_t mod, uint16_t *sampled) {
    if (mod == 0) {
        *sampled=0; return 0;
    }
    uint32_t value;
    if (core_random_range(0,mod-1,&value)) return -1;
    *sampled=(uint16_t)value; return 0;
}

static int vision_padding_len(size_t content_len, int long_padding, uint16_t *sampled) {
    if (long_padding && content_len < VISION_LONG_PAD_THRESHOLD) {
        uint16_t extra;
        if (rand_u16_mod(VISION_LONG_PAD_RANDOM,&extra)) return -1;
        size_t want = (size_t)VISION_LONG_PAD_BASE + (size_t)extra - content_len;
        if ((long)want < 0) {
            want = 0;
        }
        if (want > 0xFFFF) {
            want = 0xFFFF;
        }
        *sampled=(uint16_t)want; return 0;
    }
    return rand_u16_mod(VISION_SHORT_PAD_RANDOM,sampled);
}

enum { VISION_HELLO_PREFIX, VISION_HELLO_CIPHERS, VISION_HELLO_COMPRESSION_LENGTH,
       VISION_HELLO_COMPRESSION, VISION_HELLO_EXTENSIONS_LENGTH, VISION_HELLO_EXTENSION_HEADER, VISION_HELLO_EXTENSION };

static unsigned vision_word(const uint8_t *data) { return ((unsigned)data[0]<<8)|data[1]; }

static int vision_hello_body(vision_tls_reader_t *state, int server, const uint8_t *data, size_t length) {
    static const uint8_t retry_random[]={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    for (size_t offset=0;offset<length;) {
        size_t count=length-offset;
        if (state->phase == VISION_HELLO_PREFIX) {
            size_t need=state->prefix_need-state->prefix_used;
            if (count > need) count=need;
            memcpy(state->prefix+state->prefix_used,data+offset,count); state->prefix_used+=count;
            state->message_left-=(uint32_t)count; offset+=count;
            if (state->prefix_used != state->prefix_need) continue;
            if (state->prefix_need == 35) {
                if (state->prefix[0] != 3 || !state->prefix[1] || state->prefix[1] > 3 || (server && state->prefix[1] != 3) || state->prefix[34] > 32) return -1;
                state->prefix_need=35+state->prefix[34]+(server ? 3 : 2);
                if (state->prefix_need-state->prefix_used > state->message_left) return -1;
                continue;
            }
            unsigned word=vision_word(state->prefix+35+state->prefix[34]);
            if (server) {
                if (state->prefix[state->prefix_need-1]) return -1;
                state->cipher=word; state->retry=!memcmp(state->prefix+2,retry_random,sizeof(retry_random));
                state->phase=VISION_HELLO_EXTENSIONS_LENGTH;
            } else {
                if (word < 2 || (word&1) || word > state->message_left) return -1;
                state->skip_left=word; state->phase=VISION_HELLO_CIPHERS;
            }
        } else if (state->phase == VISION_HELLO_CIPHERS || state->phase == VISION_HELLO_COMPRESSION) {
            if (count > state->skip_left) count=state->skip_left;
            if (state->phase == VISION_HELLO_COMPRESSION && memchr(data+offset,0,count)) state->compression_seen=1;
            state->skip_left-=(uint32_t)count; state->message_left-=(uint32_t)count; offset+=count;
            if (!state->skip_left) {
                if (state->phase == VISION_HELLO_COMPRESSION && !state->compression_seen) return -1;
                state->phase=state->phase == VISION_HELLO_CIPHERS ? VISION_HELLO_COMPRESSION_LENGTH : VISION_HELLO_EXTENSIONS_LENGTH;
            }
        } else if (state->phase == VISION_HELLO_COMPRESSION_LENGTH) {
            state->skip_left=data[offset++]; state->message_left--;
            if (!state->skip_left || state->skip_left > state->message_left) return -1;
            state->phase=VISION_HELLO_COMPRESSION;
        } else if (state->phase == VISION_HELLO_EXTENSION) {
            if (count > state->extension_left) count=state->extension_left;
            if (server && state->extension == 43) {
                memcpy(state->field+state->field_used,data+offset,count); state->field_used+=count;
            }
            state->message_left-=(uint32_t)count; state->extensions_left-=(uint32_t)count;
            state->extension_left-=(uint32_t)count; offset+=count;
            if (!state->extension_left) {
                if (server && state->extension == 43) state->version=vision_word(state->field);
                state->field_used=0; state->phase=VISION_HELLO_EXTENSION_HEADER;
            }
        } else {
            size_t need=state->phase == VISION_HELLO_EXTENSIONS_LENGTH ? 2 : 4;
            if (state->phase == VISION_HELLO_EXTENSION_HEADER && state->extensions_left < need-state->field_used) return -1;
            if (count > need-state->field_used) count=need-state->field_used;
            memcpy(state->field+state->field_used,data+offset,count); state->field_used+=count;
            state->message_left-=(uint32_t)count; offset+=count;
            if (state->phase == VISION_HELLO_EXTENSION_HEADER) state->extensions_left-=(uint32_t)count;
            if (state->field_used != need) continue;
            state->field_used=0;
            if (state->phase == VISION_HELLO_EXTENSIONS_LENGTH) {
                state->extensions_left=vision_word(state->field);
                if (state->extensions_left != state->message_left) return -1;
                state->phase=VISION_HELLO_EXTENSION_HEADER;
            } else {
                state->extension=vision_word(state->field); state->extension_left=vision_word(state->field+2);
                if (state->extension_left > state->extensions_left) return -1;
                if (server && state->extension == 43) {
                    if (state->version_seen || state->extension_left != 2) return -1;
                    state->version_seen=1;
                }
                if (state->extension_left) state->phase=VISION_HELLO_EXTENSION;
            }
        }
    }
    return 0;
}

static int vision_tls_handshake(vision_wrap_t *ctx, vision_tls_reader_t *state, int server, const uint8_t *data, size_t length) {
    for (size_t offset=0;offset<length;) {
        size_t count=length-offset;
        if (state->message_used < 4) {
            if (count > 4-state->message_used) count=4-state->message_used;
            memcpy(state->message+state->message_used,data+offset,count); state->message_used+=count; offset+=count;
            if (state->message_used < 4) continue;
            state->message_left=((uint32_t)state->message[1]<<16)|((uint32_t)state->message[2]<<8)|state->message[3];
            if (state->message_left > 1024U*1024U) return -1;
            state->interested=state->message[0] == (server ? 2 : 1);
            if (state->interested) {
                if (state->message_left < 38) return -1;
                state->prefix_used=state->field_used=0; state->prefix_need=35; state->phase=VISION_HELLO_PREFIX;
                state->version=state->cipher=state->version_seen=state->retry=state->compression_seen=0;
            }
            if (!state->message_left) state->message_used=0;
            continue;
        }
        if (count > state->message_left) count=state->message_left;
        if (state->interested) {
            if (vision_hello_body(state,server,data+offset,count)) return -1;
        } else state->message_left-=(uint32_t)count;
        offset+=count;
        if (!state->message_left) {
            if (state->interested) {
                int complete=(state->phase == VISION_HELLO_EXTENSION_HEADER && !state->extensions_left && !state->field_used) ||
                    (state->phase == VISION_HELLO_EXTENSIONS_LENGTH && !state->field_used);
                if (!complete) return -1;
                if (!server) ctx->client_hello_seen=1;
                else if (!state->retry) {
                    ctx->server_hello_seen=1;
                    ctx->tls13_confirmed=state->version == 0x0304 && state->cipher >= 0x1301 && state->cipher <= 0x1304;
                }
            }
            state->message_used=0;
        }
    }
    return 0;
}

void vision_observe_tls(vision_wrap_t *ctx, int server, const uint8_t *data, size_t length) {
    vision_tls_reader_t *state=server ? &ctx->server_tls : &ctx->client_tls;
    state->last_application=0;
    if (ctx->tls_disabled || !length) return;
    for (size_t offset=0;offset<length;) {
        size_t count=length-offset;
        if (state->record_used < 5) {
            state->last_application=0;
            if (count > 5-state->record_used) count=5-state->record_used;
            memcpy(state->record+state->record_used,data+offset,count); state->record_used+=count; offset+=count;
            if (state->record[0] < 20 || state->record[0] > 23) { ctx->tls_disabled=1; return; }
            if (state->record_used < 5) continue;
            state->record_left=vision_word(state->record+3);
            if (state->record[1] != 3 || !state->record[2] || state->record[2] > 3 || state->record_left > 18432 ||
                (state->record[0] == 23 && (state->record[2] != 3 || (ctx->tls13_confirmed && state->record_left < 17))) ||
                (state->record[0] == 22 && !state->record_left) || (state->record[0] == 20 && state->record_left != 1) ||
                (state->record[0] != 22 && state->record[0] != 20 && state->message_used)) { ctx->tls_disabled=1; return; }
            if (state->record_left) continue;
        } else {
            if (count > state->record_left) count=state->record_left;
            if ((state->record[0] == 22 && vision_tls_handshake(ctx,state,server,data+offset,count)) ||
                (state->record[0] == 20 && data[offset] != 1)) { ctx->tls_disabled=1; return; }
            state->record_left-=(uint32_t)count; offset+=count;
            if (state->record_left) continue;
        }
        state->records++; state->last_application=state->record[0] == 23 && vision_word(state->record+3) != 0;
        if (!server && state->last_application && ctx->client_tls_app_records < 0x7fffffff) ctx->client_tls_app_records++;
        state->record_used=0;
    }
}

static int vision_build_block(vision_wrap_t *ctx, uint8_t command, const uint8_t *content, size_t content_len, int long_padding, core_relay_buffer_t *out) {
    if (content_len > 0xFFFF) {
        return -1;
    }

    uint16_t content16 = (uint16_t)content_len;
    uint16_t padding16;
    if (vision_padding_len(content_len,long_padding,&padding16)) return -1;
    size_t prefix = ctx->uuid_sent ? 0 : 16;
    size_t total = prefix + 1 + 2 + 2 + content_len + (size_t)padding16;

    if (core_relay_buffer_reserve(out,total) != 1) return -1;
    uint8_t *buf=out->data;

    size_t off = 0;
    if (!ctx->uuid_sent) {
        memcpy(buf + off, ctx->uuid, 16);
        off += 16;
    }

    buf[off++] = command;
    buf[off++] = (uint8_t)(content16 >> 8);
    buf[off++] = (uint8_t)(content16 & 0xFF);
    buf[off++] = (uint8_t)(padding16 >> 8);
    buf[off++] = (uint8_t)(padding16 & 0xFF);

    if (content_len > 0) {
        memcpy(buf + off, content, content_len);
        off += content_len;
    }

    if (padding16 > 0) {
        if (core_random_fill(buf + off, padding16)) {
            int cause=errno; OPENSSL_cleanse(buf,out->capacity); core_relay_buffer_clear(out); errno=cause; return -1;
        }
        off += padding16;
    }

    ctx->uuid_sent=1; out->length=off;
    return 0;
}

void vision_wrap_init(vision_wrap_t *ctx, const uint8_t uuid[16]) {
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->uuid, uuid, 16);
    ctx->uuid_sent = 0;
    ctx->padding_active = 1;
    ctx->packets_left = read_pad_packets_env();
    ctx->bootstrap_sent = 0;
}

int vision_wrap_bootstrap_buffer(vision_wrap_t *ctx,core_relay_buffer_t *out) {
    core_relay_buffer_clear(out);

    if (!ctx->padding_active || ctx->bootstrap_sent) {
        return 0;
    }
    int result=vision_build_block(ctx,CMD_CONTINUE,NULL,0,1,out);
    if (!result) ctx->bootstrap_sent=1;
    return result;
}

int vision_wrap_bootstrap(vision_wrap_t *ctx,uint8_t **out,size_t *out_len) {
    core_relay_buffer_t buffer={0}; int result=vision_wrap_bootstrap_buffer(ctx,&buffer);
    if (result) core_relay_buffer_clear(&buffer);
    *out=buffer.data; *out_len=buffer.length; return result;
}

static int vision_wrap_chunk(vision_wrap_t *ctx, const uint8_t *in, size_t in_len, core_relay_buffer_t *out) {

    if (in_len == 0) {
        return 0;
    }

    if (!ctx->padding_active) {
        return core_relay_buffer_append(out,in,in_len);
    }

    size_t payload_len = in_len;
    if (payload_len > 0xFFFF) return -1;

    uint32_t before=ctx->client_tls.records;
    vision_observe_tls(ctx,0,in,payload_len);
    uint32_t complete=ctx->tls_disabled ? 1 : ctx->client_tls.records-before;
    int partial=!ctx->tls_disabled && (ctx->client_tls.record_used || ctx->client_tls.message_used);
    uint8_t command=!partial && complete && complete >= (uint32_t)ctx->packets_left ? CMD_END : CMD_CONTINUE;
    if (!ctx->tls_disabled && ctx->client_hello_seen && ctx->server_hello_seen && ctx->client_tls.last_application)
        command=ctx->tls13_confirmed ? CMD_DIRECT : CMD_END;

    int long_padding = (payload_len < VISION_LONG_PAD_THRESHOLD) ? 1 : 0;
    if (vision_build_block(ctx, command, in, payload_len, long_padding, out) != 0) {
        return -1;
    }

    ctx->packets_left=complete >= (uint32_t)ctx->packets_left ? 0 : ctx->packets_left-(int)complete;
    if (command != CMD_CONTINUE) {
        ctx->padding_active = 0;
    }
    if (command == CMD_DIRECT) {
        ctx->direct_sent = 1;
    }
    return 0;
}

int vision_wrap_payload_buffer(vision_wrap_t *ctx, const uint8_t *in, size_t in_len, core_relay_buffer_t *out) {
    core_relay_buffer_clear(out);
    if (in_len <= 0xFFFF || !ctx->padding_active) {
        return vision_wrap_chunk(ctx, in, in_len, out);
    }
    for (size_t offset = 0; offset < in_len;) {
        size_t length = in_len - offset;
        if (ctx->padding_active && length > 0xFFFF) length = 0xFFFF;
        core_relay_buffer_t chunk={.memory=out->memory};
        if (vision_wrap_chunk(ctx, in + offset, length, &chunk) != 0 ||
            core_relay_buffer_append(out,chunk.data,chunk.length) != 0) {
            core_relay_buffer_clear(&chunk); core_relay_buffer_clear(out);
            return -1;
        }
        core_relay_buffer_clear(&chunk);
        offset += length;
    }
    return 0;
}

int vision_wrap_payload(vision_wrap_t *ctx,const uint8_t *in,size_t in_len,uint8_t **out,size_t *out_len) {
    core_relay_buffer_t buffer={0}; int result=vision_wrap_payload_buffer(ctx,in,in_len,&buffer);
    if (result) core_relay_buffer_clear(&buffer);
    *out=buffer.data; *out_len=buffer.length; return result;
}

size_t vision_wrap_buffer_bound(size_t length) {
    if (length <= 65535) return core_relay_capacity(length+21+(length < 900 ? 1399-length : 255));
    size_t parts=length/65535+(length%65535 != 0),tail=(length-1)%65535+1;
    if (parts > (SIZE_MAX-16-1399)/260 || length > SIZE_MAX-16-1399-parts*260) return SIZE_MAX;
    size_t total=length+16+parts*5+(parts-1)*255+(tail < 900 ? 1399-tail : 255);
    size_t capacity=core_relay_capacity(total),chunk=core_relay_capacity(65535+21+255);
    if (capacity > SIZE_MAX-capacity/2 || capacity+capacity/2 > SIZE_MAX-chunk) return SIZE_MAX;
    return capacity+capacity/2+chunk;
}

void vision_unpad_init(vision_unpad_t *ctx, const uint8_t uuid[16]) {
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->uuid, uuid, 16);
    ctx->remaining_command = -1;
    ctx->remaining_content = -1;
    ctx->remaining_padding = -1;
}

int vision_unpad_complete(const vision_unpad_t *ctx) {
    return ctx && !ctx->stash_len && ctx->remaining_content <= 0 && ctx->remaining_padding <= 0 &&
        (ctx->remaining_command == -1 || (ctx->remaining_command == 5 && ctx->completed_block));
}

int vision_unpad_is_raw(const vision_unpad_t *ctx) {
    return vision_unpad_complete(ctx) && (ctx->current_command == CMD_END || ctx->current_command == CMD_DIRECT);
}

size_t vision_unpad_buffer_bound(const vision_unpad_t *ctx,size_t length) {
    if (length > SIZE_MAX-ctx->stash_len) return SIZE_MAX;
    size_t capacity=core_relay_capacity(length+ctx->stash_len);
    if (capacity > SIZE_MAX-capacity/2 || capacity+capacity/2 > SIZE_MAX-capacity) return SIZE_MAX;
    size_t processing=capacity+capacity+capacity/2;
    if (ctx->stash_cap > capacity) {
        if (ctx->stash_cap > SIZE_MAX-capacity-capacity/2) return SIZE_MAX;
        processing=ctx->stash_cap+capacity+capacity/2;
    } else if (ctx->stash_cap > capacity/2) {
        size_t growing=ctx->stash_cap+capacity;
        if (growing > processing) processing=growing;
    }
    return processing;
}

void vision_unpad_free(vision_unpad_t *ctx) {
    if (ctx->stash != NULL) {
        if (ctx->memory) core_buffer_free(ctx->memory,ctx->stash,ctx->stash_cap);
        else free(ctx->stash);
        ctx->stash = NULL;
    }
    ctx->stash_len = 0;
    ctx->stash_cap = 0;
}

int vision_unpad_feed_buffer(vision_unpad_t *ctx, const uint8_t *in, size_t in_len, core_relay_buffer_t *out, int *switch_to_direct) {
    core_relay_buffer_clear(out);
    if (switch_to_direct != NULL) {
        *switch_to_direct = 0;
    }

    if (in_len > 0 && append_stash(ctx,in,in_len) != 0) {
        return -1;
    }

    size_t i = 0;
    while (i < ctx->stash_len) {
        if (ctx->remaining_command == -1 && ctx->remaining_content == -1 && ctx->remaining_padding == -1) {
            size_t remain = ctx->stash_len - i;
            int padding_ended = ctx->current_command == CMD_END || ctx->current_command == CMD_DIRECT;
            if (!padding_ended && remain < 16 && !memcmp(ctx->stash+i,ctx->uuid,remain)) {
                break;
            }
            if (padding_ended || remain < 16 || memcmp(ctx->stash + i, ctx->uuid, 16) != 0) {
                if (core_relay_buffer_append(out,ctx->stash+i,remain) != 0) {
                    core_relay_buffer_clear(out);
                    return -1;
                }
                i = ctx->stash_len;
                break;
            }
            i += 16;
            ctx->remaining_command = 5;
            ctx->remaining_content = 0;
            ctx->remaining_padding = 0;
            ctx->current_command = 0;
        }

        while (ctx->remaining_command > 0) {
            if (i >= ctx->stash_len) {
                goto done;
            }
            uint8_t b = ctx->stash[i++];
            switch (ctx->remaining_command) {
                case 5:
                    ctx->current_command = b;
                    break;
                case 4:
                    ctx->remaining_content = ((int32_t)b) << 8;
                    break;
                case 3:
                    ctx->remaining_content |= b;
                    break;
                case 2:
                    ctx->remaining_padding = ((int32_t)b) << 8;
                    break;
                case 1:
                    ctx->remaining_padding |= b;
                    break;
                default:
                    break;
            }
            ctx->remaining_command--;
        }

        if (ctx->remaining_content > 0) {
            size_t remain = ctx->stash_len - i;
            size_t take = remain;
            if (take > (size_t)ctx->remaining_content) {
                take = (size_t)ctx->remaining_content;
            }
            if (core_relay_buffer_append(out,ctx->stash+i,take) != 0) {
                core_relay_buffer_clear(out);
                return -1;
            }
            i += take;
            ctx->remaining_content -= (int32_t)take;
        }

        if (ctx->remaining_content == 0 && ctx->remaining_padding > 0) {
            size_t remain = ctx->stash_len - i;
            size_t skip = remain;
            if (skip > (size_t)ctx->remaining_padding) {
                skip = (size_t)ctx->remaining_padding;
            }
            i += skip;
            ctx->remaining_padding -= (int32_t)skip;
        }

        if (ctx->remaining_command <= 0 && ctx->remaining_content <= 0 && ctx->remaining_padding <= 0) {
            ctx->completed_block=1;
            if (ctx->current_command == CMD_CONTINUE) {
                ctx->remaining_command = 5;
                ctx->remaining_content = 0;
                ctx->remaining_padding = 0;
            } else {
                if (ctx->current_command == CMD_DIRECT && switch_to_direct != NULL) {
                    *switch_to_direct = 1;
                }
                ctx->remaining_command = -1;
                ctx->remaining_content = -1;
                ctx->remaining_padding = -1;
                if (i < ctx->stash_len) {
                    size_t remain = ctx->stash_len - i;
                    if (core_relay_buffer_append(out,ctx->stash+i,remain) != 0) {
                        core_relay_buffer_clear(out);
                        return -1;
                    }
                    i = ctx->stash_len;
                }
                break;
            }
        }
    }

done:
    if (i > 0) {
        size_t left = ctx->stash_len - i;
        memmove(ctx->stash, ctx->stash + i, left);
        ctx->stash_len = left;
    }

    if (ctx->memory && !ctx->stash_len) vision_unpad_free(ctx);
    return 0;
}

int vision_unpad_feed(vision_unpad_t *ctx,const uint8_t *in,size_t in_len,uint8_t **out,size_t *out_len,int *direct) {
    core_relay_buffer_t buffer={0}; int result=vision_unpad_feed_buffer(ctx,in,in_len,&buffer,direct);
    if (result) core_relay_buffer_clear(&buffer);
    *out=buffer.data; *out_len=buffer.length; return result;
}
