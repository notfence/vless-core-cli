#include "vision.h"

#include <openssl/rand.h>

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

static int append_bytes(uint8_t **buf, size_t *len, size_t *cap, const uint8_t *src, size_t n) {
    if (n == 0) {
        return 0;
    }
    if (*len + n > *cap) {
        size_t new_cap = (*cap == 0) ? 512 : *cap;
        while (new_cap < *len + n) {
            new_cap *= 2;
        }
        uint8_t *tmp = (uint8_t *)realloc(*buf, new_cap);
        if (tmp == NULL) {
            return -1;
        }
        *buf = tmp;
        *cap = new_cap;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    return 0;
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

static uint16_t rand_u16_mod(uint16_t mod) {
    if (mod == 0) {
        return 0;
    }
    uint16_t v = 0;
    if (RAND_bytes((uint8_t *)&v, sizeof(v)) == 1) {
        return (uint16_t)(v % mod);
    }
    return (uint16_t)(rand() % mod);
}

static uint16_t vision_padding_len(size_t content_len, int long_padding) {
    if (long_padding && content_len < VISION_LONG_PAD_THRESHOLD) {
        uint16_t extra = rand_u16_mod(VISION_LONG_PAD_RANDOM);
        size_t want = (size_t)VISION_LONG_PAD_BASE + (size_t)extra - content_len;
        if ((long)want < 0) {
            want = 0;
        }
        if (want > 0xFFFF) {
            want = 0xFFFF;
        }
        return (uint16_t)want;
    }
    return rand_u16_mod(VISION_SHORT_PAD_RANDOM);
}

static int vision_scan_tls_records(const uint8_t *in, size_t len, int *has_client_hello, int *app_records) {
    size_t pos = 0;
    int found_client_hello = 0;
    int found_app_records = 0;

    if (has_client_hello != NULL) {
        *has_client_hello = 0;
    }
    if (app_records != NULL) {
        *app_records = 0;
    }
    if (in == NULL || len < 5) {
        return 0;
    }

    while (pos < len) {
        if (len - pos < 5) {
            return 0;
        }

        uint8_t rtype = in[pos];
        uint8_t vmajor = in[pos + 1];
        size_t rlen = ((size_t)in[pos + 3] << 8) | in[pos + 4];
        if ((rtype != 0x14 && rtype != 0x16 && rtype != 0x17) || vmajor != 0x03 || rlen > 18432 || pos + 5 + rlen > len) {
            return 0;
        }

        if (rtype == 0x16 && rlen >= 4 && in[pos + 5] == 0x01) {
            found_client_hello = 1;
        } else if (rtype == 0x17) {
            found_app_records++;
        }

        pos += 5 + rlen;
    }

    if (has_client_hello != NULL) {
        *has_client_hello = found_client_hello;
    }
    if (app_records != NULL) {
        *app_records = found_app_records;
    }
    return 1;
}

static int vision_build_block(vision_wrap_t *ctx, uint8_t command, const uint8_t *content, size_t content_len, int long_padding, uint8_t **out,
                              size_t *out_len) {
    if (content_len > 0xFFFF) {
        return -1;
    }

    uint16_t content16 = (uint16_t)content_len;
    uint16_t padding16 = vision_padding_len(content_len, long_padding);
    size_t prefix = ctx->uuid_sent ? 0 : 16;
    size_t total = prefix + 1 + 2 + 2 + content_len + (size_t)padding16;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == NULL) {
        return -1;
    }

    size_t off = 0;
    if (!ctx->uuid_sent) {
        memcpy(buf + off, ctx->uuid, 16);
        off += 16;
        ctx->uuid_sent = 1;
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
        if (RAND_bytes(buf + off, padding16) != 1) {
            memset(buf + off, 0, padding16);
        }
        off += padding16;
    }

    *out = buf;
    *out_len = off;
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

int vision_wrap_bootstrap(vision_wrap_t *ctx, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    if (!ctx->padding_active || ctx->bootstrap_sent) {
        return 0;
    }
    ctx->bootstrap_sent = 1;
    return vision_build_block(ctx, CMD_CONTINUE, NULL, 0, 1, out, out_len);
}

int vision_wrap_payload(vision_wrap_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    if (in_len == 0) {
        return 0;
    }

    if (!ctx->padding_active) {
        uint8_t *cpy = (uint8_t *)malloc(in_len);
        if (cpy == NULL) {
            return -1;
        }
        memcpy(cpy, in, in_len);
        *out = cpy;
        *out_len = in_len;
        return 0;
    }

    size_t payload_len = in_len;
    if (payload_len > 0xFFFF) {
        payload_len = 0xFFFF;
    }

    int has_client_hello = 0;
    int app_records = 0;
    int tls_records = vision_scan_tls_records(in, payload_len, &has_client_hello, &app_records);
    if (tls_records && has_client_hello) {
        ctx->client_hello_seen = 1;
    }

    uint8_t command = (ctx->packets_left <= 1) ? CMD_END : CMD_CONTINUE;
    if (tls_records && ctx->client_hello_seen && app_records > 0) {
        int previous_app_records = ctx->client_tls_app_records;
        ctx->client_tls_app_records += app_records;
        if (previous_app_records > 0 || app_records > 1) {
            command = CMD_DIRECT;
        }
    }

    int long_padding = (payload_len < VISION_LONG_PAD_THRESHOLD) ? 1 : 0;
    if (vision_build_block(ctx, command, in, payload_len, long_padding, out, out_len) != 0) {
        return -1;
    }

    if (ctx->packets_left > 0) {
        ctx->packets_left--;
    }
    if (command != CMD_CONTINUE) {
        ctx->padding_active = 0;
    }
    if (command == CMD_DIRECT) {
        ctx->direct_sent = 1;
    }
    return 0;
}

void vision_unpad_init(vision_unpad_t *ctx, const uint8_t uuid[16]) {
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->uuid, uuid, 16);
    ctx->remaining_command = -1;
    ctx->remaining_content = -1;
    ctx->remaining_padding = -1;
}

void vision_unpad_free(vision_unpad_t *ctx) {
    if (ctx->stash != NULL) {
        free(ctx->stash);
        ctx->stash = NULL;
    }
    ctx->stash_len = 0;
    ctx->stash_cap = 0;
}

int vision_unpad_feed(vision_unpad_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len, int *switch_to_direct) {
    *out = NULL;
    *out_len = 0;
    if (switch_to_direct != NULL) {
        *switch_to_direct = 0;
    }

    if (in_len > 0 && append_bytes(&ctx->stash, &ctx->stash_len, &ctx->stash_cap, in, in_len) != 0) {
        return -1;
    }

    uint8_t *plain = NULL;
    size_t plain_len = 0;
    size_t plain_cap = 0;

    size_t i = 0;
    while (i < ctx->stash_len) {
        if (ctx->remaining_command == -1 && ctx->remaining_content == -1 && ctx->remaining_padding == -1) {
            size_t remain = ctx->stash_len - i;
            if (remain < 16) {
                break;
            }
            if (memcmp(ctx->stash + i, ctx->uuid, 16) != 0) {
                if (append_bytes(&plain, &plain_len, &plain_cap, ctx->stash + i, remain) != 0) {
                    free(plain);
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
            if (append_bytes(&plain, &plain_len, &plain_cap, ctx->stash + i, take) != 0) {
                free(plain);
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
                    if (append_bytes(&plain, &plain_len, &plain_cap, ctx->stash + i, remain) != 0) {
                        free(plain);
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

    *out = plain;
    *out_len = plain_len;
    return 0;
}
