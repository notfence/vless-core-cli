#include "vision.h"

#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

#define CMD_CONTINUE 0
#define CMD_END 1
#define CMD_DIRECT 2

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

void vision_wrap_init(vision_wrap_t *ctx, const uint8_t uuid[16]) {
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->uuid, uuid, 16);
    ctx->first_payload = 1;
}

int vision_wrap_bootstrap(vision_wrap_t *ctx, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    if (!ctx->first_payload) {
        return 0;
    }
    ctx->first_payload = 0;

    uint16_t content_len = 0;
    uint16_t padding_len = (uint16_t)(128 + (rand() % 128));
    size_t total = 16 + 1 + 2 + 2 + padding_len;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == NULL) {
        return -1;
    }

    size_t off = 0;
    memcpy(buf + off, ctx->uuid, 16);
    off += 16;

    buf[off++] = CMD_END;
    buf[off++] = (uint8_t)(content_len >> 8);
    buf[off++] = (uint8_t)(content_len & 0xFF);
    buf[off++] = (uint8_t)(padding_len >> 8);
    buf[off++] = (uint8_t)(padding_len & 0xFF);

    if (RAND_bytes(buf + off, padding_len) != 1) {
        memset(buf + off, 0, padding_len);
    }
    off += padding_len;

    *out = buf;
    *out_len = off;
    return 0;
}

int vision_wrap_payload(vision_wrap_t *ctx, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    if (in_len == 0) {
        return 0;
    }

    if (!ctx->first_payload) {
        uint8_t *cpy = (uint8_t *)malloc(in_len);
        if (cpy == NULL) {
            return -1;
        }
        memcpy(cpy, in, in_len);
        *out = cpy;
        *out_len = in_len;
        return 0;
    }

    ctx->first_payload = 0;

    uint16_t content_len = (uint16_t)((in_len > 0xFFFF) ? 0xFFFF : in_len);
    size_t payload_len = (size_t)content_len;

    uint16_t padding_len = 0;
    if (payload_len < 1024) {
        padding_len = (uint16_t)(32 + (rand() % 96));
    } else {
        padding_len = (uint16_t)(rand() % 32);
    }

    size_t total = 16 + 1 + 2 + 2 + payload_len + padding_len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == NULL) {
        return -1;
    }

    size_t off = 0;
    memcpy(buf + off, ctx->uuid, 16);
    off += 16;

    buf[off++] = CMD_END;
    buf[off++] = (uint8_t)(content_len >> 8);
    buf[off++] = (uint8_t)(content_len & 0xFF);
    buf[off++] = (uint8_t)(padding_len >> 8);
    buf[off++] = (uint8_t)(padding_len & 0xFF);

    memcpy(buf + off, in, payload_len);
    off += payload_len;

    if (padding_len > 0) {
        if (RAND_bytes(buf + off, padding_len) != 1) {
            memset(buf + off, 0, padding_len);
        }
        off += padding_len;
    }

    *out = buf;
    *out_len = off;
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
