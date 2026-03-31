#ifndef V2RAYIOS6_TYPES_H
#define V2RAYIOS6_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    FP_CHROME = 0,
    FP_RANDOM = 1
} fingerprint_mode_t;

typedef struct {
    char original_uri[2048];

    uint8_t uuid[16];

    char server_host[256];
    uint16_t server_port;

    char sni[256];
    char flow[64];
    char security[32];

    uint8_t pbk[32];
    size_t pbk_len;

    uint8_t short_id[16];
    size_t short_id_len;

    char spider_x[256];
    fingerprint_mode_t fp_mode;
} vless_config_t;

typedef struct {
    int client_fd;
    vless_config_t cfg;
} client_ctx_t;

#endif
