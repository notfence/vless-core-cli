#ifndef VLESS_CORE_TYPES_H
#define VLESS_CORE_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    FP_CHROME = 0,
    FP_RANDOM = 1,
    FP_QQ = 2,
    FP_RANDOMIZED = 3,
    FP_FIREFOX = 4
} fingerprint_mode_t;

typedef enum {
    TRANSPORT_VISION = 0,
    TRANSPORT_XHTTP = 1
} transport_mode_t;

typedef struct {
    char original_uri[2048];

    uint8_t uuid[16];

    char server_host[256];
    uint16_t server_port;

    char sni[256];
    char flow[64];
    char security[32];
    char alpn[128];
    int allow_insecure;

    uint8_t pbk[32];
    size_t pbk_len;

    uint8_t short_id[16];
    size_t short_id_len;

    char spider_x[256];
    fingerprint_mode_t fp_mode;

    transport_mode_t transport_mode;
    char xhttp_path[256];
    char xhttp_host[256];
    char xhttp_mode[32];
} vless_config_t;

typedef struct {
    int client_fd;
    vless_config_t cfg;
} client_ctx_t;

#endif
