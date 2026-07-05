#ifndef VLESS_CORE_TYPES_H
#define VLESS_CORE_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    FP_CHROME = 0,
    FP_RANDOM = 1,
    FP_QQ = 2,
    FP_RANDOMIZED = 3,
    FP_FIREFOX = 4,
    FP_EDGE = 5
} fingerprint_mode_t;

typedef enum {
    TRANSPORT_VISION = 0,
    TRANSPORT_XHTTP = 1,
    TRANSPORT_WS = 2
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
    char xhttp_session_placement[16];
    char xhttp_session_key[64];
    char xhttp_seq_placement[16];
    char xhttp_seq_key[64];
    char xhttp_uplink_method[8];
    char xhttp_uplink_data_placement[16];
    char xhttp_padding_placement[16];
    char xhttp_padding_key[64];
    char xhttp_padding_header[64];
    char xhttp_padding_method[16];
    int xhttp_padding_obfs;
    int xhttp_padding_min;
    int xhttp_padding_max;
} vless_config_t;

typedef struct {
    int client_fd;
    vless_config_t cfg;
} client_ctx_t;

#endif
