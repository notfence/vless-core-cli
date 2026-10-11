#include "uri.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "xhttp_config.h"
#include "core_log.h"
#include "websocket.h"
#include "grpc.h"

static void set_err(char *err, size_t cap, const char *msg) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", msg);
    }
}

static void copy_trunc(char *dst, size_t dst_cap, const char *src) {
    if (dst_cap == 0) {
        return;
    }
    size_t n = 0;
    while (n + 1 < dst_cap && src[n] != '\0') {
        n++;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void copy_lower_trunc(char *dst, size_t dst_cap, const char *src) {
    if (dst_cap == 0) {
        return;
    }
    size_t n = 0;
    while (n + 1 < dst_cap && src[n] != '\0') {
        char ch = src[n];
        if (ch >= 'A' && ch <= 'Z') {
            ch = (char)(ch - 'A' + 'a');
        }
        dst[n] = ch;
        n++;
    }
    dst[n] = '\0';
}

static void trim_in_place(char *s) {
    if (s == NULL) {
        return;
    }
    size_t n = strlen(s);
    size_t start = 0;
    while (start < n && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        start++;
    }
    size_t end = n;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }
    if (start > 0) {
        memmove(s, s + start, end - start);
    }
    s[end - start] = '\0';
}

static int starts_with_ci(const char *s, const char *prefix) {
    if (s == NULL || prefix == NULL) {
        return 0;
    }
    while (*prefix != '\0') {
        if (*s == '\0') {
            return 0;
        }
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) {
            return 0;
        }
        s++;
        prefix++;
    }
    return 1;
}

void core_config_defaults(vless_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->protocol = CORE_PROTOCOL_VLESS;
    cfg->fp_mode = FP_CHROME;
    cfg->transport_mode = TRANSPORT_VISION;
    cfg->flow[0] = '\0';
    snprintf(cfg->encryption, sizeof(cfg->encryption), "none");
    snprintf(cfg->security, sizeof(cfg->security), "none");
    cfg->alpn[0] = '\0';
    cfg->allow_insecure = 0;
    cfg->grpc_initial_window=256*1024;
    cfg->grpc_health_timeout=20;
    snprintf(cfg->spider_x, sizeof(cfg->spider_x), "/");
    snprintf(cfg->xhttp_path, sizeof(cfg->xhttp_path), "/");
    cfg->xhttp_host[0] = '\0';
    snprintf(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), "auto");
    cfg->grpc_service_name[0] = '\0';
    cfg->grpc_authority[0] = '\0';
    snprintf(cfg->xhttp_session_placement, sizeof(cfg->xhttp_session_placement), "path");
    cfg->xhttp_session_key[0] = '\0';
    snprintf(cfg->xhttp_seq_placement, sizeof(cfg->xhttp_seq_placement), "path");
    cfg->xhttp_seq_key[0] = '\0';
    snprintf(cfg->xhttp_uplink_method, sizeof(cfg->xhttp_uplink_method), "POST");
    snprintf(cfg->xhttp_uplink_data_placement, sizeof(cfg->xhttp_uplink_data_placement), "body");
    snprintf(cfg->xhttp_padding_placement, sizeof(cfg->xhttp_padding_placement), "queryinheader");
    snprintf(cfg->xhttp_padding_key, sizeof(cfg->xhttp_padding_key), "x_padding");
    snprintf(cfg->xhttp_padding_header, sizeof(cfg->xhttp_padding_header), "X-Padding");
    snprintf(cfg->xhttp_padding_method, sizeof(cfg->xhttp_padding_method), "repeat-x");
    cfg->xhttp_padding_obfs = 0;
    cfg->xhttp_padding_min = 100;
    cfg->xhttp_padding_max = 1000;
    cfg->xhttp_max_each_post_min = 1000000;
    cfg->xhttp_max_each_post_max = 1000000;
}

static int parse_host_port(const char *s, char *host, size_t host_cap, uint16_t *port) {
    if (s == NULL || host == NULL || port == NULL) {
        return -1;
    }

    if (s[0] == '[') {
        const char *end = strchr(s, ']');
        if (end == NULL || end[1] != ':') {
            return -1;
        }
        size_t hlen = (size_t)(end - (s + 1));
        if (hlen == 0 || hlen + 1 > host_cap) {
            return -1;
        }
        memcpy(host, s + 1, hlen);
        host[hlen] = '\0';
        char *port_end = NULL;
        long p = strtol(end + 2, &port_end, 10);
        if (p <= 0 || p > 65535 || port_end == end + 2 || *port_end != '\0') {
            return -1;
        }
        *port = (uint16_t)p;
        return 0;
    }

    const char *colon = strrchr(s, ':');
    if (colon == NULL) {
        return -1;
    }
    size_t hlen = (size_t)(colon - s);
    if (hlen == 0 || hlen + 1 > host_cap) {
        return -1;
    }
    memcpy(host, s, hlen);
    host[hlen] = '\0';

    char *port_end = NULL;
    long p = strtol(colon + 1, &port_end, 10);
    if (p <= 0 || p > 65535 || port_end == colon + 1 || *port_end != '\0') {
        return -1;
    }
    *port = (uint16_t)p;
    return 0;
}

static int parse_host_optional_port(const char *s, uint16_t default_port, char *host, size_t host_cap, uint16_t *port) {
    if (s == NULL || host == NULL || port == NULL) {
        return -1;
    }
    if (parse_host_port(s, host, host_cap, port) == 0) {
        return 0;
    }

    if (s[0] == '[') {
        const char *end = strchr(s, ']');
        if (end == NULL || end[1] != '\0') {
            return -1;
        }
        size_t hlen = (size_t)(end - (s + 1));
        if (hlen == 0 || hlen + 1 > host_cap) {
            return -1;
        }
        memcpy(host, s + 1, hlen);
        host[hlen] = '\0';
        *port = default_port;
        return 0;
    }

    if (strchr(s, ':') != NULL) {
        return -1;
    }
    size_t hlen = strlen(s);
    if (hlen == 0 || hlen + 1 > host_cap) {
        return -1;
    }
    memcpy(host, s, hlen);
    host[hlen] = '\0';
    *port = default_port;
    return 0;
}

#define MAX_QUERY_PARAMETERS 128
#define MAX_QUERY_KEY_LENGTH 127

static int query_value_is_valid_utf8(const unsigned char *value) {
    size_t length = strlen((const char *)value);
    for (size_t i = 0; i < length;) {
        unsigned char c = value[i];
        if (c < 0x20 || c == 0x7f) return 0;
        if (c < 0x80) {
            i++;
            continue;
        }

        size_t continuation_count = 0;
        if (c >= 0xc2 && c <= 0xdf) {
            continuation_count = 1;
        } else if (c >= 0xe0 && c <= 0xef) {
            continuation_count = 2;
        } else if (c >= 0xf0 && c <= 0xf4) {
            continuation_count = 3;
        } else {
            return 0;
        }
        if (i + continuation_count >= length) return 0;
        for (size_t j = 1; j <= continuation_count; j++) {
            if ((value[i + j] & 0xc0) != 0x80) return 0;
        }
        if ((c == 0xe0 && value[i + 1] < 0xa0) ||
            (c == 0xed && value[i + 1] >= 0xa0) ||
            (c == 0xf0 && value[i + 1] < 0x90) ||
            (c == 0xf4 && value[i + 1] >= 0x90)) {
            return 0;
        }
        i += continuation_count + 1;
    }
    return 1;
}

static int normalize_query_key(const char *encoded, char *normalized, size_t normalized_cap) {
    char decoded[MAX_QUERY_KEY_LENGTH + 1];
    if (percent_decode(encoded, decoded, sizeof(decoded)) != 0 || decoded[0] == '\0') {
        return -1;
    }

    size_t length = strlen(decoded);
    if (length >= normalized_cap) return -1;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)decoded[i];
        if (c <= 0x20 || c >= 0x7f || c == '&' || c == '=' || c == '#') return -1;
        normalized[i] = (char)tolower(c);
    }
    normalized[length] = '\0';

    const char *alias = NULL;
    if (strcmp(normalized, "type") == 0 || strcmp(normalized, "network") == 0 ||
        strcmp(normalized, "transport") == 0 || strcmp(normalized, "net") == 0) {
        alias = "transport";
    } else if (strcmp(normalized, "allowinsecure") == 0 || strcmp(normalized, "insecure") == 0) {
        alias = "allowinsecure";
    } else if (strcmp(normalized, "servicename") == 0 || strcmp(normalized, "service_name") == 0) {
        alias = "servicename";
    } else if (strcmp(normalized, "xpaddingbytes") == 0 || strcmp(normalized, "x_padding_bytes") == 0) {
        alias = "xpaddingbytes";
    } else if (strcmp(normalized, "scmaxeachpostbytes") == 0 || strcmp(normalized, "sc_max_each_post_bytes") == 0) {
        alias = "scmaxeachpostbytes";
    } else if (strcmp(normalized, "sessionidplacement") == 0) {
        alias = "sessionplacement";
    } else if (strcmp(normalized, "sessionidkey") == 0) {
        alias = "sessionkey";
    } else if (!strcmp(normalized,"maxearlydata")) {
        alias = "ed";
    }
    if (alias != NULL) copy_trunc(normalized, normalized_cap, alias);
    return 0;
}

static int parse_query(vless_config_t *cfg, char *query, char *err, size_t err_cap) {
    char *scan = malloc(strlen(query) + 1);
    if (!scan) { set_err(err, err_cap, "failed to allocate query"); return -1; }
    memcpy(scan, query, strlen(query) + 1);
    char *extra_cursor = scan;
    while (*extra_cursor) {
        char *next = strchr(extra_cursor, '&');
        if (next) *next = 0;
        char *equal = strchr(extra_cursor, '=');
        if (equal) {
            *equal = 0; char key[MAX_QUERY_KEY_LENGTH + 1];
            if (normalize_query_key(extra_cursor, key, sizeof(key)) == 0 && !strcmp(key,"transport")) {
                char decoded[4096],value[4096];
                if (percent_decode(equal+1,decoded,sizeof(decoded))) { set_err(err,err_cap,"invalid transport encoding"); free(scan); return -1; }
                copy_lower_trunc(value,sizeof(value),decoded);
                if (!strcmp(value,"tcp") || !strcmp(value,"raw") || !value[0]) cfg->transport_mode=TRANSPORT_VISION;
                else if (!strcmp(value,"xhttp") || !strcmp(value,"splithttp")) cfg->transport_mode=TRANSPORT_XHTTP;
                else if (!strcmp(value,"ws") || !strcmp(value,"websocket")) cfg->transport_mode=TRANSPORT_WS;
                else if (!strcmp(value,"grpc")) cfg->transport_mode=TRANSPORT_GRPC;
                else { set_err(err,err_cap,"unsupported transport"); free(scan); return -1; }
            }
        }
        if (!next) break;
        extra_cursor = next + 1;
    }
    memcpy(scan,query,strlen(query)+1); extra_cursor=scan;
    while (*extra_cursor) {
        char *next=strchr(extra_cursor,'&'); if (next) *next=0;
        char *equal=strchr(extra_cursor,'=');
        if (equal) {
            *equal=0; char key[MAX_QUERY_KEY_LENGTH+1];
            if (normalize_query_key(extra_cursor,key,sizeof(key)) == 0 && !strcmp(key,"extra")) {
                char decoded[4096];
                if (percent_decode(equal + 1, decoded, sizeof(decoded)) != 0) { set_err(err,err_cap,"invalid extra parameter encoding"); free(scan); return -1; }
                if (cfg->transport_mode == TRANSPORT_XHTTP) {
                    if (core_xhttp_extra(cfg, decoded, err, err_cap) != 0) { free(scan); return -1; }
                } else vc_log_warning("uri","field query.extra is not applied to this transport");
            }
        }
        if (!next) break;
        extra_cursor = next + 1;
    }
    free(scan);
    char seen[MAX_QUERY_PARAMETERS][MAX_QUERY_KEY_LENGTH + 1];
    size_t seen_count = 0;
    char *cursor = query;

    while (cursor != NULL && *cursor != '\0') {
        char *next = strchr(cursor, '&');
        if (next != NULL) *next = '\0';

        char *eq = strchr(cursor, '=');
        if (eq == NULL || eq == cursor) {
            set_err(err, err_cap, "invalid query parameter");
            return -1;
        }
        *eq = '\0';

        char key[MAX_QUERY_KEY_LENGTH + 1];
        if (normalize_query_key(cursor, key, sizeof(key)) != 0) {
            set_err(err, err_cap, "invalid query parameter name");
            return -1;
        }
        for (size_t i = 0; i < seen_count; i++) {
            if (strcmp(seen[i], key) == 0) {
                if (err && err_cap) snprintf(err,err_cap,"duplicate query parameter: %s",key);
                return -1;
            }
        }
        if (seen_count >= MAX_QUERY_PARAMETERS) {
            set_err(err, err_cap, "too many query parameters");
            return -1;
        }
        copy_trunc(seen[seen_count++], sizeof(seen[0]), key);

        char decoded[4096];
        if (percent_decode(eq + 1, decoded, sizeof(decoded)) != 0) {
            if (err && err_cap) snprintf(err,err_cap,"invalid query parameter encoding: %s",key);
            return -1;
        }
        if (strcmp(key, "extra") && strcmp(key,"headers") && strcmp(key,"downloadsettings") && !query_value_is_valid_utf8((const unsigned char *)decoded)) {
            if (err && err_cap) snprintf(err,err_cap,"invalid query parameter value: %s",key);
            return -1;
        }
        char decoded_lower[4096];
        copy_lower_trunc(decoded_lower, sizeof(decoded_lower), decoded);

        const struct { const char *key; size_t capacity; } capacities[]={
            {"sni",sizeof(cfg->sni)},{"flow",sizeof(cfg->flow)},{"encryption",sizeof(cfg->encryption)},
            {"security",sizeof(cfg->security)},{"alpn",sizeof(cfg->alpn)},{"path",sizeof(cfg->xhttp_path)},
            {"host",sizeof(cfg->xhttp_host)},{"servicename",sizeof(cfg->grpc_service_name)},
            {"authority",sizeof(cfg->grpc_authority)},{"mode",sizeof(cfg->xhttp_mode)},{"spx",sizeof(cfg->spider_x)}
        };
        for (size_t i=0;i<sizeof(capacities)/sizeof(*capacities);i++) if (!strcmp(key,capacities[i].key) && strlen(decoded) >= capacities[i].capacity) {
            if (err && err_cap) snprintf(err,err_cap,"query field %s exceeds capacity",key);
            return -1;
        }
        int common=!strcmp(key,"path") || !strcmp(key,"host") || !strcmp(key,"mode");
        int ws_parameter=cfg->transport_mode == TRANSPORT_WS ? core_ws_parameter(cfg,key,decoded,err,err_cap) : 0;
        if (ws_parameter < 0) return -1;
        int grpc_parameter=cfg->transport_mode == TRANSPORT_GRPC ? core_grpc_parameter(cfg,key,decoded,err,err_cap) : 0;
        if (grpc_parameter < 0) return -1;
        int xhttp_parameter = ws_parameter || grpc_parameter || common ? 0 : core_xhttp_parameter(cfg, key, decoded, err, err_cap);
        if (xhttp_parameter < 0) return -1;
        if (ws_parameter > 0 || grpc_parameter > 0 || xhttp_parameter > 0 || !strcmp(key, "extra")) {
            if (xhttp_parameter > 0 && cfg->transport_mode != TRANSPORT_XHTTP)
                vc_log_warning("uri","field query.%s is not applied to this transport",key);
            if (next == NULL) break;
            cursor = next + 1;
            if (*cursor == '\0') { set_err(err, err_cap, "invalid trailing query separator"); return -1; }
            continue;
        }
        if (strcmp(key, "pbk") == 0) {
            size_t n = 0;
            if (base64url_decode(decoded,cfg->pbk,sizeof(cfg->pbk),&n) || n != 32) { set_err(err,err_cap,"pbk is required and must decode to 32 bytes"); return -1; }
            cfg->pbk_len=n;
        } else if (strcmp(key, "sid") == 0) {
            size_t n = 0;
            if (hex_to_bytes(decoded,cfg->short_id,8,&n)) { set_err(err,err_cap,"invalid sid"); return -1; }
            cfg->short_id_len=n;
        } else if (strcmp(key, "sni") == 0) {
            copy_trunc(cfg->sni, sizeof(cfg->sni), decoded);
        } else if (strcmp(key, "fp") == 0) {
            if (strcmp(decoded_lower, "random") == 0) {
                cfg->fp_mode = FP_RANDOM;
            } else if (strcmp(decoded_lower, "randomized") == 0) {
                cfg->fp_mode = FP_RANDOMIZED;
            } else if (strcmp(decoded_lower, "qq") == 0) {
                cfg->fp_mode = FP_QQ;
            } else if (strcmp(decoded_lower, "firefox") == 0) {
                cfg->fp_mode = FP_FIREFOX;
            } else if (strcmp(decoded_lower, "edge") == 0) {
                cfg->fp_mode = FP_EDGE;
            } else if (!strcmp(decoded_lower,"chrome")) {
                cfg->fp_mode = FP_CHROME;
            } else { set_err(err,err_cap,"unsupported fp"); return -1; }
        } else if (strcmp(key, "flow") == 0) {
            copy_trunc(cfg->flow, sizeof(cfg->flow), decoded_lower);
        } else if (strcmp(key, "encryption") == 0) {
            copy_trunc(cfg->encryption, sizeof(cfg->encryption), decoded);
        } else if (strcmp(key, "security") == 0) {
            copy_trunc(cfg->security, sizeof(cfg->security), decoded_lower[0] != '\0' ? decoded_lower : "none");
        } else if (strcmp(key, "alpn") == 0) {
            copy_trunc(cfg->alpn, sizeof(cfg->alpn), decoded);
        } else if (strcmp(key, "allowinsecure") == 0) {
            if (strcmp(decoded_lower,"1") && strcmp(decoded_lower,"0") && strcmp(decoded_lower,"true") && strcmp(decoded_lower,"false")) { set_err(err,err_cap,"invalid allowInsecure"); return -1; }
            cfg->allow_insecure = (strcmp(decoded_lower, "1") == 0 || strcmp(decoded_lower, "true") == 0);
        } else if (strcmp(key, "transport") == 0) {
            if (strcmp(decoded_lower, "xhttp") == 0 || strcmp(decoded_lower, "splithttp") == 0) {
                cfg->transport_mode = TRANSPORT_XHTTP;
            } else if (strcmp(decoded_lower, "ws") == 0 || strcmp(decoded_lower, "websocket") == 0) {
                cfg->transport_mode = TRANSPORT_WS;
            } else if (strcmp(decoded_lower, "grpc") == 0) {
                cfg->transport_mode = TRANSPORT_GRPC;
            } else if (decoded_lower[0] == '\0' || strcmp(decoded_lower, "tcp") == 0 || !strcmp(decoded_lower,"raw")) {
                cfg->transport_mode = TRANSPORT_VISION;
            }
        } else if (strcmp(key, "path") == 0) {
            copy_trunc(cfg->xhttp_path, sizeof(cfg->xhttp_path), decoded);
        } else if (strcmp(key, "host") == 0) {
            copy_trunc(cfg->xhttp_host, sizeof(cfg->xhttp_host), decoded);
        } else if (strcmp(key, "servicename") == 0) {
            copy_trunc(cfg->grpc_service_name, sizeof(cfg->grpc_service_name), decoded);
        } else if (strcmp(key, "authority") == 0) {
            copy_trunc(cfg->grpc_authority, sizeof(cfg->grpc_authority), decoded);
        } else if (strcmp(key, "mode") == 0) {
            copy_lower_trunc(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), decoded);
        } else if (strcmp(key, "spx") == 0) {
            copy_trunc(cfg->spider_x, sizeof(cfg->spider_x), decoded);
        } else vc_log_warning("uri","unknown field query.%s ignored",key);
        if (((!strcmp(key,"path") || !strcmp(key,"host") || !strcmp(key,"mode")) && cfg->transport_mode == TRANSPORT_VISION) ||
            ((!strcmp(key,"servicename") || !strcmp(key,"authority")) && cfg->transport_mode != TRANSPORT_GRPC) ||
            (!strcmp(key,"host") && cfg->transport_mode == TRANSPORT_GRPC) || !strcmp(key,"spx")) vc_log_warning("uri","field query.%s is not applied to this transport",key);

        if (next == NULL) break;
        cursor = next + 1;
        if (*cursor == '\0') {
            set_err(err, err_cap, "invalid trailing query separator");
            return -1;
        }
    }
    return 0;
}

static int parse_vless_encryption(vless_config_t *cfg, char *err, size_t err_cap) {
    cfg->encryption_enabled = 0;
    cfg->encryption_xor_mode = 0;
    cfg->encryption_relay_count = 0;
    cfg->encryption_zero_rtt=0;
    cfg->encryption_padding_count=0;

    if (cfg->encryption[0] == '\0' || strcmp(cfg->encryption, "none") == 0) {
        return 0;
    }

    char value[sizeof(cfg->encryption)];
    copy_trunc(value, sizeof(value), cfg->encryption);

    char *parts[32];
    size_t count = 0;
    char *cursor = value;
    while (cursor != NULL && count < sizeof(parts) / sizeof(parts[0])) {
        parts[count++] = cursor;
        char *dot = strchr(cursor, '.');
        if (dot == NULL) {
            cursor = NULL;
        } else {
            *dot = '\0';
            cursor = dot + 1;
        }
    }
    if (cursor != NULL || count < 4 || strcmp(parts[0], "mlkem768x25519plus") != 0) {
        set_err(err, err_cap, "unsupported VLESS encryption");
        return -1;
    }

    if (strcmp(parts[1], "native") == 0) {
        cfg->encryption_xor_mode = 0;
    } else if (strcmp(parts[1], "xorpub") == 0) {
        cfg->encryption_xor_mode = 1;
    } else if (strcmp(parts[1], "random") == 0) {
        cfg->encryption_xor_mode = 2;
    } else {
        set_err(err, err_cap, "unsupported VLESS encryption mode");
        return -1;
    }

    if (strcmp(parts[2], "0rtt") != 0 &&
        strcmp(parts[2], "1rtt") != 0) {
        set_err(err, err_cap, "unsupported VLESS encryption handshake");
        return -1;
    }
    cfg->encryption_zero_rtt=!strcmp(parts[2],"0rtt");

    unsigned maximum_padding=0;
    for (size_t i = 3; i < count; i++) {
        if (strlen(parts[i]) < 20) {
            if (cfg->encryption_relay_count || cfg->encryption_padding_count == VLESS_ENCRYPTION_MAX_PADDING) {
                set_err(err,err_cap,"invalid VLESS encryption padding order"); return -1;
            }
            vless_encryption_padding_t *padding=&cfg->encryption_padding[cfg->encryption_padding_count];
            int *values[]={&padding->probability,&padding->min,&padding->max};
            char *item=parts[i];
            for (size_t field=0;field<3;field++) {
                unsigned value=0;
                if (!*item || *item < '0' || *item > '9') { set_err(err,err_cap,"invalid VLESS encryption padding"); return -1; }
                while (*item >= '0' && *item <= '9') {
                    if (value > 214748364U || (value == 214748364U && *item > '7')) { set_err(err,err_cap,"invalid VLESS encryption padding range"); return -1; }
                    value=value*10+(unsigned)(*item++-'0');
                }
                *values[field]=(int)value;
                if ((field < 2 && *item++ != '-') || (field == 2 && *item)) { set_err(err,err_cap,"invalid VLESS encryption padding"); return -1; }
            }
            if (!cfg->encryption_padding_count && (padding->probability < 100 || padding->min < 35 || padding->max < 35)) {
                set_err(err,err_cap,"first VLESS encryption padding must be at least 35 bytes"); return -1;
            }
            if (!(cfg->encryption_padding_count%2)) {
                unsigned largest=(unsigned)(padding->min > padding->max ? padding->min : padding->max);
                if (largest > 65553-maximum_padding) { set_err(err,err_cap,"VLESS encryption padding exceeds 65553 bytes"); return -1; }
                maximum_padding+=largest;
            }
            cfg->encryption_padding_count++;
            continue;
        }

        if (cfg->encryption_relay_count >= VLESS_ENCRYPTION_MAX_RELAYS) {
            set_err(err, err_cap, "too many VLESS encryption relay keys");
            return -1;
        }
        vless_encryption_relay_t *relay =
            &cfg->encryption_relays[cfg->encryption_relay_count];
        if (base64url_decode(parts[i], relay->key, sizeof(relay->key),
                             &relay->key_len) != 0 ||
            (relay->key_len != 32 && relay->key_len != 1184)) {
            set_err(err, err_cap, "invalid VLESS encryption relay key");
            return -1;
        }
        cfg->encryption_relay_count++;
    }

    if (cfg->encryption_relay_count == 0) {
        set_err(err, err_cap, "missing VLESS encryption relay key");
        return -1;
    }
    cfg->encryption_enabled = 1;
    return 0;
}

static int parse_socks5_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap) {
    if (uri == NULL || cfg == NULL) {
        set_err(err, err_cap, "null input");
        return -1;
    }

    core_config_defaults(cfg);
    cfg->protocol = CORE_PROTOCOL_SOCKS5;
    cfg->flow[0] = '\0';
    snprintf(cfg->security, sizeof(cfg->security), "none");
    cfg->pbk_len = 0;
    cfg->short_id_len = 0;

    if (!starts_with_ci(uri, "socks5://")) {
        set_err(err, err_cap, "URI must start with socks5://");
        return -1;
    }
    if (strlen(uri) > CORE_URI_MAX_LENGTH) {
        set_err(err, err_cap, "URI is too long");
        return -1;
    }

    char work[4096];
    memcpy(work, uri + 9, strlen(uri + 9) + 1);

    char *end = strpbrk(work, "/?#");
    if (end != NULL) {
        *end = '\0';
    }
    trim_in_place(work);
    if (work[0] == '\0') {
        set_err(err, err_cap, "missing SOCKS5 host");
        return -1;
    }

    char *host_port = work;
    char *at = strrchr(work, '@');
    if (at != NULL) {
        *at = '\0';
        host_port = at + 1;

        char *pass = strchr(work, ':');
        if (pass != NULL) {
            *pass = '\0';
            pass++;
        }
        if (percent_decode(work, cfg->socks5_user, sizeof(cfg->socks5_user)) != 0) {
            set_err(err, err_cap, "invalid SOCKS5 username");
            return -1;
        }
        if (pass != NULL && percent_decode(pass, cfg->socks5_pass, sizeof(cfg->socks5_pass)) != 0) {
            set_err(err, err_cap, "invalid SOCKS5 password");
            return -1;
        }
    }

    trim_in_place(host_port);
    if (parse_host_optional_port(host_port, 1080, cfg->server_host, sizeof(cfg->server_host), &cfg->server_port) != 0) {
        set_err(err, err_cap, "invalid SOCKS5 host:port");
        return -1;
    }
    snprintf(cfg->sni, sizeof(cfg->sni), "%s", cfg->server_host);
    return 0;
}

int parse_vless_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap) {
    if (uri == NULL || cfg == NULL) {
        set_err(err, err_cap, "null input");
        return -1;
    }

    core_config_defaults(cfg);

    if (!starts_with_ci(uri, "vless://")) {
        set_err(err, err_cap, "URI must start with vless://");
        return -1;
    }
    if (strlen(uri) > CORE_URI_MAX_LENGTH) {
        set_err(err, err_cap, "URI is too long");
        return -1;
    }

    char work[4096];
    memcpy(work, uri + 8, strlen(uri + 8) + 1);

    char *hash = strchr(work, '#');
    if (hash != NULL) {
        *hash = '\0';
    }

    char *query = strchr(work, '?');
    if (query != NULL) {
        *query = '\0';
        query++;
    }

    char *at = strchr(work, '@');
    if (at == NULL) {
        set_err(err, err_cap, "missing user@host part");
        return -1;
    }
    *at = '\0';

    if (parse_uuid(work, cfg->uuid) != 0) {
        set_err(err, err_cap, "invalid UUID in URI");
        return -1;
    }

    if (parse_host_port(at + 1, cfg->server_host, sizeof(cfg->server_host), &cfg->server_port) != 0) {
        set_err(err, err_cap, "invalid host:port in URI");
        return -1;
    }

    snprintf(cfg->sni, sizeof(cfg->sni), "%s", cfg->server_host);

    if (query != NULL && *query != '\0') {
        if (parse_query(cfg, query, err, err_cap) != 0) {
            return -1;
        }
    }

    if (parse_vless_encryption(cfg, err, err_cap) != 0) {
        return -1;
    }
    if (cfg->transport_mode == TRANSPORT_WS && core_ws_configure(cfg,err,err_cap)) return -1;
    if (cfg->flow[0] && strcmp(cfg->flow,"xtls-rprx-vision")) { set_err(err,err_cap,"unsupported flow"); return -1; }
    if (cfg->flow[0] && (cfg->transport_mode == TRANSPORT_WS || cfg->transport_mode == TRANSPORT_GRPC ||
        (cfg->transport_mode == TRANSPORT_XHTTP && !cfg->encryption_enabled))) vc_log_warning("uri","field query.flow is not applied to this transport");
    if (strcmp(cfg->security,"reality") && (cfg->pbk_len || cfg->short_id_len)) vc_log_warning("uri","fields query.pbk/query.sid are not applied without REALITY");

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        int xhttp_tls = (strcmp(cfg->security, "tls") == 0);
        int xhttp_reality = (strcmp(cfg->security, "reality") == 0);
        int xhttp_plain = (strcmp(cfg->security, "none") == 0);
        if (!xhttp_tls && !xhttp_reality && !xhttp_plain) {
            set_err(err, err_cap, "xhttp requires security=none, security=tls, or security=reality");
            return -1;
        }
        if (strcmp(cfg->xhttp_mode, "auto") == 0 || cfg->xhttp_mode[0] == '\0') {
            snprintf(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), "%s", xhttp_reality ? (cfg->xhttp_download_settings[0] ? "stream-up" : "stream-one") : "packet-up");
        }
        if (strcmp(cfg->xhttp_mode, "packet-up") != 0 && strcmp(cfg->xhttp_mode, "stream-one") != 0 &&
            strcmp(cfg->xhttp_mode, "stream-up") != 0) {
            set_err(err, err_cap, "xhttp mode must be auto, packet-up, stream-one, or stream-up");
            return -1;
        }
        if (core_xhttp_validate(cfg,err,err_cap) != 0) return -1;
        if (cfg->xhttp_download_settings[0] && !strcmp(cfg->xhttp_mode,"stream-one")) { set_err(err,err_cap,"downloadSettings cannot be used with stream-one"); return -1; }
        if (strcmp(cfg->xhttp_uplink_method, "GET") == 0 && strcmp(cfg->xhttp_mode, "packet-up") != 0) {
            set_err(err, err_cap, "xhttp uplinkHTTPMethod=GET requires mode=packet-up");
            return -1;
        }
        if (!cfg->encryption_enabled) {
            cfg->flow[0] = '\0';
        } else if (cfg->flow[0] != '\0' &&
                   strcmp(cfg->flow, "xtls-rprx-vision") != 0) {
            set_err(err, err_cap, "encrypted xhttp supports only omitted flow or flow=xtls-rprx-vision");
            return -1;
        }
        if (!xhttp_reality) {
            cfg->pbk_len = 0;
            cfg->short_id_len = 0;
        } else {
            if (cfg->pbk_len != 32) {
                set_err(err, err_cap, "pbk is required and must decode to 32 bytes");
                return -1;
            }
            if (cfg->short_id_len > 16) {
                set_err(err, err_cap, "sid must be <= 16 bytes");
                return -1;
            }
        }
        if (cfg->xhttp_path[0] == '\0') {
            snprintf(cfg->xhttp_path, sizeof(cfg->xhttp_path), "/");
        }
    } else if (cfg->transport_mode == TRANSPORT_GRPC) {
        int grpc_tls = (strcmp(cfg->security, "tls") == 0);
        int grpc_reality = (strcmp(cfg->security, "reality") == 0);
        int grpc_plain = (strcmp(cfg->security, "none") == 0);
        if (!grpc_tls && !grpc_reality && !grpc_plain) {
            set_err(err, err_cap, "grpc requires security=none, security=tls, or security=reality");
            return -1;
        }
        if (strcmp(cfg->xhttp_mode, "auto") != 0 && cfg->xhttp_mode[0] != '\0' &&
            strcmp(cfg->xhttp_mode, "gun") != 0 && strcmp(cfg->xhttp_mode, "multi") != 0) {
            set_err(err, err_cap, "unsupported grpc mode");
            return -1;
        }
        cfg->flow[0] = '\0';
        if (!grpc_reality) {
            cfg->pbk_len = 0;
            cfg->short_id_len = 0;
        } else {
            if (cfg->pbk_len != 32) {
                set_err(err, err_cap, "pbk is required and must decode to 32 bytes");
                return -1;
            }
            if (cfg->short_id_len > 16) {
                set_err(err, err_cap, "sid must be <= 16 bytes");
                return -1;
            }
        }
    } else if (cfg->transport_mode == TRANSPORT_WS) {
        if (strcmp(cfg->security, "tls") != 0 && strcmp(cfg->security, "none") != 0) {
            set_err(err, err_cap, "ws requires security=tls or security=none");
            return -1;
        }
        cfg->flow[0] = '\0';
        cfg->pbk_len = 0;
        cfg->short_id_len = 0;
        if (cfg->xhttp_path[0] == '\0') {
            snprintf(cfg->xhttp_path, sizeof(cfg->xhttp_path), "/");
        }
    } else if (strcmp(cfg->security, "reality") == 0) {
        if (cfg->pbk_len != 32) {
            set_err(err, err_cap, "pbk is required and must decode to 32 bytes");
            return -1;
        }

        if (cfg->short_id_len > 16) {
            set_err(err, err_cap, "sid must be <= 16 bytes");
            return -1;
        }

        if (cfg->flow[0] != '\0' && strcmp(cfg->flow, "xtls-rprx-vision") != 0) {
            set_err(err, err_cap, "only omitted flow or flow=xtls-rprx-vision is supported");
            return -1;
        }
    } else if (strcmp(cfg->security, "tls") == 0) {
        if (cfg->flow[0] != '\0' && strcmp(cfg->flow, "xtls-rprx-vision") != 0) {
            set_err(err, err_cap, "only omitted flow or flow=xtls-rprx-vision is supported");
            return -1;
        }

        cfg->pbk_len = 0;
        cfg->short_id_len = 0;
    } else if (strcmp(cfg->security, "none") == 0) {
        if (cfg->flow[0] != '\0') {
            set_err(err, err_cap, "tcp without security does not support flow");
            return -1;
        }
        cfg->pbk_len = 0;
        cfg->short_id_len = 0;
    } else {
        set_err(err, err_cap, "tcp requires security=none, security=reality, or security=tls");
        return -1;
    }

    return 0;
}

int parse_core_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap) {
    if (uri == NULL) {
        set_err(err, err_cap, "null input");
        return -1;
    }
    if (starts_with_ci(uri, "socks5://")) {
        return parse_socks5_uri(uri, cfg, err, err_cap);
    }
    if (starts_with_ci(uri, "vless://")) {
        return parse_vless_uri(uri, cfg, err, err_cap);
    }
    set_err(err, err_cap, "URI must start with vless:// or socks5://");
    return -1;
}
