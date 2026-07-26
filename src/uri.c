#include "uri.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

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

static void copy_upper_trunc(char *dst, size_t dst_cap, const char *src) {
    if (dst_cap == 0) {
        return;
    }
    size_t n = 0;
    while (n + 1 < dst_cap && src[n] != '\0') {
        char ch = src[n];
        if (ch >= 'a' && ch <= 'z') {
            ch = (char)(ch - 'a' + 'A');
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

static void init_config_defaults(vless_config_t *cfg, const char *uri) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->protocol = CORE_PROTOCOL_VLESS;
    cfg->fp_mode = FP_CHROME;
    cfg->transport_mode = TRANSPORT_VISION;
    cfg->flow[0] = '\0';
    snprintf(cfg->encryption, sizeof(cfg->encryption), "none");
    snprintf(cfg->security, sizeof(cfg->security), "reality");
    cfg->alpn[0] = '\0';
    cfg->allow_insecure = 0;
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
    snprintf(cfg->original_uri, sizeof(cfg->original_uri), "%s", uri ? uri : "");
}

static const char *skip_json_ws(const char *p) {
    while (p != NULL && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    return p;
}

static const char *json_find_value(const char *json, const char *key) {
    if (json == NULL || key == NULL || key[0] == '\0') {
        return NULL;
    }

    char needle[96];
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n <= 0 || (size_t)n >= sizeof(needle)) {
        return NULL;
    }

    const char *p = json;
    while ((p = strstr(p, needle)) != NULL) {
        const char *v = skip_json_ws(p + n);
        if (v != NULL && *v == ':') {
            return skip_json_ws(v + 1);
        }
        p += n;
    }
    return NULL;
}

static int json_get_scalar(const char *json, const char *key, char *out, size_t out_cap) {
    if (out == NULL || out_cap == 0) {
        return -1;
    }
    out[0] = '\0';

    const char *p = json_find_value(json, key);
    if (p == NULL || *p == '\0') {
        return -1;
    }

    size_t oi = 0;
    if (*p == '"') {
        p++;
        while (*p != '\0' && *p != '"') {
            if (oi + 1 >= out_cap) {
                return -1;
            }
            if (*p == '\\' && p[1] != '\0') {
                p++;
                switch (*p) {
                case 'n':
                    out[oi++] = '\n';
                    break;
                case 'r':
                    out[oi++] = '\r';
                    break;
                case 't':
                    out[oi++] = '\t';
                    break;
                default:
                    out[oi++] = *p;
                    break;
                }
                p++;
                continue;
            }
            out[oi++] = *p++;
        }
        out[oi] = '\0';
        return (*p == '"') ? 0 : -1;
    }

    while (*p != '\0' && *p != ',' && *p != '}') {
        if (oi + 1 >= out_cap) {
            return -1;
        }
        out[oi++] = *p++;
    }
    out[oi] = '\0';
    trim_in_place(out);
    return out[0] != '\0' ? 0 : -1;
}

static void parse_range_value_limited(const char *value, int *min_out, int *max_out, long limit) {
    if (value == NULL || min_out == NULL || max_out == NULL) {
        return;
    }
    char tmp[64];
    copy_trunc(tmp, sizeof(tmp), value);
    trim_in_place(tmp);
    if (tmp[0] == '\0') {
        return;
    }

    char *dash = strchr(tmp, '-');
    long a = 0;
    long b = 0;
    if (dash != NULL) {
        *dash = '\0';
        a = strtol(tmp, NULL, 10);
        b = strtol(dash + 1, NULL, 10);
    } else {
        a = strtol(tmp, NULL, 10);
        b = a;
    }
    if (a <= 0 || b <= 0) {
        return;
    }
    if (a > b) {
        long t = a;
        a = b;
        b = t;
    }
    if (a > limit) {
        a = limit;
    }
    if (b > limit) {
        b = limit;
    }
    *min_out = (int)a;
    *max_out = (int)b;
}

static void parse_range_value(const char *value, int *min_out, int *max_out) {
    parse_range_value_limited(value, min_out, max_out, 8192);
}

static void parse_xhttp_extra(vless_config_t *cfg, const char *json) {
    char val[256];

    if (json_get_scalar(json, "sessionPlacement", val, sizeof(val)) == 0 ||
        json_get_scalar(json, "sessionIDPlacement", val, sizeof(val)) == 0) {
        copy_lower_trunc(cfg->xhttp_session_placement, sizeof(cfg->xhttp_session_placement), val);
    }
    if (json_get_scalar(json, "sessionKey", val, sizeof(val)) == 0 ||
        json_get_scalar(json, "sessionIDKey", val, sizeof(val)) == 0) {
        copy_trunc(cfg->xhttp_session_key, sizeof(cfg->xhttp_session_key), val);
    }
    if (json_get_scalar(json, "seqPlacement", val, sizeof(val)) == 0) {
        copy_lower_trunc(cfg->xhttp_seq_placement, sizeof(cfg->xhttp_seq_placement), val);
    }
    if (json_get_scalar(json, "seqKey", val, sizeof(val)) == 0) {
        copy_trunc(cfg->xhttp_seq_key, sizeof(cfg->xhttp_seq_key), val);
    }
    if (json_get_scalar(json, "uplinkHTTPMethod", val, sizeof(val)) == 0) {
        copy_upper_trunc(cfg->xhttp_uplink_method, sizeof(cfg->xhttp_uplink_method), val);
    }
    if (json_get_scalar(json, "uplinkDataPlacement", val, sizeof(val)) == 0) {
        copy_lower_trunc(cfg->xhttp_uplink_data_placement, sizeof(cfg->xhttp_uplink_data_placement), val);
    }
    if (json_get_scalar(json, "xPaddingPlacement", val, sizeof(val)) == 0) {
        copy_lower_trunc(cfg->xhttp_padding_placement, sizeof(cfg->xhttp_padding_placement), val);
    }
    if (json_get_scalar(json, "xPaddingKey", val, sizeof(val)) == 0) {
        copy_trunc(cfg->xhttp_padding_key, sizeof(cfg->xhttp_padding_key), val);
    }
    if (json_get_scalar(json, "xPaddingHeader", val, sizeof(val)) == 0) {
        copy_trunc(cfg->xhttp_padding_header, sizeof(cfg->xhttp_padding_header), val);
    }
    if (json_get_scalar(json, "xPaddingMethod", val, sizeof(val)) == 0) {
        copy_lower_trunc(cfg->xhttp_padding_method, sizeof(cfg->xhttp_padding_method), val);
    }
    if (json_get_scalar(json, "xPaddingObfsMode", val, sizeof(val)) == 0) {
        copy_lower_trunc(val, sizeof(val), val);
        cfg->xhttp_padding_obfs = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
    }
    if (json_get_scalar(json, "xPaddingBytes", val, sizeof(val)) == 0) {
        parse_range_value(val, &cfg->xhttp_padding_min, &cfg->xhttp_padding_max);
    }
    if (json_get_scalar(json, "scMaxEachPostBytes", val, sizeof(val)) == 0) {
        parse_range_value_limited(val, &cfg->xhttp_max_each_post_min, &cfg->xhttp_max_each_post_max, 16L * 1024L * 1024L);
    }
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
        long p = strtol(end + 2, NULL, 10);
        if (p <= 0 || p > 65535) {
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

    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) {
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

static void parse_query(vless_config_t *cfg, char *query) {
    for (char *tok = strtok(query, "&"); tok != NULL; tok = strtok(NULL, "&")) {
        char *eq = strchr(tok, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *key = tok;
        const char *val = eq + 1;

        char decoded[1536];
        if (percent_decode(val, decoded, sizeof(decoded)) != 0) {
            continue;
        }

        if (strcmp(key, "pbk") == 0) {
            size_t n = 0;
            if (base64url_decode(decoded, cfg->pbk, sizeof(cfg->pbk), &n) == 0) {
                cfg->pbk_len = n;
            }
        } else if (strcmp(key, "sid") == 0) {
            size_t n = 0;
            if (hex_to_bytes(decoded, cfg->short_id, sizeof(cfg->short_id), &n) == 0) {
                cfg->short_id_len = n;
            }
        } else if (strcmp(key, "sni") == 0) {
            copy_trunc(cfg->sni, sizeof(cfg->sni), decoded);
        } else if (strcmp(key, "fp") == 0) {
            if (strcmp(decoded, "random") == 0) {
                cfg->fp_mode = FP_RANDOM;
            } else if (strcmp(decoded, "randomized") == 0) {
                cfg->fp_mode = FP_RANDOMIZED;
            } else if (strcmp(decoded, "qq") == 0) {
                cfg->fp_mode = FP_QQ;
            } else if (strcmp(decoded, "firefox") == 0) {
                cfg->fp_mode = FP_FIREFOX;
            } else if (strcmp(decoded, "edge") == 0) {
                cfg->fp_mode = FP_EDGE;
            } else {
                cfg->fp_mode = FP_CHROME;
            }
        } else if (strcmp(key, "flow") == 0) {
            copy_trunc(cfg->flow, sizeof(cfg->flow), decoded);
        } else if (strcmp(key, "encryption") == 0) {
            copy_trunc(cfg->encryption, sizeof(cfg->encryption), decoded);
        } else if (strcmp(key, "security") == 0) {
            copy_trunc(cfg->security, sizeof(cfg->security), decoded);
        } else if (strcmp(key, "alpn") == 0) {
            copy_trunc(cfg->alpn, sizeof(cfg->alpn), decoded);
        } else if (strcmp(key, "allowInsecure") == 0 || strcmp(key, "insecure") == 0) {
            cfg->allow_insecure = (strcmp(decoded, "1") == 0 || strcmp(decoded, "true") == 0);
        } else if (strcmp(key, "type") == 0 || strcmp(key, "transport") == 0 || strcmp(key, "network") == 0 || strcmp(key, "net") == 0) {
            if (strcmp(decoded, "xhttp") == 0 || strcmp(decoded, "splithttp") == 0) {
                cfg->transport_mode = TRANSPORT_XHTTP;
            } else if (strcmp(decoded, "ws") == 0 || strcmp(decoded, "websocket") == 0) {
                cfg->transport_mode = TRANSPORT_WS;
            } else if (strcmp(decoded, "grpc") == 0) {
                cfg->transport_mode = TRANSPORT_GRPC;
            } else if (decoded[0] == '\0' || strcmp(decoded, "tcp") == 0) {
                cfg->transport_mode = TRANSPORT_VISION;
            }
        } else if (strcmp(key, "path") == 0) {
            copy_trunc(cfg->xhttp_path, sizeof(cfg->xhttp_path), decoded);
        } else if (strcmp(key, "host") == 0) {
            copy_trunc(cfg->xhttp_host, sizeof(cfg->xhttp_host), decoded);
        } else if (strcmp(key, "serviceName") == 0 || strcmp(key, "service_name") == 0) {
            copy_trunc(cfg->grpc_service_name, sizeof(cfg->grpc_service_name), decoded);
        } else if (strcmp(key, "authority") == 0) {
            copy_trunc(cfg->grpc_authority, sizeof(cfg->grpc_authority), decoded);
        } else if (strcmp(key, "mode") == 0) {
            copy_lower_trunc(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), decoded);
        } else if (strcmp(key, "extra") == 0) {
            parse_xhttp_extra(cfg, decoded);
        } else if (strcmp(key, "xPaddingBytes") == 0 || strcmp(key, "x_padding_bytes") == 0) {
            parse_range_value(decoded, &cfg->xhttp_padding_min, &cfg->xhttp_padding_max);
        } else if (strcmp(key, "scMaxEachPostBytes") == 0 || strcmp(key, "sc_max_each_post_bytes") == 0) {
            parse_range_value_limited(decoded, &cfg->xhttp_max_each_post_min, &cfg->xhttp_max_each_post_max, 16L * 1024L * 1024L);
        } else if (strcmp(key, "spx") == 0) {
            copy_trunc(cfg->spider_x, sizeof(cfg->spider_x), decoded);
        }
    }
}

static int parse_vless_encryption(vless_config_t *cfg, char *err, size_t err_cap) {
    cfg->encryption_enabled = 0;
    cfg->encryption_xor_mode = 0;
    cfg->encryption_relay_count = 0;

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

    for (size_t i = 3; i < count; i++) {
        if (strlen(parts[i]) < 20) {
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

    init_config_defaults(cfg, uri);
    cfg->protocol = CORE_PROTOCOL_SOCKS5;
    cfg->flow[0] = '\0';
    snprintf(cfg->security, sizeof(cfg->security), "none");
    cfg->pbk_len = 0;
    cfg->short_id_len = 0;

    if (!starts_with_ci(uri, "socks5://")) {
        set_err(err, err_cap, "URI must start with socks5://");
        return -1;
    }

    char work[4096];
    snprintf(work, sizeof(work), "%s", uri + 9);

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

    init_config_defaults(cfg, uri);

    if (!starts_with_ci(uri, "vless://")) {
        set_err(err, err_cap, "URI must start with vless://");
        return -1;
    }

    char work[4096];
    snprintf(work, sizeof(work), "%s", uri + 8);

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
        parse_query(cfg, query);
    }

    if (parse_vless_encryption(cfg, err, err_cap) != 0) {
        return -1;
    }

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        int xhttp_tls = (strcmp(cfg->security, "tls") == 0);
        int xhttp_reality = (strcmp(cfg->security, "reality") == 0);
        int xhttp_plain = (strcmp(cfg->security, "none") == 0);
        if (!xhttp_tls && !xhttp_reality && !xhttp_plain) {
            set_err(err, err_cap, "xhttp requires security=none, security=tls, or security=reality");
            return -1;
        }
        if (strcmp(cfg->xhttp_mode, "auto") == 0 || cfg->xhttp_mode[0] == '\0') {
            snprintf(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), "%s", xhttp_reality ? "stream-one" : "packet-up");
        }
        if (strcmp(cfg->xhttp_mode, "packet-up") != 0 && strcmp(cfg->xhttp_mode, "stream-one") != 0 &&
            strcmp(cfg->xhttp_mode, "stream-up") != 0) {
            set_err(err, err_cap, "xhttp mode must be auto, packet-up, stream-one, or stream-up");
            return -1;
        }
        if (strcmp(cfg->xhttp_uplink_method, "GET") != 0 && strcmp(cfg->xhttp_uplink_method, "POST") != 0) {
            set_err(err, err_cap, "xhttp uplinkHTTPMethod must be GET or POST");
            return -1;
        }
        if (strcmp(cfg->xhttp_uplink_method, "GET") == 0 && strcmp(cfg->xhttp_mode, "packet-up") != 0) {
            set_err(err, err_cap, "xhttp uplinkHTTPMethod=GET requires mode=packet-up");
            return -1;
        }
        if (strcmp(cfg->xhttp_uplink_data_placement, "body") != 0 && strcmp(cfg->xhttp_uplink_data_placement, "auto") != 0) {
            set_err(err, err_cap, "only xhttp uplinkDataPlacement=body is supported");
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
