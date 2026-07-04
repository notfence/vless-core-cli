#include "uri.h"

#include <arpa/inet.h>
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

static void parse_query(vless_config_t *cfg, char *query) {
    for (char *tok = strtok(query, "&"); tok != NULL; tok = strtok(NULL, "&")) {
        char *eq = strchr(tok, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *key = tok;
        const char *val = eq + 1;

        char decoded[512];
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
            } else if (decoded[0] == '\0' || strcmp(decoded, "tcp") == 0) {
                cfg->transport_mode = TRANSPORT_VISION;
            }
        } else if (strcmp(key, "path") == 0) {
            copy_trunc(cfg->xhttp_path, sizeof(cfg->xhttp_path), decoded);
        } else if (strcmp(key, "host") == 0) {
            copy_trunc(cfg->xhttp_host, sizeof(cfg->xhttp_host), decoded);
        } else if (strcmp(key, "mode") == 0) {
            copy_trunc(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), decoded);
        } else if (strcmp(key, "spx") == 0) {
            copy_trunc(cfg->spider_x, sizeof(cfg->spider_x), decoded);
        }
    }
}

int parse_vless_uri(const char *uri, vless_config_t *cfg, char *err, size_t err_cap) {
    if (uri == NULL || cfg == NULL) {
        set_err(err, err_cap, "null input");
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->fp_mode = FP_CHROME;
    cfg->transport_mode = TRANSPORT_VISION;
    snprintf(cfg->flow, sizeof(cfg->flow), "xtls-rprx-vision");
    snprintf(cfg->security, sizeof(cfg->security), "reality");
    cfg->alpn[0] = '\0';
    cfg->allow_insecure = 0;
    snprintf(cfg->spider_x, sizeof(cfg->spider_x), "/");
    snprintf(cfg->xhttp_path, sizeof(cfg->xhttp_path), "/");
    cfg->xhttp_host[0] = '\0';
    snprintf(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), "auto");
    snprintf(cfg->original_uri, sizeof(cfg->original_uri), "%s", uri);

    if (strncmp(uri, "vless://", 8) != 0) {
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

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        int xhttp_tls = (strcmp(cfg->security, "tls") == 0);
        int xhttp_reality = (strcmp(cfg->security, "reality") == 0);
        if (!xhttp_tls && !xhttp_reality) {
            set_err(err, err_cap, "xhttp requires security=tls or security=reality");
            return -1;
        }
        if (strcmp(cfg->xhttp_mode, "auto") == 0 || cfg->xhttp_mode[0] == '\0') {
            snprintf(cfg->xhttp_mode, sizeof(cfg->xhttp_mode), "%s", xhttp_reality ? "stream-one" : "packet-up");
        }
        if (xhttp_tls && strcmp(cfg->xhttp_mode, "packet-up") != 0) {
            set_err(err, err_cap, "only xhttp/tls mode=packet-up is supported");
            return -1;
        }
        if (xhttp_reality && strcmp(cfg->xhttp_mode, "stream-one") != 0) {
            set_err(err, err_cap, "only xhttp/reality mode=auto or mode=stream-one is supported");
            return -1;
        }
        cfg->flow[0] = '\0';
        if (xhttp_tls) {
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

        if (strcmp(cfg->flow, "xtls-rprx-vision") != 0) {
            set_err(err, err_cap, "only flow=xtls-rprx-vision is supported");
            return -1;
        }
    } else if (strcmp(cfg->security, "tls") == 0) {
        if (strcmp(cfg->flow, "xtls-rprx-vision") != 0) {
            set_err(err, err_cap, "only flow=xtls-rprx-vision is supported");
            return -1;
        }

        cfg->pbk_len = 0;
        cfg->short_id_len = 0;
    } else {
        set_err(err, err_cap, "tcp requires security=reality or security=tls");
        return -1;
    }

    return 0;
}
