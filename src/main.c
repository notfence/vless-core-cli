#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "socks5.h"
#include "socks5_upstream.h"
#include "routing.h"
#include "socket_util.h"
#include "tls13_reality.h"
#include "types.h"
#include "uri.h"
#include "vision.h"
#include "vless.h"
#include "vless_encryption.h"

#define VLESS_CORE_VERSION "1.0.8"
#ifndef VLESS_OPENSSL_PATCH_STATUS
#define VLESS_OPENSSL_PATCH_STATUS "unpatched"
#endif

static routing_config_t g_routing;
static int g_route_control_port = 0;

static int upstream_write(tls13_conn_t *tls,
                          vless_encryption_conn_t *encryption,
                          const uint8_t *buf, size_t len) {
    return encryption != NULL
               ? vless_encryption_write(encryption, buf, len)
               : tls13_write_app(tls, buf, len);
}

static int upstream_read(tls13_conn_t *tls,
                         vless_encryption_conn_t *encryption,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    return encryption != NULL
               ? vless_encryption_read(encryption, buf, cap, out_len)
               : tls13_read_app(tls, buf, cap, out_len);
}

static void upstream_close(tls13_conn_t *tls,
                           vless_encryption_conn_t *encryption) {
    vless_encryption_close(encryption);
    tls13_reality_close(tls);
}

static ssize_t read_with_timeout(int fd, uint8_t *buf, size_t cap, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0) {
        return -1;
    }
    if (rc == 0 || !FD_ISSET(fd, &rfds)) {
        return 0;
    }
    return recv(fd, buf, cap, 0);
}

static ssize_t recv_coalesced(int fd, uint8_t *buf, size_t cap, int wait_us) {
    ssize_t first = recv(fd, buf, cap, 0);
    if (first <= 0 || wait_us <= 0) {
        return first;
    }

    size_t total = (size_t)first;
    while (total < cap) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = wait_us;
        int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0 || !FD_ISSET(fd, &rfds)) {
            break;
        }

        ssize_t n = recv(fd, buf + total, cap - total, 0);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    return (ssize_t)total;
}

static int tls_records_needed(const uint8_t *buf, size_t len, size_t *needed) {
    size_t pos = 0;

    if (needed != NULL) {
        *needed = len;
    }
    if (buf == NULL || len == 0) {
        return 0;
    }

    if (len < 5) {
        if (buf[0] == 0x14 || buf[0] == 0x16 || buf[0] == 0x17) {
            if (needed != NULL) {
                *needed = 5;
            }
            return 1;
        }
        return 0;
    }

    while (pos < len) {
        if (len - pos < 5) {
            if (needed != NULL) {
                *needed = pos + 5;
            }
            return 1;
        }

        uint8_t rtype = buf[pos];
        uint8_t vmajor = buf[pos + 1];
        uint16_t rlen = ((uint16_t)buf[pos + 3] << 8) | (uint16_t)buf[pos + 4];
        if ((rtype != 0x14 && rtype != 0x16 && rtype != 0x17) || vmajor != 0x03 || rlen > 18432) {
            return 0;
        }

        size_t end = pos + 5 + (size_t)rlen;
        if (end > len) {
            if (needed != NULL) {
                *needed = end;
            }
            return 1;
        }
        pos = end;
    }

    if (needed != NULL) {
        *needed = len;
    }
    return 1;
}

static ssize_t read_initial_payload(int fd, uint8_t *buf, size_t cap) {
    ssize_t n = read_with_timeout(fd, buf, cap, 500);
    if (n <= 0) {
        return n;
    }

    size_t len = (size_t)n;
    int tls_waits_left = 6;

    while (len < cap) {
        size_t needed = len;
        int tls_like = tls_records_needed(buf, len, &needed);
        int timeout_ms = 25;

        if (tls_like && needed > len) {
            if (needed > cap || tls_waits_left <= 0) {
                break;
            }
            timeout_ms = 200;
            tls_waits_left--;
        }

        ssize_t more = read_with_timeout(fd, buf + len, cap - len, timeout_ms);
        if (more < 0) {
            return -1;
        }
        if (more == 0) {
            break;
        }
        len += (size_t)more;
    }

    return (ssize_t)len;
}

static ssize_t read_sniff_payload(int fd, uint8_t *buf, size_t cap) {
    ssize_t n = read_with_timeout(fd, buf, cap, 200);
    if (n <= 0) {
        return n;
    }

    size_t len = (size_t)n;
    for (int attempt = 0; attempt < 3 && len < cap; attempt++) {
        size_t needed = len;
        int tls_like = tls_records_needed(buf, len, &needed);
        int timeout_ms = (tls_like && needed > len) ? 50 : 10;
        ssize_t more = read_with_timeout(fd, buf + len, cap - len, timeout_ms);
        if (more < 0) {
            return -1;
        }
        if (more == 0) {
            break;
        }
        len += (size_t)more;
    }
    return (ssize_t)len;
}

static int is_ip_literal(const char *host) {
    struct in_addr in4;
    struct in6_addr in6;
    return host != NULL && (inet_pton(AF_INET, host, &in4) == 1 || inet_pton(AF_INET6, host, &in6) == 1);
}

static int valid_sni_host(const uint8_t *name, size_t len) {
    if (name == NULL || len == 0 || len > 255) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = name[i];
        if (ch <= 0x20 || ch >= 0x7f || ch == '\t' || ch == '/') {
            return 0;
        }
    }
    return 1;
}

static int parse_tls_sni(const uint8_t *buf, size_t len, char *out, size_t out_cap) {
    if (buf == NULL || len < 9 || out == NULL || out_cap == 0) {
        return -1;
    }
    out[0] = '\0';

    size_t pos = 0;
    while (pos + 9 <= len) {
        if (buf[pos] != 0x16 || buf[pos + 1] != 0x03) {
            return -1;
        }

        size_t rec_len = ((size_t)buf[pos + 3] << 8) | (size_t)buf[pos + 4];
        size_t rec_start = pos + 5;
        size_t rec_end = rec_start + rec_len;
        if (rec_len == 0 || rec_len > 18432 || rec_end > len) {
            return -1;
        }

        if (buf[rec_start] != 0x01) {
            pos = rec_end;
            continue;
        }

        size_t hs_len = ((size_t)buf[rec_start + 1] << 16) |
                        ((size_t)buf[rec_start + 2] << 8) |
                        (size_t)buf[rec_start + 3];
        size_t hs_start = rec_start + 4;
        size_t hs_end = hs_start + hs_len;
        if (hs_len < 42 || hs_end > rec_end) {
            return -1;
        }

        size_t p = hs_start;
        p += 2;  /* legacy_version */
        p += 32; /* random */

        if (p + 1 > hs_end) return -1;
        size_t session_len = buf[p++];
        if (p + session_len + 2 > hs_end) return -1;
        p += session_len;

        size_t cipher_len = ((size_t)buf[p] << 8) | (size_t)buf[p + 1];
        p += 2;
        if (p + cipher_len + 1 > hs_end) return -1;
        p += cipher_len;

        size_t compression_len = buf[p++];
        if (p + compression_len > hs_end) return -1;
        p += compression_len;

        if (p == hs_end) return -1;
        if (p + 2 > hs_end) return -1;
        size_t extensions_len = ((size_t)buf[p] << 8) | (size_t)buf[p + 1];
        p += 2;
        if (p + extensions_len > hs_end) return -1;

        size_t ext_end = p + extensions_len;
        while (p + 4 <= ext_end) {
            uint16_t ext_type = ((uint16_t)buf[p] << 8) | (uint16_t)buf[p + 1];
            size_t ext_len = ((size_t)buf[p + 2] << 8) | (size_t)buf[p + 3];
            p += 4;
            if (p + ext_len > ext_end) return -1;

            if (ext_type == 0x0000) {
                size_t sni_pos = p;
                if (sni_pos + 2 > p + ext_len) return -1;
                size_t list_len = ((size_t)buf[sni_pos] << 8) | (size_t)buf[sni_pos + 1];
                sni_pos += 2;
                if (sni_pos + list_len > p + ext_len) return -1;
                size_t list_end = sni_pos + list_len;

                while (sni_pos + 3 <= list_end) {
                    uint8_t name_type = buf[sni_pos++];
                    size_t name_len = ((size_t)buf[sni_pos] << 8) | (size_t)buf[sni_pos + 1];
                    sni_pos += 2;
                    if (sni_pos + name_len > list_end) return -1;
                    if (name_type == 0x00 && valid_sni_host(buf + sni_pos, name_len) && name_len < out_cap) {
                        memcpy(out, buf + sni_pos, name_len);
                        out[name_len] = '\0';
                        return 0;
                    }
                    sni_pos += name_len;
                }
                return -1;
            }

            p += ext_len;
        }

        return -1;
    }

    return -1;
}

static int ascii_equal_ci(const uint8_t *value, size_t len, const char *expected) {
    size_t expected_len = strlen(expected);
    if (len != expected_len) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (tolower((unsigned char)value[i]) != tolower((unsigned char)expected[i])) {
            return 0;
        }
    }
    return 1;
}

static int valid_http_host(const uint8_t *host, size_t len) {
    if (host == NULL || len == 0 || len > 253 || host[0] == '.' || host[len - 1] == '.') {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = host[i];
        if (!(isalnum((unsigned char)ch) || ch == '-' || ch == '_' || ch == '.')) {
            return 0;
        }
        if (ch == '.' && i > 0 && host[i - 1] == '.') {
            return 0;
        }
    }
    return 1;
}

static int parse_http_host(const uint8_t *buf, size_t len, char *out, size_t out_cap) {
    if (buf == NULL || len < 8 || out == NULL || out_cap == 0) {
        return -1;
    }
    out[0] = '\0';

    size_t pos = 0;
    while (pos < len && buf[pos] != '\n') {
        pos++;
    }
    if (pos == len || memchr(buf, ' ', pos) == NULL) {
        return -1;
    }
    pos++;

    while (pos < len) {
        size_t line_start = pos;
        while (pos < len && buf[pos] != '\n') {
            pos++;
        }
        size_t line_end = pos;
        if (line_end > line_start && buf[line_end - 1] == '\r') {
            line_end--;
        }
        if (line_end == line_start) {
            return -1;
        }

        size_t colon = line_start;
        while (colon < line_end && buf[colon] != ':') {
            colon++;
        }
        if (colon < line_end && ascii_equal_ci(buf + line_start, colon - line_start, "host")) {
            size_t value_start = colon + 1;
            while (value_start < line_end &&
                   (buf[value_start] == ' ' || buf[value_start] == '\t')) {
                value_start++;
            }
            while (line_end > value_start &&
                   (buf[line_end - 1] == ' ' || buf[line_end - 1] == '\t')) {
                line_end--;
            }
            if (value_start == line_end || buf[value_start] == '[') {
                return -1;
            }

            size_t host_end = line_end;
            for (size_t i = value_start; i < line_end; i++) {
                if (buf[i] != ':') continue;
                if (i + 1 == line_end) return -1;
                for (size_t j = i + 1; j < line_end; j++) {
                    if (!isdigit((unsigned char)buf[j])) return -1;
                }
                host_end = i;
                break;
            }
            if (host_end > value_start && buf[host_end - 1] == '.') {
                host_end--;
            }
            size_t host_len = host_end - value_start;
            if (host_len >= out_cap || !valid_http_host(buf + value_start, host_len)) {
                return -1;
            }
            memcpy(out, buf + value_start, host_len);
            out[host_len] = '\0';
            return 0;
        }
        if (pos < len) {
            pos++;
        }
    }
    return -1;
}

static int sniff_domain(const uint8_t *buf, size_t len, char *out, size_t out_cap) {
    if (parse_tls_sni(buf, len, out, out_cap) == 0) {
        return 0;
    }
    return parse_http_host(buf, len, out, out_cap);
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void relay_tcp_pair(int fd_a, int fd_b) {
    uint8_t buf[8192];

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd_a, &rfds);
        FD_SET(fd_b, &rfds);

        int maxfd = (fd_a > fd_b) ? fd_a : fd_b;
        int s = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (s <= 0) {
            if (s < 0 && errno == EINTR) {
                continue;
            }
            break;
        }

        if (FD_ISSET(fd_a, &rfds)) {
            ssize_t n = recv(fd_a, buf, sizeof(buf), 0);
            if (n <= 0 || write_all(fd_b, buf, (size_t)n) != 0) {
                break;
            }
        }
        if (FD_ISSET(fd_b, &rfds)) {
            ssize_t n = recv(fd_b, buf, sizeof(buf), 0);
            if (n <= 0 || write_all(fd_a, buf, (size_t)n) != 0) {
                break;
            }
        }
    }
}

static void *client_worker(void *arg) {
    client_ctx_t *ctx = (client_ctx_t *)arg;
    int cfd = ctx->client_fd;
    vless_config_t cfg = ctx->cfg;
    free(ctx);

    char target_host[512];
    uint16_t target_port = 0;
    if (socks5_negotiate_and_get_target(cfd, target_host, sizeof(target_host), &target_port) != 0) {
        socks5_send_failure(cfd, 0x01);
        close(cfd);
        return NULL;
    }

    int socks_success_sent = 0;
    uint8_t first_payload[8192];
    ssize_t first_payload_len = 0;
    char sniffed_domain[256];
    sniffed_domain[0] = '\0';

    if (is_ip_literal(target_host) && routing_has_domain_rules(&g_routing)) {
        if (socks5_send_success(cfd) != 0) {
            close(cfd);
            return NULL;
        }
        socks_success_sent = 1;
        first_payload_len = read_sniff_payload(cfd, first_payload, sizeof(first_payload));
        if (first_payload_len < 0) {
            fprintf(stderr, "[routing] initial payload read failed for %s:%u\n",
                    target_host, (unsigned)target_port);
            close(cfd);
            return NULL;
        }
        if (first_payload_len > 0 &&
            sniff_domain(first_payload,
                         (size_t)first_payload_len,
                         sniffed_domain,
                         sizeof(sniffed_domain)) == 0) {
            fprintf(stderr,
                    "[routing] sniffed target=%s:%u domain=%s\n",
                    target_host,
                    (unsigned)target_port,
                    sniffed_domain);
        }
    }

    char routed_host[256];
    int matched_rule = -1;
    route_action_t route = routing_decide(&g_routing,
                                          target_host,
                                          target_port,
                                          sniffed_domain[0] != '\0' ? sniffed_domain : NULL,
                                          routed_host,
                                          sizeof(routed_host),
                                          &matched_rule);
    if (g_routing.enabled) {
        const char *route_source = "default";
        if (matched_rule >= 0) route_source = "rule";
        else if (matched_rule == -2) route_source = "lan";
        else if (matched_rule == -3) route_source = "dns";
        fprintf(stderr,
                "[routing] target=%s:%u%s%s action=%s source=%s\n",
                target_host,
                (unsigned)target_port,
                routed_host[0] != '\0' ? " domain=" : "",
                routed_host[0] != '\0' ? routed_host : "",
                routing_action_name(route),
                route_source);
    }

    if (route == ROUTE_ACTION_BLOCK) {
        if (!socks_success_sent) {
            socks5_send_failure(cfd, 0x02);
        }
        close(cfd);
        return NULL;
    }

    if (route == ROUTE_ACTION_DIRECT) {
        char direct_err[256] = {0};
        int direct_fd = routing_open_direct(target_host,
                                            target_port,
                                            g_route_control_port,
                                            direct_err,
                                            sizeof(direct_err));
        if (direct_fd < 0) {
            fprintf(stderr, "[routing] direct connect failed for %s:%u: %s\n",
                    target_host, (unsigned)target_port, direct_err);
            if (!socks_success_sent) {
                socks5_send_failure(cfd, 0x05);
            }
            close(cfd);
            return NULL;
        }
        if (!socks_success_sent && socks5_send_success(cfd) != 0) {
            close(direct_fd);
            close(cfd);
            return NULL;
        }
        if (first_payload_len > 0 &&
            write_all(direct_fd, first_payload, (size_t)first_payload_len) != 0) {
            close(direct_fd);
            close(cfd);
            return NULL;
        }
        relay_tcp_pair(cfd, direct_fd);
        close(direct_fd);
        close(cfd);
        return NULL;
    }

    if (cfg.protocol == CORE_PROTOCOL_SOCKS5) {
        char err[256] = {0};
        char upstream_target[512];
        snprintf(upstream_target, sizeof(upstream_target), "%s", target_host);

        int delayed_connect = (target_port == 443 && is_ip_literal(target_host));

        if (delayed_connect && first_payload_len == 0) {
            if (!socks_success_sent && socks5_send_success(cfd) != 0) {
                close(cfd);
                return NULL;
            }
            socks_success_sent = 1;

            first_payload_len = read_initial_payload(cfd, first_payload, sizeof(first_payload));
            if (first_payload_len < 0) {
                fprintf(stderr, "[socks5] first client payload read failed for %s:%u\n", target_host, (unsigned)target_port);
                close(cfd);
                return NULL;
            }
        }

        char sni[256];
        if (first_payload_len > 0 &&
            parse_tls_sni(first_payload, (size_t)first_payload_len, sni, sizeof(sni)) == 0) {
            snprintf(upstream_target, sizeof(upstream_target), "%s", sni);
            fprintf(stderr, "[socks5] remapped transparent TLS target=%s:%u to sni=%s\n",
                    target_host, (unsigned)target_port, upstream_target);
        }

        int upstream_fd = socks5_upstream_connect(&cfg, upstream_target, target_port, err, sizeof(err));
        if (upstream_fd < 0) {
            fprintf(stderr, "[socks5] upstream connect failed for %s:%u via %s:%u: %s\n",
                    upstream_target, (unsigned)target_port, cfg.server_host, (unsigned)cfg.server_port, err);
            if (!socks_success_sent) {
                socks5_send_failure(cfd, 0x05);
            }
            close(cfd);
            return NULL;
        }

        if (!socks_success_sent && socks5_send_success(cfd) != 0) {
            close(upstream_fd);
            close(cfd);
            return NULL;
        }
        if (first_payload_len > 0 && write_all(upstream_fd, first_payload, (size_t)first_payload_len) != 0) {
            close(upstream_fd);
            close(cfd);
            return NULL;
        }

        fprintf(stderr, "[socks5] connected target=%s:%u upstream_target=%s:%u via=%s:%u auth=%s\n",
                target_host,
                (unsigned)target_port,
                upstream_target,
                (unsigned)target_port,
                cfg.server_host,
                (unsigned)cfg.server_port,
                (cfg.socks5_user[0] != '\0' ? "userpass" : "none"));
        relay_tcp_pair(cfd, upstream_fd);
        close(upstream_fd);
        close(cfd);
        return NULL;
    }

    char err[256] = {0};
    tls13_conn_t *tls = NULL;
    if (tls13_reality_connect(&cfg, &tls, err, sizeof(err)) != 0) {
        fprintf(stderr, "[conn] upstream connect failed: %s\n", err);
        if (!socks_success_sent) {
            socks5_send_failure(cfd, 0x05);
        }
        close(cfd);
        return NULL;
    }

    vless_encryption_conn_t *encryption = NULL;
    if (cfg.encryption_enabled &&
        vless_encryption_connect(&cfg, tls, &encryption, err,
                                 sizeof(err)) != 0) {
        fprintf(stderr, "[conn] VLESS encryption handshake failed: %s\n", err);
        if (!socks_success_sent) {
            socks5_send_failure(cfd, 0x05);
        }
        upstream_close(tls, encryption);
        close(cfd);
        return NULL;
    }

    int use_vision = (strcmp(cfg.flow, "xtls-rprx-vision") == 0);
    int allow_raw_vision =
        (cfg.transport_mode == TRANSPORT_VISION && encryption == NULL);
    vision_wrap_t vwrap;
    vision_unpad_t vunpad;
    if (use_vision) {
        vision_wrap_init(&vwrap, cfg.uuid);
        vision_unpad_init(&vunpad, cfg.uuid);
    }

    if (use_vision) {
        uint8_t vless_req[2048];
        size_t vless_req_len = 0;
        uint8_t *vision_first = NULL;
        size_t vision_first_len = 0;
        uint8_t *first_packet = NULL;
        size_t first_packet_len = 0;

        if (!socks_success_sent && socks5_send_success(cfd) != 0) {
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
        socks_success_sent = 1;

        if (first_payload_len == 0) {
            first_payload_len = read_initial_payload(cfd, first_payload, sizeof(first_payload));
            if (first_payload_len < 0) {
                fprintf(stderr, "[conn] first client payload read failed for %s:%u\n", target_host, (unsigned)target_port);
                vision_unpad_free(&vunpad);
                upstream_close(tls, encryption);
                close(cfd);
                return NULL;
            }
        }

        if (vless_build_request(vless_req, sizeof(vless_req), &vless_req_len, &cfg, target_host, target_port) != 0) {
            fprintf(stderr, "[conn] VLESS/Vision request build failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        if (first_payload_len > 0) {
            if (vision_wrap_payload(&vwrap, first_payload, (size_t)first_payload_len, &vision_first, &vision_first_len) != 0) {
                fprintf(stderr, "[conn] first Vision payload wrap failed for %s:%u\n", target_host, (unsigned)target_port);
                vision_unpad_free(&vunpad);
                upstream_close(tls, encryption);
                close(cfd);
                return NULL;
            }
        } else if (vision_wrap_bootstrap(&vwrap, &vision_first, &vision_first_len) != 0) {
            fprintf(stderr, "[conn] Vision bootstrap build failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        first_packet_len = vless_req_len + vision_first_len;
        first_packet = (uint8_t *)malloc(first_packet_len);
        if (first_packet == NULL) {
            free(vision_first);
            fprintf(stderr, "[conn] VLESS/Vision request alloc failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        memcpy(first_packet, vless_req, vless_req_len);
        if (vision_first_len > 0) {
            memcpy(first_packet + vless_req_len, vision_first, vision_first_len);
        }
        free(vision_first);

        if (upstream_write(tls, encryption, first_packet,
                           first_packet_len) != 0) {
            free(first_packet);
            fprintf(stderr, "[conn] VLESS/Vision request send failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
        free(first_packet);

    } else if (cfg.transport_mode == TRANSPORT_WS) {
        uint8_t vless_req[2048];
        size_t vless_req_len = 0;
        uint8_t *first_packet = NULL;
        size_t first_packet_len = 0;

        if (!socks_success_sent && socks5_send_success(cfd) != 0) {
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
        socks_success_sent = 1;

        if (first_payload_len == 0) {
            first_payload_len = read_initial_payload(cfd, first_payload, sizeof(first_payload));
            if (first_payload_len < 0) {
                fprintf(stderr, "[conn] first client payload read failed for %s:%u\n", target_host, (unsigned)target_port);
                upstream_close(tls, encryption);
                close(cfd);
                return NULL;
            }
        }

        if (vless_build_request(vless_req, sizeof(vless_req), &vless_req_len, &cfg, target_host, target_port) != 0) {
            fprintf(stderr, "[conn] VLESS/WS request build failed for %s:%u\n", target_host, (unsigned)target_port);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        first_packet_len = vless_req_len + ((first_payload_len > 0) ? (size_t)first_payload_len : 0);
        first_packet = (uint8_t *)malloc(first_packet_len);
        if (first_packet == NULL) {
            fprintf(stderr, "[conn] VLESS/WS request alloc failed for %s:%u\n", target_host, (unsigned)target_port);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        memcpy(first_packet, vless_req, vless_req_len);
        if (first_payload_len > 0) {
            memcpy(first_packet + vless_req_len, first_payload, (size_t)first_payload_len);
        }

        if (upstream_write(tls, encryption, first_packet,
                           first_packet_len) != 0) {
            free(first_packet);
            fprintf(stderr, "[conn] VLESS/WS request send failed for %s:%u\n", target_host, (unsigned)target_port);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
        free(first_packet);
    } else {
        if (vless_send_request(tls, encryption, &cfg, target_host,
                               target_port) != 0) {
            fprintf(stderr, "[conn] VLESS request send failed for %s:%u\n", target_host, (unsigned)target_port);
            if (!socks_success_sent) {
                socks5_send_failure(cfd, 0x01);
            }
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
        if (first_payload_len > 0 &&
            upstream_write(tls, encryption, first_payload,
                           (size_t)first_payload_len) != 0) {
            fprintf(stderr, "[conn] initial payload send failed for %s:%u\n",
                    target_host, (unsigned)target_port);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
    }

    if (!socks_success_sent && socks5_send_success(cfd) != 0) {
        if (use_vision) {
            vision_unpad_free(&vunpad);
        }
        upstream_close(tls, encryption);
        close(cfd);
        return NULL;
    }

    int tfd = tls13_get_fd(tls);
    size_t cbuf_cap = tls13_write_batch_size(tls);
    if (cbuf_cap < 8192) {
        cbuf_cap = 8192;
    }
    uint8_t *cbuf = (uint8_t *)malloc(cbuf_cap);
    if (cbuf == NULL) {
        if (use_vision) {
            vision_unpad_free(&vunpad);
        }
        upstream_close(tls, encryption);
        close(cfd);
        return NULL;
    }
    uint8_t tbuf[8192];
    int got_vless_response = 0;
    int upstream_direct = 0;
    int downstream_direct = 0;
    int upstream_encryption_direct = 0;
    int downstream_encryption_direct = 0;
    int forwarded_client_payload = (first_payload_len > 0) ? 1 : 0;

    while (1) {
        int client_ready = 0;
        int upstream_ready = (!downstream_direct && tls13_has_pending_app(tls));
        fd_set rfds;
        FD_ZERO(&rfds);

        if (upstream_ready) {
            FD_SET(cfd, &rfds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            int s = select(cfd + 1, &rfds, NULL, NULL, &tv);
            if (s < 0 && errno != EINTR) {
                break;
            }
            client_ready = (s > 0 && FD_ISSET(cfd, &rfds));
        } else {
            FD_SET(cfd, &rfds);
            FD_SET(tfd, &rfds);

            int maxfd = (cfd > tfd) ? cfd : tfd;
            int s = select(maxfd + 1, &rfds, NULL, NULL, NULL);
            if (s <= 0) {
                break;
            }
            client_ready = FD_ISSET(cfd, &rfds);
            upstream_ready = FD_ISSET(tfd, &rfds);
        }

        if (client_ready) {
            ssize_t n = recv_coalesced(cfd, cbuf, cbuf_cap, cbuf_cap > 8192 ? 2000 : 0);
            if (n <= 0) {
                break;
            }
            if (upstream_direct) {
                if (write_all(tfd, cbuf, (size_t)n) != 0) {
                    break;
                }
                forwarded_client_payload = 1;
                continue;
            }

            if (use_vision) {
                uint8_t *wrapped = NULL;
                size_t wrapped_len = 0;
                if (vision_wrap_payload(&vwrap, cbuf, (size_t)n, &wrapped, &wrapped_len) != 0) {
                    break;
                }

                if (wrapped_len > 0) {
                    int write_rc = upstream_encryption_direct
                                       ? vless_encryption_write_raw(
                                             encryption, wrapped, wrapped_len)
                                       : upstream_write(tls, encryption,
                                                        wrapped, wrapped_len);
                    if (write_rc != 0) {
                        free(wrapped);
                        break;
                    }
                }
                free(wrapped);
                if (wrapped_len > 0) {
                    forwarded_client_payload = 1;
                }
                if (vwrap.direct_sent) {
                    if (encryption != NULL) {
                        upstream_encryption_direct = 1;
                    } else if (allow_raw_vision) {
                        upstream_direct = 1;
                    }
                }
            } else {
                if (upstream_write(tls, encryption, cbuf, (size_t)n) != 0) {
                    break;
                }
                forwarded_client_payload = 1;
            }
        }

        if (upstream_ready) {
            int drained = tls13_drain_h2_input(tls);
            if (drained < 0) {
                break;
            }
            if (drained > 0) {
                upstream_ready = tls13_has_pending_app(tls);
            }
        }

        if (upstream_ready) {
            if (downstream_direct) {
                ssize_t n = recv(tfd, tbuf, sizeof(tbuf), 0);
                if (n <= 0) {
                    break;
                }
                if (write_all(cfd, tbuf, (size_t)n) != 0) {
                    break;
                }
                continue;
            }

            if (!got_vless_response) {
                if (!forwarded_client_payload) {
                    continue;
                }
                if (vless_read_response(tls, encryption) != 0) {
                    fprintf(stderr, "[conn] VLESS response read failed for %s:%u\n", target_host, (unsigned)target_port);
                    break;
                }
                got_vless_response = 1;
            }

            size_t got = 0;
            int read_rc = downstream_encryption_direct
                              ? vless_encryption_read_raw(
                                    encryption, tbuf, sizeof(tbuf), &got)
                              : upstream_read(tls, encryption, tbuf,
                                              sizeof(tbuf), &got);
            if (read_rc < 0 || (read_rc == 0 && got == 0)) {
                break;
            }
            if (read_rc > 0) {
                continue;
            }

            if (use_vision) {
                if (allow_raw_vision && tls13_reality_is_raw_direct(tls)) {
                    if (write_all(cfd, tbuf, got) != 0) {
                        break;
                    }
                    if (!downstream_direct) {
                        downstream_direct = 1;
                        upstream_direct = 1;
                        fprintf(stderr, "[conn] switched to Vision downstream direct mode by raw fallback for %s:%u\n", target_host,
                                (unsigned)target_port);
                    }
                    continue;
                }

                uint8_t *plain = NULL;
                size_t plain_len = 0;
                int switch_to_direct = 0;
                if (vision_unpad_feed(&vunpad, tbuf, got, &plain, &plain_len, &switch_to_direct) != 0) {
                    break;
                }

                if (plain_len > 0 && write_all(cfd, plain, plain_len) != 0) {
                    free(plain);
                    break;
                }
                free(plain);

                if (switch_to_direct) {
                    if (encryption != NULL) {
                        downstream_encryption_direct = 1;
                    } else if (allow_raw_vision) {
                        downstream_direct = 1;
                        upstream_direct = 1;
                        tls13_mark_raw_direct(tls);
                    }
                }
            } else {
                if (write_all(cfd, tbuf, got) != 0) {
                    break;
                }
            }
        }
    }

    if (use_vision) {
        vision_unpad_free(&vunpad);
    }
    free(cbuf);
    upstream_close(tls, encryption);
    close(cfd);
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s --uri <vless://...|socks5://...> --listen-port <port>\n", argv0);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --uri <uri>              VLESS URI or SOCKS5 upstream URI\n");
    fprintf(stderr, "  --listen-port <port>     Local SOCKS5 listen port (127.0.0.1)\n");
    fprintf(stderr, "  --routing <rules>        Optional Proxy, Direct and Block rules\n");
    fprintf(stderr, "  --route-control-port <p> Direct-route controller port\n");
    fprintf(stderr, "  -h, --help               Show help\n");
    fprintf(stderr, "  -v, --version            Show version\n");
    fprintf(stderr, "  --openssl-patch-status   Show OpenSSL patch status\n");
}

static const char *xhttp_tls_mode_startup_label(void) {
    const char *v = getenv("VLESS_XHTTP_TLS_MODE");
    if (v == NULL || v[0] == '\0' || strcmp(v, "auto") == 0) {
        return "auto(selected=strict)";
    }
    if (strcmp(v, "strict") == 0) {
        return "strict";
    }
    if (strcmp(v, "insecure") == 0) {
        return "insecure";
    }
    if (strcmp(v, "tofu") == 0) {
        return "tofu";
    }
    return "auto(selected=strict)";
}

int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0);
    srand((unsigned int)time(NULL));

    const char *prog = strrchr(argv[0], '/');
    prog = (prog != NULL) ? (prog + 1) : argv[0];

    const char *uri = NULL;
    const char *routing_text = NULL;
    int listen_port = 0;

    routing_config_init(&g_routing);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--uri") == 0 && i + 1 < argc) {
            uri = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--routing") == 0 && i + 1 < argc) {
            routing_text = argv[++i];
        } else if (strcmp(argv[i], "--route-control-port") == 0 && i + 1 < argc) {
            g_route_control_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("vless-core %s\n", VLESS_CORE_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--openssl-patch-status") == 0) {
            printf("%s\n", VLESS_OPENSSL_PATCH_STATUS);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(prog);
            return 0;
        }
    }

    if (uri == NULL || listen_port <= 0 || listen_port > 65535) {
        usage(prog);
        return 1;
    }
    if (g_route_control_port < 0 || g_route_control_port > 65535) {
        fprintf(stderr, "Invalid route control port\n");
        return 1;
    }

    char routing_err[256] = {0};
    if (routing_config_parse(routing_text, &g_routing, routing_err, sizeof(routing_err)) != 0) {
        fprintf(stderr, "Invalid routing policy: %s\n", routing_err);
        return 1;
    }

    vless_config_t cfg;
    char err[256] = {0};
    if (parse_core_uri(uri, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "Invalid URI: %s\n", err);
        return 1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(lfd);
        return 1;
    }

    if (listen(lfd, 128) != 0) {
        perror("listen");
        close(lfd);
        return 1;
    }

    if (cfg.protocol == CORE_PROTOCOL_SOCKS5) {
        fprintf(stderr, "%s listening on 127.0.0.1:%d (upstream=socks5://%s:%u, auth=%s)\n",
                prog,
                listen_port,
                cfg.server_host,
                (unsigned)cfg.server_port,
                (cfg.socks5_user[0] != '\0' ? "userpass" : "none"));
    } else {
        const char *fp_label = "chrome";
        if (cfg.fp_mode == FP_RANDOM) {
            fp_label = "random";
        } else if (cfg.fp_mode == FP_RANDOMIZED) {
            fp_label = "randomized";
        } else if (cfg.fp_mode == FP_QQ) {
            fp_label = "qq";
        } else if (cfg.fp_mode == FP_FIREFOX) {
            fp_label = "firefox";
        } else if (cfg.fp_mode == FP_EDGE) {
            fp_label = "edge";
        }
        const char *transport_label = strcmp(cfg.flow, "xtls-rprx-vision") == 0 ? "vision" : "tcp";
        if (cfg.transport_mode == TRANSPORT_XHTTP) {
            transport_label = "xhttp";
        } else if (cfg.transport_mode == TRANSPORT_WS) {
            transport_label = "ws";
        } else if (cfg.transport_mode == TRANSPORT_GRPC) {
            transport_label = "grpc";
        }
        fprintf(stderr, "%s listening on 127.0.0.1:%d (server=%s:%u, sni=%s, security=%s, transport=%s, fp=%s)\n", prog, listen_port,
                cfg.server_host, (unsigned)cfg.server_port, cfg.sni, cfg.security, transport_label, fp_label);
        if ((cfg.transport_mode == TRANSPORT_XHTTP || cfg.transport_mode == TRANSPORT_GRPC) && strcmp(cfg.security, "tls") == 0) {
            fprintf(stderr, "[%s] tls_mode=%s\n", transport_label, xhttp_tls_mode_startup_label());
        }
    }
    if (g_routing.enabled) {
        fprintf(stderr, "[routing] enabled default=%s bypass_lan=%s rules=%lu\n",
                routing_action_name(g_routing.default_action),
                g_routing.bypass_lan ? "yes" : "no",
                (unsigned long)g_routing.rule_count);
    }

    while (1) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        core_tune_tcp_socket(cfd);

        client_ctx_t *ctx = (client_ctx_t *)calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            close(cfd);
            continue;
        }
        ctx->client_fd = cfd;
        ctx->cfg = cfg;

        pthread_t th;
        if (pthread_create(&th, NULL, client_worker, ctx) != 0) {
            free(ctx);
            close(cfd);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    return 0;
}
