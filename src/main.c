#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>

#include "core_log.h"
#include "cli_args.h"
#include "connection_trace.h"
#include "deadline.h"
#include "resolver.h"
#include "socks5.h"
#include "socks5_upstream.h"
#include "routing.h"
#include "server_ips.h"
#include "socket_util.h"
#include "tls13_reality.h"
#include "types.h"
#include "uri.h"
#include "vision.h"
#include "vless.h"
#include "vless_encryption.h"

#define VLESS_CORE_VERSION "1.1.5"
#define MAX_CLIENT_CONNECTIONS 256
#define SERVER_IP_LIST_MAX_LENGTH 511
#ifndef VLESS_OPENSSL_PATCH_STATUS
#define VLESS_OPENSSL_PATCH_STATUS "unpatched"
#endif

static routing_config_t g_routing;
static int g_route_control_port = 0;
static const char *g_route_control_socket = NULL;
static int g_connect_timeout_ms = 30000;
static pthread_mutex_t g_client_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_active_client_count = 0;

static int acquire_client_slot(void) {
    int acquired = 0;
    pthread_mutex_lock(&g_client_count_mutex);
    if (g_active_client_count < MAX_CLIENT_CONNECTIONS) {
        g_active_client_count++;
        acquired = 1;
    }
    pthread_mutex_unlock(&g_client_count_mutex);
    return acquired;
}

static void release_client_slot(void) {
    pthread_mutex_lock(&g_client_count_mutex);
    if (g_active_client_count > 0) g_active_client_count--;
    pthread_mutex_unlock(&g_client_count_mutex);
}

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
    int rc = core_wait_socket(fd, POLLIN, timeout_ms);
    if (rc < 0) {
        return -1;
    }
    if (rc == 0) {
        return 0;
    }
    return core_recv(fd, buf, cap, 0);
}

static ssize_t recv_coalesced(int fd, uint8_t *buf, size_t cap, int wait_us) {
    ssize_t first = core_recv(fd, buf, cap, 0);
    if (first <= 0 || wait_us <= 0) {
        return first;
    }

    size_t total = (size_t)first;
    while (total < cap) {
        int rc = core_wait_socket(fd, POLLIN, (wait_us + 999) / 1000);
        if (rc <= 0) {
            break;
        }

        ssize_t n = core_recv(fd, buf + total, cap - total, 0);
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

static ssize_t read_initial_payload_impl(int fd, uint8_t *buf, size_t cap) {
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

static ssize_t read_initial_payload(int fd, uint8_t *buf, size_t cap) {
    core_deadline_pause();
    ssize_t result = read_initial_payload_impl(fd, buf, cap);
    core_deadline_resume();
    return result;
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
        ssize_t n = core_send(fd, buf + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void relay_tcp_pair(int fd_a, int fd_b) {
    uint8_t buffers[2][8192];
    size_t lengths[2] = {0, 0}, offsets[2] = {0, 0};
    int descriptors[2] = {fd_a, fd_b};
    int reading[2] = {1, 1}, shutdown_sent[2] = {0, 0};
    int received_reply = 0;

    while (1) {
        struct pollfd fds[2];
        for (int i = 0; i < 2; i++) {
            int other = 1 - i;
            if (!reading[i] && offsets[i] == lengths[i] && !shutdown_sent[i]) {
                int result;
                do { result = shutdown(descriptors[other], SHUT_WR); } while (result != 0 && errno == EINTR);
                if (result != 0 && errno != ENOTCONN) return;
                shutdown_sent[i] = 1;
            }
            short events = reading[i] && lengths[i] == 0 ? POLLIN : 0;
            if (offsets[other] < lengths[other]) events |= POLLOUT;
            fds[i] = (struct pollfd){.fd=events ? descriptors[i] : -1,.events=events};
        }
        if (!reading[0] && !reading[1] && lengths[0] == 0 && lengths[1] == 0) return;
        if (core_poll(fds, 2, -1) <= 0) return;
        for (int i = 0; i < 2; i++) {
            int other = 1 - i;
            if (reading[i] && lengths[i] == 0 && (fds[i].revents & (POLLIN | POLLHUP | POLLERR))) {
                ssize_t n = core_recv(descriptors[i], buffers[i], sizeof(buffers[i]), MSG_DONTWAIT);
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return;
                if (n == 0) reading[i] = 0;
                if (n > 0) {
                    lengths[i] = (size_t)n; offsets[i] = 0;
                    if (i == 1 && !received_reply) { received_reply = 1; core_trace_complete(1); }
                }
            }
            if (offsets[other] < lengths[other] && (fds[i].revents & (POLLOUT | POLLHUP | POLLERR))) {
                ssize_t n = core_send(descriptors[i], buffers[other] + offsets[other], lengths[other] - offsets[other], MSG_DONTWAIT);
                if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) return;
                if (n > 0) {
                    offsets[other] += (size_t)n;
                    if (offsets[other] == lengths[other]) lengths[other] = offsets[other] = 0;
                }
            }
        }
    }
}

static void *client_worker_run(void *arg) {
    client_ctx_t *ctx = (client_ctx_t *)arg;
    int cfd = ctx->client_fd;
    vless_config_t cfg = ctx->cfg;
    free(ctx);

    char target_host[512];
    uint16_t target_port = 0;
    int negotiation_result = socks5_negotiate_and_get_target(cfd, target_host, sizeof(target_host), &target_port);
    if (negotiation_result != 0) {
        if (negotiation_result != SOCKS5_NEGOTIATION_REJECTED) socks5_send_failure(cfd,socks5_request_reply(negotiation_result));
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
            vc_log_error("routing", "initial payload read failed for %s:%u",
                         target_host, (unsigned)target_port);
            close(cfd);
            return NULL;
        }
        if (first_payload_len > 0 &&
            sniff_domain(first_payload,
                         (size_t)first_payload_len,
                         sniffed_domain,
                         sizeof(sniffed_domain)) == 0) {
            vc_log_debug("routing", "sniffed target=%s:%u domain=%s",
                         target_host, (unsigned)target_port, sniffed_domain);
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
        vc_log_info("routing", "target=%s:%u%s%s action=%s source=%s",
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
        core_deadline_begin(g_connect_timeout_ms);
        char direct_err[256] = {0};
        routing_direct_lease_t direct_lease;
        int direct_fd = routing_open_direct(target_host,
                                            target_port,
                                            g_route_control_port,
                                            g_route_control_socket,
                                            &direct_lease,
                                            direct_err,
                                            sizeof(direct_err));
        if (direct_fd < 0) {
            uint8_t failure=socks5_error_reply(errno);
            vc_log_error("routing", "direct connect failed for %s:%u: %s",
                         target_host, (unsigned)target_port, direct_err);
            if (!socks_success_sent) {
                socks5_send_failure(cfd,failure);
            }
            close(cfd);
            return NULL;
        }
        if (!socks_success_sent && socks5_send_success(cfd) != 0) {
            if (routing_close_direct(direct_fd, g_route_control_port,
                                     g_route_control_socket, &direct_lease) != 0)
                vc_log_error("routing", "direct bypass release failed");
            close(cfd);
            return NULL;
        }
        if (first_payload_len > 0 &&
            write_all(direct_fd, first_payload, (size_t)first_payload_len) != 0) {
            if (routing_close_direct(direct_fd, g_route_control_port,
                                     g_route_control_socket, &direct_lease) != 0)
                vc_log_error("routing", "direct bypass release failed");
            close(cfd);
            return NULL;
        }
        core_trace_stage(CORE_TRACE_CARRY);
        core_deadline_end();
        relay_tcp_pair(cfd, direct_fd);
        if (routing_close_direct(direct_fd, g_route_control_port,
                                 g_route_control_socket, &direct_lease) != 0)
            vc_log_error("routing", "direct bypass release failed");
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
                vc_log_error("socks5", "first client payload read failed for %s:%u",
                             target_host, (unsigned)target_port);
                close(cfd);
                return NULL;
            }
        }

        char sni[256];
        if (first_payload_len > 0 &&
            parse_tls_sni(first_payload, (size_t)first_payload_len, sni, sizeof(sni)) == 0) {
            snprintf(upstream_target, sizeof(upstream_target), "%s", sni);
            vc_log_info("socks5", "remapped transparent TLS target=%s:%u to sni=%s",
                        target_host, (unsigned)target_port, upstream_target);
        }

        core_deadline_begin(g_connect_timeout_ms);
        uint8_t failure=1;
        int upstream_fd = socks5_upstream_connect(&cfg,upstream_target,target_port,err,sizeof(err),&failure);
        if (upstream_fd < 0) {
            vc_log_error("socks5", "upstream connect failed for %s:%u via %s:%u: %s",
                         upstream_target, (unsigned)target_port,
                         cfg.server_host, (unsigned)cfg.server_port, err);
            if (!socks_success_sent) {
                socks5_send_failure(cfd,failure);
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

        vc_log_info("socks5", "connected target=%s:%u upstream_target=%s:%u via=%s:%u auth=%s",
                    target_host,
                    (unsigned)target_port,
                    upstream_target,
                    (unsigned)target_port,
                    cfg.server_host,
                    (unsigned)cfg.server_port,
                    (cfg.socks5_user[0] != '\0' ? "userpass" : "none"));
        core_deadline_end();
        relay_tcp_pair(cfd, upstream_fd);
        close(upstream_fd);
        close(cfd);
        return NULL;
    }

    char err[256] = {0};
    tls13_conn_t *tls = NULL;
    core_deadline_begin(g_connect_timeout_ms);
    if (tls13_reality_connect(&cfg, &tls, err, sizeof(err)) != 0) {
        uint8_t failure=socks5_error_reply(errno);
        vc_log_error("connection", "upstream connect failed: %s", err);
        if (!socks_success_sent) {
            socks5_send_failure(cfd,failure);
        }
        close(cfd);
        return NULL;
    }

    vless_encryption_conn_t *encryption = NULL;
    core_trace_stage(CORE_TRACE_PROTOCOL);
    if (cfg.encryption_enabled &&
        vless_encryption_connect(&cfg, tls, &encryption, err,
                                 sizeof(err)) != 0) {
        vc_log_error("connection", "VLESS encryption handshake failed: %s", err);
        if (!socks_success_sent) {
            socks5_send_failure(cfd, 0x01);
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
                vc_log_error("connection", "first client payload read failed for %s:%u",
                             target_host, (unsigned)target_port);
                vision_unpad_free(&vunpad);
                upstream_close(tls, encryption);
                close(cfd);
                return NULL;
            }
        }

        if (vless_build_request(vless_req, sizeof(vless_req), &vless_req_len, &cfg, target_host, target_port) != 0) {
            vc_log_error("connection", "VLESS/Vision request build failed for %s:%u",
                         target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        if (first_payload_len > 0) {
            if (vision_wrap_payload(&vwrap, first_payload, (size_t)first_payload_len, &vision_first, &vision_first_len) != 0) {
                vc_log_error("connection", "first Vision payload wrap failed for %s:%u",
                             target_host, (unsigned)target_port);
                vision_unpad_free(&vunpad);
                upstream_close(tls, encryption);
                close(cfd);
                return NULL;
            }
        } else if (vision_wrap_bootstrap(&vwrap, &vision_first, &vision_first_len) != 0) {
            vc_log_error("connection", "Vision bootstrap build failed for %s:%u",
                         target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        first_packet_len = vless_req_len + vision_first_len;
        first_packet = (uint8_t *)malloc(first_packet_len);
        if (first_packet == NULL) {
            free(vision_first);
            vc_log_error("connection", "VLESS/Vision request alloc failed for %s:%u",
                         target_host, (unsigned)target_port);
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
            vc_log_error("connection", "VLESS/Vision request send failed for %s:%u",
                         target_host, (unsigned)target_port);
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
                vc_log_error("connection", "first client payload read failed for %s:%u",
                             target_host, (unsigned)target_port);
                upstream_close(tls, encryption);
                close(cfd);
                return NULL;
            }
        }

        if (vless_build_request(vless_req, sizeof(vless_req), &vless_req_len, &cfg, target_host, target_port) != 0) {
            vc_log_error("connection", "VLESS/WS request build failed for %s:%u",
                         target_host, (unsigned)target_port);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }

        first_packet_len = vless_req_len + ((first_payload_len > 0) ? (size_t)first_payload_len : 0);
        first_packet = (uint8_t *)malloc(first_packet_len);
        if (first_packet == NULL) {
            vc_log_error("connection", "VLESS/WS request alloc failed for %s:%u",
                         target_host, (unsigned)target_port);
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
            vc_log_error("connection", "VLESS/WS request send failed for %s:%u",
                         target_host, (unsigned)target_port);
            upstream_close(tls, encryption);
            close(cfd);
            return NULL;
        }
        free(first_packet);
    } else {
        if (vless_send_request(tls, encryption, &cfg, target_host,
                               target_port) != 0) {
            vc_log_error("connection", "VLESS request send failed for %s:%u",
                         target_host, (unsigned)target_port);
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
            vc_log_error("connection", "initial payload send failed for %s:%u",
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
    vc_log_debug("connection", "upstream fd=%d target=%s:%u", tfd, target_host, (unsigned)target_port);
    size_t cbuf_cap = tls13_write_batch_size(tls);
    if (cbuf_cap < 8192) {
        cbuf_cap = 8192;
    }
    uint8_t *cbuf = (uint8_t *)malloc(cbuf_cap),*output=malloc(256U*1024U);
    if (cbuf == NULL || output == NULL || tls13_start_relay(tls)) {
        if (use_vision) {
            vision_unpad_free(&vunpad);
        }
        upstream_close(tls, encryption);
        free(cbuf); free(output);
        close(cfd);
        return NULL;
    }
    int waiting_initial_payload=first_payload_len == 0;
    if (waiting_initial_payload) core_deadline_pause();
    uint8_t tbuf[8192];
    int got_vless_response = 0;
    int received_reply = 0;
    int upstream_direct = 0;
    int downstream_direct = 0;
    int upstream_encryption_direct = 0;
    int downstream_encryption_direct = 0;
    int client_eof=0,upstream_eof=0,upstream_failed=0;
    int client_send_closed=0; size_t output_length=0;
    vless_response_t response={0};

    while (1) {
        if (!got_vless_response && core_deadline_active() && !core_deadline_remaining()) break;
        if (!upstream_failed && (tls13_flush(tls) || tls13_tick(tls))) { upstream_failed=client_eof=upstream_eof=1; }
        if (output_length) {
            ssize_t sent=core_send(cfd,output,output_length,MSG_DONTWAIT);
            if (sent > 0) { output_length-=(size_t)sent; memmove(output,output+sent,output_length); }
            else if (!sent || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) break;
        }
        if (upstream_eof && !output_length && !client_send_closed) {
            if (shutdown(cfd,SHUT_WR)) break;
            client_send_closed=1;
        }
        int finishing=upstream_failed ? 0 : tls13_finish_pending(tls);
        if (finishing < 0) { upstream_failed=client_eof=upstream_eof=1; finishing=0; }
        if (client_eof && upstream_eof && !finishing && !output_length) break;
        int client_ready = 0;
        int client_writable = !client_eof && tls13_write_capacity(tls) >= 128U*1024U;
        int receive_capacity=output_length <= 256U*1024U-sizeof(tbuf);
        int upstream_ready = !upstream_eof && receive_capacity &&
                             (downstream_direct ? tls13_has_pending_raw(tls) : tls13_has_pending_input(tls) || vless_encryption_has_pending_input(encryption));
        if (upstream_ready) {
            int s = client_writable ? core_wait_socket(cfd, POLLIN, 0) : 0;
            if (s < 0 && errno != EINTR) {
                break;
            }
            client_ready = s > 0;
        } else {
            struct pollfd fds[2] = {{.fd=client_writable || output_length ? cfd : -1,.events=(short)((client_writable ? POLLIN : 0)|(output_length ? POLLOUT : 0))},
                {.fd=!upstream_eof || finishing || tls13_needs_write(tls) ? tfd : -1,.events=(short)(((!upstream_eof && receive_capacity) || finishing ? POLLIN : 0) | (tls13_needs_write(tls) ? POLLOUT : 0))}};
            int s = core_poll(fds, 2, tls13_idle_timeout(tls));
            if (s < 0 || (!upstream_failed && tls13_tick(tls))) {
                break;
            }
            if (s == 0) continue;
            client_ready = (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
            upstream_ready = receive_capacity && (fds[1].revents & (POLLIN | POLLHUP | POLLERR | (tls13_uses_async_io(tls) ? POLLOUT : 0))) != 0;
        }

        if (client_ready && tls13_reserve_write(tls, 128U*1024U)) {
            if (waiting_initial_payload) { core_deadline_resume(); waiting_initial_payload=0; }
            ssize_t n = recv_coalesced(cfd, cbuf, cbuf_cap, cbuf_cap > 8192 ? 2000 : 0);
            if (n <= 0) {
                tls13_release_write(tls);
                if (n < 0) break;
                client_eof=1;
                if (tls13_finish_write(tls,upstream_direct)) break;
                continue;
            }
            if (upstream_direct) {
                if (tls13_write_raw(tls, cbuf, (size_t)n) != 0) {
                    break;
                }
            } else if (use_vision) {
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
            }
            tls13_release_write(tls);
        }

        if (upstream_ready) {
            int drained = tls13_drain_h2_input(tls);
            if (drained < 0) {
                upstream_failed=client_eof=upstream_eof=1; continue;
            }
            if (tls13_uses_h2(tls) || tls13_uses_async_io(tls)) {
                upstream_ready = tls13_has_pending_app(tls) || vless_encryption_has_pending_input(encryption);
            }
            if (upstream_eof) upstream_ready=0;
        }

        if (upstream_ready) {
            if (downstream_direct) {
                size_t got=0; int result=tls13_read_raw(tls,tbuf,sizeof(tbuf),&got);
                if (result < 0) { upstream_failed=client_eof=upstream_eof=1; continue; }
                if (result > 0) continue;
                if (!got) {
                    upstream_eof=1;
                    continue;
                }
                if (!received_reply) { received_reply = 1; core_trace_complete(1); }
                memcpy(output+output_length,tbuf,got); output_length+=got;
                continue;
            }

            size_t got = 0;
            int read_rc = downstream_encryption_direct
                              ? vless_encryption_read_raw(
                                    encryption, tbuf, sizeof(tbuf), &got)
                              : upstream_read(tls, encryption, tbuf,
                                              sizeof(tbuf), &got);
            if (read_rc < 0) {
                if (!got_vless_response) vc_log_error("connection","VLESS response read failed: transport closed before the complete header");
                upstream_failed=client_eof=upstream_eof=1; continue;
            }
            if (read_rc > 0) {
                continue;
            }
            if (!got) {
                if (!got_vless_response) {
                    vc_log_error("connection","VLESS response read failed: truncated header"); break;
                }
                if (use_vision && !vision_unpad_complete(&vunpad)) { vc_log_error("connection","truncated Vision response"); break; }
                upstream_eof=1;
                if (tls13_full_close(tls)) {
                    client_eof=1;
                    if (tls13_finish_write(tls,0)) break;
                }
                continue;
            }
            if (!got_vless_response) {
                if (waiting_initial_payload) { core_deadline_resume(); waiting_initial_payload=0; }
                size_t consumed=0;
                int parsed=vless_consume_response(&response,tbuf,got,&consumed);
                if (parsed < 0) { vc_log_error("connection","VLESS response read failed: invalid version"); break; }
                got-=consumed;
                if (got) memmove(tbuf,tbuf+consumed,got);
                if (!parsed) continue;
                got_vless_response=1; core_deadline_end(); core_trace_stage(CORE_TRACE_CARRY);
                if (!got) continue;
            }

            if (use_vision) {
                if (allow_raw_vision && tls13_reality_is_raw_direct(tls)) {
                    if (!received_reply) { received_reply = 1; core_trace_complete(1); }
                    memcpy(output+output_length,tbuf,got); output_length+=got;
                    if (!downstream_direct) {
                        downstream_direct = 1;
                        vc_log_warning("connection", "switched to authenticated Vision downstream direct mode for %s:%u",
                                       target_host, (unsigned)target_port);
                    }
                    continue;
                }

                uint8_t *plain = NULL;
                size_t plain_len = 0;
                int switch_to_direct = 0;
                if (vision_unpad_feed(&vunpad, tbuf, got, &plain, &plain_len, &switch_to_direct) != 0) {
                    break;
                }

                if (plain_len > 0 && !received_reply) { received_reply = 1; core_trace_complete(1); }
                if (plain_len > 256U*1024U-output_length) { free(plain); break; }
                if (plain_len) { memcpy(output+output_length,plain,plain_len); output_length+=plain_len; }
                free(plain);

                if (switch_to_direct) {
                    if (encryption != NULL) {
                        downstream_encryption_direct = 1;
                    } else if (allow_raw_vision) {
                        downstream_direct = 1;
                        tls13_mark_raw_direct(tls);
                    }
                }
            } else {
                if (!received_reply) { received_reply = 1; core_trace_complete(1); }
                memcpy(output+output_length,tbuf,got); output_length+=got;
            }
        }
    }

    if (!got_vless_response && core_deadline_active() && !core_deadline_remaining()) {
        vc_log_error("connection","VLESS response deadline expired"); core_trace_failure(CORE_TRACE_PROTOCOL);
    }
    if (use_vision) {
        vision_unpad_free(&vunpad);
    }
    free(cbuf);
    free(output);
    upstream_close(tls, encryption);
    close(cfd);
    return NULL;
}

static void *client_worker(void *arg) {
    core_connection_trace_t trace;
    core_deadline_t deadline;
    if (core_deadline_attach(&deadline) != 0) {
        client_ctx_t *ctx = arg;
        close(ctx->client_fd); free(ctx); release_client_slot();
        return NULL;
    }
    int attached = core_trace_attach(&trace) == 0;
    void *result = client_worker_run(arg);
    if (attached) {
        core_trace_complete(0);
        core_trace_detach();
    }
    release_client_slot();
    core_deadline_detach();
    return result;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s (--uri <uri> | --uri-fd <fd> | --connection-fd <fd>) --listen-port <port>\n", argv0);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --uri <uri>              VLESS URI or SOCKS5 upstream URI\n");
    fprintf(stderr, "  --uri-fd <fd>            Read the URI from a file descriptor\n");
    fprintf(stderr, "  --connection-fd <fd>     Read URI and pre-resolved server IPs from a file descriptor\n");
    fprintf(stderr, "  --listen-port <port>     Local SOCKS5 listen port (127.0.0.1)\n");
    fprintf(stderr, "  --connect-timeout-ms <n> Connection budget, 1-300000 ms (default 30000)\n");
    fprintf(stderr, "  --routing <rules>        Optional Proxy, Direct and Block rules\n");
    fprintf(stderr, "  --route-control-port <p> Direct-route controller port\n");
    fprintf(stderr, "  --route-control-socket <path> Direct-route controller Unix socket\n");
    fprintf(stderr, "  --server-ips <list>      Pre-resolved server IPv4 addresses\n");
    fprintf(stderr, "  --xray-version <x.y.z>   Xray version reported by vless-core-cli\n");
    fprintf(stderr, "  -h, --help               Show help\n");
    fprintf(stderr, "  -v, --version            Show version\n");
    fprintf(stderr, "  --openssl-patch-status   Show OpenSSL patch status\n");
}

static int read_uri_from_fd(int fd, char out[CORE_URI_MAX_LENGTH + 1]) {
    size_t used = 0;
    for (;;) {
        uint8_t buffer[1024];
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count <= 0) {
            OPENSSL_cleanse(buffer,sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return -1;
            break;
        }
        if ((size_t)count > CORE_URI_MAX_LENGTH - used || memchr(buffer, '\0', (size_t)count) != NULL) {
            OPENSSL_cleanse(buffer,sizeof(buffer)); return -1;
        }
        memcpy(out + used, buffer, (size_t)count);
        OPENSSL_cleanse(buffer,sizeof(buffer));
        used += (size_t)count;
    }
    out[used] = '\0';
    return used > 0 ? 0 : -1;
}

static int read_connection_from_fd(int fd, char uri[CORE_URI_MAX_LENGTH + 1],
                                   char server_ips[SERVER_IP_LIST_MAX_LENGTH + 1]) {
    char input[CORE_URI_MAX_LENGTH + SERVER_IP_LIST_MAX_LENGTH + 3];
    int result=-1;
    size_t used = 0;
    for (;;) {
        ssize_t count = read(fd, input + used, sizeof(input) - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto input_cleanup;
        if (count == 0) break;
        if ((size_t)count > sizeof(input) - 1 - used) goto input_cleanup;
        used += (size_t)count;
        if (used == sizeof(input) - 1) {
            char extra;
            do {
                count = read(fd, &extra, 1);
            } while (count < 0 && errno == EINTR);
            OPENSSL_cleanse(&extra,sizeof(extra));
            if (count != 0) goto input_cleanup;
            break;
        }
    }
    if (used == 0 || memchr(input, '\0', used) != NULL) goto input_cleanup;
    input[used] = '\0';

    char *separator = memchr(input, '\n', used);
    if (separator == NULL || separator == input || separator == input + used - 1 ||
        memchr(separator + 1, '\n', (size_t)((input + used) - (separator + 1))) != NULL ||
        memchr(input, '\r', used) != NULL) {
        goto input_cleanup;
    }

    size_t uri_length = (size_t)(separator - input);
    size_t server_ips_length = (size_t)((input + used) - (separator + 1));
    if (uri_length > CORE_URI_MAX_LENGTH || server_ips_length > SERVER_IP_LIST_MAX_LENGTH) goto input_cleanup;

    memcpy(uri, input, uri_length);
    uri[uri_length] = '\0';
    memcpy(server_ips, separator + 1, server_ips_length);
    server_ips[server_ips_length] = '\0';
    result=0;
input_cleanup:
    OPENSSL_cleanse(input,sizeof(input));
    return result;
}

static const char *tls_mode_startup_label(int allow_insecure) {
    if (allow_insecure) return "insecure";
    const char *v = getenv("VLESS_TLS_MODE");
    if (v == NULL || v[0] == '\0') v = getenv("VLESS_XHTTP_TLS_MODE");
    if (v == NULL || v[0] == '\0') return "strict";
    if (strcmp(v, "insecure") == 0) {
        return "insecure";
    }
    if (strcmp(v, "tofu") == 0) {
        return "tofu";
    }
    return "strict";
}

int main(int argc, char **argv) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        core_cli_args_scrub(argc,argv);
        vc_log_error("startup", "failed to ignore SIGPIPE: %s", strerror(errno));
        return 1;
    }
    setvbuf(stderr, NULL, _IONBF, 0);
    srand((unsigned int)time(NULL));

    const char *prog = strrchr(argv[0], '/');
    prog = (prog != NULL) ? (prog + 1) : argv[0];

    char uri_storage[CORE_URI_MAX_LENGTH + 1];
    memset(uri_storage, 0, sizeof(uri_storage));
    char server_ips_storage[SERVER_IP_LIST_MAX_LENGTH + 1];
    memset(server_ips_storage, 0, sizeof(server_ips_storage));
    vless_config_t cfg={0};
    core_cli_args_t arguments;
    char argument_error[160]={0};
    if (core_cli_args_parse(argc,argv,&arguments,argument_error,sizeof(argument_error))) {
        vc_log_error("startup","%s",argument_error); goto startup_failure;
    }
    if (arguments.action) {
        core_cli_args_scrub(argc,argv);
        if (arguments.action == CORE_CLI_HELP) usage(prog);
        else if (arguments.action == CORE_CLI_VERSION) printf("vless-core %s\n",VLESS_CORE_VERSION);
        else printf("%s\n",VLESS_OPENSSL_PATCH_STATUS);
        return 0;
    }
    const char *routing_text=arguments.routing;
    const char *xray_ver=arguments.xray_version ? arguments.xray_version : getenv("XRAY_VER");
    const char *server_ips=arguments.server_ips;
    int listen_port=arguments.listen_port;
    routing_config_init(&g_routing);
    g_connect_timeout_ms=arguments.connect_timeout;
    g_route_control_port=arguments.route_port; g_route_control_socket=arguments.route_socket;
    if (arguments.source == CORE_CLI_URI_ARGUMENT) {
        size_t length=strlen(arguments.uri);
        if (length > CORE_URI_MAX_LENGTH) { vc_log_error("startup","invalid URI: URI is too long"); goto startup_failure; }
        memcpy(uri_storage,arguments.uri,length+1); core_cli_args_scrub(argc,argv);
    }
    if (g_route_control_port > 0 && g_route_control_socket != NULL) {
        vc_log_error("startup","only one route control endpoint may be configured"); goto startup_failure;
    }
    if (g_route_control_socket != NULL) {
        size_t path_length = strlen(g_route_control_socket);
        if (path_length == 0 || path_length >= ROUTING_CONTROL_SOCKET_PATH_MAX ||
            g_route_control_socket[0] != '/') {
            vc_log_error("startup", "invalid route control socket path");
            goto startup_failure;
        }
        for (size_t i = 0; i < path_length; i++) {
            unsigned char c = (unsigned char)g_route_control_socket[i];
            if (c < 0x20 || c == 0x7f) {
                vc_log_error("startup", "invalid route control socket path");
                goto startup_failure;
            }
        }
    }
    if (xray_ver != NULL && tls13_reality_set_xray_version(xray_ver) != 0) {
        vc_log_error("startup", "invalid Xray version (expected x.y.z, each component 0-255)");
        goto startup_failure;
    }

    char routing_err[256] = {0};
    if (routing_config_parse(routing_text, &g_routing, routing_err, sizeof(routing_err)) != 0) {
        vc_log_error("startup", "invalid routing policy: %s", routing_err);
        goto startup_failure;
    }

    if (arguments.source == CORE_CLI_URI_FD || arguments.source == CORE_CLI_CONNECTION_FD) {
        int read_result=arguments.source == CORE_CLI_URI_FD ? read_uri_from_fd(arguments.source_fd,uri_storage) :
            read_connection_from_fd(arguments.source_fd,uri_storage,server_ips_storage);
        close(arguments.source_fd);
        if (read_result) { vc_log_error("startup","failed to read configuration from %s",arguments.source == CORE_CLI_URI_FD ? "--uri-fd" : "--connection-fd"); goto startup_failure; }
        if (arguments.source == CORE_CLI_CONNECTION_FD) server_ips=server_ips_storage;
    }
    char err[256] = {0};
    if (parse_core_uri(uri_storage, &cfg, err, sizeof(err)) != 0) {
        vc_log_error("startup", "invalid URI: %s", err);
        OPENSSL_cleanse(uri_storage,sizeof(uri_storage));
        goto startup_failure;
    }
    OPENSSL_cleanse(uri_storage,sizeof(uri_storage));
    if (server_ips != NULL) {
        if (core_set_server_ips(server_ips) != 0) {
            vc_log_error("startup", "invalid pre-resolved server IP list");
            goto startup_failure;
        }
    }
    OPENSSL_cleanse(server_ips_storage,sizeof(server_ips_storage));

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        int error_number = errno;
        vc_log_error("startup", "socket failed: %s", strerror(error_number));
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
        int error_number = errno;
        vc_log_error("startup", "bind failed: %s", strerror(error_number));
        close(lfd);
        return 1;
    }

    if (listen(lfd, 128) != 0) {
        int error_number = errno;
        vc_log_error("startup", "listen failed: %s", strerror(error_number));
        close(lfd);
        return 1;
    }

    if (core_resolver_init() != 0) {
        vc_log_error("startup", "failed to start DNS workers"); close(lfd); return 1;
    }

    if (cfg.protocol == CORE_PROTOCOL_SOCKS5) {
        vc_log_info("core", "%s listening on 127.0.0.1:%d (upstream=socks5://%s:%u, auth=%s)",
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
        vc_log_info("core", "%s listening on 127.0.0.1:%d (server=%s:%u, sni=%s, security=%s, transport=%s, fp=%s)",
                    prog, listen_port, cfg.server_host, (unsigned)cfg.server_port,
                    cfg.sni, cfg.security, transport_label, fp_label);
        if ((cfg.transport_mode == TRANSPORT_XHTTP || cfg.transport_mode == TRANSPORT_GRPC) && strcmp(cfg.security, "tls") == 0) {
            vc_log_info(transport_label, "tls_mode=%s", tls_mode_startup_label(cfg.allow_insecure));
        }
    }
    if (g_routing.enabled) {
        vc_log_info("routing", "enabled default=%s bypass_lan=%s rules=%lu",
                    routing_action_name(g_routing.default_action),
                    g_routing.bypass_lan ? "yes" : "no",
                    (unsigned long)g_routing.rule_count);
    }

    uint64_t last_accept_warning = 0;
    int listener_result = 0;
    while (1) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            int error_number = errno;
            if (error_number == ECONNABORTED || error_number == EAGAIN || error_number == EWOULDBLOCK) continue;
#ifdef __linux__
            if (error_number == ENETDOWN || error_number == EPROTO || error_number == ENOPROTOOPT ||
                error_number == EHOSTDOWN || error_number == ENONET || error_number == EHOSTUNREACH ||
                error_number == EOPNOTSUPP || error_number == ENETUNREACH) continue;
#endif
            if (error_number == EMFILE || error_number == ENFILE || error_number == ENOBUFS || error_number == ENOMEM) {
                uint64_t now = core_now_ms();
                if (last_accept_warning == 0 || now - last_accept_warning >= 1000) {
                    vc_log_warning("core", "accept temporarily unavailable: %s", strerror(error_number));
                    last_accept_warning = now;
                }
                (void)core_poll(NULL, 0, 100);
                continue;
            }
            vc_log_error("core", "accept failed: %s", strerror(error_number));
            listener_result = 1;
            break;
        }
        core_tune_tcp_socket(cfd);
        if (!acquire_client_slot()) {
            close(cfd);
            continue;
        }

        client_ctx_t *ctx = (client_ctx_t *)calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            release_client_slot();
            close(cfd);
            continue;
        }
        ctx->client_fd = cfd;
        ctx->cfg = cfg;

        pthread_t th;
        if (pthread_create(&th, NULL, client_worker, ctx) != 0) {
            free(ctx);
            release_client_slot();
            close(cfd);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    return listener_result;
startup_failure:
    core_cli_args_scrub(argc,argv);
    OPENSSL_cleanse(uri_storage,sizeof(uri_storage)); OPENSSL_cleanse(server_ips_storage,sizeof(server_ips_storage));
    OPENSSL_cleanse(&cfg,sizeof(cfg));
    return 1;
}
