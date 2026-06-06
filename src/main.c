#include <arpa/inet.h>
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
#include "tls13_reality.h"
#include "types.h"
#include "uri.h"
#include "vision.h"
#include "vless.h"

#define VLESS_CORE_VERSION "1.0.4"

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

    char err[256] = {0};
    tls13_conn_t *tls = NULL;
    if (tls13_reality_connect(&cfg, &tls, err, sizeof(err)) != 0) {
        fprintf(stderr, "[conn] upstream connect failed: %s\n", err);
        socks5_send_failure(cfd, 0x05);
        close(cfd);
        return NULL;
    }

    int use_vision = (cfg.transport_mode == TRANSPORT_VISION);
    vision_wrap_t vwrap;
    vision_unpad_t vunpad;
    if (use_vision) {
        vision_wrap_init(&vwrap, cfg.uuid);
        vision_unpad_init(&vunpad, cfg.uuid);
    }

    int socks_success_sent = 0;
    uint8_t first_payload[8192];
    ssize_t first_payload_len = 0;

    if (use_vision) {
        uint8_t vless_req[2048];
        size_t vless_req_len = 0;
        uint8_t *vision_first = NULL;
        size_t vision_first_len = 0;
        uint8_t *first_packet = NULL;
        size_t first_packet_len = 0;

        if (socks5_send_success(cfd) != 0) {
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }
        socks_success_sent = 1;

        first_payload_len = read_initial_payload(cfd, first_payload, sizeof(first_payload));
        if (first_payload_len < 0) {
            fprintf(stderr, "[conn] first client payload read failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }

        if (vless_build_request(vless_req, sizeof(vless_req), &vless_req_len, &cfg, target_host, target_port) != 0) {
            fprintf(stderr, "[conn] VLESS/Vision request build failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }

        if (first_payload_len > 0) {
            if (vision_wrap_payload(&vwrap, first_payload, (size_t)first_payload_len, &vision_first, &vision_first_len) != 0) {
                fprintf(stderr, "[conn] first Vision payload wrap failed for %s:%u\n", target_host, (unsigned)target_port);
                vision_unpad_free(&vunpad);
                tls13_reality_close(tls);
                close(cfd);
                return NULL;
            }
        } else if (vision_wrap_bootstrap(&vwrap, &vision_first, &vision_first_len) != 0) {
            fprintf(stderr, "[conn] Vision bootstrap build failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }

        first_packet_len = vless_req_len + vision_first_len;
        first_packet = (uint8_t *)malloc(first_packet_len);
        if (first_packet == NULL) {
            free(vision_first);
            fprintf(stderr, "[conn] VLESS/Vision request alloc failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }

        memcpy(first_packet, vless_req, vless_req_len);
        if (vision_first_len > 0) {
            memcpy(first_packet + vless_req_len, vision_first, vision_first_len);
        }
        free(vision_first);

        if (tls13_write_app(tls, first_packet, first_packet_len) != 0) {
            free(first_packet);
            fprintf(stderr, "[conn] VLESS/Vision request send failed for %s:%u\n", target_host, (unsigned)target_port);
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }
        free(first_packet);

    } else {
        if (vless_send_request(tls, &cfg, target_host, target_port) != 0) {
            fprintf(stderr, "[conn] VLESS request send failed for %s:%u\n", target_host, (unsigned)target_port);
            socks5_send_failure(cfd, 0x01);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }
    }

    if (!socks_success_sent && socks5_send_success(cfd) != 0) {
        if (use_vision) {
            vision_unpad_free(&vunpad);
        }
        tls13_reality_close(tls);
        close(cfd);
        return NULL;
    }

    int tfd = tls13_get_fd(tls);
    uint8_t cbuf[8192];
    uint8_t tbuf[8192];
    int got_vless_response = 0;
    int upstream_direct = 0;
    int downstream_direct = 0;
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
            ssize_t n = recv(cfd, cbuf, sizeof(cbuf), 0);
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

                if (wrapped_len > 0 && tls13_write_app(tls, wrapped, wrapped_len) != 0) {
                    free(wrapped);
                    break;
                }
                free(wrapped);
                if (wrapped_len > 0) {
                    forwarded_client_payload = 1;
                }
                if (vwrap.direct_sent) {
                    upstream_direct = 1;
                }
            } else {
                if (tls13_write_app(tls, cbuf, (size_t)n) != 0) {
                    break;
                }
                forwarded_client_payload = 1;
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
                if (vless_read_response(tls) != 0) {
                    fprintf(stderr, "[conn] VLESS response read failed for %s:%u\n", target_host, (unsigned)target_port);
                    break;
                }
                got_vless_response = 1;
            }

            size_t got = 0;
            if (tls13_read_app(tls, tbuf, sizeof(tbuf), &got) != 0 || got == 0) {
                break;
            }

            if (use_vision) {
                if (tls13_reality_is_raw_direct(tls)) {
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
                    downstream_direct = 1;
                    upstream_direct = 1;
                    tls13_mark_raw_direct(tls);
                    fprintf(stderr, "[conn] switched to Vision downstream direct mode for %s:%u\n", target_host, (unsigned)target_port);
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
    tls13_reality_close(tls);
    close(cfd);
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s --uri <vless://...> --listen-port <port>\n", argv0);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --uri <vless://...>      VLESS URI (Reality/Vision, TLS/Vision, TLS/XHTTP, or Reality/XHTTP)\n");
    fprintf(stderr, "  --listen-port <port>     Local SOCKS5 listen port (127.0.0.1)\n");
    fprintf(stderr, "  -h, --help               Show help\n");
    fprintf(stderr, "  -v, --version            Show version\n");
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
    int listen_port = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--uri") == 0 && i + 1 < argc) {
            uri = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("vless-core %s\n", VLESS_CORE_VERSION);
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

    vless_config_t cfg;
    char err[256] = {0};
    if (parse_vless_uri(uri, &cfg, err, sizeof(err)) != 0) {
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
    fprintf(stderr, "%s listening on 127.0.0.1:%d (server=%s:%u, sni=%s, security=%s, transport=%s, fp=%s)\n", prog, listen_port,
            cfg.server_host, (unsigned)cfg.server_port, cfg.sni, cfg.security,
            cfg.transport_mode == TRANSPORT_XHTTP ? "xhttp" : "vision", fp_label);
    if (cfg.transport_mode == TRANSPORT_XHTTP && strcmp(cfg.security, "tls") == 0) {
        fprintf(stderr, "[xhttp] tls_mode=%s\n", xhttp_tls_mode_startup_label());
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
