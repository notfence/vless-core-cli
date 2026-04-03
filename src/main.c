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

#define VLESS_CORE_VERSION "1.0.1"

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

    if (vless_send_request(tls, &cfg, target_host, target_port) != 0) {
        fprintf(stderr, "[conn] VLESS request send failed for %s:%u\n", target_host, (unsigned)target_port);
        socks5_send_failure(cfd, 0x01);
        if (use_vision) {
            vision_unpad_free(&vunpad);
        }
        tls13_reality_close(tls);
        close(cfd);
        return NULL;
    }

    if (use_vision) {
        uint8_t *bootstrap = NULL;
        size_t bootstrap_len = 0;
        if (vision_wrap_bootstrap(&vwrap, &bootstrap, &bootstrap_len) != 0 ||
            (bootstrap_len > 0 && tls13_write_app(tls, bootstrap, bootstrap_len) != 0)) {
            free(bootstrap);
            fprintf(stderr, "[conn] Vision bootstrap send failed for %s:%u\n", target_host, (unsigned)target_port);
            socks5_send_failure(cfd, 0x01);
            vision_unpad_free(&vunpad);
            tls13_reality_close(tls);
            close(cfd);
            return NULL;
        }
        free(bootstrap);
    }

    if (socks5_send_success(cfd) != 0) {
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
    int tunnel_direct = 0;

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(tfd, &rfds);

        int maxfd = (cfd > tfd) ? cfd : tfd;
        int s = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (s <= 0) {
            break;
        }

        if (FD_ISSET(cfd, &rfds)) {
            ssize_t n = recv(cfd, cbuf, sizeof(cbuf), 0);
            if (n <= 0) {
                break;
            }

            if (tunnel_direct) {
                if (write_all(tfd, cbuf, (size_t)n) != 0) {
                    break;
                }
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
            } else {
                if (tls13_write_app(tls, cbuf, (size_t)n) != 0) {
                    break;
                }
            }
        }

        if (FD_ISSET(tfd, &rfds)) {
            if (tunnel_direct) {
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
                    tunnel_direct = 1;
                    fprintf(stderr, "[conn] switched to Vision direct mode for %s:%u\n", target_host, (unsigned)target_port);
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
    fprintf(stderr, "  --uri <vless://...>      VLESS URI (Reality/Vision or TLS/XHTTP)\n");
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

    fprintf(stderr, "%s listening on 127.0.0.1:%d (server=%s:%u, sni=%s, security=%s, transport=%s, fp=%s)\n", prog, listen_port,
            cfg.server_host, (unsigned)cfg.server_port, cfg.sni, cfg.security,
            cfg.transport_mode == TRANSPORT_XHTTP ? "xhttp" : "vision", cfg.fp_mode == FP_RANDOM ? "random" : "chrome");
    if (cfg.transport_mode == TRANSPORT_XHTTP) {
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
