#define _POSIX_C_SOURCE 200112L

#include "socks5_upstream.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void set_errf(char *err, size_t cap, const char *fmt, ...) {
    if (err == NULL || cap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static int read_exact(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, p + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return connect(fd, addr, addr_len);
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return connect(fd, addr, addr_len);
    }

    int rc = connect(fd, addr, addr_len);
    if (rc == 0) {
        (void)fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) {
        (void)fcntl(fd, F_SETFL, flags);
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
        (void)fcntl(fd, F_SETFL, flags);
        errno = (rc == 0) ? ETIMEDOUT : errno;
        return -1;
    }

    int soerr = 0;
    socklen_t soerr_len = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) != 0 || soerr != 0) {
        (void)fcntl(fd, F_SETFL, flags);
        errno = (soerr != 0) ? soerr : errno;
        return -1;
    }

    (void)fcntl(fd, F_SETFL, flags);
    return 0;
}

static int connect_tcp_host(const char *host, uint16_t port, char *err, size_t err_cap) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0) {
        set_errf(err, err_cap, "SOCKS5 resolve failed for %s:%u: %s", host, (unsigned)port, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    int saved_errno = 0;
    for (struct addrinfo *it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            saved_errno = errno;
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 12;
        tv.tv_usec = 0;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect_with_timeout(fd, it->ai_addr, (socklen_t)it->ai_addrlen, 12000) == 0) {
            freeaddrinfo(res);
            return fd;
        }

        saved_errno = errno;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    set_errf(err, err_cap, "SOCKS5 TCP connect failed for %s:%u: errno=%d", host, (unsigned)port, saved_errno);
    return -1;
}

static int socks5_read_address_tail(int fd, uint8_t atyp) {
    uint8_t tmp[260];
    size_t tail = 0;

    if (atyp == 0x01) {
        tail = 4 + 2;
    } else if (atyp == 0x04) {
        tail = 16 + 2;
    } else if (atyp == 0x03) {
        uint8_t len = 0;
        if (read_exact(fd, &len, 1) != 0) {
            return -1;
        }
        tail = (size_t)len + 2;
    } else {
        return -1;
    }

    if (tail > sizeof(tmp)) {
        return -1;
    }
    return read_exact(fd, tmp, tail);
}

static int socks5_authenticate(int fd, const vless_config_t *cfg, char *err, size_t err_cap) {
    int has_auth = (cfg->socks5_user[0] != '\0' || cfg->socks5_pass[0] != '\0');
    uint8_t hello[4];
    size_t n = 0;
    hello[n++] = 0x05;
    if (has_auth) {
        hello[n++] = 0x02;
        hello[n++] = 0x02;
        hello[n++] = 0x00;
    } else {
        hello[n++] = 0x01;
        hello[n++] = 0x00;
    }

    if (write_exact(fd, hello, n) != 0) {
        set_errf(err, err_cap, "SOCKS5 method negotiation send failed");
        return -1;
    }

    uint8_t resp[2];
    if (read_exact(fd, resp, sizeof(resp)) != 0 || resp[0] != 0x05) {
        set_errf(err, err_cap, "SOCKS5 method negotiation read failed");
        return -1;
    }
    if (resp[1] == 0xFF) {
        set_errf(err, err_cap, "SOCKS5 server rejected authentication methods");
        return -1;
    }
    if (resp[1] == 0x00) {
        return 0;
    }
    if (resp[1] != 0x02) {
        set_errf(err, err_cap, "SOCKS5 server selected unsupported auth method 0x%02x", resp[1]);
        return -1;
    }

    size_t ulen = strlen(cfg->socks5_user);
    size_t plen = strlen(cfg->socks5_pass);
    if (ulen == 0 || ulen > 255 || plen > 255) {
        set_errf(err, err_cap, "SOCKS5 username/password length is invalid");
        return -1;
    }

    uint8_t auth[513];
    n = 0;
    auth[n++] = 0x01;
    auth[n++] = (uint8_t)ulen;
    memcpy(auth + n, cfg->socks5_user, ulen);
    n += ulen;
    auth[n++] = (uint8_t)plen;
    if (plen > 0) {
        memcpy(auth + n, cfg->socks5_pass, plen);
        n += plen;
    }

    if (write_exact(fd, auth, n) != 0) {
        set_errf(err, err_cap, "SOCKS5 username/password auth send failed");
        return -1;
    }

    uint8_t auth_resp[2];
    if (read_exact(fd, auth_resp, sizeof(auth_resp)) != 0 || auth_resp[0] != 0x01 || auth_resp[1] != 0x00) {
        set_errf(err, err_cap, "SOCKS5 username/password auth failed");
        return -1;
    }
    return 0;
}

static int socks5_send_connect(int fd, const char *target_host, uint16_t target_port, char *err, size_t err_cap) {
    uint8_t req[300];
    size_t n = 0;
    req[n++] = 0x05;
    req[n++] = 0x01;
    req[n++] = 0x00;

    struct in_addr in4;
    struct in6_addr in6;
    if (inet_pton(AF_INET, target_host, &in4) == 1) {
        req[n++] = 0x01;
        memcpy(req + n, &in4, 4);
        n += 4;
    } else if (inet_pton(AF_INET6, target_host, &in6) == 1) {
        req[n++] = 0x04;
        memcpy(req + n, &in6, 16);
        n += 16;
    } else {
        size_t hlen = strlen(target_host);
        if (hlen == 0 || hlen > 255) {
            set_errf(err, err_cap, "SOCKS5 target domain length is invalid");
            return -1;
        }
        req[n++] = 0x03;
        req[n++] = (uint8_t)hlen;
        memcpy(req + n, target_host, hlen);
        n += hlen;
    }

    req[n++] = (uint8_t)((target_port >> 8) & 0xFF);
    req[n++] = (uint8_t)(target_port & 0xFF);

    if (write_exact(fd, req, n) != 0) {
        set_errf(err, err_cap, "SOCKS5 CONNECT send failed");
        return -1;
    }

    uint8_t resp[4];
    if (read_exact(fd, resp, sizeof(resp)) != 0 || resp[0] != 0x05) {
        set_errf(err, err_cap, "SOCKS5 CONNECT response read failed");
        return -1;
    }
    if (socks5_read_address_tail(fd, resp[3]) != 0) {
        set_errf(err, err_cap, "SOCKS5 CONNECT bind address read failed");
        return -1;
    }
    if (resp[1] != 0x00) {
        set_errf(err, err_cap, "SOCKS5 CONNECT rejected target with code 0x%02x", resp[1]);
        return -1;
    }
    return 0;
}

int socks5_upstream_connect(const vless_config_t *cfg, const char *target_host, uint16_t target_port, char *err, size_t err_cap) {
    if (cfg == NULL || target_host == NULL || target_host[0] == '\0' || target_port == 0) {
        set_errf(err, err_cap, "invalid SOCKS5 upstream input");
        return -1;
    }

    int fd = connect_tcp_host(cfg->server_host, cfg->server_port, err, err_cap);
    if (fd < 0) {
        return -1;
    }

    if (socks5_authenticate(fd, cfg, err, err_cap) != 0 ||
        socks5_send_connect(fd, target_host, target_port, err, err_cap) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}
