#include "socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

int socks5_send_failure(int fd, uint8_t rep) {
    uint8_t resp[10] = {0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return write_exact(fd, resp, sizeof(resp));
}

int socks5_send_success(int fd) {
    uint8_t resp[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return write_exact(fd, resp, sizeof(resp));
}

int socks5_negotiate_and_get_target(int fd, char *host, size_t host_cap, uint16_t *port) {
    if (host == NULL || host_cap == 0 || port == NULL) {
        return -1;
    }

    uint8_t hello[2];
    if (read_exact(fd, hello, sizeof(hello)) != 0) {
        return -1;
    }
    if (hello[0] != 0x05) {
        return -1;
    }

    uint8_t n_methods = hello[1];
    uint8_t methods[256];
    if (n_methods == 0 || read_exact(fd, methods, n_methods) != 0) {
        return -1;
    }

    uint8_t method_resp[2] = {0x05, 0x00};
    if (write_exact(fd, method_resp, sizeof(method_resp)) != 0) {
        return -1;
    }

    uint8_t req_head[4];
    if (read_exact(fd, req_head, sizeof(req_head)) != 0) {
        return -1;
    }

    if (req_head[0] != 0x05 || req_head[1] != 0x01) {
        return -1;
    }

    uint8_t atyp = req_head[3];
    if (atyp == 0x01) {
        uint8_t ip4[4];
        if (read_exact(fd, ip4, sizeof(ip4)) != 0) {
            return -1;
        }
        if (inet_ntop(AF_INET, ip4, host, (socklen_t)host_cap) == NULL) {
            return -1;
        }
    } else if (atyp == 0x03) {
        uint8_t dlen = 0;
        if (read_exact(fd, &dlen, 1) != 0) {
            return -1;
        }
        if (dlen == 0 || (size_t)dlen + 1 > host_cap) {
            return -1;
        }
        if (read_exact(fd, host, dlen) != 0) {
            return -1;
        }
        host[dlen] = '\0';
    } else if (atyp == 0x04) {
        uint8_t ip6[16];
        if (read_exact(fd, ip6, sizeof(ip6)) != 0) {
            return -1;
        }
        if (inet_ntop(AF_INET6, ip6, host, (socklen_t)host_cap) == NULL) {
            return -1;
        }
    } else {
        return -1;
    }

    uint8_t pbuf[2];
    if (read_exact(fd, pbuf, sizeof(pbuf)) != 0) {
        return -1;
    }
    *port = (uint16_t)((pbuf[0] << 8) | pbuf[1]);

    return 0;
}
