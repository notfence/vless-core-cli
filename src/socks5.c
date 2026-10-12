#include "socks5.h"
#include "socket_util.h"
#include "deadline.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int socks5_domain_valid(const uint8_t *domain, size_t length) {
    if (!domain || !length || length > 255) return 0;
    for (size_t i=0;i<length;i++) if (domain[i] <= 0x20 || domain[i] == 0x7f) return 0;
    return 1;
}

uint8_t socks5_error_reply(int error) {
    if (error == EACCES || error == EPERM) return 2;
    if (error == ENETUNREACH || error == ENETDOWN) return 3;
    if (error == EHOSTUNREACH || error == EHOSTDOWN) return 4;
    if (error == ECONNREFUSED) return 5;
    if (error == EAFNOSUPPORT) return 8;
    return 1;
}

uint8_t socks5_request_reply(int result) {
    return result == SOCKS5_COMMAND_UNSUPPORTED ? 7 : result == SOCKS5_ADDRESS_UNSUPPORTED ? 8 : 1;
}

static int read_exact(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = core_recv(fd, p + off, len - off, 0);
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
        ssize_t n = core_send(fd, p + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int socks5_send_failure(int fd, uint8_t rep) {
    uint8_t resp[10] = {0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    core_deadline_pause();
    int result = write_exact(fd, resp, sizeof(resp));
    core_deadline_resume();
    return result;
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

    int no_auth = memchr(methods, 0x00, n_methods) != NULL;
    uint8_t method_resp[2] = {0x05, no_auth ? 0x00 : 0xff};
    if (write_exact(fd, method_resp, sizeof(method_resp)) != 0) {
        return -1;
    }
    if (!no_auth) {
        return SOCKS5_NEGOTIATION_REJECTED;
    }

    uint8_t req_head[4];
    if (read_exact(fd, req_head, sizeof(req_head)) != 0) {
        return -1;
    }

    if (req_head[0] != 0x05 || req_head[2] != 0x00) {
        return -1;
    }
    if (req_head[1] != 0x01) return SOCKS5_COMMAND_UNSUPPORTED;

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
        if (!socks5_domain_valid((const uint8_t *)host,dlen)) return -1;
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
        return SOCKS5_ADDRESS_UNSUPPORTED;
    }

    uint8_t pbuf[2];
    if (read_exact(fd, pbuf, sizeof(pbuf)) != 0) {
        return -1;
    }
    *port = (uint16_t)((pbuf[0] << 8) | pbuf[1]);
    return *port ? 0 : -1;
}
