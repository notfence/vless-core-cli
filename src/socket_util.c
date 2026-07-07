#define _POSIX_C_SOURCE 200112L

#include "socket_util.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

void core_tune_tcp_socket(int fd) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

void core_set_socket_io_timeout(int fd, int timeout_ms) {
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    if (timeout_ms > 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int core_connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms) {
    if (timeout_ms <= 0) {
        return connect(fd, addr, addr_len);
    }

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
        int saved_errno = errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved_errno;
        return -1;
    }

    do {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc > 0 && !FD_ISSET(fd, &wfds)) {
            rc = 0;
        }
    } while (rc < 0 && errno == EINTR);

    if (rc <= 0) {
        int saved_errno = (rc == 0) ? ETIMEDOUT : errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved_errno;
        return -1;
    }

    int soerr = 0;
    socklen_t soerr_len = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) != 0 || soerr != 0) {
        int saved_errno = (soerr != 0) ? soerr : errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved_errno;
        return -1;
    }

    (void)fcntl(fd, F_SETFL, flags);
    return 0;
}
