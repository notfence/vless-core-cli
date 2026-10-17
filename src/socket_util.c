#define _POSIX_C_SOURCE 200112L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "socket_util.h"
#include "connection_trace.h"
#include "deadline.h"
#include "resolver.h"

#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

uint64_t core_now_ms(void) {
#ifdef __APPLE__
    mach_timebase_info_data_t scale;
    if (mach_timebase_info(&scale) != KERN_SUCCESS || scale.denom == 0) return 0;
    return (uint64_t)((double)mach_absolute_time() * scale.numer / scale.denom / 1000000.0);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

int core_poll(struct pollfd *fds, nfds_t count, int timeout_ms) {
    timeout_ms = core_deadline_limit(timeout_ms);
    if (core_deadline_active() && core_deadline_remaining() == 0) return 0;
    uint64_t deadline = timeout_ms >= 0 ? core_now_ms() + (unsigned)timeout_ms : 0;
    int wait = timeout_ms;
    for (;;) {
        int result = poll(fds, count, wait);
        if (result >= 0) {
            for (nfds_t i = 0; i < count; i++) {
                if (fds[i].revents & POLLNVAL) { errno = EBADF; return -1; }
            }
            return result;
        }
        if (errno != EINTR) return -1;
        if (timeout_ms >= 0) {
            uint64_t now = core_now_ms();
            if (now >= deadline) return 0;
            uint64_t left = deadline - now;
            wait = left > INT_MAX ? INT_MAX : (int)left;
        }
        wait = core_deadline_limit(wait);
    }
}

int core_wait_socket(int fd, short events, int timeout_ms) {
    if (fd < 0) { errno = EBADF; return -1; }
    struct pollfd socket = {.fd = fd, .events = events};
    return core_poll(&socket, 1, timeout_ms);
}

ssize_t core_recv(int fd, void *buffer, size_t length, int flags) {
    for (;;) {
        int bounded = core_deadline_active();
        if (bounded && core_deadline_remaining() == 0) return -1;
        ssize_t result = recv(fd, buffer, length, flags | (bounded ? MSG_DONTWAIT : 0));
        if (result >= 0 || (errno != EINTR && (!bounded || (errno != EAGAIN && errno != EWOULDBLOCK)))) return result;
        if (errno == EINTR) continue;
        int ready = core_wait_socket(fd, POLLIN, -1);
        if (ready <= 0) { if (ready == 0) errno = ETIMEDOUT; return -1; }
    }
}

ssize_t core_send(int fd, const void *buffer, size_t length, int flags) {
    for (;;) {
        int bounded = core_deadline_active();
        if (bounded && core_deadline_remaining() == 0) return -1;
        ssize_t result = send(fd, buffer, length, flags | (bounded ? MSG_DONTWAIT : 0));
        if (result >= 0 || (errno != EINTR && (!bounded || (errno != EAGAIN && errno != EWOULDBLOCK)))) return result;
        if (errno == EINTR) continue;
        int ready = core_wait_socket(fd, POLLOUT, -1);
        if (ready <= 0) { if (ready == 0) errno = ETIMEDOUT; return -1; }
    }
}

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

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms) {
    timeout_ms = core_deadline_limit(timeout_ms <= 0 ? -1 : timeout_ms);
    if (timeout_ms == 0) { errno = ETIMEDOUT; return -1; }
    if (timeout_ms <= 0) {
        return connect(fd, addr, addr_len);
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }

    int rc = connect(fd, addr, addr_len);
    if (rc == 0) {
        (void)fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS && errno != EINTR) {
        int saved_errno = errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved_errno;
        return -1;
    }

    rc = core_wait_socket(fd, POLLOUT, timeout_ms);

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

int core_connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms) {
    core_trace_stage(CORE_TRACE_TCP);
    int result = connect_with_timeout(fd, addr, addr_len, timeout_ms);
    if (result == 0) core_trace_stage(CORE_TRACE_TRANSPORT);
    return result;
}

int core_numeric_address(const char *host, uint16_t port, struct sockaddr_storage *address, socklen_t *length) {
    if (!host || !address || !length) { errno=EINVAL; return -1; }
    struct sockaddr_storage numeric={0};
    struct sockaddr_in *v4=(void *)&numeric;
    struct sockaddr_in6 *v6=(void *)&numeric;
    if (inet_pton(AF_INET,host,&v4->sin_addr) == 1) {
        v4->sin_family=AF_INET; v4->sin_port=htons(port); *length=sizeof(*v4);
#ifdef __APPLE__
        v4->sin_len=sizeof(*v4);
#endif
    } else if (inet_pton(AF_INET6,host,&v6->sin6_addr) == 1) {
        v6->sin6_family=AF_INET6; v6->sin6_port=htons(port); *length=sizeof(*v6);
#ifdef __APPLE__
        v6->sin6_len=sizeof(*v6);
#endif
    } else return 0;
    *address=numeric; return 1;
}

int core_notify_socket(int fd) {
    int saved=errno,flags=MSG_DONTWAIT; uint8_t byte=1; ssize_t sent;
#ifdef MSG_NOSIGNAL
    flags|=MSG_NOSIGNAL;
#endif
    do { sent=send(fd,&byte,1,flags); } while (sent < 0 && errno == EINTR);
    int result=sent == 1 || (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    errno=saved; return result;
}

void core_drain_socket(int fd) {
    int saved=errno; uint8_t bytes[128]; ssize_t received;
    do { received=recv(fd,bytes,sizeof(bytes),MSG_DONTWAIT); }
    while (received > 0 || (received < 0 && errno == EINTR));
    errno=saved;
}

int core_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **addresses) {
    core_trace_stage(CORE_TRACE_DNS);
    core_resolver_query_t *query = core_resolver_start(host, service, hints);
    if (!query) { *addresses = NULL; return EAI_SYSTEM; }
    int result = core_resolver_wait(query, addresses);
    int saved_errno = errno;
    core_resolver_release(query);
    errno = saved_errno;
    if (result == 0) core_trace_stage(CORE_TRACE_TCP);
    return result;
}
