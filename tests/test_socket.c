#include "../src/socket_util.c"
#include "check.h"
#include <arpa/inet.h>
static int mode, interrupted;
int __real_connect(int fd, const struct sockaddr *address, socklen_t length);
int __real_poll(struct pollfd *fds, nfds_t count, int timeout);
int __real_getsockopt(int fd, int level, int option, void *value, socklen_t *length);
int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) { if (mode) { errno = EINPROGRESS; return -1; } return __real_connect(fd,address,length); }
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (mode == 1) return 0;
    if (mode == 3 && !interrupted++) { errno = EINTR; return -1; }
    if (mode) { for (nfds_t i=0;i<count;i++) fds[i].revents=fds[i].events; return 1; }
    return __real_poll(fds,count,timeout);
}
int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
    if (mode && level == SOL_SOCKET && option == SO_ERROR) { *(int *)value = mode == 2 ? ECONNREFUSED : 0; *length = sizeof(int); return 0; }
    return __real_getsockopt(fd,level,option,value,length);
}
int main(void) {
    struct sockaddr_in address = {.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    for (mode = 1; mode <= 3; mode++) {
        int fd = socket(AF_INET,SOCK_STREAM,0); int flags = fcntl(fd,F_GETFL); interrupted = 0;
        int result = core_connect_with_timeout(fd,(void *)&address,sizeof(address),10);
        if (mode == 1) CHECK("socket/connect-timeout", result == -1 && errno == ETIMEDOUT);
        if (mode == 2) CHECK("socket/connect-refused", result == -1 && errno == ECONNREFUSED);
        if (mode == 3) CHECK("socket/connect-eintr-retry", result == 0 && interrupted == 2);
        CHECK("socket/restore-flags", fcntl(fd,F_GETFL) == flags); close(fd);
    }
    mode = 0;
    int listener = socket(AF_INET,SOCK_STREAM,0); REQUIRE("socket/listener", bind(listener,(void *)&address,sizeof(address)) == 0 && listen(listener,1) == 0);
    socklen_t length = sizeof(address); REQUIRE("socket/port", getsockname(listener,(void *)&address,&length) == 0);
    int fd = socket(AF_INET,SOCK_STREAM,0); REQUIRE("socket/real-connect", core_connect_with_timeout(fd,(void *)&address,sizeof(address),100) == 0); int peer = accept(listener,NULL,NULL);
    core_tune_tcp_socket(fd); int option = 0; length = sizeof(option);
    CHECK("socket/tcp-nodelay", getsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&option,&length) == 0 && option == 1);
    CHECK("socket/keepalive", getsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&option,&length) == 0 && option == 1);
    core_set_socket_io_timeout(fd,250); struct timeval timeout; length = sizeof(timeout);
    CHECK("socket/io-timeout", getsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,&length) == 0 && timeout.tv_sec == 0 && timeout.tv_usec >= 250000);
    core_set_socket_io_timeout(fd,0); getsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,&length); CHECK("socket/reset-timeout", timeout.tv_sec == 0 && timeout.tv_usec == 0);
    close(peer); close(fd); close(listener);
    int pair[2]; REQUIRE("socket/high-fd-pair", socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    int high = fcntl(pair[0],F_DUPFD,4096); REQUIRE("socket/high-fd", high >= 4096); close(pair[0]);
    CHECK("socket/high-fd-empty", core_wait_socket(high,POLLIN,0) == 0);
    REQUIRE("socket/high-fd-write", write(pair[1],"v",1) == 1);
    CHECK("socket/high-fd-ready", core_wait_socket(high,POLLIN,100) == 1);
    char byte; CHECK("socket/high-fd-data", read(high,&byte,1) == 1 && byte == 'v'); close(pair[1]);
    CHECK("socket/high-fd-eof", core_wait_socket(high,POLLIN,100) == 1 && read(high,&byte,1) == 0);
    close(high); CHECK("socket/closed-fd", core_wait_socket(high,POLLIN,0) == -1 && errno == EBADF);
    CHECK("socket/invalid-fd", core_connect_with_timeout(-1,(void *)&address,sizeof(address),100) != 0);
    return test_result();
}
