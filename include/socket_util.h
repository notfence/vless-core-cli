#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
struct addrinfo;

uint64_t core_now_ms(void);
int core_poll(struct pollfd *fds, nfds_t count, int timeout_ms);
int core_wait_socket(int fd, short events, int timeout_ms);
ssize_t core_recv(int fd, void *buffer, size_t length, int flags);
ssize_t core_send(int fd, const void *buffer, size_t length, int flags);
int core_notify_socket(int);
void core_drain_socket(int);
void core_tune_tcp_socket(int fd);
void core_set_socket_io_timeout(int fd, int timeout_ms);
int core_connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms);
int core_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **addresses);
int core_numeric_address(const char *, uint16_t, struct sockaddr_storage *, socklen_t *);

#endif
