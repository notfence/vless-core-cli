#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H

#include <sys/socket.h>
#include <netdb.h>

void core_tune_tcp_socket(int fd);
void core_set_socket_io_timeout(int fd, int timeout_ms);
int core_connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int timeout_ms);
int core_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **addresses);

#endif
