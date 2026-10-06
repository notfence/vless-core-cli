#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
int __real_connect(int fd, const struct sockaddr *address, socklen_t length);
int __real_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **result);
int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    int allowed = address && address->sa_family == AF_UNIX;
    if (address && address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) allowed = (ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr) >> 24) == 127;
    if (address && address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) allowed = IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)address)->sin6_addr);
    if (!allowed) { fprintf(stderr,"FAIL network/non-loopback-connect: blocked by test sandbox\n"); errno = EACCES; return -1; }
    return __real_connect(fd,address,length);
}
int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
    struct in_addr ipv4; struct in6_addr ipv6;
    int numeric = host && (inet_pton(AF_INET,host,&ipv4) == 1 || inet_pton(AF_INET6,host,&ipv6) == 1);
    const char *mapped = host;
    if (!numeric) {
        if (host && (!strcmp(host,"localhost") || !strcmp(host,"vless-core.test"))) mapped = "127.0.0.1";
        else { fprintf(stderr,"FAIL network/external-dns: refused %s\n", host ? host : "null"); return EAI_NONAME; }
    }
    struct addrinfo local = hints ? *hints : (struct addrinfo){0}; local.ai_flags |= AI_NUMERICHOST;
    return __real_getaddrinfo(mapped,service,&local,result);
}
