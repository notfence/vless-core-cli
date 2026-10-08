#ifndef VLESS_CORE_SERVER_IPS_H
#define VLESS_CORE_SERVER_IPS_H

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

int core_set_server_ips(const char *value);
size_t core_server_ip_count(void);
const struct in_addr *core_server_ip_at(size_t index);
int core_server_address_at(size_t index, uint16_t port, struct sockaddr_storage *address, socklen_t *length);

#endif
