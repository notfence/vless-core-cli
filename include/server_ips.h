#ifndef VLESS_CORE_SERVER_IPS_H
#define VLESS_CORE_SERVER_IPS_H

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>
#include "types.h"

enum { CORE_IP_NONE, CORE_IP_PRIMARY, CORE_IP_DOWNLOAD };
int core_set_download_server_ips(const char *);
size_t core_ip_count(int);
int core_ip_address_at(int, size_t, uint16_t, struct sockaddr_storage *, socklen_t *);
int core_config_ip_source(const vless_config_t *);

int core_set_server_ips(const char *value);
size_t core_server_ip_count(void);
const struct in_addr *core_server_ip_at(size_t index);
int core_server_address_at(size_t index, uint16_t port, struct sockaddr_storage *address, socklen_t *length);

#endif
