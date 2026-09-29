#ifndef VLESS_CORE_SERVER_IPS_H
#define VLESS_CORE_SERVER_IPS_H

#include <netinet/in.h>
#include <stddef.h>

int core_set_server_ips(const char *value);
size_t core_server_ip_count(void);
const struct in_addr *core_server_ip_at(size_t index);

#endif
