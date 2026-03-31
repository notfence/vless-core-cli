#ifndef VLESS_CORE_SOCKS5_H
#define VLESS_CORE_SOCKS5_H

#include <stddef.h>
#include <stdint.h>

int socks5_negotiate_and_get_target(int fd, char *host, size_t host_cap, uint16_t *port);
int socks5_send_success(int fd);
int socks5_send_failure(int fd, uint8_t rep);

#endif
