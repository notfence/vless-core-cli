#ifndef VLESS_CORE_SOCKS5_H
#define VLESS_CORE_SOCKS5_H

#include <stddef.h>
#include <stdint.h>

#define SOCKS5_NEGOTIATION_TIMEOUT_MS 10000

enum { SOCKS5_NEGOTIATION_REJECTED = -2, SOCKS5_COMMAND_UNSUPPORTED = -3, SOCKS5_ADDRESS_UNSUPPORTED = -4 };

int socks5_negotiate_and_get_target(int fd, char *host, size_t host_cap, uint16_t *port);
int socks5_send_success(int fd);
int socks5_send_failure(int fd, uint8_t rep);
int socks5_domain_valid(const uint8_t *, size_t);
uint8_t socks5_error_reply(int);
uint8_t socks5_request_reply(int);

#endif
