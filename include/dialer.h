#ifndef CORE_DIALER_H
#define CORE_DIALER_H
#include <stdint.h>
#include <sys/socket.h>

typedef struct core_dialer core_dialer_t;
core_dialer_t *core_dialer_start(const char *host, uint16_t port, int use_server_ips, int timeout_ms,
                               const struct sockaddr *preferred, socklen_t preferred_length);
int core_dialer_next(core_dialer_t *dialer, struct sockaddr_storage *address, socklen_t *length);
void core_dialer_free(core_dialer_t *dialer);
int core_dial_host(const char *host, uint16_t port, int use_server_ips, int timeout_ms);
#endif
