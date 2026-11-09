#ifndef CORE_DIALER_H
#define CORE_DIALER_H
#include <stdint.h>
#include <sys/socket.h>
#include "sockopt.h"

typedef struct core_dialer core_dialer_t;
core_dialer_t *core_dialer_start(const char *host, uint16_t port, int use_server_ips, int timeout_ms,
                               const struct sockaddr *preferred, socklen_t preferred_length);
int core_dialer_next(core_dialer_t *dialer, struct sockaddr_storage *address, socklen_t *length);
void core_dialer_free(core_dialer_t *dialer);
void core_dialer_set_sockopt(core_dialer_t *, const core_sockopt_t *);
int core_dial_host_options(const char *, uint16_t, int, int, const core_sockopt_t *);
int core_dial_host(const char *host, uint16_t port, int use_server_ips, int timeout_ms);
#endif
