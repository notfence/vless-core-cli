#ifndef CORE_CLI_ARGS_H
#define CORE_CLI_ARGS_H
#include <stddef.h>

enum { CORE_CLI_URI_NONE, CORE_CLI_URI_ARGUMENT, CORE_CLI_URI_FD, CORE_CLI_CONNECTION_FD };
enum { CORE_CLI_RUN, CORE_CLI_HELP, CORE_CLI_VERSION, CORE_CLI_PATCH_STATUS, CORE_CLI_INSPECT };
typedef struct {
    const char *uri, *routing, *route_socket, *server_ips, *download_server_ips, *xray_version;
    int source, source_fd, listen_port, route_port, connect_timeout, action;
} core_cli_args_t;
int core_cli_args_parse(int, char *const *, core_cli_args_t *, char *, size_t);
void core_cli_args_scrub(int, char *const *);
#endif
