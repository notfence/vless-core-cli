#ifndef CORE_RESOLVER_H
#define CORE_RESOLVER_H
#include <netdb.h>
struct addrinfo;

typedef struct core_resolver_query core_resolver_query_t;
int core_resolver_init(void);
core_resolver_query_t *core_resolver_start(const char *host, const char *service, const struct addrinfo *hints);
int core_resolver_result(core_resolver_query_t *query, struct addrinfo **addresses, int *error);
void core_resolver_release(core_resolver_query_t *query);
int core_resolver_wait(core_resolver_query_t *query, struct addrinfo **addresses);
#endif
