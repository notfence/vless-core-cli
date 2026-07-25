#ifndef VLESS_CORE_ROUTING_H
#define VLESS_CORE_ROUTING_H

#include <stddef.h>
#include <stdint.h>

#define ROUTING_MAX_RULES 48

typedef enum {
    ROUTE_ACTION_PROXY = 0,
    ROUTE_ACTION_DIRECT = 1,
    ROUTE_ACTION_BLOCK = 2
} route_action_t;

typedef enum {
    ROUTE_MATCH_DOMAIN = 0,
    ROUTE_MATCH_SUFFIX = 1,
    ROUTE_MATCH_CIDR = 2,
    ROUTE_MATCH_PORT = 3
} route_match_t;

typedef struct {
    route_action_t action;
    route_match_t match;
    char value[256];
    uint16_t port_first;
    uint16_t port_last;
} routing_rule_t;

typedef struct {
    int enabled;
    int bypass_lan;
    route_action_t default_action;
    size_t rule_count;
    routing_rule_t rules[ROUTING_MAX_RULES];
} routing_config_t;

void routing_config_init(routing_config_t *config);
int routing_config_parse(const char *text, routing_config_t *config, char *err, size_t err_cap);
route_action_t routing_decide(const routing_config_t *config,
                              const char *target_host,
                              uint16_t target_port,
                              const char *observed_domain,
                              char *matched_host,
                              size_t matched_host_cap,
                              int *matched_rule);
int routing_has_domain_rules(const routing_config_t *config);
const char *routing_action_name(route_action_t action);
int routing_open_direct(const char *host,
                        uint16_t port,
                        int control_port,
                        char *err,
                        size_t err_cap);

#endif
