#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "routing.h"
#include "check.h"

static int expect_action(const routing_config_t *config,
                         const char *host,
                         uint16_t port,
                         route_action_t expected) {
    route_action_t actual = routing_decide(config, host, port, NULL, NULL, 0, NULL);
    if (actual != expected) {
        fprintf(stderr, "%s:%u expected=%s actual=%s\n",
                host, (unsigned)port,
                routing_action_name(expected),
                routing_action_name(actual));
        return -1;
    }
    return 0;
}

static int expect_action_with_domain(const routing_config_t *config,
                                     const char *host,
                                     uint16_t port,
                                     const char *domain,
                                     route_action_t expected) {
    route_action_t actual = routing_decide(config,
                                           host,
                                           port,
                                           domain,
                                           NULL,
                                           0,
                                           NULL);
    if (actual != expected) {
        fprintf(stderr, "%s:%u domain=%s expected=%s actual=%s\n",
                host,
                (unsigned)port,
                domain,
                routing_action_name(expected),
                routing_action_name(actual));
        return -1;
    }
    return 0;
}

int main(void) {
    routing_config_t config;
    char err[256];

    if (routing_config_parse(
            "1;block;0;direct,suffix,example.com;proxy,cidr,203.0.113.0/24;block,port,25",
            &config, err, sizeof(err)) != 0) {
        fprintf(stderr, "parse failed: %s\n", err);
        return 1;
    }
    if (expect_action(&config, "api.example.com", 443, ROUTE_ACTION_DIRECT) != 0 ||
        expect_action(&config, "API.EXAMPLE.COM", 443, ROUTE_ACTION_DIRECT) != 0 ||
        expect_action(&config, "notexample.com", 443, ROUTE_ACTION_BLOCK) != 0 ||
        expect_action(&config, "203.0.113.9", 443, ROUTE_ACTION_PROXY) != 0 ||
        expect_action(&config, "203.0.114.9", 443, ROUTE_ACTION_BLOCK) != 0 ||
        expect_action(&config, "192.0.2.1", 25, ROUTE_ACTION_BLOCK) != 0 ||
        expect_action(&config, "192.0.2.1", 443, ROUTE_ACTION_BLOCK) != 0) {
        return 1;
    }

    if (!routing_has_domain_rules(&config) ||
        expect_action_with_domain(&config,
                                  "198.51.100.2",
                                  443,
                                  "cdn.example.com",
                                  ROUTE_ACTION_DIRECT) != 0) {
        return 1;
    }

    if (routing_config_parse(
            "1;block;0;proxy,cidr,198.51.100.0/24;direct,suffix,example.com",
            &config, err, sizeof(err)) != 0 ||
        expect_action_with_domain(&config,
                                  "198.51.100.2",
                                  443,
                                  "cdn.example.com",
                                  ROUTE_ACTION_PROXY) != 0) {
        return 1;
    }

    if (routing_config_parse(
            "1;block;0;direct,domain,api.example.com;proxy,cidr,2001:db8::/32;direct,port,8000-8999",
            &config, err, sizeof(err)) != 0 ||
        expect_action(&config, "api.example.com", 443, ROUTE_ACTION_DIRECT) != 0 ||
        expect_action(&config, "2001:db8::42", 443, ROUTE_ACTION_PROXY) != 0 ||
        expect_action(&config, "2001:db9::42", 443, ROUTE_ACTION_BLOCK) != 0 ||
        expect_action(&config, "192.0.2.1", 8500, ROUTE_ACTION_DIRECT) != 0 ||
        expect_action(&config, "8.8.8.8", 53, ROUTE_ACTION_PROXY) != 0) {
        return 1;
    }

    if (routing_config_parse("1;proxy;1", &config, err, sizeof(err)) != 0 ||
        expect_action(&config, "192.168.1.1", 80, ROUTE_ACTION_DIRECT) != 0 ||
        expect_action(&config, "8.8.8.8", 443, ROUTE_ACTION_PROXY) != 0) {
        return 1;
    }
    if (routing_config_parse("0;block;1;block,port,443", &config, err, sizeof(err)) != 0 ||
        expect_action(&config, "192.168.1.1", 443, ROUTE_ACTION_PROXY) != 0) {
        return 1;
    }
    if (routing_config_parse("1;proxy;2", &config, err, sizeof(err)) == 0 ||
        routing_config_parse("1;proxy;1;block,cidr,999.1.1.1/24", &config, err, sizeof(err)) == 0 ||
        routing_config_parse("1;proxy;1;block,cidr,192.0.2.1/-1", &config, err, sizeof(err)) == 0 ||
        routing_config_parse("1;proxy;1;block,port,9000-8000", &config, err, sizeof(err)) == 0 ||
        routing_config_parse("1;proxy;1;block,suffix,.example.com", &config, err, sizeof(err)) == 0 ||
        routing_config_parse("1;proxy;1;block,domain,api..example.com", &config, err, sizeof(err)) == 0) {
        fprintf(stderr, "invalid policy accepted\n");
        return 1;
    }
    puts("routing tests passed");
    char policy[8192] = "1;block;0";
    for (int i = 0; i < ROUTING_MAX_RULES; i++) strcat(policy, ";direct,port,443");
    CHECK("routes/rule-limit", routing_config_parse(policy, &config, err, sizeof(err)) == 0 && config.rule_count == ROUTING_MAX_RULES);
    strcat(policy, ";direct,port,443"); CHECK("routes/rule-overflow", routing_config_parse(policy, &config, err, sizeof(err)) != 0);
    CHECK("routes/ipv4-zero-prefix", routing_config_parse("1;block;0;direct,cidr,0.0.0.0/0", &config, err, sizeof(err)) == 0 && expect_action(&config, "198.51.100.1", 443, ROUTE_ACTION_DIRECT) == 0);
    CHECK("routes/ipv6-zero-prefix", routing_config_parse("1;block;0;direct,cidr,::/0", &config, err, sizeof(err)) == 0 && expect_action(&config, "2001:db8::1", 443, ROUTE_ACTION_DIRECT) == 0);
    CHECK("routes/exact-cidrs", routing_config_parse("1;block;0;direct,cidr,192.0.2.1/32;direct,cidr,2001:db8::1/128", &config, err, sizeof(err)) == 0 && expect_action(&config, "192.0.2.1", 443, ROUTE_ACTION_DIRECT) == 0 && expect_action(&config, "192.0.2.2", 443, ROUTE_ACTION_BLOCK) == 0 && expect_action(&config, "2001:db8::2", 443, ROUTE_ACTION_BLOCK) == 0);
    CHECK("routes/invalid-prefix-boundaries", routing_config_parse("1;proxy;0;direct,cidr,192.0.2.1/33", &config, err, sizeof(err)) != 0 && routing_config_parse("1;proxy;0;direct,cidr,::1/129", &config, err, sizeof(err)) != 0);
    CHECK("routes/port-boundaries", routing_config_parse("1;block;0;direct,port,1-65535", &config, err, sizeof(err)) == 0 && expect_action(&config, "192.0.2.1", 1, ROUTE_ACTION_DIRECT) == 0 && expect_action(&config, "192.0.2.1", 65535, ROUTE_ACTION_DIRECT) == 0);
    int matched = -10; char domain[256];
    CHECK("routes/lan-priority", routing_config_parse("1;block;1;block,port,443", &config, err, sizeof(err)) == 0 && routing_decide(&config, "127.0.0.1", 443, NULL, domain, sizeof(domain), &matched) == ROUTE_ACTION_DIRECT && matched == -2);
    CHECK("routes/dns-rule-priority", routing_config_parse("1;direct;0;block,port,53", &config, err, sizeof(err)) == 0 && routing_decide(&config, "8.8.8.8", 53, NULL, NULL, 0, &matched) == ROUTE_ACTION_BLOCK && matched == 0);
    CHECK("routes/dns-fallback", routing_config_parse("1;block;0", &config, err, sizeof(err)) == 0 && routing_decide(&config, "8.8.8.8", 53, NULL, NULL, 0, &matched) == ROUTE_ACTION_PROXY && matched == -3);
    CHECK("routes/observed-host-normalized", routing_config_parse("1;block;0;direct,suffix,vless-core.test", &config, err, sizeof(err)) == 0 && routing_decide(&config, "192.0.2.1", 443, "API.VLESS-CORE.TEST", domain, sizeof(domain), &matched) == ROUTE_ACTION_DIRECT && strcmp(domain,"api.vless-core.test") == 0 && matched == 0);
    return test_result();
}
