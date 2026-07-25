#define _POSIX_C_SOURCE 200112L

#include "routing.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket_util.h"

#define ROUTING_CONNECT_TIMEOUT_MS 10000
#define ROUTING_CONTROL_TIMEOUT_MS 2000

static void set_err(char *err, size_t cap, const char *message) {
    if (err != NULL && cap > 0) {
        snprintf(err, cap, "%s", message != NULL ? message : "routing error");
    }
}

static void copy_lower(char *dst, size_t cap, const char *src) {
    if (dst == NULL || cap == 0) {
        return;
    }
    size_t i = 0;
    while (src != NULL && src[i] != '\0' && i + 1 < cap) {
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

static int parse_action(const char *value, route_action_t *action) {
    if (strcmp(value, "proxy") == 0) {
        *action = ROUTE_ACTION_PROXY;
    } else if (strcmp(value, "direct") == 0) {
        *action = ROUTE_ACTION_DIRECT;
    } else if (strcmp(value, "block") == 0) {
        *action = ROUTE_ACTION_BLOCK;
    } else {
        return -1;
    }
    return 0;
}

static int parse_match(const char *value, route_match_t *match) {
    if (strcmp(value, "domain") == 0) {
        *match = ROUTE_MATCH_DOMAIN;
    } else if (strcmp(value, "suffix") == 0) {
        *match = ROUTE_MATCH_SUFFIX;
    } else if (strcmp(value, "cidr") == 0) {
        *match = ROUTE_MATCH_CIDR;
    } else if (strcmp(value, "port") == 0) {
        *match = ROUTE_MATCH_PORT;
    } else {
        return -1;
    }
    return 0;
}

static int parse_port_range(const char *value, uint16_t *first, uint16_t *last) {
    char tmp[32];
    if (value == NULL || strlen(value) >= sizeof(tmp)) {
        return -1;
    }
    snprintf(tmp, sizeof(tmp), "%s", value);

    char *dash = strchr(tmp, '-');
    if (dash != NULL) {
        *dash++ = '\0';
    }

    char *end = NULL;
    long a = strtol(tmp, &end, 10);
    if (end == tmp || *end != '\0' || a <= 0 || a > 65535) {
        return -1;
    }
    long b = a;
    if (dash != NULL) {
        end = NULL;
        b = strtol(dash, &end, 10);
        if (end == dash || *end != '\0' || b <= 0 || b > 65535) {
            return -1;
        }
    }
    if (a > b) return -1;
    *first = (uint16_t)a;
    *last = (uint16_t)b;
    return 0;
}

static int parse_cidr(const char *value, int *family, unsigned char *network, int *prefix) {
    char tmp[INET6_ADDRSTRLEN + 8];
    if (value == NULL || strlen(value) >= sizeof(tmp)) {
        return -1;
    }
    snprintf(tmp, sizeof(tmp), "%s", value);

    char *slash = strchr(tmp, '/');
    int has_prefix = slash != NULL;
    int bits = -1;
    if (slash != NULL) {
        *slash++ = '\0';
        char *end = NULL;
        long parsed = strtol(slash, &end, 10);
        if (end == slash || *end != '\0' || parsed < 0) {
            return -1;
        }
        bits = (int)parsed;
    }

    if (inet_pton(AF_INET, tmp, network) == 1) {
        if (!has_prefix) bits = 32;
        if (bits > 32) return -1;
        *family = AF_INET;
    } else if (inet_pton(AF_INET6, tmp, network) == 1) {
        if (!has_prefix) bits = 128;
        if (bits > 128) return -1;
        *family = AF_INET6;
    } else {
        return -1;
    }
    *prefix = bits;
    return 0;
}

static int valid_domain(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    size_t len = strlen(value);
    if (len > 253 || value[0] == '.' || value[len - 1] == '.') {
        return 0;
    }
    const unsigned char *previous = NULL;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.')) {
            return 0;
        }
        if (*p == '.' && previous != NULL && *previous == '.') {
            return 0;
        }
        previous = p;
    }
    return 1;
}

void routing_config_init(routing_config_t *config) {
    if (config == NULL) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->default_action = ROUTE_ACTION_PROXY;
    config->bypass_lan = 1;
}

int routing_config_parse(const char *text, routing_config_t *config, char *err, size_t err_cap) {
    if (config == NULL) {
        set_err(err, err_cap, "missing routing config");
        return -1;
    }
    routing_config_init(config);
    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    size_t text_len = strlen(text);
    if (text_len > 8191) {
        set_err(err, err_cap, "routing config is too long");
        return -1;
    }
    char *copy = (char *)malloc(text_len + 1);
    if (copy == NULL) {
        set_err(err, err_cap, "out of memory");
        return -1;
    }
    memcpy(copy, text, text_len + 1);

    char *save = NULL;
    char *token = strtok_r(copy, ";", &save);
    if (token == NULL || (strcmp(token, "0") != 0 && strcmp(token, "1") != 0)) {
        free(copy);
        set_err(err, err_cap, "invalid enabled flag");
        return -1;
    }
    config->enabled = (token[0] == '1');

    token = strtok_r(NULL, ";", &save);
    if (token == NULL || parse_action(token, &config->default_action) != 0) {
        free(copy);
        set_err(err, err_cap, "invalid default action");
        return -1;
    }

    token = strtok_r(NULL, ";", &save);
    if (token == NULL || (strcmp(token, "0") != 0 && strcmp(token, "1") != 0)) {
        free(copy);
        set_err(err, err_cap, "invalid LAN flag");
        return -1;
    }
    config->bypass_lan = (token[0] == '1');

    while ((token = strtok_r(NULL, ";", &save)) != NULL) {
        if (config->rule_count >= ROUTING_MAX_RULES) {
            free(copy);
            set_err(err, err_cap, "too many routing rules");
            return -1;
        }

        char *comma1 = strchr(token, ',');
        char *comma2 = comma1 != NULL ? strchr(comma1 + 1, ',') : NULL;
        if (comma1 == NULL || comma2 == NULL || comma2[1] == '\0') {
            free(copy);
            set_err(err, err_cap, "invalid routing rule");
            return -1;
        }
        *comma1++ = '\0';
        *comma2++ = '\0';

        routing_rule_t *rule = &config->rules[config->rule_count];
        memset(rule, 0, sizeof(*rule));
        if (parse_action(token, &rule->action) != 0 ||
            parse_match(comma1, &rule->match) != 0 ||
            strlen(comma2) >= sizeof(rule->value)) {
            free(copy);
            set_err(err, err_cap, "invalid routing rule fields");
            return -1;
        }
        copy_lower(rule->value, sizeof(rule->value), comma2);

        if (rule->match == ROUTE_MATCH_PORT) {
            if (parse_port_range(rule->value, &rule->port_first, &rule->port_last) != 0) {
                free(copy);
                set_err(err, err_cap, "invalid port rule");
                return -1;
            }
        } else if (rule->match == ROUTE_MATCH_CIDR) {
            int family = 0;
            int prefix = 0;
            unsigned char network[16];
            if (parse_cidr(rule->value, &family, network, &prefix) != 0) {
                free(copy);
                set_err(err, err_cap, "invalid CIDR rule");
                return -1;
            }
        } else if (!valid_domain(rule->value)) {
            free(copy);
            set_err(err, err_cap, "invalid domain rule");
            return -1;
        }
        config->rule_count++;
    }

    free(copy);
    return 0;
}

static int ip_in_cidr(const char *host, const char *cidr) {
    unsigned char address[16];
    unsigned char network[16];
    int family = 0;
    int prefix = 0;
    if (parse_cidr(cidr, &family, network, &prefix) != 0 ||
        inet_pton(family, host, address) != 1) {
        return 0;
    }

    int full = prefix / 8;
    int remaining = prefix % 8;
    if (full > 0 && memcmp(address, network, (size_t)full) != 0) {
        return 0;
    }
    if (remaining > 0) {
        unsigned char mask = (unsigned char)(0xff << (8 - remaining));
        if ((address[full] & mask) != (network[full] & mask)) {
            return 0;
        }
    }
    return 1;
}

static int is_local_address(const char *host) {
    return ip_in_cidr(host, "10.0.0.0/8") ||
           ip_in_cidr(host, "100.64.0.0/10") ||
           ip_in_cidr(host, "127.0.0.0/8") ||
           ip_in_cidr(host, "169.254.0.0/16") ||
           ip_in_cidr(host, "172.16.0.0/12") ||
           ip_in_cidr(host, "192.168.0.0/16") ||
           ip_in_cidr(host, "224.0.0.0/4") ||
           ip_in_cidr(host, "::1/128") ||
           ip_in_cidr(host, "fc00::/7") ||
           ip_in_cidr(host, "fe80::/10");
}

static int domain_suffix_match(const char *host, const char *suffix) {
    size_t host_len = strlen(host);
    size_t suffix_len = strlen(suffix);
    if (host_len < suffix_len) {
        return 0;
    }
    if (strcmp(host + host_len - suffix_len, suffix) != 0) {
        return 0;
    }
    return host_len == suffix_len || host[host_len - suffix_len - 1] == '.';
}

route_action_t routing_decide(const routing_config_t *config,
                              const char *target_host,
                              uint16_t target_port,
                              const char *observed_domain,
                              char *matched_host,
                              size_t matched_host_cap,
                              int *matched_rule) {
    if (matched_host != NULL && matched_host_cap > 0) matched_host[0] = '\0';
    if (matched_rule != NULL) *matched_rule = -1;
    if (config == NULL || !config->enabled || target_host == NULL) {
        return ROUTE_ACTION_PROXY;
    }

    char domain[256];
    domain[0] = '\0';
    struct in_addr in4;
    struct in6_addr in6;
    int is_ip = inet_pton(AF_INET, target_host, &in4) == 1 ||
                inet_pton(AF_INET6, target_host, &in6) == 1;
    if (observed_domain != NULL && valid_domain(observed_domain)) {
        copy_lower(domain, sizeof(domain), observed_domain);
    } else if (!is_ip) {
        copy_lower(domain, sizeof(domain), target_host);
    }
    if (matched_host != NULL && matched_host_cap > 0 && domain[0] != '\0') {
        snprintf(matched_host, matched_host_cap, "%s", domain);
    }

    if (config->bypass_lan && is_ip && is_local_address(target_host)) {
        if (matched_rule != NULL) *matched_rule = -2;
        return ROUTE_ACTION_DIRECT;
    }

    for (size_t i = 0; i < config->rule_count; i++) {
        const routing_rule_t *rule = &config->rules[i];
        int matches = 0;
        if (rule->match == ROUTE_MATCH_PORT) {
            matches = target_port >= rule->port_first && target_port <= rule->port_last;
        } else if (rule->match == ROUTE_MATCH_CIDR) {
            matches = is_ip && ip_in_cidr(target_host, rule->value);
        } else if (rule->match == ROUTE_MATCH_DOMAIN) {
            matches = domain[0] != '\0' && strcmp(domain, rule->value) == 0;
        } else if (rule->match == ROUTE_MATCH_SUFFIX) {
            matches = domain[0] != '\0' && domain_suffix_match(domain, rule->value);
        }
        if (matches) {
            if (matched_rule != NULL) *matched_rule = (int)i;
            return rule->action;
        }
    }

    if (target_port == 53 && strcmp(target_host, "8.8.8.8") == 0) {
        if (matched_rule != NULL) *matched_rule = -3;
        return ROUTE_ACTION_PROXY;
    }
    return config->default_action;
}

int routing_has_domain_rules(const routing_config_t *config) {
    if (config == NULL || !config->enabled) {
        return 0;
    }
    for (size_t i = 0; i < config->rule_count; i++) {
        if (config->rules[i].match == ROUTE_MATCH_DOMAIN ||
            config->rules[i].match == ROUTE_MATCH_SUFFIX) {
            return 1;
        }
    }
    return 0;
}

const char *routing_action_name(route_action_t action) {
    if (action == ROUTE_ACTION_DIRECT) return "direct";
    if (action == ROUTE_ACTION_BLOCK) return "block";
    return "proxy";
}

static int write_all(int fd, const char *data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = send(fd, data + offset, len - offset, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (size_t)n;
    }
    return 0;
}

static int update_bypass(int control_port, const char *operation, const char *ip) {
    if (control_port <= 0) {
        return 0;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    core_set_socket_io_timeout(fd, ROUTING_CONTROL_TIMEOUT_MS);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((uint16_t)control_port);
    if (core_connect_with_timeout(fd, (const struct sockaddr *)&addr, sizeof(addr), ROUTING_CONTROL_TIMEOUT_MS) != 0) {
        close(fd);
        return -1;
    }

    char command[128];
    int len = snprintf(command, sizeof(command), "%s\t%s\n", operation, ip);
    if (len <= 0 || (size_t)len >= sizeof(command) ||
        write_all(fd, command, (size_t)len) != 0) {
        close(fd);
        return -1;
    }

    char reply[64];
    ssize_t n = recv(fd, reply, sizeof(reply) - 1, 0);
    close(fd);
    if (n <= 0) return -1;
    reply[n] = '\0';
    return strncmp(reply, "OK", 2) == 0 ? 0 : -1;
}

int routing_open_direct(const char *host,
                        uint16_t port,
                        int control_port,
                        char *err,
                        size_t err_cap) {
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = control_port > 0 ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int gai = getaddrinfo(host, port_text, &hints, &result);
    if (gai != 0) {
        set_err(err, err_cap, "direct DNS resolution failed");
        return -1;
    }

    int fd = -1;
    int last_errno = 0;
    for (struct addrinfo *it = result; it != NULL; it = it->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        void *address = NULL;
        if (it->ai_family == AF_INET) {
            address = &((struct sockaddr_in *)it->ai_addr)->sin_addr;
        } else if (it->ai_family == AF_INET6) {
            address = &((struct sockaddr_in6 *)it->ai_addr)->sin6_addr;
        } else {
            continue;
        }
        if (inet_ntop(it->ai_family, address, ip, sizeof(ip)) == NULL) {
            continue;
        }

        int bypass_added = 0;
        if (control_port > 0) {
            if (it->ai_family != AF_INET ||
                update_bypass(control_port, "ROUTE_DIRECT_ADD", ip) != 0) {
                last_errno = EACCES;
                continue;
            }
            bypass_added = 1;
        }

        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd >= 0) {
            core_tune_tcp_socket(fd);
            if (core_connect_with_timeout(fd, it->ai_addr, (socklen_t)it->ai_addrlen,
                                          ROUTING_CONNECT_TIMEOUT_MS) == 0) {
                if (bypass_added) {
                    (void)update_bypass(control_port, "ROUTE_DIRECT_REMOVE", ip);
                }
                break;
            }
            last_errno = errno;
            close(fd);
            fd = -1;
        } else {
            last_errno = errno;
        }
        if (bypass_added) {
            (void)update_bypass(control_port, "ROUTE_DIRECT_REMOVE", ip);
        }
    }
    freeaddrinfo(result);

    if (fd < 0) {
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "direct connect failed: %s", strerror(last_errno));
        }
        return -1;
    }
    return fd;
}
