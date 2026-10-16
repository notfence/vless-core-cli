#include "server_ips.h"

#include <arpa/inet.h>
#include <string.h>

#define SERVER_IP_OVERRIDE_MAX 64

typedef struct { struct sockaddr_storage addresses[SERVER_IP_OVERRIDE_MAX]; size_t count; } server_ip_list_t;
static server_ip_list_t primary_ips, download_ips;

static int set_ips(server_ip_list_t *list, const char *value) {
    if (value == NULL || value[0] == '\0') return -1;

    struct sockaddr_storage parsed[SERVER_IP_OVERRIDE_MAX];
    size_t parsed_count = 0;
    const char *cursor = value;

    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        const char *end = cursor;
        while (*end != '\0' && *end != ',') end++;
        const char *trimmed_end = end;
        while (trimmed_end > cursor && (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t')) trimmed_end--;

        size_t length = (size_t)(trimmed_end - cursor);
        if (length == 0 || length >= INET6_ADDRSTRLEN || parsed_count >= SERVER_IP_OVERRIDE_MAX) return -1;

        char ip[INET6_ADDRSTRLEN];
        memcpy(ip, cursor, length);
        ip[length] = '\0';

        struct sockaddr_storage address = {0};
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        if (inet_pton(AF_INET, ip, &ipv4->sin_addr) == 1) address.ss_family = AF_INET;
        else if (inet_pton(AF_INET6, ip, &ipv6->sin6_addr) == 1) address.ss_family = AF_INET6;
        else return -1;

        int duplicate = 0;
        for (size_t i = 0; i < parsed_count; i++) {
            if (memcmp(&parsed[i], &address, sizeof(address)) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) parsed[parsed_count++] = address;

        if (*end == '\0') break;
        cursor = end + 1;
        if (*cursor == '\0') return -1;
    }

    if (parsed_count == 0) return -1;
    memcpy(list->addresses, parsed, parsed_count * sizeof(parsed[0]));
    list->count = parsed_count;
    return 0;
}

int core_set_server_ips(const char *value) { return set_ips(&primary_ips,value); }
int core_set_download_server_ips(const char *value) { return set_ips(&download_ips,value); }
size_t core_server_ip_count(void) { return primary_ips.count; }
size_t core_ip_count(int source) { return source == CORE_IP_PRIMARY ? primary_ips.count : source == CORE_IP_DOWNLOAD ? download_ips.count : 0; }
int core_config_ip_source(const vless_config_t *config) {
    return config->xhttp_download_only && download_ips.count ? CORE_IP_DOWNLOAD : config->ignore_server_ips ? CORE_IP_NONE : CORE_IP_PRIMARY;
}

const struct in_addr *core_server_ip_at(size_t index) {
    return index < primary_ips.count && primary_ips.addresses[index].ss_family == AF_INET ?
        &((const struct sockaddr_in *)&primary_ips.addresses[index])->sin_addr : NULL;
}

int core_server_address_at(size_t index, uint16_t port, struct sockaddr_storage *address, socklen_t *length) {
    return core_ip_address_at(CORE_IP_PRIMARY,index,port,address,length);
}

int core_ip_address_at(int source, size_t index, uint16_t port, struct sockaddr_storage *address, socklen_t *length) {
    const server_ip_list_t *list=source == CORE_IP_PRIMARY ? &primary_ips : source == CORE_IP_DOWNLOAD ? &download_ips : NULL;
    if (!list || index >= list->count || !address || !length) return -1;
    *address = list->addresses[index];
    if (address->ss_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
        ipv4->sin_port = htons(port); *length = sizeof(*ipv4);
#ifdef __APPLE__
        ipv4->sin_len = sizeof(*ipv4);
#endif
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;
        ipv6->sin6_port = htons(port); *length = sizeof(*ipv6);
#ifdef __APPLE__
        ipv6->sin6_len = sizeof(*ipv6);
#endif
    }
    return 0;
}
