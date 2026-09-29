#include "server_ips.h"

#include <arpa/inet.h>
#include <string.h>

#define SERVER_IP_OVERRIDE_MAX 64

static struct in_addr g_server_ips[SERVER_IP_OVERRIDE_MAX];
static size_t g_server_ip_count;

int core_set_server_ips(const char *value) {
    if (value == NULL || value[0] == '\0') return -1;

    struct in_addr parsed[SERVER_IP_OVERRIDE_MAX];
    size_t parsed_count = 0;
    const char *cursor = value;

    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        const char *end = cursor;
        while (*end != '\0' && *end != ',') end++;
        const char *trimmed_end = end;
        while (trimmed_end > cursor && (trimmed_end[-1] == ' ' || trimmed_end[-1] == '\t')) trimmed_end--;

        size_t length = (size_t)(trimmed_end - cursor);
        if (length == 0 || length >= INET_ADDRSTRLEN || parsed_count >= SERVER_IP_OVERRIDE_MAX) return -1;

        char ip[INET_ADDRSTRLEN];
        memcpy(ip, cursor, length);
        ip[length] = '\0';

        struct in_addr address;
        if (inet_pton(AF_INET, ip, &address) != 1) return -1;

        int duplicate = 0;
        for (size_t i = 0; i < parsed_count; i++) {
            if (parsed[i].s_addr == address.s_addr) {
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
    memcpy(g_server_ips, parsed, parsed_count * sizeof(parsed[0]));
    g_server_ip_count = parsed_count;
    return 0;
}

size_t core_server_ip_count(void) {
    return g_server_ip_count;
}

const struct in_addr *core_server_ip_at(size_t index) {
    return index < g_server_ip_count ? &g_server_ips[index] : NULL;
}
