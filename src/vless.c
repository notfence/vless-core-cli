#include "vless.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static int append(uint8_t *buf, size_t cap, size_t *off, const void *src, size_t n) {
    if (*off + n > cap) {
        return -1;
    }
    memcpy(buf + *off, src, n);
    *off += n;
    return 0;
}

int vless_send_request(tls13_conn_t *tls, const vless_config_t *cfg, const char *target_host, uint16_t target_port) {
    uint8_t packet[2048];
    size_t off = 0;

    packet[off++] = 0x00;
    if (append(packet, sizeof(packet), &off, cfg->uuid, 16) != 0) {
        return -1;
    }

    uint8_t addons[128];
    size_t addons_len = 0;
    const char *flow = cfg->flow;
    size_t flow_len = strlen(flow);
    if (flow_len > 64) {
        return -1;
    }

    addons[addons_len++] = 0x0A;
    addons[addons_len++] = (uint8_t)flow_len;
    memcpy(addons + addons_len, flow, flow_len);
    addons_len += flow_len;

    packet[off++] = (uint8_t)addons_len;
    if (append(packet, sizeof(packet), &off, addons, addons_len) != 0) {
        return -1;
    }

    packet[off++] = 0x01;
    packet[off++] = (uint8_t)(target_port >> 8);
    packet[off++] = (uint8_t)(target_port & 0xFF);

    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, target_host, &ipv4) == 1) {
        packet[off++] = 0x01;
        if (append(packet, sizeof(packet), &off, &ipv4, 4) != 0) {
            return -1;
        }
    } else if (inet_pton(AF_INET6, target_host, &ipv6) == 1) {
        packet[off++] = 0x03;
        if (append(packet, sizeof(packet), &off, &ipv6, 16) != 0) {
            return -1;
        }
    } else {
        size_t dlen = strlen(target_host);
        if (dlen == 0 || dlen > 255) {
            return -1;
        }
        packet[off++] = 0x02;
        packet[off++] = (uint8_t)dlen;
        if (append(packet, sizeof(packet), &off, target_host, dlen) != 0) {
            return -1;
        }
    }

    return tls13_write_app(tls, packet, off);
}

int vless_read_response(tls13_conn_t *tls) {
    uint8_t hdr[2];
    if (tls13_read_exact_app(tls, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (hdr[0] != 0x00) {
        return -1;
    }

    uint8_t addon_len = hdr[1];
    if (addon_len > 0) {
        uint8_t tmp[256];
        if (tls13_read_exact_app(tls, tmp, addon_len) != 0) {
            return -1;
        }
    }

    return 0;
}
