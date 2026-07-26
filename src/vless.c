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

static int append_byte(uint8_t *buf, size_t cap, size_t *off, uint8_t v) {
    return append(buf, cap, off, &v, 1);
}

int vless_build_request(uint8_t *packet, size_t cap, size_t *out_len, const vless_config_t *cfg, const char *target_host, uint16_t target_port) {
    size_t off = 0;

    if (out_len == NULL) {
        return -1;
    }
    *out_len = 0;

    if (append_byte(packet, cap, &off, 0x00) != 0 || append(packet, cap, &off, cfg->uuid, 16) != 0) {
        return -1;
    }

    uint8_t addons[128];
    size_t addons_len = 0;
    const char *flow = cfg->flow;
    size_t flow_len = strlen(flow);
    if (flow_len > 64) {
        return -1;
    }
    if (flow_len > 0) {
        addons[addons_len++] = 0x0A;
        addons[addons_len++] = (uint8_t)flow_len;
        memcpy(addons + addons_len, flow, flow_len);
        addons_len += flow_len;
    }

    if (append_byte(packet, cap, &off, (uint8_t)addons_len) != 0 || append(packet, cap, &off, addons, addons_len) != 0) {
        return -1;
    }

    if (append_byte(packet, cap, &off, 0x01) != 0 || append_byte(packet, cap, &off, (uint8_t)(target_port >> 8)) != 0 ||
        append_byte(packet, cap, &off, (uint8_t)(target_port & 0xFF)) != 0) {
        return -1;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, target_host, &ipv4) == 1) {
        if (append_byte(packet, cap, &off, 0x01) != 0 || append(packet, cap, &off, &ipv4, 4) != 0) {
            return -1;
        }
    } else if (inet_pton(AF_INET6, target_host, &ipv6) == 1) {
        if (append_byte(packet, cap, &off, 0x03) != 0 || append(packet, cap, &off, &ipv6, 16) != 0) {
            return -1;
        }
    } else {
        size_t dlen = strlen(target_host);
        if (dlen == 0 || dlen > 255) {
            return -1;
        }
        if (append_byte(packet, cap, &off, 0x02) != 0 || append_byte(packet, cap, &off, (uint8_t)dlen) != 0 ||
            append(packet, cap, &off, target_host, dlen) != 0) {
            return -1;
        }
    }

    *out_len = off;
    return 0;
}

int vless_send_request(tls13_conn_t *tls, vless_encryption_conn_t *encryption,
                       const vless_config_t *cfg, const char *target_host,
                       uint16_t target_port) {
    uint8_t packet[2048];
    size_t packet_len = 0;

    if (vless_build_request(packet, sizeof(packet), &packet_len, cfg, target_host, target_port) != 0) {
        return -1;
    }

    if (encryption != NULL) {
        return vless_encryption_write(encryption, packet, packet_len);
    }
    return tls13_write_app(tls, packet, packet_len);
}

int vless_read_response(tls13_conn_t *tls,
                        vless_encryption_conn_t *encryption) {
    uint8_t hdr[2];
    int rc = encryption != NULL
                 ? vless_encryption_read_exact(encryption, hdr, sizeof(hdr))
                 : tls13_read_exact_app(tls, hdr, sizeof(hdr));
    if (rc != 0) {
        return -1;
    }
    if (hdr[0] != 0x00) {
        return -1;
    }

    uint8_t addon_len = hdr[1];
    if (addon_len > 0) {
        uint8_t tmp[256];
        rc = encryption != NULL
                 ? vless_encryption_read_exact(encryption, tmp, addon_len)
                 : tls13_read_exact_app(tls, tmp, addon_len);
        if (rc != 0) {
            return -1;
        }
    }

    return 0;
}
