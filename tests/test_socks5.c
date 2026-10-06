#include "check.h"
#include "socks5.h"
#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_wire(const uint8_t *wire, size_t length, char *host, size_t capacity, uint16_t *port) {
    int pair[2]; REQUIRE("socks/server-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    REQUIRE("socks/server-feed", send(pair[1], wire, length, 0) == (ssize_t)length && shutdown(pair[1], SHUT_WR) == 0);
    int result = socks5_negotiate_and_get_target(pair[0], host, capacity, port);
    close(pair[0]); close(pair[1]);
    return result;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    uint8_t wire[300] = {5,1,0,5,1,0,1,127,0,0,1,0x1f,0x90};
    const uint8_t types[] = {1,3,4};
    const char *hosts[] = {"127.0.0.1","vless-core.test","::1"};
    for (int address = 0; address < 3; address++) {
        size_t length = 7; wire[6] = types[address];
        if (types[address] == 1) { inet_pton(AF_INET, hosts[address], wire+length); length += 4; }
        else if (types[address] == 4) { inet_pton(AF_INET6, hosts[address], wire+length); length += 16; }
        else { wire[length++] = (uint8_t)strlen(hosts[address]); memcpy(wire+length, hosts[address], strlen(hosts[address])); length += strlen(hosts[address]); }
        wire[length++] = 0x1f; wire[length++] = 0x90;
        char host[260]; uint16_t port = 0;
        CHECK("socks/server-addresses", parse_wire(wire, length, host, sizeof(host), &port) == 0 && strcmp(host, hosts[address]) == 0 && port == 8080);
        CHECK("socks/server-exact-capacity", parse_wire(wire, length, host, strlen(hosts[address])+1, &port) == 0);
        CHECK("socks/server-small-capacity", parse_wire(wire, length, host, strlen(hosts[address]), &port) != 0);
        for (size_t cut = 0; cut < length; cut++) CHECK("socks/server-truncated-request", parse_wire(wire, cut, host, sizeof(host), &port) != 0);
    }
    const uint8_t valid[] = {5,1,0,5,1,0,1,127,0,0,1,0x1f,0x90};
    char host[260]; uint16_t port = 0;
    const size_t positions[] = {0,1,3,4,6}; const uint8_t invalid[] = {4,0,4,2,0xff};
    for (size_t i = 0; i < sizeof(positions)/sizeof(*positions); i++) {
        memcpy(wire, valid, sizeof(valid)); wire[positions[i]] = invalid[i];
        CHECK("socks/server-invalid-request", parse_wire(wire, sizeof(valid), host, sizeof(host), &port) != 0);
    }
    memcpy(wire, valid, sizeof(valid)); wire[4] = 3;
    CHECK("socks/server-udp-associate-rejected", parse_wire(wire, sizeof(valid), host, sizeof(host), &port) != 0);
    memcpy(wire, valid, sizeof(valid)); wire[2] = 2;
    CHECK("socks/server-no-supported-method", parse_wire(wire, sizeof(valid), host, sizeof(host), &port) != 0);
    memcpy(wire, valid, sizeof(valid)); wire[6] = 3; wire[7] = 0;
    CHECK("socks/server-empty-domain", parse_wire(wire, sizeof(valid), host, sizeof(host), &port) != 0);
    wire[7] = 255; memset(wire+8, 'a', 255); wire[263] = 0x1f; wire[264] = 0x90;
    CHECK("socks/server-max-domain", parse_wire(wire, 265, host, sizeof(host), &port) == 0 && strlen(host) == 255 && port == 8080);
    CHECK("socks/server-max-domain-capacity", parse_wire(wire, 265, host, 255, &port) != 0);
    CHECK("socks/server-null-host", socks5_negotiate_and_get_target(-1, NULL, 0, &port) != 0);
    CHECK("socks/server-null-port", socks5_negotiate_and_get_target(-1, host, sizeof(host), NULL) != 0);
    CHECK("socks/server-invalid-fd", socks5_negotiate_and_get_target(-1, host, sizeof(host), &port) != 0);
    for (int code = 0; code <= 8; code++) {
        int pair[2]; REQUIRE("socks/reply-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        uint8_t expected[10] = {5,(uint8_t)code,0,1}, reply[10];
        REQUIRE("socks/reply-send", (code ? socks5_send_failure(pair[0], (uint8_t)code) : socks5_send_success(pair[0])) == 0);
        CHECK("socks/reply-golden", recv(pair[1], reply, sizeof(reply), MSG_WAITALL) == sizeof(reply) && memcmp(reply, expected, sizeof(reply)) == 0);
        close(pair[0]); close(pair[1]);
    }
    CHECK("socks/reply-invalid-fd", socks5_send_success(-1) != 0 && socks5_send_failure(-1, 1) != 0);
    return test_result();
}
