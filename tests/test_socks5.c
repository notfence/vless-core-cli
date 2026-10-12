#include "check.h"
#include "socks5.h"
#include <arpa/inet.h>
#include <errno.h>
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

static void check_methods(const uint8_t *methods, uint8_t count, int accepted) {
    int pair[2]; REQUIRE("socks/method-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    uint8_t wire[270] = {5,count}; memcpy(wire+2,methods,count);
    const uint8_t request[] = {5,1,0,1,127,0,0,1,0x1f,0x90};
    memcpy(wire+2+count,request,sizeof(request));
    REQUIRE("socks/method-feed", send(pair[1],wire,2+count+sizeof(request),0) == (ssize_t)(2+count+sizeof(request)) && shutdown(pair[1],SHUT_WR) == 0);
    char host[64] = "unchanged"; uint16_t port = 0xbeef;
    int result = socks5_negotiate_and_get_target(pair[0],host,sizeof(host),&port);
    uint8_t reply[2], expected[] = {5,accepted ? 0 : 0xff};
    CHECK("socks/method-reply", recv(pair[1],reply,sizeof(reply),MSG_WAITALL) == sizeof(reply) && memcmp(reply,expected,sizeof(reply)) == 0);
    if (accepted) CHECK("socks/method-target", result == 0 && strcmp(host,"127.0.0.1") == 0 && port == 8080);
    else {
        CHECK("socks/method-reject", result == SOCKS5_NEGOTIATION_REJECTED && strcmp(host,"unchanged") == 0 && port == 0xbeef);
        uint8_t pending[sizeof(request)];
        CHECK("socks/method-no-connect-read", recv(pair[0],pending,sizeof(pending),MSG_WAITALL) == sizeof(pending) && memcmp(pending,request,sizeof(pending)) == 0);
    }
    close(pair[0]); close(pair[1]);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    const int errors[]={EACCES,EPERM,ENETDOWN,ENETUNREACH,EHOSTDOWN,EHOSTUNREACH,ECONNREFUSED,EAFNOSUPPORT,ETIMEDOUT,EIO,0};
    const uint8_t replies[]={2,2,3,3,4,4,5,8,1,1,1};
    for (size_t i=0;i<sizeof(errors)/sizeof(*errors);i++) CHECK("socks/system-error-replies",socks5_error_reply(errors[i]) == replies[i]);
    CHECK("socks/command-reply",socks5_request_reply(SOCKS5_COMMAND_UNSUPPORTED) == 7);
    CHECK("socks/address-reply",socks5_request_reply(SOCKS5_ADDRESS_UNSUPPORTED) == 8);
    CHECK("socks/general-reply",socks5_request_reply(-1) == 1);
    CHECK("socks/domain-validation-bounds",!socks5_domain_valid(NULL,1) && !socks5_domain_valid((const uint8_t *)"",0) && !socks5_domain_valid((const uint8_t *)"x",256));
    for (int method = 0; method <= 255; method++) { uint8_t value = (uint8_t)method; check_methods(&value,1,method == 0); }
    const uint8_t first[] = {0,2,1}, last[] = {2,1,0};
    check_methods(first,sizeof(first),1); check_methods(last,sizeof(last),1);
    uint8_t maximum[255]; memset(maximum,2,sizeof(maximum)); check_methods(maximum,sizeof(maximum),0);
    maximum[254] = 0; check_methods(maximum,sizeof(maximum),1);
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
    memcpy(wire,valid,sizeof(valid)); wire[5]=1;
    CHECK("socks/reserved-byte-rejected",parse_wire(wire,sizeof(valid),host,sizeof(host),&port) != 0);
    memcpy(wire,valid,sizeof(valid)); wire[11]=wire[12]=0;
    CHECK("socks/zero-destination-port-rejected",parse_wire(wire,sizeof(valid),host,sizeof(host),&port) != 0);
    const uint8_t bad_domain[]={5,1,0,5,1,0,3,3,'a',0,'b',0x1f,0x90};
    CHECK("socks/nul-domain-rejected",parse_wire(bad_domain,sizeof(bad_domain),host,sizeof(host),&port) != 0);
    for (unsigned control=1;control<33;control++) {
        memcpy(wire,bad_domain,sizeof(bad_domain)); wire[9]=(uint8_t)control;
        CHECK("socks/control-domain-rejected",parse_wire(wire,sizeof(bad_domain),host,sizeof(host),&port) != 0);
    }
    memcpy(wire,bad_domain,sizeof(bad_domain)); wire[9]=0x7f;
    CHECK("socks/del-domain-rejected",parse_wire(wire,sizeof(bad_domain),host,sizeof(host),&port) != 0);
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
