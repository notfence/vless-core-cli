#include "check.h"
#include "uri.h"
#include "httpupgrade.h"
#include <openssl/crypto.h>
#include <string.h>

static vless_config_t config;
static char error[256];

static int parse(const char *query) {
    char uri[4096];
    snprintf(uri,sizeof(uri),"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?%s",query);
    return parse_vless_uri(uri,&config,error,sizeof(error));
}

int main(void) {
    CHECK("httpupgrade/uri-supported",parse("type=httpupgrade&security=none") == 0);
    CHECK("httpupgrade/uri-tls",parse("network=httpupgrade&security=tls&alpn=http%2F1.1") == 0);
    CHECK("httpupgrade/uri-ed-uint32",parse("transport=httpupgrade&security=none&ed=4294967295") == 0);
    CHECK("httpupgrade/uri-reality-rejected",parse("type=httpupgrade&security=reality") < 0);
    CHECK("httpupgrade/uri-h2-rejected",parse("type=httpupgrade&security=tls&alpn=h2") < 0);
    CHECK("httpupgrade/uri-host-injection-rejected",parse("type=httpupgrade&security=none&host=good%0D%0AX-Bad%3Ayes") < 0);
    CHECK("httpupgrade/uri-ed-overflow-rejected",parse("type=httpupgrade&security=none&ed=4294967296") < 0);
    CHECK("httpupgrade/uri-ed-negative-rejected",parse("type=httpupgrade&security=none&ed=-1") < 0);
    CHECK("httpupgrade/uri-vision-without-encryption-rejected",parse("type=httpupgrade&security=tls&flow=xtls-rprx-vision") < 0);
    CHECK("httpupgrade/uri-defaults",parse("type=httpupgrade&security=none") == 0 && config.transport_mode==TRANSPORT_HTTPUPGRADE && !strcmp(config.xhttp_path,"/") && !config.httpupgrade_early_data);
    CHECK("httpupgrade/uri-path-ed",!parse("type=httpupgrade&security=none&path=%2Ftest%3Fed%3D4294967295") && config.httpupgrade_early_data==UINT32_MAX && !strcmp(config.xhttp_path,"/test"));
    CHECK("httpupgrade/uri-explicit-ed-precedence",!parse("type=httpupgrade&security=none&path=%2Ftest%3Fed%3D1%26keep%3Da%252Fb&maxEarlyData=0") && !config.httpupgrade_early_data && !strcmp(config.xhttp_path,"/test?keep=a%2Fb"));
    CHECK("httpupgrade/uri-path-ed-duplicate",parse("type=httpupgrade&security=none&path=%2Ftest%3Fed%3D1%26ed%3D2")<0);
    CHECK("httpupgrade/uri-ed-query-order-matches-xray",!parse("type=httpupgrade&security=none&path=%2Ftest%3Fz%3D2%26ed%3D0%26a%3D1") && !strcmp(config.xhttp_path,"/test?a=1&z=2"));
    CHECK("httpupgrade/uri-ed-path-escaping-matches-xray",!parse("type=httpupgrade&security=none&path=%2Fwith%20space%3Fed%3D0") && !strcmp(config.xhttp_path,"/with%20space"));
    CHECK("httpupgrade/uri-path-without-ed-not-normalized",!parse("type=httpupgrade&security=none&path=%2Fempty%3F") && !strcmp(config.xhttp_path,"/empty?"));
    CHECK("httpupgrade/uri-ed-fragment-matches-xray",!parse("type=httpupgrade&security=none&path=%2Ftest%3Fed%3D0%23part") && !strcmp(config.xhttp_path,"/test#part"));
    CHECK("httpupgrade/uri-ed-does-not-hide-control",parse("type=httpupgrade&security=none&path=%2Fbad%01%3Fed%3D0")<0);
    CHECK("httpupgrade/uri-ed-does-not-hide-backslash",parse("type=httpupgrade&security=none&path=%2Fbad%5Cpath%3Fed%3D0")<0);
    CHECK("httpupgrade/uri-host-in-headers-rejected",parse("type=httpupgrade&security=none&headers=%7B%22Host%22%3A%22other%22%7D")<0);
    CHECK("httpupgrade/uri-heartbeat-rejected",parse("type=httpupgrade&security=none&heartbeatPeriod=1")<0);
    CHECK("httpupgrade/uri-tls-mixed-alpn",!parse("type=httpupgrade&security=tls&alpn=h2%2Chttp%2F1.1"));
    const char *response="HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    size_t length=strlen(response);
    CHECK("httpupgrade/response-valid",!core_httpupgrade_validate((const uint8_t *)response,length));
    for (size_t i=0;i<length;i++) CHECK("httpupgrade/response-truncated",core_httpupgrade_validate((const uint8_t *)response,i)<0);
    const char *invalid[]={
        "HTTP/1.1 101 Wrong\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: other\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nBad Name: value\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Bad: \x01\r\n\r\n"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) CHECK("httpupgrade/response-malformed",core_httpupgrade_validate((const uint8_t *)invalid[i],strlen(invalid[i]))<0);
    char escaped[1024];
    CHECK("httpupgrade/path-go-url-path-semantics",!core_httpupgrade_path("name ?a=%2F&b=+",escaped,sizeof(escaped)) && !strcmp(escaped,"/name%20%3Fa=%252F&b=+"));
    OPENSSL_cleanse(&config,sizeof(config));
    return test_result();
}
