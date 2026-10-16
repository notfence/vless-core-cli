#include "config_inspect.h"
#include "uri.h"
#include "server_ips.h"
#include "check.h"
#include <arpa/inet.h>

int main(void) {
    vless_config_t config; char error[256]={0},output[1024];
    REQUIRE("inspect/uri",parse_core_uri("socks5://user:private-vless-core@offline.invalid:1080",&config,error,sizeof(error)) == 0);
    CHECK("inspect/endpoints-only",core_config_inspect(&config,output,sizeof(output),error,sizeof(error)) == 0 && !strcmp(output,"CONFIG\t1\nPRIMARY\toffline.invalid\t1080\nEND\n"));
    CHECK("inspect/no-secret",!strstr(output,"private") && !strstr(output,"user"));
    size_t required=strlen(output)+1;
    for (size_t size=0;size<required;size++) CHECK("inspect/capacity",core_config_inspect(&config,output,size,error,sizeof(error)) < 0);
    memcpy(config.server_host,"bad\tname",9);
    CHECK("inspect/no-control-injection",core_config_inspect(&config,output,sizeof(output),error,sizeof(error)) < 0);
    core_config_defaults(&config); config.ignore_server_ips=1;
    CHECK("pins/legacy-independent-download",core_config_ip_source(&config) == CORE_IP_NONE);
    REQUIRE("pins/primary-list",core_set_server_ips("127.0.0.1") == 0);
    REQUIRE("pins/download-list",core_set_download_server_ips("127.0.0.2,::1,127.0.0.2") == 0);
    CHECK("pins/separate-counts",core_server_ip_count() == 1 && core_ip_count(CORE_IP_DOWNLOAD) == 2);
    config.xhttp_download_only=1;
    CHECK("pins/download-takes-precedence",core_config_ip_source(&config) == CORE_IP_DOWNLOAD);
    config.xhttp_download_only=0; config.ignore_server_ips=0;
    CHECK("pins/upload-retains-primary",core_config_ip_source(&config) == CORE_IP_PRIMARY);
    struct sockaddr_storage address; socklen_t length;
    CHECK("pins/download-ipv4",core_ip_address_at(CORE_IP_DOWNLOAD,0,8443,&address,&length) == 0 && ((struct sockaddr_in *)&address)->sin_addr.s_addr == inet_addr("127.0.0.2") && ntohs(((struct sockaddr_in *)&address)->sin_port) == 8443);
    CHECK("pins/download-ipv6",core_ip_address_at(CORE_IP_DOWNLOAD,1,8443,&address,&length) == 0 && address.ss_family == AF_INET6);
    CHECK("pins/invalid-does-not-replace",core_set_download_server_ips("127.0.0.4,bad") < 0 && core_ip_count(CORE_IP_DOWNLOAD) == 2);
    return test_result();
}
