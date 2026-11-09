#include "check.h"
#include "uri.h"
#include "sockopt.h"
#include "xhttp_download.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <openssl/evp.h>

static void parser(void) {
    char error[256]; core_sockopt_t options={0};
    CHECK("sockopt/default",!core_sockopt_json("{}",&options,error,sizeof(error)) && !options.present);
    CHECK("sockopt/all-fields",!core_sockopt_json("{\"tcpUserTimeout\":2147483647,\"tcpKeepAliveIdle\":17,\"tcpKeepAliveInterval\":9}",&options,error,sizeof(error)) && options.present==7 && options.user_timeout==INT32_MAX && options.keepalive_idle==17 && options.keepalive_interval==9);
    CHECK("sockopt/signed-minimum",!core_sockopt_json("{\"tcpKeepAliveIdle\":-2147483648}",&options,error,sizeof(error)) && options.keepalive_idle==INT32_MIN);
    CHECK("sockopt/identical-duplicate",!core_sockopt_json("{\"tcpUserTimeout\":123,\"tcpUserTimeout\":123}",&options,error,sizeof(error)) && options.user_timeout==123);
    const char *invalid[]={"[]","null","true","", "{", "{\"tcpUserTimeout\":true}","{\"tcpUserTimeout\":\"1000\"}","{\"tcpUserTimeout\":1.0}","{\"tcpUserTimeout\":1e3}","{\"tcpUserTimeout\":-1}","{\"tcpUserTimeout\":2147483648}","{\"tcpKeepAliveIdle\":-2147483649}","{\"tcpKeepAliveInterval\":2147483648}","{\"tcpKeepAliveIdle\":-1,\"tcpKeepAliveInterval\":1}","{\"tcpKeepAliveIdle\":1,\"tcpKeepAliveInterval\":-1}","{\"tcpUserTimeout\":1,\"tcpUserTimeout\":2}","{\"mark\":1}","{\"private-fixture-secret\":1}"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        options=(core_sockopt_t){.user_timeout=42,.present=1};
        CHECK("sockopt/invalid-rejected",core_sockopt_json(invalid[i],&options,error,sizeof(error)) < 0);
        CHECK("sockopt/invalid-does-not-mutate",options.user_timeout==42 && options.present==1);
        CHECK("sockopt/safe-error",!strstr(error,"private-fixture-secret"));
    }
    const char *links[]={"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?","trojan://test@127.0.0.1:443?","vmess://00000000-0000-0000-0000-000000000001@127.0.0.1:443?","ss://aes-128-gcm:test@127.0.0.1:443?","socks5://127.0.0.1:1080?"};
    for (size_t i=0;i<sizeof(links)/sizeof(*links);i++) {
        char uri[1024]; vless_config_t config;
        snprintf(uri,sizeof(uri),"%ssockopt=%%7B%%22tcpUserTimeout%%22%%3A1234%%2C%%22tcpKeepAliveIdle%%22%%3A17%%2C%%22tcpKeepAliveInterval%%22%%3A9%%7D",links[i]);
        CHECK("sockopt/all-protocols",!parse_core_uri(uri,&config,error,sizeof(error)) && config.sockopt.present==7 && config.sockopt.user_timeout==1234 && config.sockopt.keepalive_interval==9);
    }
    const char *json="{\"id\":\"00000000-0000-0000-0000-000000000001\",\"add\":\"127.0.0.1\",\"port\":443,\"net\":\"tcp\",\"sockopt\":{\"tcpUserTimeout\":1234}}";
    char uri[1024]; memcpy(uri,"vmess://",8); EVP_EncodeBlock((unsigned char *)uri+8,(const unsigned char *)json,(int)strlen(json)); vless_config_t config;
    CHECK("sockopt/vmess-json",!parse_core_uri(uri,&config,error,sizeof(error)) && config.sockopt.present==1 && config.sockopt.user_timeout==1234);
    core_config_defaults(&config);
    strcpy(config.xhttp_download_settings,"{\"address\":\"127.0.0.1\",\"port\":443,\"network\":\"xhttp\",\"sockopt\":{\"tcpKeepAliveIdle\":17}}");
    vless_config_t download; config.sockopt=(core_sockopt_t){.present=1,.user_timeout=1234};
    CHECK("sockopt/independent-download",!core_xhttp_download_config(&config,&download,error,sizeof(error)) && download.sockopt.present==2 && download.sockopt.keepalive_idle==17 && !download.sockopt.user_timeout);
    strcpy(config.xhttp_download_settings,"{\"address\":\"127.0.0.1\",\"port\":443,\"network\":\"xhttp\"}");
    CHECK("sockopt/download-no-inheritance",!core_xhttp_download_config(&config,&download,error,sizeof(error)) && !download.sockopt.present);
}

static int option(int fd,int level,int name) {
    int value=-1; socklen_t length=sizeof(value);
    CHECK("sockopt/getsockopt",!getsockopt(fd,level,name,&value,&length));
    return value;
}

int main(void) {
    parser();
    for (unsigned i=0;i<2;i++) {
        int fd=socket(i ? AF_INET6 : AF_INET,SOCK_STREAM,IPPROTO_TCP);
        REQUIRE("sockopt/socket",fd>=0);
        core_sockopt_t settings={.present=7,.user_timeout=1234,.keepalive_idle=17,.keepalive_interval=9};
        errno=EINTR;
        core_sockopt_result_t result=core_sockopt_apply(fd,&settings);
        CHECK("sockopt/preserve-errno",errno==EINTR);
        CHECK("sockopt/keepalive-enabled",option(fd,SOL_SOCKET,SO_KEEPALIVE)==1);
#ifdef __linux__
        CHECK("sockopt/linux-all-applied",result.applied==7 && !result.unavailable && !result.adapted);
        CHECK("sockopt/linux-timeout",option(fd,IPPROTO_TCP,TCP_USER_TIMEOUT)==1234);
        CHECK("sockopt/linux-idle",option(fd,IPPROTO_TCP,TCP_KEEPIDLE)==17);
        CHECK("sockopt/linux-interval",option(fd,IPPROTO_TCP,TCP_KEEPINTVL)==9);
#else
        (void)result;
#endif
        settings=(core_sockopt_t){.present=2,.keepalive_idle=-1};
        result=core_sockopt_apply(fd,&settings);
        CHECK("sockopt/negative-disables",!result.unavailable && option(fd,SOL_SOCKET,SO_KEEPALIVE)==0);
        settings=(core_sockopt_t){.present=7};
        result=core_sockopt_apply(fd,&settings);
        CHECK("sockopt/zero-keeps-defaults",!result.unavailable && !result.applied && option(fd,SOL_SOCKET,SO_KEEPALIVE)==0);
        close(fd);
    }
    core_sockopt_t settings={.present=7,.user_timeout=1234,.keepalive_idle=17,.keepalive_interval=9};
    core_sockopt_result_t failure=core_sockopt_apply(-1,&settings);
    CHECK("sockopt/failure-reported",failure.unavailable==7 && !failure.applied && failure.errors[0]==EBADF);
    return test_result();
}
