#include "cli_args.h"
#include "check.h"
#include <limits.h>

int main(void) {
    core_cli_args_t result; char error[160];
    char *base[]={"vless-core","--uri","socks5://127.0.0.1:1080#vless-core","--listen-port","1"};
    REQUIRE("arguments/defaults",core_cli_args_parse(5,base,&result,error,sizeof(error)) == 0);
    CHECK("arguments/default-values",result.source == CORE_CLI_URI_ARGUMENT && result.listen_port == 1 && result.route_port == 0 && result.connect_timeout == 30000 && result.source_fd == -1 && !result.action);
    const char *numeric[]={"--listen-port","--route-control-port","--connect-timeout-ms","--uri-fd","--connection-fd"};
    const char *minimum[]={"1","0","1","0","0"},*maximum[]={"65535","65535","300000","2147483647","2147483647"};
    for (unsigned field=0;field<5;field++) {
        for (unsigned boundary=0;boundary<2;boundary++) {
            char *arguments[]={"vless-core",(char *)numeric[field],(char *)(boundary ? maximum[field] : minimum[field]),"--help"};
            REQUIRE("arguments/numeric-boundaries",core_cli_args_parse(4,arguments,&result,error,sizeof(error)) == 0);
            int value=field == 0 ? result.listen_port : field == 1 ? result.route_port : field == 2 ? result.connect_timeout : result.source_fd;
            CHECK("arguments/numeric-boundary-values",value == (boundary ? field < 2 ? 65535 : field == 2 ? 300000 : INT_MAX : field == 0 || field == 2 ? 1 : 0));
        }
        const char *invalid[]={"","+1","-0"," 1","1 ","1x","4294967296","18446744073709551616","999999999999999999999999999999999999999999"};
        for (unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
            char *arguments[]={"vless-core",(char *)numeric[field],(char *)invalid[i],"--help"};
            CHECK("arguments/strict-unsigned-integers",core_cli_args_parse(4,arguments,&result,error,sizeof(error)) < 0 && strstr(error,numeric[field]));
        }
    }
    for (unsigned i=0;i<5;i++) {
        char *arguments[]={"vless-core",(char *)numeric[i],"00001","-h"};
        CHECK("arguments/leading-zeroes-and-help-alias",core_cli_args_parse(4,arguments,&result,error,sizeof(error)) == 0 && result.action == CORE_CLI_HELP);
    }
    char *version[]={"vless-core","-v"};
    char *inspection[]={"vless-core","--inspect-config","--uri-fd","0"};
    CHECK("arguments/offline-inspection",core_cli_args_parse(4,inspection,&result,error,sizeof(error)) == 0 && result.action == CORE_CLI_INSPECT && result.source == CORE_CLI_URI_FD && !result.listen_port);
    for (unsigned i=0;i<2;i++) {
        char *conflicting[]={"vless-core","--uri-fd","0","--inspect-config",i ? "--help" : "--inspect-config"};
        CHECK("arguments/inspection-action-conflicts",core_cli_args_parse(5,conflicting,&result,error,sizeof(error)) < 0);
    }
    char *inspection_listener[]={"vless-core","--inspect-config","--uri-fd","0","--listen-port","1080"};
    CHECK("arguments/inspection-does-not-start-listener",core_cli_args_parse(6,inspection_listener,&result,error,sizeof(error)) < 0);
    CHECK("arguments/version-alias",core_cli_args_parse(2,version,&result,error,sizeof(error)) == 0 && result.action == CORE_CLI_VERSION);
    char *private_value[]={"vless-core","vless-core-private-value"};
    CHECK("arguments/unknown-values-are-not-logged",core_cli_args_parse(2,private_value,&result,error,sizeof(error)) < 0 && !strstr(error,private_value[1]));
    char *source_conflict[]={"vless-core","--connection-fd","3","--server-ips","127.0.0.1","--help"};
    CHECK("arguments/connection-fd-does-not-mix-with-pins",core_cli_args_parse(6,source_conflict,&result,error,sizeof(error)) < 0);
    char *source_reverse[]={"vless-core","--server-ips","::1","--connection-fd","3","--help"};
    CHECK("arguments/source-conflicts-independent-of-order",core_cli_args_parse(6,source_reverse,&result,error,sizeof(error)) < 0);
    char value[]="socks5://user:secret@127.0.0.1:1080#vless-core",second[]="vless://secret-vless-core";
    char *secrets[]={"vless-core","--uri",value,"--uri",second};
    core_cli_args_scrub(5,secrets);
    CHECK("arguments/all-uri-arguments-cleared",!memcmp(value,(char[sizeof(value)]){0},sizeof(value)) && !memcmp(second,(char[sizeof(second)]){0},sizeof(second)));
    CHECK("arguments/null-outputs-and-inputs",core_cli_args_parse(5,base,NULL,error,sizeof(error)) < 0 && core_cli_args_parse(0,NULL,&result,error,sizeof(error)) < 0);
    return test_result();
}
