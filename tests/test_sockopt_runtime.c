#define _DARWIN_C_SOURCE
#include "check.h"
#include "sockopt.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <unistd.h>

static int read_option(int fd,int level,int option) {
    int value=-1; socklen_t size=sizeof(value);
    if (getsockopt(fd,level,option,&value,&size)) return -1;
    return value;
}

int main(int argc,char **argv) {
    int report=argc==2 && !strcmp(argv[1],"--probe");
    const int timeouts[]={1,1000,1001,1234,2147483647};
    for (unsigned family=0;family<2;family++) for (unsigned i=0;i<sizeof(timeouts)/sizeof(*timeouts);i++) {
        int fd=socket(family ? AF_INET6 : AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if (fd<0 && family) continue;
        REQUIRE("sockopt-runtime/socket",fd>=0);
        core_sockopt_t settings={.present=7,.user_timeout=timeouts[i],.keepalive_idle=17,.keepalive_interval=9};
        core_sockopt_result_t result=core_sockopt_apply(fd,&settings);
        int idle=-1,interval=-1,timeout=-1,persist=-1;
#ifdef __APPLE__
        idle=read_option(fd,IPPROTO_TCP,TCP_KEEPALIVE);
        interval=read_option(fd,IPPROTO_TCP,TCP_KEEPINTVL);
        timeout=read_option(fd,IPPROTO_TCP,TCP_RXT_CONNDROPTIME);
        persist=read_option(fd,IPPROTO_TCP,PERSIST_TIMEOUT);
        if (!(result.unavailable & 1)) CHECK("sockopt-runtime/rounded-up",timeout==(timeouts[i]+999LL)/1000 && persist==timeout);
#else
        idle=read_option(fd,IPPROTO_TCP,TCP_KEEPIDLE);
        interval=read_option(fd,IPPROTO_TCP,TCP_KEEPINTVL);
        timeout=read_option(fd,IPPROTO_TCP,TCP_USER_TIMEOUT);
        if (!(result.unavailable & 1)) CHECK("sockopt-runtime/linux-milliseconds",timeout==timeouts[i]);
#endif
        if (!(result.unavailable & 2)) CHECK("sockopt-runtime/idle-not-swapped",idle==17);
        if (!(result.unavailable & 4)) CHECK("sockopt-runtime/interval-not-swapped",interval==9);
        CHECK("sockopt-runtime/keepalive-on",read_option(fd,SOL_SOCKET,SO_KEEPALIVE)>0);
        if (report) printf("{\"family\":%u,\"requested_ms\":%d,\"applied\":%u,\"adapted\":%u,\"unavailable\":%u,\"idle\":%d,\"interval\":%d,\"timeout\":%d,\"persist\":%d,\"errors\":[%d,%d,%d]}\n",family ? 6U : 4U,timeouts[i],result.applied,result.adapted,result.unavailable,idle,interval,timeout,persist,result.errors[0],result.errors[1],result.errors[2]);
        settings=(core_sockopt_t){.present=2,.keepalive_idle=-1};
        result=core_sockopt_apply(fd,&settings);
        CHECK("sockopt-runtime/negative-disables",!result.unavailable && read_option(fd,SOL_SOCKET,SO_KEEPALIVE)==0);
        close(fd);
    }
    return test_result();
}
