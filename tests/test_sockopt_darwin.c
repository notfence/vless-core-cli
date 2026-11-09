#include "check.h"
#include "sockopt.h"
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static int failed_option,call_count,options[16],values[16];
static int fixture_setsockopt(int fd,int level,int option,const void *value,socklen_t size) {
    (void)fd; (void)level; (void)size;
    if (call_count<16) { options[call_count]=option; values[call_count]=*(const int *)value; }
    call_count++;
    if (option==failed_option) { errno=ENOPROTOOPT; return -1; }
    return 0;
}

#define __APPLE__ 1
#define TCP_KEEPALIVE 0x10
#undef TCP_KEEPINTVL
#define TCP_KEEPINTVL 0x101
#define TCP_RXT_CONNDROPTIME 0x80
#define PERSIST_TIMEOUT 0x40
#define setsockopt fixture_setsockopt
#define core_sockopt_parse darwin_sockopt_parse
#define core_sockopt_json darwin_sockopt_json
#define core_sockopt_apply darwin_sockopt_apply
#define core_sockopt_check darwin_sockopt_check
#define core_sockopt_field darwin_sockopt_field
#define core_sockopt_notice darwin_sockopt_notice
#include "../src/sockopt.c"

int main(void) {
    core_sockopt_t settings={.present=7,.user_timeout=1001,.keepalive_idle=17,.keepalive_interval=9};
    core_sockopt_result_t result=core_sockopt_apply(123,&settings);
    CHECK("sockopt-darwin/applied-and-adapted",result.applied==7 && result.adapted==1 && !result.unavailable);
    CHECK("sockopt-darwin/distinct-idle-and-interval",call_count==6 && options[1]==TCP_KEEPALIVE && values[1]==17 && options[3]==TCP_KEEPINTVL && values[3]==9);
    CHECK("sockopt-darwin/round-up-both-timers",options[4]==TCP_RXT_CONNDROPTIME && values[4]==2 && options[5]==PERSIST_TIMEOUT && values[5]==2);
    failed_option=TCP_KEEPINTVL; call_count=0; errno=EINTR;
    result=core_sockopt_apply(123,&settings);
    CHECK("sockopt-darwin/unsupported-does-not-stop-other-options",result.unavailable==4 && result.applied==3 && result.errors[2]==ENOPROTOOPT && errno==EINTR && call_count==6);
    failed_option=PERSIST_TIMEOUT; call_count=0;
    result=core_sockopt_apply(123,&settings);
    CHECK("sockopt-darwin/partial-adapter-warns",result.unavailable==1 && result.adapted==1 && result.errors[0]==ENOPROTOOPT);
    failed_option=0; call_count=0;
    settings=(core_sockopt_t){.present=7,.user_timeout=INT32_MAX,.keepalive_idle=INT32_MAX,.keepalive_interval=INT32_MAX};
    result=core_sockopt_apply(123,&settings);
    CHECK("sockopt-darwin/no-kernel-timer-overflow",result.unavailable==7 && result.errors[0]==ERANGE && result.errors[1]==ERANGE && result.errors[2]==ERANGE);
    for (int i=0;i<call_count;i++) CHECK("sockopt-darwin/overflow-not-sent",options[i]==SO_KEEPALIVE);
    call_count=0; settings=(core_sockopt_t){.present=6,.keepalive_interval=-1}; result=core_sockopt_apply(123,&settings);
    CHECK("sockopt-darwin/negative-disables-only",result.applied==6 && !result.unavailable && call_count==1 && options[0]==SO_KEEPALIVE && !values[0]);
    char message[192]; core_sockopt_notice(1,1,0,message,sizeof(message));
    CHECK("sockopt-darwin/explicit-approximation",strstr(message,"approximate Darwin") && strstr(message,"rounded up"));
    return test_result();
}
