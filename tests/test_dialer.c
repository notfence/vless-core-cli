#define _POSIX_C_SOURCE 200809L
#include "../src/dialer.c"
#include "check.h"
#include <arpa/inet.h>
#include <pthread.h>

static int fixture_mode, stalled_fd=-1;
static uint64_t ipv4_delay, ipv6_delay, connect_times[8];
static int connect_families[8], connect_count;
static pthread_mutex_t blocked_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t blocked_ready=PTHREAD_COND_INITIALIZER;
static unsigned blocked_workers;
static int release_workers;
int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int __real_connect(int, const struct sockaddr *, socklen_t);
int __real_poll(struct pollfd *, nfds_t, int);

int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
    if (!strcmp(host,"resource-vless-core.test")) { *result=NULL; errno=EMFILE; return EAI_SYSTEM; }
    if (!strcmp(host,"blocked-vless-core.test")) {
        pthread_mutex_lock(&blocked_lock); blocked_workers++; pthread_cond_broadcast(&blocked_ready);
        while (!release_workers) pthread_cond_wait(&blocked_ready,&blocked_lock);
        pthread_mutex_unlock(&blocked_lock); *result=NULL; return EAI_NONAME;
    }
    if (strcmp(host,"vless-core.test")) return EAI_NONAME;
    uint64_t delay=hints->ai_family == AF_INET6 ? ipv6_delay : ipv4_delay;
    struct timespec wait={.tv_sec=delay/1000,.tv_nsec=(long)(delay%1000)*1000000};
    while (nanosleep(&wait,&wait) != 0 && errno == EINTR) {}
    return __real_getaddrinfo(hints->ai_family == AF_INET6 ? "::1" : "127.0.0.1",service,hints,result);
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (connect_count < 8) { connect_families[connect_count]=address->sa_family; connect_times[connect_count++]=core_now_ms(); }
    if (fixture_mode == 1 && address->sa_family == AF_INET6) { stalled_fd=fd; errno=EINPROGRESS; return -1; }
    if (fixture_mode == 2) { errno=ECONNREFUSED; return -1; }
    return __real_connect(fd,address,length);
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (stalled_fd < 0) return __real_poll(fds,count,timeout);
    struct pollfd copy[2];
    if (count > 2) { errno=EINVAL; return -1; }
    for (nfds_t i=0;i<count;i++) { copy[i]=fds[i]; if (copy[i].fd == stalled_fd) copy[i].fd=-1; }
    int result=__real_poll(copy,count,timeout);
    for (nfds_t i=0;i<count;i++) fds[i].revents=copy[i].revents;
    return result;
}

static int listener(int family, uint16_t *port) {
    int fd=socket(family,SOCK_STREAM,0); struct sockaddr_storage address={0}; socklen_t length;
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6=(void *)&address; v6->sin6_family=family; v6->sin6_addr=in6addr_loopback; length=sizeof(*v6);
        int one=1; setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one));
    } else {
        struct sockaddr_in *v4=(void *)&address; v4->sin_family=family; v4->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*v4);
    }
    REQUIRE("dial/listener", fd >= 0 && bind(fd,(void *)&address,length) == 0 && listen(fd,8) == 0 && getsockname(fd,(void *)&address,&length) == 0);
    *port=ntohs(family == AF_INET6 ? ((struct sockaddr_in6 *)&address)->sin6_port : ((struct sockaddr_in *)&address)->sin_port);
    return fd;
}

static void numeric_without_resolver(void) {
    core_resolver_query_t *queries[4];
    struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM};
    for (unsigned i=0;i<4;i++) REQUIRE("dial/busy-resolver-job",(queries[i]=core_resolver_start("blocked-vless-core.test","80",&hints)) != NULL);
    pthread_mutex_lock(&blocked_lock);
    while (blocked_workers != 4) pthread_cond_wait(&blocked_ready,&blocked_lock);
    pthread_mutex_unlock(&blocked_lock);
    for (unsigned i=0;i<2;i++) {
        uint16_t port; int family=i ? AF_INET6 : AF_INET;
        int server=listener(family,&port); connect_count=0; core_deadline_begin(150);
        core_dialer_t *dialer=core_dialer_start(i ? "::1" : "127.0.0.1",port,0,150,NULL,0);
        REQUIRE("dial/numeric-start",dialer);
        CHECK("dial/numeric-does-not-queue-dns",!dialer->queries[0] && !dialer->queries[1] && dialer->resolved[0] && dialer->resolved[1] && dialer->count == 1);
        int fd=core_dialer_next(dialer,NULL,NULL);
        CHECK("dial/numeric-connects-with-all-dns-workers-busy",fd >= 0 && connect_count == 1 && connect_families[0] == family);
        if (fd >= 0) close(fd);
        core_dialer_free(dialer); core_deadline_end(); close(server);
    }
    uint16_t port; int server=listener(AF_INET6,&port);
    struct sockaddr_storage preferred; socklen_t preferred_length;
    REQUIRE("dial/numeric-preferred-address",core_numeric_address("::1",port,&preferred,&preferred_length) == 1);
    core_deadline_begin(150);
    core_dialer_t *cached=core_dialer_start("127.0.0.2",port,0,150,(void *)&preferred,preferred_length);
    REQUIRE("dial/numeric-cached-start",cached);
    struct sockaddr_storage selected; socklen_t selected_length;
    int fd=core_dialer_next(cached,&selected,&selected_length);
    CHECK("dial/numeric-preserves-cached-address-priority",fd >= 0 && selected.ss_family == AF_INET6 && !cached->queries[0] && !cached->queries[1]);
    if (fd >= 0) close(fd);
    core_dialer_free(cached); core_deadline_end();
    REQUIRE("dial/numeric-pinned-address",core_set_server_ips("::1") == 0);
    core_deadline_begin(150);
    cached=core_dialer_start("127.0.0.2",port,1,150,NULL,0);
    REQUIRE("dial/numeric-pinned-start",cached);
    fd=core_dialer_next(cached,&selected,&selected_length);
    CHECK("dial/pins-override-numeric-server-host",fd >= 0 && selected.ss_family == AF_INET6 && cached->count == 1);
    if (fd >= 0) close(fd);
    core_dialer_free(cached); core_deadline_end(); close(server);
    pthread_mutex_lock(&blocked_lock); release_workers=1; pthread_cond_broadcast(&blocked_ready); pthread_mutex_unlock(&blocked_lock);
    for (unsigned i=0;i<4;i++) {
        struct addrinfo *addresses=NULL;
        CHECK("dial/busy-resolver-job-completes",core_resolver_wait(queries[i],&addresses) == EAI_NONAME && !addresses);
        core_resolver_release(queries[i]);
    }
}

static void dns_system_failure(void) {
    core_connection_trace_t trace; core_connection_error_t failure;
    REQUIRE("dial/dns-resource-trace",core_trace_attach(&trace) == 0);
    core_deadline_begin(1000);
    core_dialer_t *dialer=core_dialer_start("resource-vless-core.test",443,0,1000,NULL,0);
    REQUIRE("dial/dns-resource-start",dialer != NULL);
    CHECK("dial/dns-system-cause-survives-worker-transfer",core_dialer_next(dialer,NULL,NULL) < 0 && errno == EMFILE);
    core_dialer_free(dialer);
    CHECK("dial/dns-resource-not-host-unreachable",core_trace_error_get(&failure) && failure.stage == CORE_TRACE_DNS && failure.kind == CORE_FAILURE_RESOURCE && failure.system_error == EMFILE);
    core_deadline_end(); core_trace_detach();
}

int main(void) {
    core_deadline_t deadline; REQUIRE("dial/deadline-attach", core_deadline_attach(&deadline) == 0);
    dns_system_failure();
    numeric_without_resolver();
    for (int scenario=0;scenario<5;scenario++) {
        connect_count=0; stalled_fd=-1; fixture_mode=0;
        ipv4_delay=scenario == 4 ? 500 : 0; ipv6_delay=scenario == 0 ? 500 : scenario == 1 ? 20 : 0;
        int family=scenario == 1 || scenario == 4 ? AF_INET6 : AF_INET;
        uint16_t port; int server=listener(family,&port);
        if (scenario == 2) fixture_mode=1;
        uint64_t started=core_now_ms(); core_deadline_begin(1000);
        core_dialer_t *dialer=core_dialer_start("vless-core.test",port,0,1000,NULL,0);
        REQUIRE("dial/start", dialer != NULL);
        struct sockaddr_storage address; socklen_t length;
        int fd=core_dialer_next(dialer,&address,&length);
        CHECK("dial/family-fallback-connects", fd >= 0 && address.ss_family == family);
        if (scenario == 0) CHECK("dial/independent-dns-and-family-grace", core_now_ms()-started >= 40 && core_now_ms()-started < 250);
        if (scenario == 1) CHECK("dial/ipv6-within-grace-wins", connect_count == 1 && connect_families[0] == AF_INET6);
        if (scenario == 4) CHECK("dial/ipv6-independent-of-delayed-ipv4", core_now_ms()-started < 200);
        if (scenario == 2) {
            CHECK("dial/staggered-attempt", connect_count == 2 && connect_times[1]-connect_times[0] >= 230 && connect_times[1]-connect_times[0] < 450);
            CHECK("dial/loser-closed", fcntl(stalled_fd,F_GETFD) == -1 && errno == EBADF);
        }
        CHECK("dial/winner-is-blocking", fd >= 0 && !(fcntl(fd,F_GETFL)&O_NONBLOCK));
        if (fd >= 0) close(fd);
        core_dialer_free(dialer); core_deadline_end(); close(server); stalled_fd=-1;
    }
    ipv4_delay=ipv6_delay=500; connect_count=0; core_deadline_begin(25);
    core_dialer_t *dialer=core_dialer_start("vless-core.test",80,0,1000,NULL,0);
    uint64_t started=core_now_ms();
    CHECK("dial/delayed-dns-budget", core_dialer_next(dialer,NULL,NULL) < 0 && errno == ETIMEDOUT && core_now_ms()-started < 150 && !connect_count);
    core_dialer_free(dialer); core_deadline_end();
    struct timespec settle={1,0}; nanosleep(&settle,NULL);
    fixture_mode=0; connect_count=0; stalled_fd=-1;
    uint16_t pinned_port; int pinned_server=listener(AF_INET,&pinned_port);
    REQUIRE("dial/separate-primary-pins",core_set_server_ips("127.0.0.2") == 0);
    REQUIRE("dial/separate-download-pins",core_set_download_server_ips("127.0.0.1") == 0);
    struct sockaddr_storage wrong; socklen_t wrong_length;
    REQUIRE("dial/cached-primary-address",core_ip_address_at(CORE_IP_PRIMARY,0,pinned_port,&wrong,&wrong_length) == 0);
    dialer=core_dialer_start("download.invalid",pinned_port,CORE_IP_DOWNLOAD,1000,(void *)&wrong,wrong_length);
    REQUIRE("dial/pinned-no-dns-or-outside-cache",dialer && !dialer->queries[0] && !dialer->queries[1] && dialer->count == 1 && !dialer->has_preferred);
    int pinned=core_dialer_next(dialer,NULL,NULL);
    CHECK("dial/download-isolated-connect",pinned >= 0 && connect_count == 1);
    if (pinned >= 0) close(pinned);
    core_dialer_free(dialer); close(pinned_server);
    core_deadline_detach();
    return test_result();
}
