#define _POSIX_C_SOURCE 200809L
#include "../src/resolver.c"
#include "check.h"
#include "deadline.h"
#include <arpa/inet.h>

static pthread_mutex_t fixture_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fixture_ready = PTHREAD_COND_INITIALIZER;
static int fixture_active, fixture_finished, fixture_unblocked;
static uint64_t fixture_now;
static uint64_t fake_now(void) { return fixture_now; }
int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);

int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **addresses) {
    if (!strcmp(host,"resource-vless-core.test")) { *addresses=NULL; errno=EMFILE; return EAI_SYSTEM; }
    if (!strcmp(host, "vless-core-slow.test")) {
        pthread_mutex_lock(&fixture_lock); fixture_active++;
        while (!fixture_unblocked) pthread_cond_wait(&fixture_ready, &fixture_lock);
        fixture_active--; fixture_finished++; pthread_mutex_unlock(&fixture_lock);
        host = "127.0.0.1";
    }
    if (strcmp(host, "127.0.0.1")) return EAI_NONAME;
    return __real_getaddrinfo(host, service, hints, addresses);
}

int main(void) {
    REQUIRE("dns/pool-init", core_resolver_init() == 0 && resolver_workers == 4);
    struct addrinfo hints = {.ai_family=AF_INET,.ai_socktype=SOCK_STREAM};
    core_resolver_query_t *resource=core_resolver_start("resource-vless-core.test","80",&hints);
    REQUIRE("dns/resource-start",resource != NULL);
    struct addrinfo *resource_addresses=NULL; errno=EBADF;
    CHECK("dns/wait-preserves-worker-system-cause",core_resolver_wait(resource,&resource_addresses) == EAI_SYSTEM && errno == EMFILE);
    core_resolver_release(resource);
    core_resolver_query_t *running[4];
    for (int i=0;i<4;i++) REQUIRE("dns/slow-start", (running[i]=core_resolver_start("vless-core-slow.test","80",&hints)) != NULL);
    uint64_t end = core_now_ms() + 1000;
    int active = 0;
    while (core_now_ms() < end) {
        pthread_mutex_lock(&fixture_lock); active=fixture_active; pthread_mutex_unlock(&fixture_lock);
        if (active == 4) break;
        core_poll(NULL,0,1);
    }
    REQUIRE("dns/four-workers-busy", active == 4);
    core_resolver_query_t *queued[512];
    for (int i=0;i<512;i++) REQUIRE("dns/bounded-queue-fill", (queued[i]=core_resolver_start("127.0.0.1","80",&hints)) != NULL);
    CHECK("dns/queue-overflow", core_resolver_start("127.0.0.1","80",&hints) == NULL && errno == EAGAIN);
    for (int i=0;i<512;i++) core_resolver_release(queued[i]);
    pthread_mutex_lock(&resolver_lock); unsigned pending=resolver_queued; pthread_mutex_unlock(&resolver_lock);
    CHECK("dns/cancel-queued", pending == 0);
    core_deadline_t deadline; REQUIRE("dns/deadline-attach", core_deadline_attach(&deadline) == 0);
    core_deadline_begin(25); struct addrinfo *addresses = NULL;
    uint64_t started=core_now_ms();
    CHECK("dns/absolute-timeout", core_resolver_wait(running[0],&addresses) == EAI_SYSTEM && errno == ETIMEDOUT && !addresses && core_now_ms()-started < 150);
    for (int i=0;i<4;i++) core_resolver_release(running[i]);
    core_deadline_end();
    pthread_mutex_lock(&fixture_lock); fixture_unblocked=1; pthread_cond_broadcast(&fixture_ready); pthread_mutex_unlock(&fixture_lock);
    end=core_now_ms()+1000;
    int finished=0;
    while (core_now_ms()<end) {
        pthread_mutex_lock(&fixture_lock); finished=fixture_finished; pthread_mutex_unlock(&fixture_lock);
        if (finished == 4) break;
        core_poll(NULL,0,1);
    }
    CHECK("dns/late-results-released", finished == 4);
    core_deadline_begin(1000);
    CHECK("dns/recovery", core_getaddrinfo("127.0.0.1","80",&hints,&addresses) == 0 && addresses && addresses->ai_family == AF_INET);
    if (addresses) freeaddrinfo(addresses);
    deadline.now_ms=fake_now; fixture_now=1000; core_deadline_begin(10);
    core_resolver_query_t *late=core_resolver_start("127.0.0.1","80",&hints);
    REQUIRE("dns/late-ready-query-start",late != NULL);
    end=core_now_ms()+1000; int done=0;
    while (core_now_ms()<end) {
        pthread_mutex_lock(&resolver_lock); done=late->done; pthread_mutex_unlock(&resolver_lock);
        if (done) break;
        core_poll(NULL,0,1);
    }
    REQUIRE("dns/late-ready-query-completed",done);
    fixture_now=1010; addresses=NULL;
    CHECK("dns/ready-result-cannot-pass-expired-deadline",core_resolver_wait(late,&addresses) == EAI_SYSTEM && errno == ETIMEDOUT && !addresses);
    if (addresses) freeaddrinfo(addresses);
    core_resolver_release(late);
    core_deadline_end(); core_deadline_detach();
    return test_result();
}
