#define _POSIX_C_SOURCE 200809L
#include "dialer.h"
#include "deadline.h"
#include "resolver.h"
#include "server_ips.h"
#include "socket_util.h"
#include "connection_trace.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define DIALER_ADDRESS_LIMIT 128

typedef struct {
    struct sockaddr_storage address;
    socklen_t length;
    int state;
} dialer_address_t;
typedef struct { int fd, flags; size_t index; } dialer_attempt_t;
struct core_dialer {
    core_resolver_query_t *queries[2];
    int resolved[2], dns_error[2], dns_system_error[2];
    dialer_address_t addresses[DIALER_ADDRESS_LIMIT];
    size_t count;
    dialer_attempt_t attempts[2];
    uint64_t until_ms, first_ready_ms, next_attempt_ms;
    int last_family, last_error, started_tcp, has_preferred;
};

static int append_address(core_dialer_t *dialer, const struct sockaddr *address, socklen_t length) {
    if (!address || (address->sa_family != AF_INET && address->sa_family != AF_INET6) || length > sizeof(struct sockaddr_storage) ||
        length < (address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) return -1;
    for (size_t i=0;i<dialer->count;i++)
        if (dialer->addresses[i].length == length && !memcmp(&dialer->addresses[i].address,address,length)) return 0;
    if (dialer->count == DIALER_ADDRESS_LIMIT) { errno = EOVERFLOW; return -1; }
    dialer_address_t *entry = &dialer->addresses[dialer->count++];
    memcpy(&entry->address,address,length); entry->length=length;
    if (!dialer->first_ready_ms) dialer->first_ready_ms=core_now_ms();
    return 0;
}

core_dialer_t *core_dialer_start(const char *host, uint16_t port, int use_server_ips, int timeout_ms,
                               const struct sockaddr *preferred, socklen_t preferred_length) {
    if (!host || !port || timeout_ms <= 0) { errno=EINVAL; return NULL; }
    core_dialer_t *dialer=calloc(1,sizeof(*dialer));
    if (!dialer) return NULL;
    dialer->until_ms=core_now_ms()+(unsigned)(core_deadline_active() ? core_deadline_remaining() : timeout_ms);
    dialer->last_error=ECONNREFUSED;
    dialer->attempts[0].fd=dialer->attempts[1].fd=-1;
    if (preferred && !core_ip_count(use_server_ips) && append_address(dialer,preferred,preferred_length) != 0) goto failure;
    dialer->has_preferred=preferred != NULL && !core_ip_count(use_server_ips);
    if (core_ip_count(use_server_ips)) {
        for (size_t i=0;i<core_ip_count(use_server_ips);i++) {
            struct sockaddr_storage address; socklen_t length;
            if (core_ip_address_at(use_server_ips,i,port,&address,&length) != 0 || append_address(dialer,(void *)&address,length) != 0) goto failure;
        }
        if (preferred) for (size_t i=0;i<dialer->count;i++) if (dialer->addresses[i].length == preferred_length && !memcmp(&dialer->addresses[i].address,preferred,preferred_length)) {
            dialer_address_t first=dialer->addresses[0]; dialer->addresses[0]=dialer->addresses[i]; dialer->addresses[i]=first; dialer->has_preferred=1; break;
        }
        dialer->resolved[0]=dialer->resolved[1]=1;
    } else {
        struct sockaddr_storage address; socklen_t length;
        int numeric=core_numeric_address(host,port,&address,&length);
        if (numeric < 0) goto failure;
        if (numeric) {
            if (append_address(dialer,(void *)&address,length)) goto failure;
            dialer->resolved[0]=dialer->resolved[1]=1;
        } else {
            core_trace_stage(CORE_TRACE_DNS);
            char service[16]; snprintf(service,sizeof(service),"%u",(unsigned)port);
            for (size_t i=0;i<2;i++) {
                struct addrinfo hints={.ai_family=i ? AF_INET : AF_INET6,.ai_socktype=SOCK_STREAM,.ai_protocol=IPPROTO_TCP};
                dialer->queries[i]=core_resolver_start(host,service,&hints);
                if (!dialer->queries[i]) { dialer->resolved[i]=1; dialer->dns_error[i]=EAI_SYSTEM; dialer->dns_system_error[i]=dialer->last_error=errno; }
            }
        }
    }
    return dialer;
failure:
    { int saved=errno; core_dialer_free(dialer); errno=saved; return NULL; }
}

static int collect_addresses(core_dialer_t *dialer) {
    for (size_t i=0;i<2;i++) {
        if (dialer->resolved[i]) continue;
        struct addrinfo *addresses=NULL; int error;
        if (!core_resolver_result(dialer->queries[i],&addresses,&error)) continue;
        dialer->dns_system_error[i]=error == EAI_SYSTEM ? errno : 0;
        core_resolver_release(dialer->queries[i]); dialer->queries[i]=NULL;
        dialer->resolved[i]=1; dialer->dns_error[i]=error;
        int result=0;
        if (!error) for (struct addrinfo *entry=addresses;entry;entry=entry->ai_next)
            if (append_address(dialer,entry->ai_addr,(socklen_t)entry->ai_addrlen) != 0) { result=-1; break; }
        if (addresses) freeaddrinfo(addresses);
        if (result != 0) return -1;
    }
    return 0;
}

static size_t choose_address(core_dialer_t *dialer) {
    if (dialer->has_preferred && dialer->addresses[0].state == 0) return 0;
    int preferred=dialer->last_family == AF_INET6 ? AF_INET : AF_INET6;
    size_t first=SIZE_MAX;
    for (size_t i=0;i<dialer->count;i++) {
        if (dialer->addresses[i].state) continue;
        if (first == SIZE_MAX) first=i;
        if (dialer->addresses[i].address.ss_family == preferred) return i;
    }
    return first;
}

static void close_attempt(core_dialer_t *dialer, size_t slot, int state) {
    dialer_attempt_t *attempt=&dialer->attempts[slot];
    if (attempt->fd < 0) return;
    close(attempt->fd); attempt->fd=-1;
    dialer->addresses[attempt->index].state=state;
}

static int select_winner(core_dialer_t *dialer, size_t slot, struct sockaddr_storage *address, socklen_t *length) {
    dialer_attempt_t *attempt=&dialer->attempts[slot];
    int fd=attempt->fd;
    if (fcntl(fd,F_SETFL,attempt->flags) != 0) { dialer->last_error=errno; close_attempt(dialer,slot,2); return -1; }
    dialer_address_t *entry=&dialer->addresses[attempt->index];
    if (address) *address=entry->address;
    if (length) *length=entry->length;
    entry->state=3; attempt->fd=-1;
    close_attempt(dialer,1-slot,0);
    core_trace_stage(CORE_TRACE_TRANSPORT);
    return fd;
}

int core_dialer_next(core_dialer_t *dialer, struct sockaddr_storage *address, socklen_t *length) {
    if (!dialer) { errno=EINVAL; return -1; }
    for (;;) {
        uint64_t now=core_now_ms();
        if (now >= dialer->until_ms || (core_deadline_active() && !core_deadline_remaining())) { errno=ETIMEDOUT; break; }
        if (collect_addresses(dialer) != 0) break;
        int active=(dialer->attempts[0].fd >= 0)+(dialer->attempts[1].fd >= 0);
        size_t candidate=choose_address(dialer);
        int family_wait=!dialer->has_preferred && !dialer->started_tcp && candidate != SIZE_MAX &&
            dialer->addresses[candidate].address.ss_family == AF_INET && !dialer->resolved[0] && now < dialer->first_ready_ms+50;
        if (!family_wait && active < 2 && candidate != SIZE_MAX && (!active || now >= dialer->next_attempt_ms)) {
            dialer_address_t *entry=&dialer->addresses[candidate];
            size_t slot=dialer->attempts[0].fd < 0 ? 0 : 1;
            entry->state=1; dialer->last_family=entry->address.ss_family;
            dialer->started_tcp=1; core_trace_stage(CORE_TRACE_TCP);
            int fd=socket(entry->address.ss_family,SOCK_STREAM,IPPROTO_TCP);
            if (fd < 0) { entry->state=2; dialer->last_error=errno; continue; }
            core_tune_tcp_socket(fd);
            int flags=fcntl(fd,F_GETFL,0);
            dialer->attempts[slot]=(dialer_attempt_t){.fd=fd,.flags=flags,.index=candidate};
            if (flags < 0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK) != 0) {
                dialer->last_error=errno; close_attempt(dialer,slot,2); continue;
            }
            int result=connect(fd,(void *)&entry->address,entry->length);
            if (result == 0) { int winner=select_winner(dialer,slot,address,length); if (winner >= 0) return winner; continue; }
            if (errno != EINPROGRESS && errno != EINTR && errno != EWOULDBLOCK) {
                dialer->last_error=errno; close_attempt(dialer,slot,2); dialer->next_attempt_ms=0; continue;
            }
            dialer->next_attempt_ms=now+250;
            continue;
        }
        if (!active && candidate == SIZE_MAX && dialer->resolved[0] && dialer->resolved[1]) {
            errno=dialer->last_error;
            if (!dialer->count) {
                int cause=dialer->dns_system_error[0] ? dialer->dns_system_error[0] : dialer->dns_system_error[1];
                errno=cause ? cause : EHOSTUNREACH;
                core_trace_error_set(core_connection_error(CORE_TRACE_DNS,cause == EAGAIN ? CORE_FAILURE_RESOURCE : CORE_FAILURE_SYSTEM,errno));
            }
            break;
        }
        int wait=(int)(dialer->until_ms-now);
        if ((!dialer->resolved[0] || !dialer->resolved[1]) && wait > 5) wait=5;
        if (family_wait && wait > (int)(dialer->first_ready_ms+50-now)) wait=(int)(dialer->first_ready_ms+50-now);
        if (active < 2 && candidate != SIZE_MAX && dialer->next_attempt_ms > now && wait > (int)(dialer->next_attempt_ms-now)) wait=(int)(dialer->next_attempt_ms-now);
        struct pollfd sockets[2];
        for (size_t i=0;i<2;i++) sockets[i]=(struct pollfd){.fd=dialer->attempts[i].fd,.events=POLLOUT};
        int result=core_poll(sockets,2,wait);
        if (result < 0) break;
        for (size_t i=0;i<2;i++) if (sockets[i].fd >= 0 && sockets[i].revents) {
            int error=0; socklen_t error_length=sizeof(error);
            if (getsockopt(sockets[i].fd,SOL_SOCKET,SO_ERROR,&error,&error_length) != 0) error=errno;
            if (!error) { int winner=select_winner(dialer,i,address,length); if (winner >= 0) return winner; }
            else { dialer->last_error=error; close_attempt(dialer,i,2); }
            dialer->next_attempt_ms=0;
        }
    }
    int saved=errno; close_attempt(dialer,0,2); close_attempt(dialer,1,2); errno=saved;
    return -1;
}

void core_dialer_free(core_dialer_t *dialer) {
    if (!dialer) return;
    int saved=errno;
    for (size_t i=0;i<2;i++) { core_resolver_release(dialer->queries[i]); close_attempt(dialer,i,2); }
    free(dialer); errno=saved;
}

int core_dial_host(const char *host, uint16_t port, int use_server_ips, int timeout_ms) {
    core_dialer_t *dialer=core_dialer_start(host,port,use_server_ips,timeout_ms,NULL,0);
    if (!dialer) return -1;
    int fd=core_dialer_next(dialer,NULL,NULL);
    core_dialer_free(dialer);
    return fd;
}
