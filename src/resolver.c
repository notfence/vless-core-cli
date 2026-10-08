#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "resolver.h"
#include "deadline.h"
#include "socket_util.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RESOLVER_WORKERS 4
#define RESOLVER_QUEUE_LIMIT 512

struct core_resolver_query {
    struct core_resolver_query *next;
    char *host;
    char *service;
    struct addrinfo hints;
    struct addrinfo *addresses;
    int error;
    int done;
    int started;
    unsigned references;
    pthread_cond_t ready;
};

static pthread_mutex_t resolver_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t resolver_ready = PTHREAD_COND_INITIALIZER;
static pthread_once_t resolver_once = PTHREAD_ONCE_INIT;
static core_resolver_query_t *resolver_head, *resolver_tail;
static unsigned resolver_queued, resolver_workers;

static void resolver_free(core_resolver_query_t *query) {
    if (query->addresses) freeaddrinfo(query->addresses);
    pthread_cond_destroy(&query->ready);
    free(query->host); free(query->service); free(query);
}

static void *resolver_worker(void *unused) {
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&resolver_lock);
        while (!resolver_head) pthread_cond_wait(&resolver_ready, &resolver_lock);
        core_resolver_query_t *query = resolver_head;
        resolver_head = query->next;
        if (!resolver_head) resolver_tail = NULL;
        resolver_queued--;
        query->started = 1;
        pthread_mutex_unlock(&resolver_lock);
        struct addrinfo *addresses = NULL;
        int error = getaddrinfo(query->host, query->service, &query->hints, &addresses);
        pthread_mutex_lock(&resolver_lock);
        query->addresses = addresses; query->error = error; query->done = 1;
        pthread_cond_signal(&query->ready);
        int release = --query->references == 0;
        pthread_mutex_unlock(&resolver_lock);
        if (release) resolver_free(query);
    }
    return NULL;
}

static void resolver_init_once(void) {
    for (unsigned i = 0; i < RESOLVER_WORKERS; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, resolver_worker, NULL) != 0) break;
        pthread_detach(thread);
        resolver_workers++;
    }
}

int core_resolver_init(void) {
    pthread_once(&resolver_once, resolver_init_once);
    if (resolver_workers != RESOLVER_WORKERS) { errno = EAGAIN; return -1; }
    return 0;
}

core_resolver_query_t *core_resolver_start(const char *host, const char *service, const struct addrinfo *hints) {
    if (!host || core_resolver_init() != 0) return NULL;
    core_resolver_query_t *query = calloc(1, sizeof(*query));
    if (!query) return NULL;
    pthread_condattr_t attributes;
    int status = pthread_condattr_init(&attributes);
    if (status != 0) { free(query); errno = status; return NULL; }
#ifndef __APPLE__
    status = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
#endif
    if (status == 0) status = pthread_cond_init(&query->ready, &attributes);
    pthread_condattr_destroy(&attributes);
    if (status != 0) { free(query); errno = status; return NULL; }
    query->host = strdup(host); query->service = service ? strdup(service) : NULL;
    if (!query->host || (service && !query->service)) { resolver_free(query); return NULL; }
    if (hints) {
        query->hints.ai_flags = hints->ai_flags;
        query->hints.ai_family = hints->ai_family;
        query->hints.ai_socktype = hints->ai_socktype;
        query->hints.ai_protocol = hints->ai_protocol;
    }
    pthread_mutex_lock(&resolver_lock);
    if (resolver_queued >= RESOLVER_QUEUE_LIMIT) {
        pthread_mutex_unlock(&resolver_lock); resolver_free(query); errno = EAGAIN; return NULL;
    }
    query->references = 2;
    if (resolver_tail) resolver_tail->next = query; else resolver_head = query;
    resolver_tail = query; resolver_queued++;
    pthread_cond_signal(&resolver_ready);
    pthread_mutex_unlock(&resolver_lock);
    return query;
}

int core_resolver_result(core_resolver_query_t *query, struct addrinfo **addresses, int *error) {
    if (!query || !addresses || !error) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&resolver_lock);
    int done = query->done;
    if (done) { *addresses = query->addresses; query->addresses = NULL; *error = query->error; }
    pthread_mutex_unlock(&resolver_lock);
    return done;
}

void core_resolver_release(core_resolver_query_t *query) {
    if (!query) return;
    pthread_mutex_lock(&resolver_lock);
    if (!query->started && !query->done) {
        core_resolver_query_t **cursor = &resolver_head, *previous = NULL;
        while (*cursor && *cursor != query) { previous = *cursor; cursor = &(*cursor)->next; }
        if (*cursor) {
            *cursor = query->next;
            if (resolver_tail == query) resolver_tail = previous;
            resolver_queued--; query->references--;
        }
    }
    int release = --query->references == 0;
    pthread_mutex_unlock(&resolver_lock);
    if (release) resolver_free(query);
}

int core_resolver_wait(core_resolver_query_t *query, struct addrinfo **addresses) {
    if (!query || !addresses) { errno = EINVAL; return EAI_SYSTEM; }
    *addresses = NULL;
    pthread_mutex_lock(&resolver_lock);
    for (;;) {
        int wait = core_deadline_limit(50);
        if (wait == 0) { pthread_mutex_unlock(&resolver_lock); errno = ETIMEDOUT; return EAI_SYSTEM; }
        if (query->done) {
            *addresses = query->addresses; query->addresses = NULL;
            int error = query->error;
            pthread_mutex_unlock(&resolver_lock); return error;
        }
#ifdef __APPLE__
        struct timespec until = {.tv_sec=wait/1000,.tv_nsec=(long)(wait%1000)*1000000};
        int result = pthread_cond_timedwait_relative_np(&query->ready, &resolver_lock, &until);
#else
        struct timespec until;
        clock_gettime(CLOCK_MONOTONIC, &until);
        until.tv_sec += wait / 1000;
        until.tv_nsec += (long)(wait % 1000) * 1000000;
        if (until.tv_nsec >= 1000000000) { until.tv_sec++; until.tv_nsec -= 1000000000; }
        int result = pthread_cond_timedwait(&query->ready, &resolver_lock, &until);
#endif
        if (result != 0 && result != ETIMEDOUT) {
            pthread_mutex_unlock(&resolver_lock); errno = result; return EAI_SYSTEM;
        }
    }
}
