#include "relay_memory.h"
#include "socket_util.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t relay_wait_lock=PTHREAD_MUTEX_INITIALIZER;
static core_relay_memory_t *relay_waiters;

size_t core_relay_capacity(size_t needed) {
    size_t capacity=512;
    while (capacity < needed) {
        if (capacity > SIZE_MAX/2) return needed;
        capacity*=2;
    }
    return capacity;
}

int core_relay_buffer_reserve(core_relay_buffer_t *buffer,size_t needed) {
    if (needed <= buffer->capacity) return 1;
    size_t limit=buffer->limit ? buffer->limit : SIZE_MAX;
    if (needed > limit) { errno=EMSGSIZE; return -1; }
    size_t capacity=core_relay_capacity(needed);
    if (capacity < buffer->minimum) capacity=buffer->minimum;
    if (capacity > limit) capacity=limit;
    void *previous=buffer->cleanse ? NULL : buffer->data;
    size_t previous_size=buffer->cleanse ? 0 : buffer->capacity;
    void *data=buffer->memory ? core_buffer_realloc(buffer->memory,previous,previous_size,capacity) : realloc(previous,capacity);
    if (!data) return errno == ENOBUFS ? 0 : -1;
    if (buffer->cleanse && buffer->data) {
        memcpy(data,buffer->data,buffer->capacity);
        OPENSSL_cleanse(buffer->data,buffer->capacity);
        if (buffer->memory) core_buffer_free(buffer->memory,buffer->data,buffer->capacity);
        else free(buffer->data);
    }
    buffer->data=data; buffer->capacity=capacity; return 1;
}

int core_relay_buffer_append(core_relay_buffer_t *buffer,const void *data,size_t length) {
    if (length > SIZE_MAX-buffer->length) { errno=EOVERFLOW; return -1; }
    if (core_relay_buffer_reserve(buffer,buffer->length+length) != 1) return -1;
    if (length) memcpy(buffer->data+buffer->length,data,length);
    buffer->length+=length; return 0;
}

void core_relay_buffer_consume(core_relay_buffer_t *buffer,size_t length) {
    if (length > buffer->length) length=buffer->length;
    buffer->length-=length;
    if (buffer->length) memmove(buffer->data,buffer->data+length,buffer->length);
    if (buffer->cleanse && length) OPENSSL_cleanse(buffer->data+buffer->length,length);
}

void core_relay_buffer_clear(core_relay_buffer_t *buffer) {
    if (buffer->cleanse && buffer->data) OPENSSL_cleanse(buffer->data,buffer->capacity);
    if (buffer->memory) core_buffer_free(buffer->memory,buffer->data,buffer->capacity);
    else free(buffer->data);
    buffer->data=NULL; buffer->length=buffer->capacity=0;
}

int core_relay_buffer_trim(core_relay_buffer_t *buffer) {
    if (buffer->length || buffer->capacity <= buffer->minimum) return 1;
    core_relay_buffer_clear(buffer);
    return core_relay_buffer_reserve(buffer,buffer->minimum);
}

int core_relay_memory_init(core_relay_memory_t *memory,size_t input_limit) {
    if (!memory->initialized) {
        memory->initialized=1;
        if (input_limit < CORE_RELAY_MINIMUM) input_limit=CORE_RELAY_MINIMUM;
        memory->input=(core_relay_buffer_t){.memory=&memory->upload,.minimum=CORE_RELAY_MINIMUM,.limit=input_limit};
        memory->output=(core_relay_buffer_t){.memory=&memory->download,.minimum=CORE_RELAY_MINIMUM,.limit=CORE_RELAY_OUTPUT_LIMIT};
        memory->wrapped.memory=memory->plain.memory=memory->packet.memory=&memory->temporary;
    }
    if (core_buffer_budget_init(&memory->upload,CORE_BUFFER_RELAY,CORE_RELAY_MINIMUM) ||
        core_buffer_budget_init(&memory->download,CORE_BUFFER_RELAY,CORE_RELAY_MINIMUM) ||
        core_buffer_budget_init(&memory->temporary,CORE_BUFFER_RELAY,0)) return errno == ENOBUFS ? 0 : -1;
    int result=core_relay_buffer_reserve(&memory->input,CORE_RELAY_MINIMUM);
    return result == 1 ? core_relay_buffer_reserve(&memory->output,CORE_RELAY_MINIMUM) : result;
}

int core_relay_memory_credit(core_relay_memory_t *memory,size_t needed) {
    if (memory->temporary.minimum == needed) return 1;
    return core_buffer_budget_init(&memory->temporary,CORE_BUFFER_RELAY,needed) ? (errno == ENOBUFS ? 0 : -1) : 1;
}

int core_relay_memory_watch(core_relay_memory_t *memory,unsigned mask) {
    if (!memory->registered) {
        int descriptors[2];
        if (socketpair(AF_UNIX,SOCK_STREAM,0,descriptors)) return -1;
        for (unsigned i=0;i<2;i++) {
            int flags=fcntl(descriptors[i],F_GETFL,0);
            if (flags < 0 || fcntl(descriptors[i],F_SETFL,flags|O_NONBLOCK) < 0 || fcntl(descriptors[i],F_SETFD,FD_CLOEXEC) < 0) {
                int saved=errno; close(descriptors[0]); close(descriptors[1]); errno=saved; return -1;
            }
            core_tune_tcp_socket(descriptors[i]);
        }
        pthread_mutex_lock(&relay_wait_lock);
        memory->notify[0]=descriptors[0]; memory->notify[1]=descriptors[1]; memory->registered=1;
        memory->next=relay_waiters; relay_waiters=memory;
        pthread_mutex_unlock(&relay_wait_lock);
    }
    pthread_mutex_lock(&relay_wait_lock); memory->waiting|=mask; pthread_mutex_unlock(&relay_wait_lock);
    return 0;
}

void core_relay_memory_unwatch(core_relay_memory_t *memory,unsigned mask) {
    pthread_mutex_lock(&relay_wait_lock); memory->waiting&=~mask; pthread_mutex_unlock(&relay_wait_lock);
}

unsigned core_relay_memory_ack(core_relay_memory_t *memory) {
    int saved=errno;
    pthread_mutex_lock(&relay_wait_lock);
    unsigned waiting=memory->waiting;
    memory->waiting=0; memory->notified=0;
    uint8_t bytes[64];
    if (memory->registered) {
        ssize_t received;
        do { received=recv(memory->notify[0],bytes,sizeof(bytes),MSG_DONTWAIT); }
        while (received > 0 || (received < 0 && errno == EINTR));
    }
    pthread_mutex_unlock(&relay_wait_lock); errno=saved; return waiting;
}

int core_relay_memory_fd(const core_relay_memory_t *memory) {
    return memory->registered && memory->waiting ? memory->notify[0] : -1;
}

void core_relay_memory_released(void) {
    int saved=errno;
    pthread_mutex_lock(&relay_wait_lock);
    for (core_relay_memory_t *memory=relay_waiters;memory;memory=memory->next) {
        if (!memory->waiting || memory->notified) continue;
        uint8_t byte=1;
        int flags=MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
        flags|=MSG_NOSIGNAL;
#endif
        ssize_t sent;
        do { sent=send(memory->notify[1],&byte,1,flags); } while (sent < 0 && errno == EINTR);
        if (sent == 1 || (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) memory->notified=1;
    }
    pthread_mutex_unlock(&relay_wait_lock);
    errno=saved;
}

void core_relay_memory_clear(core_relay_memory_t *memory) {
    if (memory->registered) {
        pthread_mutex_lock(&relay_wait_lock);
        core_relay_memory_t **entry=&relay_waiters;
        while (*entry && *entry != memory) entry=&(*entry)->next;
        if (*entry) *entry=memory->next;
        close(memory->notify[0]); close(memory->notify[1]); memory->registered=0;
        pthread_mutex_unlock(&relay_wait_lock);
    }
    if (memory->initialized) {
        core_relay_buffer_clear(&memory->input); core_relay_buffer_clear(&memory->output);
        core_relay_buffer_clear(&memory->wrapped); core_relay_buffer_clear(&memory->plain); core_relay_buffer_clear(&memory->packet);
        (void)core_buffer_budget_clear(&memory->upload); (void)core_buffer_budget_clear(&memory->download); (void)core_buffer_budget_clear(&memory->temporary);
    }
    memset(memory,0,sizeof(*memory));
}
