#include "http2_queue.h"
#include "http2_pool.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct core_http2_block {
    core_http2_block_t *next;
    size_t start, end;
    uint8_t data[CORE_HTTP2_QUEUE_BLOCK];
};

static pthread_mutex_t cache_lock=PTHREAD_MUTEX_INITIALIZER;
static core_http2_block_t *cache[CORE_BUFFER_DIRECTIONS];
static size_t cache_bytes[CORE_BUFFER_DIRECTIONS];
static core_buffer_budget_t cache_memory[CORE_BUFFER_DIRECTIONS]={
    {.direction=CORE_BUFFER_UPLOAD},{.direction=CORE_BUFFER_DOWNLOAD}
};

static core_buffer_budget_t *queue_memory(core_http2_queue_t *queue) {
    return queue->account ? queue->account : &queue->memory;
}

static core_http2_block_t *block_new(core_buffer_budget_t *memory) {
    unsigned direction=memory->direction;
    pthread_mutex_lock(&cache_lock);
    core_http2_block_t *block=cache[direction];
    if (block && !core_buffer_transfer(cache_memory+direction,memory,sizeof(*block))) {
        cache[direction]=block->next; cache_bytes[direction]-=sizeof(*block);
    } else block=NULL;
    pthread_mutex_unlock(&cache_lock);
    if (!block) block=core_buffer_alloc(memory,sizeof(*block));
    if (block) { block->next=NULL; block->start=block->end=0; }
    return block;
}

static void block_free(core_buffer_budget_t *memory, core_http2_block_t *block) {
    unsigned direction=memory->direction; int retained=0;
    pthread_mutex_lock(&cache_lock);
    if (sizeof(*block) <= CORE_HTTP2_QUEUE_CACHE-cache_bytes[direction] &&
        !core_buffer_transfer(memory,cache_memory+direction,sizeof(*block))) {
        block->next=cache[direction]; cache[direction]=block; cache_bytes[direction]+=sizeof(*block); retained=1;
    }
    pthread_mutex_unlock(&cache_lock);
    if (!retained) core_buffer_free(memory,block,sizeof(*block));
}

static void update_view(core_http2_queue_t *queue) {
    queue->data=queue->head ? queue->head->data : NULL;
    queue->start=queue->head ? queue->head->start : 0;
}

size_t core_http2_queue_reservation(size_t length) {
    if (length > CORE_BUFFER_TOTAL_LIMIT) return SIZE_MAX;
    size_t count=(length+CORE_HTTP2_QUEUE_BLOCK-1)/CORE_HTTP2_QUEUE_BLOCK+1;
    return count*sizeof(core_http2_block_t);
}

int core_http2_queue_append_parts(core_http2_queue_t *queue, const uint8_t *prefix, size_t prefix_length, const uint8_t *data, size_t data_length, size_t limit) {
    if (prefix_length > SIZE_MAX-data_length) { errno=EOVERFLOW; return -1; }
    if (!queue || (prefix_length && !prefix) || (data_length && !data)) { errno=EINVAL; return -1; }
    size_t length=prefix_length+data_length;
    if (queue->length > limit || length > limit-queue->length) { errno=ENOBUFS; return -1; }
    if (!length) return 0;
    if (limit != CORE_HTTP2_STREAM_LIMIT) {
        if (queue->start+queue->length+length > queue->capacity) {
            if (queue->start) { memmove(queue->data,queue->data+queue->start,queue->length); queue->start=0; }
            if (queue->length+length > queue->capacity) {
                size_t capacity=queue->capacity ? queue->capacity : 4096;
                while (capacity < queue->length+length) capacity=capacity > limit/2 ? limit : capacity*2;
                uint8_t *replacement=core_buffer_realloc(queue_memory(queue),queue->data,queue->capacity,capacity);
                if (!replacement) return -1;
                queue->data=replacement; queue->capacity=capacity;
            }
        }
        if (prefix_length) memcpy(queue->data+queue->start+queue->length,prefix,prefix_length);
        if (data_length) memcpy(queue->data+queue->start+queue->length+prefix_length,data,data_length);
        queue->length+=length; return 0;
    }
    size_t room=queue->tail ? CORE_HTTP2_QUEUE_BLOCK-queue->tail->end : 0;
    size_t needed=length > room ? (length-room+CORE_HTTP2_QUEUE_BLOCK-1)/CORE_HTTP2_QUEUE_BLOCK : 0;
    core_http2_block_t *first=NULL,*last=NULL;
    for (size_t i=0;i<needed;i++) {
        core_http2_block_t *block=block_new(queue_memory(queue));
        if (!block) {
            while (first) { block=first->next; block_free(queue_memory(queue),first); first=block; }
            return -1;
        }
        if (last) last->next=block; else first=block;
        last=block;
    }
    core_http2_block_t *write=queue->tail;
    if (queue->tail) queue->tail->next=first; else queue->head=first;
    if (last) queue->tail=last;
    if (!write) write=first;
    size_t offset=0;
    while (offset < length) {
        size_t amount=CORE_HTTP2_QUEUE_BLOCK-write->end;
        if (amount > length-offset) amount=length-offset;
        if (offset < prefix_length && amount > prefix_length-offset) amount=prefix_length-offset;
        if (amount) memcpy(write->data+write->end,offset < prefix_length ? prefix+offset : data+(offset-prefix_length),amount);
        write->end+=amount; offset+=amount;
        if (write->end == CORE_HTTP2_QUEUE_BLOCK) write=write->next;
    }
    queue->length+=length; queue->capacity+=needed*CORE_HTTP2_QUEUE_BLOCK; update_view(queue); return 0;
}

int core_http2_queue_append(core_http2_queue_t *queue, const uint8_t *data, size_t length, size_t limit) {
    return core_http2_queue_append_parts(queue,NULL,0,data,length,limit);
}

void core_http2_queue_consume(core_http2_queue_t *queue, size_t length) {
    if (length > queue->length) length=queue->length;
    queue->length-=length;
    if (!queue->head) {
        queue->start+=length;
        if (!queue->length) {
            core_buffer_free(queue_memory(queue),queue->data,queue->capacity);
            queue->data=NULL; queue->start=queue->capacity=0;
        }
        return;
    }
    while (length) {
        core_http2_block_t *block=queue->head;
        size_t amount=block->end-block->start;
        if (amount > length) amount=length;
        block->start+=amount; length-=amount;
        if (block->start == block->end) {
            queue->head=block->next; queue->capacity-=CORE_HTTP2_QUEUE_BLOCK; block_free(queue_memory(queue),block);
        }
    }
    if (!queue->head) queue->tail=NULL;
    update_view(queue);
}

void core_http2_queue_clear(core_http2_queue_t *queue) {
    core_http2_queue_consume(queue,queue->length);
    if (queue->data) { core_buffer_free(queue_memory(queue),queue->data,queue->capacity); queue->data=NULL; queue->capacity=queue->start=0; }
    if (!queue->account) core_buffer_budget_clear(&queue->memory);
}

size_t core_http2_queue_span(const core_http2_queue_t *queue) {
    return queue->head ? queue->head->end-queue->head->start : queue->length;
}

void core_http2_queue_copy(const core_http2_queue_t *queue, uint8_t *data, size_t length) {
    if (!queue->head) { if (length) memcpy(data,queue->data+queue->start,length); return; }
    for (core_http2_block_t *block=queue->head;length;block=block->next) {
        size_t amount=block->end-block->start;
        if (amount > length) amount=length;
        memcpy(data,block->data+block->start,amount); data+=amount; length-=amount;
    }
}

void core_http2_queue_cache_clear(void) {
    pthread_mutex_lock(&cache_lock);
    for (unsigned direction=0;direction<CORE_BUFFER_DIRECTIONS;direction++) {
        while (cache[direction]) {
            core_http2_block_t *block=cache[direction]; cache[direction]=block->next;
            core_buffer_free(cache_memory+direction,block,sizeof(*block));
        }
        cache_bytes[direction]=0;
    }
    pthread_mutex_unlock(&cache_lock);
}
