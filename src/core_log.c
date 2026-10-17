#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "core_log.h"
#include "socket_util.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    char text[2304];
    size_t length;
    uint64_t sequence;
    unsigned category;
} log_record_t;
static struct {
    log_record_t records[54],active;
    uint64_t sequence,dropped[5],retry_ms;
    int wake[2],completed[2],started,busy;
    unsigned count,ordinary;
    char report[384];
} logger={.wake={-1,-1},.completed={-1,-1}};
static int log_fork_registered,log_exit_registered;
_Static_assert(sizeof(logger)+sizeof(g_log_mutex) <= 128U*1024U,"log storage exceeds its budget");

static void log_signal(int fd) {
    unsigned char byte=1;
    int flags=MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
    flags|=MSG_NOSIGNAL;
#endif
    ssize_t sent;
    do { sent=send(fd,&byte,1,flags); } while (sent < 0 && errno == EINTR);
}

static void log_drain(int fd) {
    unsigned char bytes[128]; ssize_t received;
    do { received=recv(fd,bytes,sizeof(bytes),MSG_DONTWAIT); }
    while (received > 0 || (received < 0 && errno == EINTR));
}

static int log_pair(int descriptors[2]) {
    if (socketpair(AF_UNIX,SOCK_STREAM,0,descriptors)) return -1;
    for (unsigned i=0;i<2;i++) {
        int flags=fcntl(descriptors[i],F_GETFL);
        if (flags < 0 || fcntl(descriptors[i],F_SETFL,flags|O_NONBLOCK) || fcntl(descriptors[i],F_SETFD,FD_CLOEXEC)) {
            close(descriptors[0]); close(descriptors[1]); descriptors[0]=descriptors[1]=-1; return -1;
        }
        core_tune_tcp_socket(descriptors[i]);
    }
    return 0;
}

static void log_fork_prepare(void) { pthread_mutex_lock(&g_log_mutex); }
static void log_fork_parent(void) { pthread_mutex_unlock(&g_log_mutex); }
static void log_fork_child(void) {
    for (unsigned i=0;i<2;i++) {
        if (logger.wake[i] >= 0) close(logger.wake[i]);
        if (logger.completed[i] >= 0) close(logger.completed[i]);
        logger.wake[i]=logger.completed[i]=-1;
    }
    memset(logger.records,0,sizeof(logger.records)); memset(&logger.active,0,sizeof(logger.active));
    memset(logger.dropped,0,sizeof(logger.dropped)); memset(logger.report,0,sizeof(logger.report));
    logger.started=logger.busy=0; logger.count=logger.ordinary=0; logger.sequence=logger.retry_ms=0;
    pthread_mutex_unlock(&g_log_mutex);
}

static void format_timestamp(char *destination, size_t capacity) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned int milliseconds = (unsigned int)(tv.tv_usec / 1000);
    time_t seconds = tv.tv_sec;
    struct tm local_time;
    char calendar[24];
    if (localtime_r(&seconds, &local_time) == NULL ||
        strftime(calendar, sizeof(calendar), "%Y-%m-%d %H:%M:%S", &local_time) == 0) {
        snprintf(destination, capacity, "%ld.%03u",
                 (long)tv.tv_sec, milliseconds);
        return;
    }
    snprintf(destination, capacity, "%s.%03u", calendar, milliseconds);
}

static void sanitize_text(const char *source, char *destination, size_t capacity) {
    size_t used = 0;
    if (source) {
        while (*source && used + 1 < capacity) {
            unsigned char byte = (unsigned char)*source++;
            destination[used++] = (byte < 0x20 || byte == 0x7f) ? ' ' : (char)byte;
        }
    }
    while (used > 0 && destination[used - 1] == ' ') used--;
    destination[used] = '\0';
}

static int write_all_stderr(const char *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(STDERR_FILENO, data + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd descriptor={.fd=STDERR_FILENO,.events=POLLOUT}; int ready;
            do { ready=poll(&descriptor,1,-1); } while (ready < 0 && errno == EINTR);
            if (ready <= 0 || (descriptor.revents&(POLLERR|POLLHUP|POLLNVAL))) return -1;
            continue;
        }
        if (written <= 0) return -1;
        offset += (size_t)written;
    }
    return 0;
}

static void log_drop(unsigned category) {
    if (logger.dropped[category] != UINT64_MAX) logger.dropped[category]++;
}

static void *log_output_worker(void *unused) {
    (void)unused;
    sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked,SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK,&blocked,NULL);
    for (;;) {
        pthread_mutex_lock(&g_log_mutex);
        int selected=-1;
        for (unsigned i=0;i<54;i++) if (logger.records[i].length &&
            (selected < 0 || logger.records[i].sequence < logger.records[selected].sequence)) selected=(int)i;
        if (selected < 0) {
            pthread_mutex_unlock(&g_log_mutex);
            struct pollfd descriptor={.fd=logger.wake[0],.events=POLLIN}; int result;
            do { result=poll(&descriptor,1,-1); } while (result < 0 && errno == EINTR);
            if (result > 0) log_drain(logger.wake[0]);
            continue;
        }
        logger.active=logger.records[selected]; logger.records[selected].length=0;
        logger.count--; if (logger.active.category < 3) logger.ordinary--;
        logger.busy=1; pthread_mutex_unlock(&g_log_mutex);
        int written=write_all_stderr(logger.active.text,logger.active.length);
        uint64_t dropped[5];
        pthread_mutex_lock(&g_log_mutex);
        if (written) log_drop(logger.active.category);
        memcpy(dropped,logger.dropped,sizeof(dropped));
        pthread_mutex_unlock(&g_log_mutex);
        if (!written && (dropped[0] || dropped[1] || dropped[2] || dropped[3] || dropped[4])) {
            char timestamp[40]; format_timestamp(timestamp,sizeof(timestamp));
            int length=snprintf(logger.report,sizeof(logger.report),
                "%s W [log] dropped debug=%llu info=%llu warning=%llu error=%llu diagnostic=%llu\n",timestamp,
                (unsigned long long)dropped[0],(unsigned long long)dropped[1],(unsigned long long)dropped[2],
                (unsigned long long)dropped[3],(unsigned long long)dropped[4]);
            if (length > 0 && (size_t)length < sizeof(logger.report) && !write_all_stderr(logger.report,(size_t)length)) {
                pthread_mutex_lock(&g_log_mutex);
                for (unsigned i=0;i<5;i++) logger.dropped[i]-=dropped[i];
                pthread_mutex_unlock(&g_log_mutex);
            }
        }
        pthread_mutex_lock(&g_log_mutex);
        memset(&logger.active,0,sizeof(logger.active)); memset(logger.report,0,sizeof(logger.report)); logger.busy=0;
        log_signal(logger.completed[1]); pthread_mutex_unlock(&g_log_mutex);
    }
    return NULL;
}

int vc_log_flush(void) {
    int saved=errno,result=0;
    uint64_t start=core_now_ms();
    for (;;) {
        pthread_mutex_lock(&g_log_mutex);
        int pending=logger.count || logger.busy,started=logger.started,fd=logger.completed[0];
        pthread_mutex_unlock(&g_log_mutex);
        if (!pending) break;
        uint64_t now=core_now_ms();
        if (!started || now-start >= 250) { result=-1; break; }
        struct pollfd descriptor={.fd=fd,.events=POLLIN};
        int ready=poll(&descriptor,1,(int)(250-(now-start)));
        if (ready > 0) log_drain(fd);
        else if (!ready || errno != EINTR) { result=-1; break; }
    }
    errno=saved; return result;
}

static void log_at_exit(void) { (void)vc_log_flush(); }

static int log_start(void) {
    if (logger.started) return 0;
    uint64_t now=core_now_ms();
    if (now < logger.retry_ms) return -1;
    logger.retry_ms=now > UINT64_MAX-1000 ? UINT64_MAX : now+1000;
    if (!log_fork_registered) {
        if (pthread_atfork(log_fork_prepare,log_fork_parent,log_fork_child)) return -1;
        log_fork_registered=1;
    }
    if (!log_exit_registered) { if (atexit(log_at_exit)) return -1; log_exit_registered=1; }
    if (log_pair(logger.wake) || log_pair(logger.completed)) goto failure;
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes)) goto failure;
    pthread_t thread;
    int result=pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED);
    if (!result) result=pthread_create(&thread,&attributes,log_output_worker,NULL);
    pthread_attr_destroy(&attributes);
    if (result) goto failure;
    logger.started=1; return 0;
failure:
    for (unsigned i=0;i<2;i++) {
        if (logger.wake[i] >= 0) close(logger.wake[i]);
        if (logger.completed[i] >= 0) close(logger.completed[i]);
        logger.wake[i]=logger.completed[i]=-1;
    }
    return -1;
}

static void log_enqueue(const char *text,size_t length,unsigned category) {
    pthread_mutex_lock(&g_log_mutex);
    if (log_start()) { log_drop(category); pthread_mutex_unlock(&g_log_mutex); return; }
    int selected=-1;
    if (category < 3 && logger.ordinary >= 39) { log_drop(category); pthread_mutex_unlock(&g_log_mutex); return; }
    for (unsigned i=0;i<54;i++) if (!logger.records[i].length) { selected=(int)i; break; }
    if (selected < 0 && category >= 3) {
        for (unsigned i=0;i<54;i++) if (logger.records[i].category < 3 &&
            (selected < 0 || logger.records[i].sequence < logger.records[selected].sequence)) selected=(int)i;
        if (selected >= 0) { log_drop(logger.records[selected].category); logger.ordinary--; logger.count--; }
    }
    if (selected < 0) { log_drop(category); pthread_mutex_unlock(&g_log_mutex); return; }
    int empty=!logger.count;
    log_record_t *record=logger.records+selected;
    memcpy(record->text,text,length); record->length=length; record->sequence=++logger.sequence; record->category=category;
    logger.count++; if (category < 3) logger.ordinary++;
    if (empty) log_signal(logger.wake[1]);
    pthread_mutex_unlock(&g_log_mutex);
}

static void vc_log_vmessage(const char *level, const char *component,
                            const char *format, va_list arguments,unsigned category) {
    if (!format) return;
    int saved_errno = errno;
    char message[2048];
    char safe_message[2048];
    char safe_component[48];
    char timestamp[40];
    char record[2304];

    message[0] = '\0';
    int message_length = vsnprintf(message, sizeof(message), format, arguments);
    if (message_length < 0) {
        snprintf(message, sizeof(message), "log message formatting failed");
    } else if ((size_t)message_length >= sizeof(message)) {
        memcpy(message + sizeof(message) - 4, "...", 3);
    }
    message[sizeof(message) - 1] = '\0';
    sanitize_text(message, safe_message, sizeof(safe_message));
    sanitize_text(component && *component ? component : "core",
                  safe_component, sizeof(safe_component));
    format_timestamp(timestamp, sizeof(timestamp));

    int record_length = snprintf(record, sizeof(record), "%s %s [%s] %s\n",
                                 timestamp, level, safe_component, safe_message);
    if (record_length > 0) {
        size_t write_length = (size_t)record_length < sizeof(record)
                                  ? (size_t)record_length
                                  : sizeof(record) - 1;
        log_enqueue(record,write_length,category);
    }
    errno = saved_errno;
}

#define DEFINE_LOG_FUNCTION(function_name, level_name, category)               \
    void function_name(const char *component, const char *format, ...) {       \
        va_list arguments;                                                     \
        va_start(arguments, format);                                           \
        vc_log_vmessage(level_name, component, format, arguments, category);   \
        va_end(arguments);                                                      \
    }

DEFINE_LOG_FUNCTION(vc_log_debug, "D",0)
DEFINE_LOG_FUNCTION(vc_log_info, "I",1)
DEFINE_LOG_FUNCTION(vc_log_warning, "W",2)
DEFINE_LOG_FUNCTION(vc_log_error, "E",3)

static void log_probe_message(const char *level,const char *format,...) {
    va_list arguments; va_start(arguments,format); vc_log_vmessage(level,"probe",format,arguments,4); va_end(arguments);
}

void vc_log_probe(int success,const char *text) { log_probe_message(success ? "I" : "W","%s",text); }
