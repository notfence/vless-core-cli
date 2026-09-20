#define _POSIX_C_SOURCE 200809L

#include "core_log.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

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

static void write_all_stderr(const char *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(STDERR_FILENO, data + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) break;
        offset += (size_t)written;
    }
}

static void vc_log_vmessage(const char *level, const char *component,
                            const char *format, va_list arguments) {
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
        pthread_mutex_lock(&g_log_mutex);
        write_all_stderr(record, write_length);
        pthread_mutex_unlock(&g_log_mutex);
    }
    errno = saved_errno;
}

#define DEFINE_LOG_FUNCTION(function_name, level_name)                         \
    void function_name(const char *component, const char *format, ...) {       \
        va_list arguments;                                                     \
        va_start(arguments, format);                                           \
        vc_log_vmessage(level_name, component, format, arguments);             \
        va_end(arguments);                                                      \
    }

DEFINE_LOG_FUNCTION(vc_log_debug, "D")
DEFINE_LOG_FUNCTION(vc_log_info, "I")
DEFINE_LOG_FUNCTION(vc_log_warning, "W")
DEFINE_LOG_FUNCTION(vc_log_error, "E")
