#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#define _DARWIN_C_SOURCE
#include "sockopt.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

const char *core_sockopt_field(unsigned bit) {
    return bit == CORE_SOCKOPT_TIMEOUT ? "tcpUserTimeout" : bit == CORE_SOCKOPT_IDLE ? "tcpKeepAliveIdle" : "tcpKeepAliveInterval";
}

static int invalid(char *error, size_t capacity, const char *field) {
    if (error && capacity) snprintf(error,capacity,"Invalid sockopt field: %.64s",field);
    return -1;
}

static int integer(const core_json_t *node, int32_t *output) {
    if (!node || node->type != CORE_JSON_NUMBER || !node->text) return -1;
    const unsigned char *p=(const unsigned char *)node->text;
    int negative=*p == '-'; if (negative) p++;
    uint32_t number=0, maximum=negative ? 2147483648U : INT32_MAX;
    if (!*p) return -1;
    for (;*p;p++) {
        if (*p < '0' || *p > '9' || number > (maximum-(*p-'0'))/10U) return -1;
        number=number*10U+(*p-'0');
    }
    *output=negative ? (int32_t)(-(int64_t)number) : (int32_t)number;
    return 0;
}

int core_sockopt_parse(const core_json_t *root, core_sockopt_t *output, char *error, size_t capacity) {
    if (!output || !root || root->type != CORE_JSON_OBJECT) return invalid(error,capacity,"object");
    core_sockopt_t result={0};
    for (const core_json_t *node=root->child;node;node=node->next) {
        unsigned bit=0; int32_t value;
        for (unsigned candidate=1;candidate<=4;candidate<<=1) if (!strcmp(node->key,core_sockopt_field(candidate))) bit=candidate;
        if (!bit) {
            static const char *unsupported[]={"mark","tcpFastOpen","tproxy","domainStrategy","dialerProxy","tcpCongestion","tcpWindowClamp","tcpMaxSeg","interface","customSockopt"};
            for (size_t i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++) if (!strcmp(node->key,unsupported[i])) return invalid(error,capacity,unsupported[i]);
            return invalid(error,capacity,"unsupported option");
        }
        if (integer(node,&value) || (bit == CORE_SOCKOPT_TIMEOUT && value < 0)) return invalid(error,capacity,core_sockopt_field(bit));
        int32_t *field=bit == 1 ? &result.user_timeout : bit == 2 ? &result.keepalive_idle : &result.keepalive_interval;
        if ((result.present & bit) && *field != value) return invalid(error,capacity,core_sockopt_field(bit));
        *field=value; result.present|=bit;
    }
    if ((result.keepalive_idle < 0 && result.keepalive_interval > 0) || (result.keepalive_interval < 0 && result.keepalive_idle > 0))
        return invalid(error,capacity,"conflicting keepalive values");
    *output=result;
    return 0;
}

int core_sockopt_json(const char *text, core_sockopt_t *output, char *error, size_t capacity) {
    core_json_t *root=text ? core_json_parse(text,error,capacity) : NULL;
    if (!root) { invalid(error,capacity,"JSON"); return -1; }
    int result=core_sockopt_parse(root,output,error,capacity);
    core_json_free(root);
    return result;
}

static void apply(int fd, int level, int option, int value, unsigned bit, core_sockopt_result_t *result) {
    unsigned index=bit == 1 ? 0 : bit == 2 ? 1 : 2;
    if (setsockopt(fd,level,option,&value,sizeof(value))) {
        result->unavailable|=bit; result->errors[index]=errno;
    } else result->applied|=bit;
}

core_sockopt_result_t core_sockopt_apply(int fd, const core_sockopt_t *settings) {
    core_sockopt_result_t result={0};
    int saved=errno;
    if (!settings) return result;
    if (settings->keepalive_idle < 0 || settings->keepalive_interval < 0) {
        unsigned bits=settings->present & (CORE_SOCKOPT_IDLE|CORE_SOCKOPT_INTERVAL);
        int zero=0;
        if (setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&zero,sizeof(zero))) {
            result.unavailable|=bits; result.errors[1]=result.errors[2]=errno;
        } else result.applied|=bits;
    } else {
        for (unsigned bit=2;bit<=4;bit<<=1) {
            int value=bit == 2 ? settings->keepalive_idle : settings->keepalive_interval;
            if (!(settings->present & bit) || !value) continue;
            int one=1;
            if (setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one))) {
                result.unavailable|=bit; result.errors[bit == 2 ? 1 : 2]=errno; continue;
            }
#if defined(__APPLE__)
            if (value > INT32_MAX/1000) {
                result.unavailable|=bit; result.errors[bit == 2 ? 1 : 2]=ERANGE; continue;
            }
            if (bit == 2) apply(fd,IPPROTO_TCP,TCP_KEEPALIVE,value,bit,&result);
#ifdef TCP_KEEPINTVL
            else apply(fd,IPPROTO_TCP,TCP_KEEPINTVL,value,bit,&result);
#else
            else { result.unavailable|=bit; result.errors[2]=ENOPROTOOPT; }
#endif
#elif defined(__linux__)
            apply(fd,IPPROTO_TCP,bit == 2 ? TCP_KEEPIDLE : TCP_KEEPINTVL,value,bit,&result);
#else
            result.unavailable|=bit; result.errors[bit == 2 ? 1 : 2]=ENOPROTOOPT;
#endif
        }
    }
    if ((settings->present & CORE_SOCKOPT_TIMEOUT) && settings->user_timeout > 0) {
#if defined(__APPLE__) && defined(TCP_RXT_CONNDROPTIME) && defined(PERSIST_TIMEOUT)
        int seconds=(int)(((int64_t)settings->user_timeout+999)/1000);
        if (seconds > INT32_MAX/1000) { result.unavailable|=1; result.errors[0]=ERANGE; }
        else {
            result.adapted|=1;
            apply(fd,IPPROTO_TCP,TCP_RXT_CONNDROPTIME,seconds,1,&result);
            apply(fd,IPPROTO_TCP,PERSIST_TIMEOUT,seconds,1,&result);
        }
#elif defined(__linux__) && defined(TCP_USER_TIMEOUT)
        apply(fd,IPPROTO_TCP,TCP_USER_TIMEOUT,settings->user_timeout,1,&result);
#else
        result.unavailable|=1; result.errors[0]=ENOPROTOOPT;
#endif
    }
    errno=saved;
    return result;
}

int core_sockopt_notice(unsigned bit, int adapted, int system_error, char *message, size_t capacity) {
    if (!message || !capacity) return -1;
    return snprintf(message,capacity,adapted ? "%s uses an approximate Darwin TCP timeout (rounded up to seconds)." :
        "%s could not be fully applied on this system (error %d).",core_sockopt_field(bit),system_error);
}

static core_sockopt_result_t capabilities;
static pthread_once_t capability_once=PTHREAD_ONCE_INIT;

static void probe_capabilities(void) {
    int fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (fd < 0) {
        capabilities.unavailable=7;
        capabilities.errors[0]=capabilities.errors[1]=capabilities.errors[2]=errno;
        return;
    }
    const core_sockopt_t options={.present=7,.user_timeout=1234,.keepalive_idle=17,.keepalive_interval=9};
    capabilities=core_sockopt_apply(fd,&options); close(fd);
}

core_sockopt_result_t core_sockopt_check(const core_sockopt_t *options) {
    core_sockopt_result_t result={0};
    if (!options || !options->present) return result;
    pthread_once(&capability_once,probe_capabilities);
    result=capabilities;
    unsigned used=(options->user_timeout > 0 ? 1U : 0U) | (options->keepalive_idle > 0 ? 2U : 0U) | (options->keepalive_interval > 0 ? 4U : 0U);
    if (options->keepalive_idle < 0 || options->keepalive_interval < 0) used&=1;
#ifdef __APPLE__
    for (unsigned bit=1;bit<=4;bit<<=1) {
        int64_t value=bit == 1 ? ((int64_t)options->user_timeout+999)/1000 : bit == 2 ? options->keepalive_idle : options->keepalive_interval;
        if ((used & bit) && value > INT32_MAX/1000) { result.unavailable|=bit; result.errors[bit == 1 ? 0 : bit == 2 ? 1 : 2]=ERANGE; }
    }
#endif
    result.applied&=used; result.adapted&=used; result.unavailable&=used;
    return result;
}
