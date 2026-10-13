#include "cli_args.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

enum { URI, URI_FD, CONNECTION_FD, LISTEN, ROUTE_PORT, TIMEOUT, ROUTING, ROUTE_SOCKET, IPS, XRAY_VERSION, HELP, VERSION, PATCH };
typedef struct { const char *name; unsigned id, value, minimum, maximum; } option_t;
static const option_t options[]={
    {"--uri",URI,1,0,0},{"--uri-fd",URI_FD,1,0,INT_MAX},{"--connection-fd",CONNECTION_FD,1,0,INT_MAX},
    {"--listen-port",LISTEN,1,1,65535},{"--route-control-port",ROUTE_PORT,1,0,65535},
    {"--connect-timeout-ms",TIMEOUT,1,1,300000},{"--routing",ROUTING,1,0,0},
    {"--route-control-socket",ROUTE_SOCKET,1,0,0},{"--server-ips",IPS,1,0,0},{"--xray-version",XRAY_VERSION,1,0,0},
    {"--help",HELP,0,0,0},{"-h",HELP,0,0,0},{"--version",VERSION,0,0,0},{"-v",VERSION,0,0,0},
    {"--openssl-patch-status",PATCH,0,0,0}
};

static const option_t *lookup(const char *text) {
    if (text) for (size_t i=0;i<sizeof(options)/sizeof(*options);i++) if (!strcmp(text,options[i].name)) return options+i;
    return NULL;
}

static int error(char *message, size_t capacity, const char *reason, const char *field) {
    if (message && capacity) snprintf(message,capacity,"%s%s%s",reason,field ? ": " : "",field ? field : "");
    return -1;
}

static int number(const char *text, unsigned minimum, unsigned maximum, int *result) {
    if (!text || !*text) return -1;
    unsigned value=0;
    for (const unsigned char *cursor=(const unsigned char *)text;*cursor;cursor++) {
        unsigned digit=*cursor-'0';
        if (digit > 9 || value > maximum/10 || (value == maximum/10 && digit > maximum%10)) return -1;
        value=value*10+digit;
    }
    if (value < minimum) return -1;
    *result=(int)value; return 0;
}

int core_cli_args_parse(int count, char *const *arguments, core_cli_args_t *result, char *message, size_t capacity) {
    if (!result || !arguments || count < 1) return error(message,capacity,"invalid startup arguments",NULL);
    memset(result,0,sizeof(*result)); result->source_fd=-1; result->connect_timeout=30000;
    uint32_t seen=0;
    for (int i=1;i<count;i++) {
        const option_t *option=lookup(arguments[i]);
        if (!option) return error(message,capacity,"unknown startup argument",NULL);
        if (!option->value) {
            if (!result->action) result->action=option->id == HELP ? CORE_CLI_HELP : option->id == VERSION ? CORE_CLI_VERSION : CORE_CLI_PATCH_STATUS;
            continue;
        }
        if (seen&(1U<<option->id)) return error(message,capacity,"duplicate startup parameter",option->name);
        if (i+1 >= count || !arguments[i+1] || lookup(arguments[i+1])) return error(message,capacity,"missing startup parameter value",option->name);
        const char *value=arguments[++i]; int parsed=0;
        if (option->maximum && number(value,option->minimum,option->maximum,&parsed))
            return error(message,capacity,option->id == TIMEOUT ? "invalid connection timeout (expected 1-300000 ms)" : "invalid startup parameter",option->name);
        if (option->id <= CONNECTION_FD) {
            if (result->source) return error(message,capacity,"conflicting URI sources",option->name);
            if (option->id == CONNECTION_FD && (seen&(1U<<IPS))) return error(message,capacity,"conflicting server IP sources",option->name);
            result->source=option->id == URI ? CORE_CLI_URI_ARGUMENT : option->id == URI_FD ? CORE_CLI_URI_FD : CORE_CLI_CONNECTION_FD;
            if (option->id == URI) result->uri=value; else result->source_fd=parsed;
        } else switch (option->id) {
            case LISTEN: result->listen_port=parsed; break;
            case ROUTE_PORT: result->route_port=parsed; break;
            case TIMEOUT: result->connect_timeout=parsed; break;
            case ROUTING: result->routing=value; break;
            case ROUTE_SOCKET: result->route_socket=value; break;
            case IPS:
                if (result->source == CORE_CLI_CONNECTION_FD) return error(message,capacity,"conflicting server IP sources",option->name);
                result->server_ips=value; break;
            case XRAY_VERSION: result->xray_version=value; break;
        }
        seen|=1U<<option->id;
    }
    if (!result->action && !result->source) return error(message,capacity,"missing URI source","--uri/--uri-fd/--connection-fd");
    if (!result->action && !result->listen_port) return error(message,capacity,"missing startup parameter","--listen-port");
    return 0;
}

void core_cli_args_scrub(int count, char *const *arguments) {
    if (!arguments) return;
    for (int i=1;i+1<count;i++)
        if (arguments[i] && !strcmp(arguments[i],"--uri") && arguments[i+1] && !lookup(arguments[i+1]))
            OPENSSL_cleanse(arguments[i+1],strlen(arguments[i+1]));
}
