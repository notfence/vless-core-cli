#include "xhttp_download.h"
#include "xhttp_config.h"
#include "uri.h"
#include "utils.h"
#include "core_log.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

static int invalid(const char *field, char *error, size_t capacity) {
    if (error && capacity) snprintf(error,capacity,"invalid downloadSettings field %s",field);
    return -1;
}

static void unknown(const char *scope, const char *name) {
    char path[192]; size_t used=(size_t)snprintf(path,sizeof(path),"extra.downloadSettings.%s",scope);
    for (;*name && used+1<sizeof(path);name++) path[used++]=(unsigned char)*name >= 0x21 && (unsigned char)*name < 0x7f ? *name : '?';
    path[used]=0; vc_log_warning("xhttp","unknown field %s ignored",path);
}

static int string(const core_json_t *value, char *destination, size_t capacity, const char *field, char *error, size_t error_capacity) {
    if (!value || value->type != CORE_JSON_STRING || strlen(value->text) >= capacity) return invalid(field,error,error_capacity);
    for (const unsigned char *p=(const unsigned char *)value->text;*p;p++) if (*p < 0x20 || *p == 0x7f) return invalid(field,error,error_capacity);
    memcpy(destination,value->text,strlen(value->text)+1); return 0;
}

static int fingerprint(const core_json_t *value, fingerprint_mode_t *mode, char *error, size_t capacity) {
    const char *names[]={"chrome","random","qq","randomized","firefox","edge"};
    if (value->type != CORE_JSON_STRING) return invalid("fingerprint",error,capacity);
    for (size_t i=0;i<sizeof(names)/sizeof(*names);i++) if (!strcasecmp(value->text,names[i])) { *mode=(fingerprint_mode_t)i; return 0; }
    return invalid("fingerprint",error,capacity);
}

static int duplicate_fields(const core_json_t *object, const char *const *names, size_t count, char *error, size_t capacity) {
    for (const core_json_t *entry=object->child;entry;entry=entry->next) {
        int known=0;
        for (size_t i=0;i<count;i++) if (!strcasecmp(entry->key,names[i])) known=1;
        if (!known) continue;
        for (const core_json_t *previous=object->child;previous != entry;previous=previous->next)
            if (!strcasecmp(entry->key,previous->key) && !core_json_equal(entry,previous)) return invalid(entry->key,error,capacity);
    }
    return 0;
}

static int security_settings(const core_json_t *settings, int reality, vless_config_t *config, char *error, size_t capacity) {
    if (settings->type != CORE_JSON_OBJECT) return invalid(reality ? "realitySettings" : "tlsSettings",error,capacity);
    const char *tls_names[]={"serverName","allowInsecure","fingerprint","alpn"};
    const char *reality_names[]={"serverName","fingerprint","publicKey","password","shortId","spiderX"};
    if (duplicate_fields(settings,reality ? reality_names : tls_names,reality ? 6 : 4,error,capacity) != 0) return -1;
    for (const core_json_t *entry=settings->child;entry;entry=entry->next) {
        if (!strcasecmp(entry->key,"serverName")) {
            if (string(entry,config->sni,sizeof(config->sni),"serverName",error,capacity) != 0) return -1;
        } else if (!strcasecmp(entry->key,"allowInsecure") && !reality) {
            if (entry->type != CORE_JSON_BOOL) return invalid("tlsSettings.allowInsecure",error,capacity);
            config->allow_insecure=!strcmp(entry->text,"true");
        } else if (!strcasecmp(entry->key,"fingerprint")) {
            if (fingerprint(entry,&config->fp_mode,error,capacity) != 0) return -1;
        } else if ((!strcasecmp(entry->key,"publicKey") || !strcasecmp(entry->key,"password")) && reality) {
            uint8_t key[32]; size_t length;
            if (entry->type != CORE_JSON_STRING || base64url_decode(entry->text,key,sizeof(key),&length) != 0 || length != 32) return invalid("realitySettings.publicKey",error,capacity);
            if (config->pbk_len && memcmp(config->pbk,key,32)) return invalid("realitySettings.publicKey/password collision",error,capacity);
            memcpy(config->pbk,key,32); config->pbk_len=32;
        } else if (!strcasecmp(entry->key,"shortId") && reality) {
            if (entry->type != CORE_JSON_STRING || hex_to_bytes(entry->text,config->short_id,sizeof(config->short_id),&config->short_id_len) != 0) return invalid("realitySettings.shortId",error,capacity);
        } else if (!strcasecmp(entry->key,"spiderX") && reality) {
            if (string(entry,config->spider_x,sizeof(config->spider_x),"realitySettings.spiderX",error,capacity) != 0) return -1;
        } else if (!strcasecmp(entry->key,"alpn") && !reality) {
            if (entry->type != CORE_JSON_ARRAY) return invalid("tlsSettings.alpn",error,capacity);
            size_t used=0;
            for (const core_json_t *protocol=entry->child;protocol;protocol=protocol->next) {
                if (protocol->type != CORE_JSON_STRING || (strcmp(protocol->text,"h2") && strcmp(protocol->text,"http/1.1"))) return invalid("tlsSettings.alpn supports only h2/http/1.1",error,capacity);
                size_t length=strlen(protocol->text);
                if (used+length+(used ? 1 : 0) >= sizeof(config->alpn)) return invalid("tlsSettings.alpn capacity",error,capacity);
                if (used) config->alpn[used++]=',';
                memcpy(config->alpn+used,protocol->text,length+1); used+=length;
            }
        } else unknown(reality ? "realitySettings." : "tlsSettings.",entry->key);
    }
    return 0;
}

int core_xhttp_download_parse(const core_json_t *root, vless_config_t *config, char *error, size_t capacity) {
    if (!root || root->type != CORE_JSON_OBJECT || !config) return invalid("object",error,capacity);
    const char *names[]={"address","port","network","security","xhttpSettings","splithttpSettings","tlsSettings","realitySettings","downloadSettings"};
    if (duplicate_fields(root,names,sizeof(names)/sizeof(*names),error,capacity) != 0) return -1;
    core_config_defaults(config); config->transport_mode=TRANSPORT_XHTTP; config->xhttp_download_only=1;
    const core_json_t *xhttp=NULL,*tls=NULL,*reality=NULL;
    int address=0,port=0,network=0;
    for (const core_json_t *entry=root->child;entry;entry=entry->next) {
        if (!strcasecmp(entry->key,"address")) {
            if (string(entry,config->server_host,sizeof(config->server_host),"address",error,capacity) != 0 || !config->server_host[0]) return invalid("address",error,capacity);
            for (const unsigned char *p=(const unsigned char *)config->server_host;*p;p++) if (*p <= ' ' || strchr("/?#@[]",*p)) return invalid("address",error,capacity);
            address=1;
        } else if (!strcasecmp(entry->key,"port")) {
            core_range_t range;
            if (entry->type != CORE_JSON_NUMBER || core_xhttp_range(entry,&range,65535) != 0 || !range.min || range.min != range.max) return invalid("port",error,capacity);
            config->server_port=(uint16_t)range.min; port=1;
        } else if (!strcasecmp(entry->key,"network")) {
            if (entry->type != CORE_JSON_STRING || (strcasecmp(entry->text,"xhttp") && strcasecmp(entry->text,"splithttp"))) return invalid("network must be xhttp",error,capacity);
            network=1;
        } else if (!strcasecmp(entry->key,"security")) {
            if (string(entry,config->security,sizeof(config->security),"security",error,capacity) != 0) return -1;
            for (char *p=config->security;*p;p++) *p=(char)tolower((unsigned char)*p);
            if (!config->security[0]) strcpy(config->security,"none");
            if (strcmp(config->security,"none") && strcmp(config->security,"tls") && strcmp(config->security,"reality")) return invalid("security",error,capacity);
        } else if (!strcasecmp(entry->key,"xhttpSettings") || !strcasecmp(entry->key,"splithttpSettings")) {
            if (xhttp && !core_json_equal(xhttp,entry)) return invalid("xhttpSettings/splithttpSettings collision",error,capacity);
            xhttp=entry;
        } else if (!strcasecmp(entry->key,"tlsSettings")) tls=entry;
        else if (!strcasecmp(entry->key,"realitySettings")) reality=entry;
        else if (!strcasecmp(entry->key,"downloadSettings")) return invalid("recursive downloadSettings",error,capacity);
        else unknown("",entry->key);
    }
    if (!address || !port) return invalid("address/port required",error,capacity);
    if (!network) return invalid("network must explicitly select xhttp",error,capacity);
    snprintf(config->sni,sizeof(config->sni),"%s",config->server_host);
    if (tls && security_settings(tls,0,config,error,capacity) != 0) return -1;
    if (reality && security_settings(reality,1,config,error,capacity) != 0) return -1;
    if ((tls && strcmp(config->security,"tls")) || (reality && strcmp(config->security,"reality"))) return invalid("security settings do not match security",error,capacity);
    if (!strcmp(config->security,"reality") && config->pbk_len != 32) return invalid("realitySettings.publicKey required",error,capacity);
    if (xhttp) {
        if (xhttp->type != CORE_JSON_OBJECT) return invalid("xhttpSettings",error,capacity);
        const char *extra_names[]={"extra"};
        if (duplicate_fields(xhttp,extra_names,1,error,capacity) != 0) return -1;
        const core_json_t *extra=NULL;
        for (const core_json_t *entry=xhttp->child;entry;entry=entry->next) if (!strcasecmp(entry->key,"extra")) extra=entry;
        if (extra && core_xhttp_apply_object(config,extra,"extra.downloadSettings.xhttpSettings.extra",error,capacity) != 0) return -1;
        if (core_xhttp_apply_object(config,xhttp,"extra.downloadSettings.xhttpSettings",error,capacity) != 0) return -1;
    }
    if (strcmp(config->xhttp_mode,"auto") && config->xhttp_mode[0] && strcmp(config->xhttp_mode,"packet-up") && strcmp(config->xhttp_mode,"stream-up") && strcmp(config->xhttp_mode,"stream-one")) return invalid("xhttpSettings.mode",error,capacity);
    strcpy(config->xhttp_mode,"packet-up");
    return core_xhttp_validate(config,error,capacity);
}

int core_xhttp_download_config(const vless_config_t *parent, vless_config_t *download, char *error, size_t capacity) {
    core_json_t *root=core_json_parse(parent->xhttp_download_settings,error,capacity);
    if (!root) return -1;
    int result=core_xhttp_download_parse(root,download,error,capacity); core_json_free(root);
    if (!result) download->ignore_server_ips=strcmp(parent->server_host,download->server_host) || parent->server_port != download->server_port;
    return result;
}
