#include "config_internal.h"
#include "json.h"
#include "core_log.h"
#include "utils.h"
#include <ctype.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int invalid(char *error,size_t capacity,const char *field) {
    if (error && capacity) snprintf(error,capacity,"invalid VMess field %s",field);
    return -1;
}

static int decimal(const char *text,unsigned maximum,unsigned *output) {
    unsigned value=0;
    if (!text || !*text) return -1;
    for (const unsigned char *p=(const unsigned char *)text;*p;p++) {
        if (*p < '0' || *p > '9' || (unsigned)(*p-'0') > maximum || value > (maximum-(*p-'0'))/10U) return -1;
        value=value*10U+(*p-'0');
    }
    *output=value; return 0;
}

int core_vmess_parameter(vless_config_t *config,const char *key,const char *value,char *error,size_t capacity) {
    if (!strcmp(key,"aid") || !strcmp(key,"alterid")) {
        unsigned aid;
        return decimal(value,0,&aid) ? invalid(error,capacity,"alterId") : 1;
    }
    if (!strcmp(key,"scy") || !strcmp(key,"encryption")) {
        const struct { const char *name; core_vmess_security_t mode; } modes[]={
            {"auto",CORE_VMESS_AUTO},{"aes-128-gcm",CORE_VMESS_AES128_GCM},{"chacha20-poly1305",CORE_VMESS_CHACHA20_POLY1305},
            {"none",CORE_VMESS_NONE},{"zero",CORE_VMESS_ZERO}};
        for (size_t i=0;i<sizeof(modes)/sizeof(*modes);i++) if (!strcmp(value,modes[i].name)) {
            config->vmess_security=modes[i].mode; strcpy(config->encryption,modes[i].name); return 1;
        }
        return invalid(error,capacity,"encryption");
    }
    if (!strcmp(key,"flow")) return *value ? invalid(error,capacity,"flow") : 1;
    static const char *unsupported[]={"authenticatedlength","noterminationsignal","experiments","globalpadding","chunkstream","chunkmasking","mux","packetencoding","headertype","cert","ca","pinsha256","pinnedpeercertificatesha256","pinnedpeercertificatespkiSha256","verifycert","peer","vcn","pcs"};
    for (size_t i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++) if (!strcasecmp(key,unsupported[i])) return invalid(error,capacity,unsupported[i]);
    return 0;
}

static int decode_base64(const char *encoded,char *output,size_t capacity) {
    size_t size=strlen(encoded),symbols=size,padding=0,written=0; unsigned bits=0,value=0; int alphabet=0;
    while (symbols && encoded[symbols-1] == '=') symbols--,padding++;
    if (!symbols || padding > 2 || symbols%4 == 1 || (padding && (size%4 || padding != (4-symbols%4)%4))) return -1;
    for (size_t i=0;i<symbols;i++) {
        unsigned char byte=(unsigned char)encoded[i]; unsigned digit;
        if (byte >= 'A' && byte <= 'Z') digit=byte-'A';
        else if (byte >= 'a' && byte <= 'z') digit=byte-'a'+26;
        else if (byte >= '0' && byte <= '9') digit=byte-'0'+52;
        else if (byte == '+' || byte == '/') { if (alphabet == 2) return -1; alphabet=1; digit=byte == '+' ? 62 : 63; }
        else if (byte == '-' || byte == '_') { if (alphabet == 1) return -1; alphabet=2; digit=byte == '-' ? 62 : 63; }
        else return -1;
        value=(value<<6)|digit; bits+=6;
        if (bits >= 8) {
            bits-=8;
            unsigned char decoded=(unsigned char)(value>>bits);
            if (!decoded || written+1 >= capacity) return -1;
            output[written++]=(char)decoded;
        }
        value&=(1U<<bits)-1;
    }
    if (value) return -1;
    output[written]=0; return 0;
}

static int scalar(const core_json_t *node,const char **output) {
    if (node->type != CORE_JSON_STRING && node->type != CORE_JSON_NUMBER && node->type != CORE_JSON_BOOL) return -1;
    *output=node->text; return 0;
}

static const char *canonical(const char *key) {
    const struct { const char *from,*to; } aliases[]={
        {"scy","encryption"},{"alterid","aid"},{"net","transport"},{"network","transport"},{"tls","security"},
        {"insecure","allowinsecure"},{"service_name","servicename"},{"maxearlydata","ed"},{"x_padding_bytes","xpaddingbytes"},
        {"sc_max_each_post_bytes","scmaxeachpostbytes"},{"sessionidplacement","sessionplacement"},{"sessionidkey","sessionkey"}};
    for (size_t i=0;i<sizeof(aliases)/sizeof(*aliases);i++) if (!strcmp(key,aliases[i].from)) return aliases[i].to;
    return key;
}

static int json_config(vless_config_t *config,const char *text,char *error,size_t capacity) {
    char reason[128]; core_json_t *root=core_json_parse(text,reason,sizeof(reason)); int result=-1;
    if (!root || root->type != CORE_JSON_OBJECT) { invalid(error,capacity,"JSON"); goto cleanup; }
    for (const core_json_t *network=root->child;network;network=network->next) {
        if (strcasecmp(network->key,"net") && strcasecmp(network->key,"network") && strcasecmp(network->key,"transport")) continue;
        if (network->type != CORE_JSON_STRING || core_config_parameter(config,"transport",network->text,error,capacity) < 0) { invalid(error,capacity,"net"); goto cleanup; }
    }
    char seen_keys[128][128]; const core_json_t *seen_values[128]; size_t seen=0;
    for (const core_json_t *node=root->child;node;node=node->next) {
        char lowered[128]; size_t length=strlen(node->key);
        if (!length || length >= sizeof(lowered)) { invalid(error,capacity,"name"); goto cleanup; }
        for (size_t i=0;i<=length;i++) {
            unsigned char c=(unsigned char)node->key[i];
            if (i<length && (c <= 0x20 || c >= 0x7f || strchr("%&=#",c))) { invalid(error,capacity,"name"); goto cleanup; }
            lowered[i]=(char)tolower(c);
        }
        const char *key=canonical(lowered),*value=NULL;
        if (!strcmp(key,"ps")) { if (node->type != CORE_JSON_STRING) { invalid(error,capacity,"ps"); goto cleanup; } continue; }
        size_t previous=0;
        for (;previous<seen;previous++) if (!strcmp(seen_keys[previous],key)) break;
        if (previous<seen) {
            if (!core_json_equal(seen_values[previous],node)) {
                const char *old=NULL;
                if (scalar(seen_values[previous],&old) || scalar(node,&value) || strcmp(old,value)) { invalid(error,capacity,"conflicting aliases"); goto cleanup; }
            }
            continue;
        }
        if (seen == 128) { invalid(error,capacity,"field count"); goto cleanup; }
        strcpy(seen_keys[seen],key); seen_values[seen++]=node;
        if (!strcmp(key,"extra") || !strcmp(key,"headers") || !strcmp(key,"downloadsettings")) {
            char object[4096];
            if (node->type == CORE_JSON_STRING) value=node->text;
            else if (node->type == CORE_JSON_OBJECT && node->source_length < sizeof(object)) {
                memcpy(object,node->source,node->source_length); object[node->source_length]=0; value=object;
            } else { invalid(error,capacity,key); goto cleanup; }
            int applied=core_config_parameter(config,key,value,error,capacity);
            OPENSSL_cleanse(object,sizeof(object)); if (applied) goto cleanup;
            continue;
        }
        if (scalar(node,&value)) {
            if (!strcmp(key,"id") || !strcmp(key,"add") || !strcmp(key,"port") || !strcmp(key,"aid") || !strcmp(key,"v") || !strcmp(key,"type")) { invalid(error,capacity,key); goto cleanup; }
            int applied=core_config_parameter(config,key,"",error,capacity);
            if (applied == 1) continue;
            invalid(error,capacity,key); goto cleanup;
        }
        if (!strcmp(key,"v") || !strcmp(key,"port") || !strcmp(key,"aid")) {
            unsigned number,maximum=!strcmp(key,"port") ? 65535 : !strcmp(key,"v") ? 2 : 0;
            if ((node->type != CORE_JSON_STRING && node->type != CORE_JSON_NUMBER) || decimal(value,maximum,&number) ||
                (!strcmp(key,"v") && number != 2) || (!strcmp(key,"port") && !number)) { invalid(error,capacity,key); goto cleanup; }
            if (!strcmp(key,"port")) config->server_port=(uint16_t)number;
        } else if (!strcmp(key,"id")) {
            if (node->type != CORE_JSON_STRING || parse_uuid(value,config->uuid)) { invalid(error,capacity,"id"); goto cleanup; }
        } else if (!strcmp(key,"add")) {
            if (node->type != CORE_JSON_STRING || strlen(value) >= sizeof(config->server_host) || !core_server_host_valid(value)) { invalid(error,capacity,"add"); goto cleanup; }
            strcpy(config->server_host,value);
        } else if (!strcmp(key,"type")) {
            if (node->type != CORE_JSON_STRING) { invalid(error,capacity,"type"); goto cleanup; }
            if (config->transport_mode == TRANSPORT_GRPC) {
                if (!strcmp(value,"multi")) value="multi";
                else if (!*value || !strcmp(value,"gun") || !strcmp(value,"none")) value="gun";
                else { invalid(error,capacity,"type"); goto cleanup; }
                if (core_config_parameter(config,"mode",value,error,capacity)) goto cleanup;
            } else if (*value && strcmp(value,"none")) { invalid(error,capacity,"type"); goto cleanup; }
        } else {
            if (!strcmp(key,"security") && !*value) value="none";
            if (config->transport_mode == TRANSPORT_GRPC && !strcmp(key,"path")) key="servicename";
            else if (config->transport_mode == TRANSPORT_GRPC && !strcmp(key,"host")) key="authority";
            int applied=core_config_parameter(config,key,value,error,capacity);
            if (applied < 0) goto cleanup;
            if (!applied && (node->type == CORE_JSON_NUMBER || node->type == CORE_JSON_BOOL)) {
                static const char *numeric[]={"ed","heartbeatperiod","idletimeout","healthchecktimeout","initialwindowssize","permitwithoutstream","allowinsecure"};
                int allowed=0; for (size_t i=0;i<sizeof(numeric)/sizeof(*numeric);i++) if (!strcmp(key,numeric[i])) allowed=1;
                if (!allowed) { invalid(error,capacity,key); goto cleanup; }
            }
        }
    }
    if (!core_json_get(root,"id") || !config->server_host[0] || !config->server_port) { invalid(error,capacity,"required fields"); goto cleanup; }
    if (!config->sni[0]) strcpy(config->sni,config->server_host);
    result=0;
cleanup:
    core_json_free(root); return result;
}

int core_vmess_parse_uri(const char *uri,vless_config_t *config,char *error,size_t capacity) {
    if (!uri || !config) return invalid(error,capacity,"input");
    core_config_defaults(config); config->protocol=CORE_PROTOCOL_VMESS; strcpy(config->encryption,"auto");
    if (error && capacity) *error=0;
    if (strlen(uri) > CORE_URI_MAX_LENGTH) return invalid(error,capacity,"URI length");
    char work[CORE_URI_MAX_LENGTH+1]={0},decoded[CORE_URI_MAX_LENGTH+1]={0}; int result=-1;
    strcpy(work,uri+8);
    char *fragment=strchr(work,'#'); if (fragment) *fragment=0;
    char *at=strchr(work,'@');
    if (at) {
        *at=0; char *query=strchr(at+1,'?'); if (query) *query++=0;
        if (parse_uuid(work,config->uuid) || core_config_endpoint(at+1,config->server_host,sizeof(config->server_host),&config->server_port)) { invalid(error,capacity,"UUID or endpoint"); goto cleanup; }
        strcpy(config->sni,config->server_host);
        if (query && *query && core_config_query(config,query,error,capacity)) goto cleanup;
    } else if (decode_base64(work,decoded,sizeof(decoded)) || json_config(config,decoded,error,capacity)) { if (!error || !*error) invalid(error,capacity,"Base64 JSON"); goto cleanup; }
    if (config->flow[0]) { invalid(error,capacity,"flow"); goto cleanup; }
    if (config->transport_mode != TRANSPORT_VISION && config->transport_mode != TRANSPORT_WS) { invalid(error,capacity,"transport not yet supported"); goto cleanup; }
    if (core_config_finalize(config,error,capacity)) goto cleanup;
    result=0;
cleanup:
    OPENSSL_cleanse(work,sizeof(work)); OPENSSL_cleanse(decoded,sizeof(decoded));
    if (result) OPENSSL_cleanse(config,sizeof(*config));
    return result;
}
