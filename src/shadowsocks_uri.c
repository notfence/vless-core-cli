#include "config_internal.h"
#include "shadowsocks.h"
#include "utils.h"
#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static int invalid(char *error,size_t capacity,const char *field) {
    if (error && capacity) snprintf(error,capacity,"invalid Shadowsocks field %s",field);
    return -1;
}

static int percent_bytes(const char *input,size_t length,uint8_t *output,size_t capacity,size_t *written) {
    size_t used=0;
    for (size_t i=0;i<length;i++) {
        unsigned value=(unsigned char)input[i];
        if (value == '%') {
            if (i+2>=length || !isxdigit((unsigned char)input[i+1]) || !isxdigit((unsigned char)input[i+2])) return -1;
            unsigned a=(unsigned char)input[++i],b=(unsigned char)input[++i];
            a=a <= '9' ? a-'0' : (a|32U)-'a'+10U; b=b <= '9' ? b-'0' : (b|32U)-'a'+10U;
            value=(a<<4)|b;
        }
        if (used>=capacity) return -1;
        output[used++]=(uint8_t)value;
    }
    *written=used; return 0;
}

static int decode64(char *input,size_t length,int standard,uint8_t *output,size_t capacity,size_t *written) {
    unsigned alphabet=0;
    if (!length || (standard && length%4)) return -1;
    for (size_t i=0;i<length;i++) {
        if (input[i] == '+' || input[i] == '/') {
            alphabet|=1; input[i]=input[i] == '+' ? '-' : '_';
        } else if (input[i] == '-' || input[i] == '_') alphabet|=2;
    }
    if (alphabet == 3 || (standard && (alphabet&2))) return -1;
    return base64url_decode(input,output,capacity,written);
}

int core_ss_parameter(vless_config_t *config,const char *key,const char *value,char *error,size_t capacity) {
    if (!strcmp(key,"flow")) return *value ? invalid(error,capacity,"query.flow") : 1;
    if (!strcmp(key,"encryption")) {
        if (*value && strcasecmp(value,"none")) return invalid(error,capacity,"query.encryption");
        strcpy(config->encryption,"none"); return 1;
    }
    if (!strcmp(key,"plugin")) return *value ? invalid(error,capacity,"query.plugin") : 1;
    static const char *unsupported[]={"method","password","scy","aid","alterid","mux","uot","udp","packetencoding","obfs","headertype",
        "cert","ca","pinsha256","pinnedpeercertificatesha256","pinnedpeercertificatespkisha256","verifycert","peer","vcn","pcs"};
    for (size_t i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++) if (!strcmp(key,unsupported[i])) return invalid(error,capacity,unsupported[i]);
    return 0;
}

int core_ss_parse_uri(const char *uri,vless_config_t *config,char *error,size_t capacity) {
    if (!uri || !config || strlen(uri)<5) return invalid(error,capacity,"URI");
    core_config_defaults(config); config->protocol=CORE_PROTOCOL_SHADOWSOCKS;
    if (strlen(uri)>CORE_URI_MAX_LENGTH) return invalid(error,capacity,"URI-length");
    char work[CORE_URI_MAX_LENGTH+1],method[64];
    uint8_t decoded[CORE_URI_MAX_LENGTH+1],raw[CORE_SS_KEY_BYTES],key[32];
    size_t used=0,user_length=0; int encoded=0,result=-1;
    memcpy(work,uri+5,strlen(uri+5)+1);
    char *fragment=strchr(work,'#'); if (fragment) *fragment=0;
    char *query=strchr(work,'?'); if (query) *query++=0;
    char *at=strchr(work,'@'),*endpoint=NULL;
    if (at) {
        if (strchr(at+1,'@')) { invalid(error,capacity,"server"); goto cleanup; }
        *at=0; endpoint=at+1;
        if (percent_bytes(work,strlen(work),decoded,CORE_URI_MAX_LENGTH,&used)) { invalid(error,capacity,"userinfo-encoding"); goto cleanup; }
        decoded[used]=0;
        if (!memchr(decoded,':',used)) {
            if (memchr(decoded,0,used) || decode64((char *)decoded,used,0,decoded,CORE_URI_MAX_LENGTH,&used)) { invalid(error,capacity,"userinfo-base64"); goto cleanup; }
            encoded=1; decoded[used]=0;
        }
        user_length=used;
    } else {
        if (percent_bytes(work,strlen(work),decoded,CORE_URI_MAX_LENGTH,&used)) { invalid(error,capacity,"legacy-encoding"); goto cleanup; }
        decoded[used]=0;
        if (memchr(decoded,0,used) || decode64((char *)decoded,used,0,decoded,CORE_URI_MAX_LENGTH,&used)) { invalid(error,capacity,"legacy-base64"); goto cleanup; }
        decoded[used]=0; encoded=1;
        size_t separator=used;
        while (separator && decoded[separator-1] != '@') separator--;
        if (!separator || separator==used || memchr(decoded+separator,0,used-separator)) { invalid(error,capacity,"legacy-server"); goto cleanup; }
        user_length=separator-1; decoded[user_length]=0; endpoint=(char *)decoded+separator;
    }
    size_t endpoint_length=strlen(endpoint);
    if (endpoint_length && endpoint[endpoint_length-1]=='/') endpoint[--endpoint_length]=0;
    if (core_config_endpoint(endpoint,config->server_host,sizeof(config->server_host),&config->server_port)) { invalid(error,capacity,"server"); goto cleanup; }
    uint8_t *colon=memchr(decoded,':',user_length);
    if (!colon || colon==decoded || colon+1==decoded+user_length) { invalid(error,capacity,"credentials"); goto cleanup; }
    size_t method_length=(size_t)(colon-decoded);
    if (method_length>=sizeof(method) || memchr(decoded,0,method_length)) { invalid(error,capacity,"method"); goto cleanup; }
    memcpy(method,decoded,method_length); method[method_length]=0;
    if (core_ss_method(method,&config->ss.method)) { invalid(error,capacity,"method"); goto cleanup; }
    size_t size=core_ss_key_size(config->ss.method),password_length=user_length-method_length-1;
    if (core_ss_is_2022(config->ss.method)) {
        if (encoded || memchr(colon+1,0,password_length)) { invalid(error,capacity,"2022-key-encoding"); goto cleanup; }
        colon[1+password_length]=0; char *cursor=(char *)colon+1;
        for (;;) {
            char *next=strchr(cursor,':'); if (next) *next=0;
            size_t decoded_length=0;
            if (config->ss.count>=CORE_SS_KEY_BYTES/size || decode64(cursor,strlen(cursor),1,raw,sizeof(raw),&decoded_length) || core_ss_normalize(config->ss.method,raw,decoded_length,key)) { invalid(error,capacity,"2022-key"); goto cleanup; }
            memcpy(config->ss.keys+config->ss.count*size,key,size); config->ss.count++;
            OPENSSL_cleanse(raw,sizeof(raw)); OPENSSL_cleanse(key,sizeof(key));
            if (!next) break;
            cursor=next+1;
        }
        if (config->ss.method==CORE_SS_2022_CHACHA20_POLY1305 && config->ss.count!=1) { invalid(error,capacity,"2022-key-chain"); goto cleanup; }
    } else {
        if (core_ss_master(config->ss.method,colon+1,password_length,config->ss.keys)) { invalid(error,capacity,"credentials"); goto cleanup; }
        config->ss.count=1;
    }
    snprintf(config->sni,sizeof(config->sni),"%s",config->server_host);
    if (query && *query && core_config_query(config,query,error,capacity)) goto cleanup;
    if (core_config_finalize(config,error,capacity)) goto cleanup;
    if (config->transport_mode!=TRANSPORT_VISION && config->transport_mode!=TRANSPORT_WS && config->transport_mode!=TRANSPORT_GRPC) { invalid(error,capacity,"transport-not-yet-supported"); goto cleanup; }
    result=0;
cleanup:
    OPENSSL_cleanse(work,sizeof(work)); OPENSSL_cleanse(decoded,sizeof(decoded)); OPENSSL_cleanse(raw,sizeof(raw)); OPENSSL_cleanse(key,sizeof(key));
    if (result) OPENSSL_cleanse(config,sizeof(*config));
    return result;
}
