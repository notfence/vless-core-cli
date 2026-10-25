#include "http_headers.h"
#include "httpupgrade.h"
#include "uri.h"
#include "utils.h"
#include "xhttp_payload.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

static int invalid(char *error,size_t capacity,const char *field) {
    if (error && capacity) snprintf(error,capacity,"invalid HTTPUpgrade %s",field);
    return -1;
}

static int decimal(const char *value,uint32_t *output) {
    uint32_t result=0;
    if (!*value) return -1;
    for (;*value;value++) {
        unsigned digit=(unsigned char)*value-'0';
        if (digit>9 || result>(UINT32_MAX-digit)/10) return -1;
        result=result*10+digit;
    }
    *output=result; return 0;
}

int core_httpupgrade_parameter(vless_config_t *config,const char *key,const char *value,char *error,size_t capacity) {
    if (!strcmp(key,"ed")) {
        if (decimal(value,&config->httpupgrade_early_data)) return invalid(error,capacity,"ed");
        config->httpupgrade_early_explicit=1; return 1;
    }
    if (!strcmp(key,"heartbeatperiod")) return invalid(error,capacity,"heartbeatPeriod");
    if (strcmp(key,"headers")) return 0;
    core_json_t *root=core_json_parse(value,error,capacity);
    if (!root) return invalid(error,capacity,"headers");
    int result=core_http_headers_parse(root,config->ws_headers,sizeof(config->ws_headers),error,capacity);
    core_json_free(root);
    return result ? invalid(error,capacity,"headers") : 1;
}

int core_httpupgrade_path(const char *input,char *output,size_t capacity) {
    static const char hex[]="0123456789ABCDEF";
    size_t used=0;
    if (!input || !output || !capacity) return -1;
    if (*input!='/') { if (capacity<2) return -1; output[used++]='/'; }
    for (const unsigned char *p=(const unsigned char *)input;*p;p++) {
        unsigned byte=*p;
        if (byte<0x20 || byte==0x7f || byte=='\\') return -1;
        int plain=(byte>='a' && byte<='z') || (byte>='A' && byte<='Z') || (byte>='0' && byte<='9') || strchr("-_.~$&+,/:;=@",byte);
        size_t count=plain ? 1 : 3;
        if (count>=capacity-used) return -1;
        if (plain) output[used++]=(char)byte;
        else { output[used++]='%'; output[used++]=hex[byte>>4]; output[used++]=hex[byte&15]; }
    }
    output[used]=0; return 0;
}

typedef struct { char *name,*value; size_t order; } upgrade_query_item_t;

static int upgrade_query_compare(const void *left,const void *right) {
    const upgrade_query_item_t *a=left,*b=right;
    int result=strcmp(a->name,b->name);
    return result ? result : a->order<b->order ? -1 : a->order>b->order;
}

static int upgrade_query_put(char *output,size_t capacity,size_t *used,const char *value) {
    static const char hex[]="0123456789ABCDEF";
    for (const unsigned char *p=(const unsigned char *)value;*p;p++) {
        unsigned byte=*p;
        int plain=(byte>='a' && byte<='z') || (byte>='A' && byte<='Z') || (byte>='0' && byte<='9') || strchr("-_.~",byte);
        size_t count=plain || byte==' ' ? 1 : 3;
        if (count>=capacity-*used) return -1;
        if (plain || byte==' ') output[(*used)++]=byte==' ' ? '+' : (char)byte;
        else { output[(*used)++]='%'; output[(*used)++]=hex[byte>>4]; output[(*used)++]=hex[byte&15]; }
    }
    output[*used]=0; return 0;
}

static int upgrade_path_after_ed(char *path,size_t capacity,const char *fragment) {
    char normalized[256],query[256]; upgrade_query_item_t items[128]; size_t count=0;
    char *mark=strchr(path,'?');
    if (mark) { strcpy(query,mark+1); *mark=0; }
    if (core_request_target(path,normalized,sizeof(normalized))) return -1;
    if (mark) for (char *field=query;*field;) {
        char *next=strchr(field,'&'); if (next) *next=0;
        if (*field) {
            if (count==sizeof(items)/sizeof(*items) || strchr(field,';')) return -1;
            char *equal=strchr(field,'='),*value=equal ? equal+1 : field+strlen(field);
            if (equal) *equal=0;
            if (percent_decode(field,field,strlen(field)+1) || percent_decode(value,value,strlen(value)+1)) return -1;
            items[count]=(upgrade_query_item_t){field,value,count}; count++;
        }
        if (!next) break;
        field=next+1;
    }
    qsort(items,count,sizeof(*items),upgrade_query_compare);
    size_t used=strlen(normalized);
    for (size_t i=0;i<count;i++) {
        if (used+1>=sizeof(normalized)) return -1;
        normalized[used++]=i ? '&' : '?'; normalized[used]=0;
        if (upgrade_query_put(normalized,sizeof(normalized),&used,items[i].name) || used+1>=sizeof(normalized)) return -1;
        normalized[used++]='='; normalized[used]=0;
        if (upgrade_query_put(normalized,sizeof(normalized),&used,items[i].value)) return -1;
    }
    if (fragment && fragment[1]) {
        if (used+1>=sizeof(normalized)) return -1;
        normalized[used++]='#';
        if (core_request_target(fragment+1,normalized+used,sizeof(normalized)-used)) return -1;
    }
    if (strlen(normalized)>=capacity) return -1;
    strcpy(path,normalized); return 0;
}

int core_httpupgrade_configure(vless_config_t *config,char *error,size_t capacity) {
    for (const unsigned char *p=(const unsigned char *)config->xhttp_path;*p;p++)
        if (*p<0x20 || *p==0x7f || *p=='\\') return invalid(error,capacity,"path");
    char path[sizeof(config->xhttp_path)]; size_t used=0;
    char original[sizeof(config->xhttp_path)],fragment[sizeof(config->xhttp_path)]={0}; strcpy(original,config->xhttp_path);
    char *hash=strchr(original,'#'); if (hash) { strcpy(fragment,hash); *hash=0; }
    const char *query=strchr(original,'?');
    uint32_t embedded=0; int seen=0;
    if (query) {
        used=(size_t)(query-original); memcpy(path,original,used); path[used]=0;
        for (const char *item=query+1;*item;) {
            const char *next=strchr(item,'&'),*end=next ? next : item+strlen(item),*equal=memchr(item,'=',(size_t)(end-item));
            char name[256]={0},value[256]={0},decoded[256];
            size_t length=equal ? (size_t)(equal-item) : (size_t)(end-item);
            if (length>=sizeof(name)) return invalid(error,capacity,"path");
            memcpy(name,item,length);
            if (percent_decode(name,decoded,sizeof(decoded))) return invalid(error,capacity,"path");
            if (!strcmp(decoded,"ed")) {
                if (seen++ || !equal || (size_t)(end-equal-1)>=sizeof(value)) return invalid(error,capacity,"path.ed");
                memcpy(value,equal+1,(size_t)(end-equal-1));
                if (percent_decode(value,decoded,sizeof(decoded)) || decimal(decoded,&embedded)) return invalid(error,capacity,"path.ed");
            } else {
                length=(size_t)(end-item);
                if (length+1>=sizeof(path)-used) return invalid(error,capacity,"path");
                path[used++]=strchr(path,'?') ? '&' : '?'; memcpy(path+used,item,length); used+=length; path[used]=0;
            }
            if (!next) break;
            item=next+1;
        }
        if (seen) {
            if (upgrade_path_after_ed(path,sizeof(path),fragment)) return invalid(error,capacity,"path");
            strcpy(config->xhttp_path,path);
        }
    }
    if (seen && !config->httpupgrade_early_explicit) config->httpupgrade_early_data=embedded;
    if (!config->xhttp_path[0]) strcpy(config->xhttp_path,"/");
    char target[3*sizeof(config->xhttp_path)+2],authority[sizeof(config->xhttp_host)+2];
    const char *host=config->xhttp_host[0] ? config->xhttp_host : !strcmp(config->security,"tls") && config->sni[0] ? config->sni : config->server_host;
    if (core_http_authority_format(host,authority,sizeof(authority))) return invalid(error,capacity,"host");
    if (core_httpupgrade_path(config->xhttp_path,target,sizeof(target))) return invalid(error,capacity,"path");
    if (strcmp(config->security,"none") && strcmp(config->security,"tls")) return invalid(error,capacity,"security");
    if (config->flow[0] && !config->encryption_enabled) return invalid(error,capacity,"flow");
    if (!strcmp(config->security,"tls") && config->alpn[0]) {
        int found=0;
        for (const char *p=config->alpn;*p;) {
            const char *end=strchr(p,','); size_t length=end ? (size_t)(end-p) : strlen(p);
            if (length==8 && !memcmp(p,"http/1.1",8)) found=1;
            if (!end) break;
            p=end+1;
        }
        if (!found) return invalid(error,capacity,"alpn");
    }
    return 0;
}

int core_httpupgrade_validate(const uint8_t *data,size_t length) {
    static const char status[]="HTTP/1.1 101 Switching Protocols\r\n";
    if (!data || length>32768 || length<sizeof(status)-1+2 || memcmp(data,status,sizeof(status)-1)) return -1;
    size_t offset=sizeof(status)-1; int upgrade=0,connection=0;
    while (offset+1<length) {
        size_t start=offset;
        while (offset+1<length && !(data[offset]=='\r' && data[offset+1]=='\n')) offset++;
        if (offset+1>=length) return -1;
        size_t end=offset; offset+=2;
        if (end==start) return offset==length && upgrade && connection ? 0 : -1;
        const uint8_t *colon=memchr(data+start,':',end-start);
        if (!colon || colon==data+start) return -1;
        size_t name=(size_t)(colon-data-start),begin=(size_t)(colon-data)+1;
        for (size_t i=start;i<start+name;i++) {
            unsigned byte=data[i];
            if (!((byte>='a' && byte<='z') || (byte>='A' && byte<='Z') || (byte>='0' && byte<='9') || (byte && strchr("!#$%&'*+-.^_`|~",byte)))) return -1;
        }
        for (size_t i=begin;i<end;i++) if ((data[i]<0x20 && data[i]!='\t') || data[i]==0x7f) return -1;
        while (begin<end && (data[begin]==' ' || data[begin]=='\t')) begin++;
        while (end>begin && (data[end-1]==' ' || data[end-1]=='\t')) end--;
        if (name==7 && !strncasecmp((const char *)data+start,"Upgrade",name)) {
            if (upgrade++ || end-begin!=9 || strncasecmp((const char *)data+begin,"websocket",9)) return -1;
        } else if (name==10 && !strncasecmp((const char *)data+start,"Connection",name)) {
            if (connection++ || end-begin!=7 || strncasecmp((const char *)data+begin,"upgrade",7)) return -1;
        }
    }
    return -1;
}

static int failure(char *error, size_t capacity, const char *name) {
    char path[160]; size_t used=0;
    if (!name) name="headers";
    for (;*name && used+1<sizeof(path);name++) path[used++]=(unsigned char)*name >= 0x21 && (unsigned char)*name < 0x7f ? *name : '?';
    path[used]=0;
    if (error && capacity) snprintf(error,capacity,"invalid XHTTP headers field %s",path);
    return -1;
}

static int valid_value(const char *value) {
    for (const unsigned char *cursor=(const unsigned char *)value;*cursor;cursor++) if ((*cursor < 0x20 && *cursor != '\t') || *cursor == 0x7f) return 0;
    return 1;
}

int core_http_header_allowed(const char *name) {
    if (!core_http_token(name) || strlen(name) >= 128) return 0;
    const char *reserved[]={"host","content-length","transfer-encoding","connection","keep-alive","proxy-connection","upgrade","trailer","te"};
    for (size_t i=0;i<sizeof(reserved)/sizeof(*reserved);i++) if (!strcasecmp(name,reserved[i])) return 0;
    return 1;
}

const char *core_http_header_get(const char *headers, const char *name, size_t *length) {
    if (!headers || !name) return NULL;
    for (const char *line=headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!end || !colon) return NULL;
        if ((size_t)(colon-line) == strlen(name) && !strncasecmp(line,name,strlen(name))) {
            const char *value=colon+1;
            while (value < end && (*value == ' ' || *value == '\t')) value++;
            const char *last=end; while (last > value && (last[-1] == ' ' || last[-1] == '\t')) last--;
            if (length) *length=(size_t)(last-value);
            return value;
        }
        line=end+2;
    }
    return NULL;
}

int core_http_header_set(char *headers, size_t capacity, const char *name, const char *value) {
    if (!headers || !name || !value || !core_http_token(name) || !valid_value(value)) return -1;
    size_t used=strlen(headers),replacement=strlen(name)+strlen(value)+4,removed=0;
    if (used >= capacity) return -1;
    for (const char *line=headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!end || !colon) return -1;
        if ((size_t)(colon-line) == strlen(name) && !strncasecmp(line,name,strlen(name))) removed+=(size_t)(end+2-line);
        line=end+2;
    }
    if (replacement >= capacity || used-removed >= capacity-replacement) return -1;
    for (char *line=headers;*line;) {
        char *end=strstr(line,"\r\n"),*colon=memchr(line,':',(size_t)(end-line));
        if ((size_t)(colon-line) == strlen(name) && !strncasecmp(line,name,strlen(name))) {
            size_t length=(size_t)(end+2-line); memmove(line,end+2,strlen(end+2)+1); used-=length;
        } else line=end+2;
    }
    int size=snprintf(headers+used,capacity-used,"%s: %s\r\n",name,value);
    return size < 0 || (size_t)size >= capacity-used ? -1 : 0;
}

int core_http_header_append_cookie(char *headers, size_t capacity, const char *cookie) {
    size_t length=0; const char *existing=core_http_header_get(headers,"Cookie",&length);
    if (!existing || !length) return core_http_header_set(headers,capacity,"Cookie",cookie);
    size_t added=strlen(cookie);
    if (length > capacity || added > capacity-length || length+added+3 > capacity) return -1;
    char *combined=malloc(length+added+3);
    if (!combined) return -1;
    memcpy(combined,existing,length); memcpy(combined+length,"; ",2); memcpy(combined+length+2,cookie,added+1);
    int result=core_http_header_set(headers,capacity,"Cookie",combined); free(combined); return result;
}

static int compare(const void *left, const void *right) {
    const core_json_t *a=*(const core_json_t *const *)left,*b=*(const core_json_t *const *)right;
    return strcasecmp(a->key,b->key);
}

int core_http_headers_parse(const core_json_t *value, char *output, size_t capacity, char *error, size_t error_capacity) {
    if (!value || value->type != CORE_JSON_OBJECT || !capacity) return failure(error,error_capacity,NULL);
    const core_json_t *entries[512]; size_t count=0;
    for (const core_json_t *entry=value->child;entry;entry=entry->next) {
        if (count == sizeof(entries)/sizeof(*entries) || !core_http_header_allowed(entry->key) || entry->type != CORE_JSON_STRING || !valid_value(entry->text)) return failure(error,error_capacity,entry->key);
        entries[count++]=entry;
    }
    qsort(entries,count,sizeof(*entries),compare); memset(output,0,capacity);
    for (size_t i=0;i<count;i++) {
        if (i && !strcasecmp(entries[i]->key,entries[i-1]->key)) {
            if (strcmp(entries[i]->text,entries[i-1]->text)) return failure(error,error_capacity,entries[i]->key);
            continue;
        }
        char name[128]; size_t length=strlen(entries[i]->key);
        for (size_t byte=0;byte<=length;byte++) name[byte]=(char)(entries[i]->key[byte] >= 'A' && entries[i]->key[byte] <= 'Z' ? entries[i]->key[byte]+('a'-'A') : entries[i]->key[byte]);
        if (core_http_header_set(output,capacity,name,entries[i]->text) != 0) return failure(error,error_capacity,"capacity");
    }
    return 0;
}
