#include "tls_transport_internal.h"
#include "uri.h"

static int httpupgrade_read_wire(tls13_conn_t *connection,uint8_t *data,size_t capacity,size_t *received) {
    if (connection->tls_md) return manual_stream_read(connection,data,capacity,received);
    if (!connection->relay_async) return fd_read_some(connection->fd,data,capacity,received);
    *received=0;
    ssize_t result=core_recv(connection->fd,data,capacity,MSG_DONTWAIT);
    if (result<0) return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ? 1 : -1;
    *received=(size_t)result; return 0;
}

static int httpupgrade_response(tls13_conn_t *connection) {
    dynbuf_t *input=&connection->ws_net_cache;
    for (;;) {
        size_t headers=find_double_crlf(input->data,input->len);
        if (headers) {
            if (core_httpupgrade_validate(input->data,headers)) { errno=EPROTO; return -1; }
            db_consume(input,headers); connection->httpupgrade_pending=0;
            if (!input->len) db_free(input);
            return 0;
        }
        if (input->len>=32768) { errno=EMSGSIZE; return -1; }
        size_t capacity=32768-input->len;
        if (capacity>4096) capacity=4096;
        if (db_reserve(input,capacity)) return -1;
        size_t received=0;
        int result=httpupgrade_read_wire(connection,input->data+input->len,capacity,&received);
        if (result) return result;
        if (!received) { errno=EPROTO; return -1; }
        input->len+=received;
    }
}

int httpupgrade_read_app(tls13_conn_t *connection,uint8_t *data,size_t capacity,size_t *received) {
    *received=0;
    if (!capacity) return 0;
    if (connection->httpupgrade_pending) {
        int result=httpupgrade_response(connection);
        if (result) return result;
        if (!connection->ws_net_cache.len) return 1;
    }
    dynbuf_t *input=&connection->ws_net_cache;
    if (!input->len) return httpupgrade_read_wire(connection,data,capacity,received);
    size_t take=input->len<capacity ? input->len : capacity;
    memcpy(data,input->data,take); db_consume(input,take); *received=take;
    if (!input->len) db_free(input);
    return 0;
}

int httpupgrade_connect(const vless_config_t *config,tls13_conn_t *connection,char *error,size_t capacity) {
    connection->httpupgrade=connection->httpupgrade_pending=1;
    connection->mode=!strcmp(config->security,"tls") ? CONN_MODE_TLS : CONN_MODE_PLAIN;
    snprintf(connection->remote_host,sizeof(connection->remote_host),"%s",config->server_host);
    connection->remote_port=config->server_port;
    snprintf(connection->remote_sni,sizeof(connection->remote_sni),"%s",config->sni[0] ? config->sni : config->server_host);
    if (connection->mode==CONN_MODE_TLS) {
        vless_config_t tls_config=*config;
        snprintf(tls_config.alpn,sizeof(tls_config.alpn),"http/1.1");
        int result=connect_manual_tls(&tls_config,connection,error,capacity);
        OPENSSL_cleanse(&tls_config,sizeof(tls_config));
        if (result) return -1;
        if (connection->tls_selected_alpn[0] && strcmp(connection->tls_selected_alpn,"http/1.1")) {
            set_err(error,capacity,"HTTPUpgrade server selected incompatible ALPN"); errno=EPROTO; return -1;
        }
    } else {
        connection->fd=tcp_connect_host(config->server_host,config->server_port,connection->ip_source);
        if (connection->fd<0) { set_err(error,capacity,"HTTPUpgrade tcp connect failed"); return -1; }
    }
    const char *host=config->xhttp_host[0] ? config->xhttp_host : connection->mode==CONN_MODE_TLS ? connection->remote_sni : config->server_host;
    char authority[sizeof(config->xhttp_host)+2],path[3*sizeof(config->xhttp_path)+2];
    if (core_http_authority_format(host,authority,sizeof(authority)) || core_httpupgrade_path(config->xhttp_path,path,sizeof(path))) {
        set_err(error,capacity,"invalid HTTPUpgrade request"); return -1;
    }
    char headers[8192]=
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nDNT: 1\r\n"
        "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
        "Sec-CH-UA: \"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"\r\n"
        "Sec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\n";
    for (const char *line=config->ws_headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!colon) { OPENSSL_cleanse(headers,sizeof(headers)); set_err(error,capacity,"invalid HTTPUpgrade headers"); return -1; }
        char name[128],value[4096]; size_t length=(size_t)(colon-line),size=(size_t)(end-colon-1);
        if (length>=sizeof(name) || size>=sizeof(value)) { OPENSSL_cleanse(headers,sizeof(headers)); return -1; }
        memcpy(name,line,length); name[length]=0; memcpy(value,colon+1,size); value[size]=0; trim_ascii(value);
        int result=core_http_header_set(headers,sizeof(headers),name,value);
        OPENSSL_cleanse(value,sizeof(value));
        if (result) { OPENSSL_cleanse(headers,sizeof(headers)); return -1; }
        line=end+2;
    }
    dynbuf_t request={.memory=connection->output_memory ? connection->output_memory : &connection->record_memory,.limit=16384};
    size_t needed=strlen(path)+strlen(authority)+strlen(headers)+128;
    if (db_reserve(&request,needed)) { OPENSSL_cleanse(headers,sizeof(headers)); set_err(error,capacity,"HTTPUpgrade request memory exhausted"); return -1; }
    int length=snprintf((char *)request.data,request.cap,"GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",path,authority,headers);
    int result=length>0 && (size_t)length<request.cap ? ws_conn_write_all(connection,request.data,(size_t)length) : -1;
    OPENSSL_cleanse(headers,sizeof(headers)); OPENSSL_cleanse(request.data,request.cap); db_free(&request);
    if (result) { set_err(error,capacity,"failed to send HTTPUpgrade request"); return -1; }
    connection->ws_net_cache.limit=32768;
    if (!config->httpupgrade_early_data && httpupgrade_response(connection)) {
        set_err(error,capacity,"invalid or incomplete HTTPUpgrade response"); return -1;
    }
    if (tls13_start_relay(connection)) return -1;
    vc_log_info("httpupgrade","connected security=%s early_data=%u",config->security,(unsigned)config->httpupgrade_early_data);
    return 0;
}
