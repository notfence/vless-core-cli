#include "tls_transport_internal.h"
#include "uri.h"

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
static int normalize_ws_path(const char *in, char *out, size_t out_cap);
static int ws_make_key(char out[25]);
static int ws_make_accept(const char *key, char out[29]);
static int parse_ws_upgrade_response(tls13_conn_t *c, dynbuf_t *cache, const char *accept, const char *protocol, char *err, size_t err_cap);

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t need = 4 * ((in_len + 2) / 3);
    if (need + 1 > out_cap || in_len > (size_t)INT_MAX) {
        return -1;
    }
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (n < 0 || (size_t)n != need) {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

static int normalize_ws_path(const char *in, char *out, size_t out_cap) {
    return core_http_path(in,out,out_cap,0);
}

int http_host(const char *input, char *output, size_t capacity) {
    return core_http_authority_format(input,output,capacity);
}

static int ws_make_key(char out[25]) {
    uint8_t r[16];
    if (RAND_bytes(r, sizeof(r)) != 1) {
        return -1;
    }
    return base64_encode(r, sizeof(r), out, 25);
}

static int ws_make_accept(const char *key, char out[29]) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t digest[SHA_DIGEST_LENGTH];
    char material[128];
    int n = snprintf(material, sizeof(material), "%s%s", key, guid);
    if (n <= 0 || (size_t)n >= sizeof(material)) {
        return -1;
    }
    if (SHA1((const uint8_t *)material, (size_t)n, digest) == NULL) {
        return -1;
    }
    return base64_encode(digest, sizeof(digest), out, 29);
}

static int parse_ws_upgrade_response(tls13_conn_t *c, dynbuf_t *cache, const char *accept, const char *protocol, char *err, size_t err_cap) {
    for (;;) {
        size_t headers=find_double_crlf(cache->data,cache->len);
        if (headers) {
            if (core_ws_validate_upgrade(cache->data,headers,accept,protocol)) {
                set_err(err,err_cap,"invalid WebSocket upgrade response"); return -1;
            }
            if (c->credential_write) OPENSSL_cleanse(cache->data,headers);
            db_consume(cache,headers); return 0;
        }
        if (cache->len >= 32768) { set_err(err,err_cap,"WebSocket response headers too large"); return -1; }
        uint8_t input[4096]; size_t received=0;
        if (ws_conn_read_some(c,input,sizeof(input),&received) || !received) {
            set_err(err,err_cap,"failed to read WebSocket upgrade response"); return -1;
        }
        int result=db_append(cache,input,received);
        if (c->credential_write) OPENSSL_cleanse(input,sizeof(input));
        if (result) { set_err(err,err_cap,"oom"); return -1; }
    }
}

int ws_write_frame(tls13_conn_t *c, uint8_t opcode, const uint8_t *buf, size_t len) {
    if (len > CORE_WS_MESSAGE_LIMIT || (opcode >= 8 && len > 125)) return -1;
    uint8_t header[14],mask[4],chunk[8192];
    size_t size=0;
    header[size++]=(uint8_t)(0x80|opcode);
    if (len <= 125) header[size++]=(uint8_t)(0x80|len);
    else if (len <= 65535) {
        header[size++]=0xfe; header[size++]=(uint8_t)(len>>8); header[size++]=(uint8_t)len;
    } else {
        header[size++]=0xff;
        for (int i=7;i>=0;i--) header[size++]=(uint8_t)((uint64_t)len>>(i*8));
    }
    if (RAND_bytes(mask,sizeof(mask)) != 1) return -1;
    memcpy(header+size,mask,4); size+=4;
    if (ws_conn_write_all(c,header,size)) return -1;
    for (size_t offset=0;offset<len;) {
        size_t take=len-offset < sizeof(chunk) ? len-offset : sizeof(chunk);
        for (size_t i=0;i<take;i++) chunk[i]=buf[offset+i]^mask[(offset+i)%4];
        int result=ws_conn_write_all(c,chunk,take);
        if (c->credential_write) OPENSSL_cleanse(chunk,take);
        if (result) return -1;
        offset+=take;
    }
    return 0;
}

int ws_fill_app_cache(tls13_conn_t *c) {
    for (;;) {
        if (c->ws_decoder.closed) return 0;
        if (c->ws_net_cache.len) {
            core_ws_event_t event; size_t consumed=0;
            int result=core_ws_decode(&c->ws_decoder,c->ws_net_cache.data,c->ws_net_cache.len,&consumed,&event);
            if (result < 0) return -1;
            if (result && event.opcode < 8 && db_append(&c->app_cache,event.data,event.length)) return -1;
            if (result && event.opcode == 9 && ws_write_frame(c,10,event.data,event.length)) return -1;
            if (result && event.opcode == 8 && !c->ws_close_sent) {
                if (ws_write_frame(c,8,event.data,event.length)) return -1;
                c->ws_close_sent=1;
            }
            db_consume(&c->ws_net_cache,consumed);
            if (c->app_cache.len || c->ws_decoder.closed) return 0;
            if (c->ws_net_cache.len) continue;
        }
        uint8_t input[8192]; size_t received=0;
        int result=ws_conn_read_some(c,input,sizeof(input),&received);
        if (result) return result;
        if (!received) return -1;
        if (db_append(&c->ws_net_cache,input,received)) return -1;
    }
}

int ws_upgrade(tls13_conn_t *c, const uint8_t *early, size_t early_length, char *err, size_t err_cap) {
    char authority[sizeof(c->ws_host)+2];
    if (http_host(c->ws_host,authority,sizeof(authority)) || strcmp(authority,c->ws_host)) {
        set_err(err,err_cap,"invalid ws host"); return -1;
    }
    char key[25],expected[29];
    if (ws_make_key(key) || ws_make_accept(key,expected)) { set_err(err,err_cap,"failed to build WebSocket key"); return -1; }
    char headers[8192]=
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nDNT: 1\r\n"
        "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
        "Sec-CH-UA: \"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"\r\n"
        "Sec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\n";
    for (const char *line=c->ws_headers;*line;) {
        const char *end=strstr(line,"\r\n"),*colon=end ? memchr(line,':',(size_t)(end-line)) : NULL;
        if (!colon) return -1;
        char name[128],value[4096];
        size_t length=(size_t)(colon-line),value_length=(size_t)(end-colon-1);
        if (length >= sizeof(name) || value_length >= sizeof(value)) return -1;
        memcpy(name,line,length); name[length]=0;
        memcpy(value,colon+1,value_length); value[value_length]=0; trim_ascii(value);
        if (core_http_header_set(headers,sizeof(headers),name,value)) return -1;
        line=end+2;
    }
    size_t encoded_capacity=4*((early_length+2)/3)+1;
    char *encoded=calloc(1,encoded_capacity);
    if (!encoded) return -1;
    if (early_length) {
        if (base64_encode(early,early_length,encoded,encoded_capacity)) { OPENSSL_clear_free(encoded,encoded_capacity); return -1; }
        for (char *byte=encoded;*byte;byte++) {
            if (*byte == '+') *byte='-';
            else if (*byte == '/') *byte='_';
            else if (*byte == '=') { *byte=0; break; }
        }
    }
    size_t capacity=strlen(headers)+strlen(c->ws_path)+strlen(c->ws_host)+strlen(encoded)+256;
    char *request=malloc(capacity);
    if (!request) { OPENSSL_clear_free(encoded,encoded_capacity); return -1; }
    int length=snprintf(request,capacity,
        "GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n%s%s%s\r\n",
        c->ws_path,c->ws_host,headers,key,early_length ? "Sec-WebSocket-Protocol: " : "",
        early_length ? encoded : "",early_length ? "\r\n" : "");
    int result=length > 0 && (size_t)length < capacity ? ws_conn_write_all(c,request,(size_t)length) : -1;
    OPENSSL_clear_free(request,capacity);
    if (result) { OPENSSL_clear_free(encoded,encoded_capacity); set_err(err,err_cap,"failed to send WebSocket upgrade request"); return -1; }
    result=parse_ws_upgrade_response(c,&c->ws_net_cache,expected,encoded,err,err_cap);
    OPENSSL_clear_free(encoded,encoded_capacity);
    if (result) { if (c->credential_write) OPENSSL_cleanse(c->ws_net_cache.data,c->ws_net_cache.cap); return -1; }
    int flags=fcntl(c->fd,F_GETFL,0);
    if (flags < 0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return -1;
    c->ws_upgraded=1;
    if (c->tls_md && tls13_start_relay(c)) return -1;
    c->ws_next_heartbeat=c->ws_heartbeat_ms ? core_now_ms()+c->ws_heartbeat_ms : 0;
    return 0;
}

int ws_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->mode = CONN_MODE_WS;
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);
    int ws_tls = (strcmp(cfg->security, "tls") == 0);

    if (normalize_ws_path(cfg->xhttp_path, c->ws_path, sizeof(c->ws_path)) != 0) {
        set_err(err, err_cap, "invalid ws path");
        return -1;
    }

    const char *host = cfg->xhttp_host[0] != '\0' ? cfg->xhttp_host : (ws_tls ? c->remote_sni : cfg->server_host);
    if (http_host(host,c->ws_host,sizeof(c->ws_host))) { set_err(err,err_cap,"invalid ws host"); return -1; }

    if (ws_tls) {
        unsigned char h1_alpn[256]; unsigned int h1_alpn_length=0;
        const char *protocols=cfg->alpn[0] ? cfg->alpn : "http/1.1";
        if (!alpn_csv_has_token(protocols,"http/1.1") || build_xhttp_tls_alpn(protocols,h1_alpn,sizeof(h1_alpn),&h1_alpn_length)) {
            set_err(err,err_cap,"WebSocket requires http/1.1 ALPN"); return -1;
        }
        vless_config_t tls_config=*cfg;
        OPENSSL_cleanse(tls_config.trojan_hash,sizeof(tls_config.trojan_hash));
        if (tls_config.protocol == CORE_PROTOCOL_VMESS) OPENSSL_cleanse(tls_config.uuid,sizeof(tls_config.uuid));
        snprintf(tls_config.alpn,sizeof(tls_config.alpn),"%s",protocols);
        if (connect_manual_tls(&tls_config,c,err,err_cap)) return -1;
        if (c->tls_selected_alpn[0] && strcmp(c->tls_selected_alpn,"http/1.1")) {
            core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,EPROTO)); errno=EPROTO;
            set_err(err,err_cap,"WebSocket server selected incompatible ALPN"); return -1;
        }
    } else {
        c->fd = tcp_connect_host(c->remote_host, c->remote_port, c->ip_source);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
    }

    memcpy(c->ws_headers,cfg->ws_headers,sizeof(c->ws_headers));
    c->ws_early_data=cfg->ws_early_data;
    c->ws_heartbeat_ms=(uint64_t)cfg->ws_heartbeat_period*1000;
    if (!c->ws_early_data && ws_upgrade(c,NULL,0,err,err_cap)) return -1;
    vc_log_info("ws","connected security=%s early_data=%d",cfg->security,c->ws_early_data);
    return 0;
}
