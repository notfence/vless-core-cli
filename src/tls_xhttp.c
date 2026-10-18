#include "tls_transport_internal.h"

const char xhttp_user_agent[]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

static int normalize_xhttp_path(const char *in, char *out, size_t out_cap);
static int random_xpadding_value(int min_len, int max_len, const char *method, char *buf, size_t cap);
static int xhttp_read_http1_response(SSL *ssl, int fd, const char *method, char *err, size_t err_cap);
static int xhttp_buffer_available(tls13_conn_t *c);
static int xhttp_encode_component(const char *input, char *output, size_t capacity);
static int xhttp_append_path_segment(char *path, size_t cap, const char *segment);
static int xhttp_append_query_param(char *path, size_t cap, const char *key, const char *value);
static int xhttp_append_header_line(char *headers, size_t cap, const char *key, const char *value);
static int xhttp_append_cookie_pair(char *cookies, size_t cap, const char *key, const char *value);
static const char *xhttp_meta_key(const char *placement, const char *configured, const char *header_default, const char *other_default);
static int xhttp_apply_meta_one(char *path, size_t path_cap, char *headers, size_t headers_cap, char *cookies, size_t cookies_cap,
                                const char *placement, const char *key, const char *value);
static int xhttp_apply_padding(tls13_conn_t *c, char *path, size_t path_cap, char *headers, size_t headers_cap, char *cookies,
                               size_t cookies_cap);
static int xhttp_conn_write_all(tls13_conn_t *c, const void *buf, size_t len);
static void *xhttp_plain_upload_reader(void *arg);
static int xhttp_start_plain_upload_reader(tls13_conn_t *c);
static int xhttp_send_plain_stream_request(tls13_conn_t *c, int fd, char *err, size_t err_cap);
static int xhttp_send_download_request(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);
static int xhttp_post_packet_plain(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap);

static int normalize_xhttp_path(const char *in, char *out, size_t out_cap) {
    return core_http_path(in,out,out_cap,1);
}

static int random_xpadding_value(int min_len, int max_len, const char *method, char *buf, size_t cap) {
    return core_xhttp_padding((core_range_t){min_len,max_len},method,buf,cap);
}

size_t find_double_crlf(const uint8_t *buf, size_t len) {
    if (len < 4) {
        return 0;
    }
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return 0;
}

void trim_ascii(char *s) {
    if (s == NULL) {
        return;
    }
    size_t n = strlen(s);
    size_t start = 0;
    while (start < n && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        start++;
    }
    size_t end = n;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }
    if (start > 0) {
        memmove(s, s + start, end - start);
    }
    s[end - start] = '\0';
}

static int xhttp_read_http1_response(SSL *ssl, int fd, const char *method, char *err, size_t err_cap) {
    core_http1_response_t parser={.head_response=!strcmp(method,"HEAD")}; dynbuf_t cache={.limit=73728}; int eof=0,result=-1;
    for (;;) {
        core_http1_event_t event;
        int parsed=core_http1_next(&parser,cache.data,cache.len,eof,8192,&event);
        if (parsed < 0) break;
        if (!parsed && event.kind == 1 && event.status >= 200 && event.status != 200) {
            if (err && err_cap) snprintf(err,err_cap,"XHTTP HTTP/1.1 response returned non-200: %d",event.status);
            db_free(&cache); return -1;
        }
        db_consume(&cache,event.consumed);
        if (!parsed && event.kind == 3) { if (!cache.len) result=0; break; }
        if (!parsed) continue;
        uint8_t input[4096]; size_t received=0;
        int read_result=ssl ? ssl_read_some(ssl,input,sizeof(input),&received) : fd_read_some(fd,input,sizeof(input),&received);
        if (read_result < 0 && (!ssl || !(SSL_get_shutdown(ssl)&SSL_RECEIVED_SHUTDOWN))) break;
        if (read_result > 0) {
            if (core_wait_socket(fd,POLLIN,-1) <= 0) break;
            continue;
        }
        if (!received) eof=1;
        else if (db_append(&cache,input,received)) break;
    }
    db_free(&cache);
    if (result) set_err(err,err_cap,"invalid or truncated XHTTP HTTP/1.1 response");
    return result;
}

static int xhttp_buffer_available(tls13_conn_t *c) {
    c->xhttp_net_cache.limit=73728;
    if (c->xhttp_wire_eof) return 0;
    uint8_t input[4096];
    if (c->tls_md) {
        int previous=c->relay_async; c->relay_async=1;
        size_t received=0; int result=manual_stream_read(c,input,sizeof(input),&received);
        c->relay_async=previous;
        if (result < 0) return -1;
        if (result > 0) return 0;
        if (received) return db_append(&c->xhttp_net_cache,input,received);
        c->xhttp_wire_eof=1; return 0;
    }
    if (c->ssl) {
        int flags=fcntl(c->fd,F_GETFL,0);
        if (flags < 0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return -1;
        ERR_clear_error();
        int received=SSL_read(c->ssl,input,sizeof(input));
        int error=received > 0 ? SSL_ERROR_NONE : SSL_get_error(c->ssl,received),saved=errno;
        if (fcntl(c->fd,F_SETFL,flags)) return -1;
        errno=saved;
        if (received > 0) return db_append(&c->xhttp_net_cache,input,(size_t)received);
        if (error == SSL_ERROR_ZERO_RETURN) { c->xhttp_wire_eof=1; return 0; }
        return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE || (error == SSL_ERROR_SYSCALL && saved == EINTR) ? 0 : -1;
    }
    int ready=core_wait_socket(c->fd,POLLIN,0);
    if (ready <= 0) return ready < 0 && errno != EINTR ? -1 : 0;
    ssize_t received=recv(c->fd,input,sizeof(input),MSG_DONTWAIT);
    if (received > 0) return db_append(&c->xhttp_net_cache,input,(size_t)received);
    if (!received) { c->xhttp_wire_eof=1; return 0; }
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
}

int xhttp_fill_app_cache(tls13_conn_t *c) {
    if (c->xhttp_eof) return -1;
    for (;;) {
        core_http1_event_t event;
        int result=core_http1_next(&c->xhttp_http1_response,c->xhttp_net_cache.data,c->xhttp_net_cache.len,c->xhttp_wire_eof,8192,&event);
        if (result < 0) { vc_log_error("xhttp","invalid or truncated XHTTP HTTP/1.1 response"); return -1; }
        if (!result && event.kind == 1 && event.status >= 200 && event.status != 200) {
            vc_log_error("xhttp","GET returned non-200: %d",event.status); return -1;
        }
        if (!result && event.kind == 2 && db_append(&c->app_cache,c->xhttp_net_cache.data+event.offset,event.length)) return -1;
        db_consume(&c->xhttp_net_cache,event.consumed);
        if (!result && event.kind == 3) {
            if (c->xhttp_net_cache.len) return -1;
            c->xhttp_eof=1; return -1;
        }
        if (c->app_cache.len) return 0;
        if (!result) continue;
        size_t before=c->xhttp_net_cache.len;
        int previous_eof=c->xhttp_wire_eof;
        if (xhttp_buffer_available(c)) return -1;
        if (before == c->xhttp_net_cache.len && previous_eof == c->xhttp_wire_eof) return 1;
    }
}

static int xhttp_encode_component(const char *input, char *output, size_t capacity) {
    size_t used=0; const char *hex="0123456789ABCDEF";
    for (const unsigned char *cursor=(const unsigned char *)input;*cursor;cursor++) {
        unsigned char ch=*cursor;
        int plain=(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~';
        size_t need=plain ? 1 : 3;
        if (used+need >= capacity) return -1;
        if (plain) output[used++]=(char)ch;
        else { output[used++]='%'; output[used++]=hex[ch>>4]; output[used++]=hex[ch&15]; }
    }
    if (used >= capacity) return -1;
    output[used]=0; return 0;
}

static int xhttp_append_path_segment(char *path, size_t cap, const char *segment) {
    if (path == NULL || segment == NULL || segment[0] == '\0') {
        return 0;
    }
    size_t len = strlen(path);
    if (len == 0) {
        if (cap < 2) {
            return -1;
        }
        path[0] = '/';
        path[1] = '\0';
        len = 1;
    }
    char encoded[1024];
    if (xhttp_encode_component(segment,encoded,sizeof(encoded)) != 0) return -1;
    const char *query=strchr(path,'?'); size_t path_length=query ? (size_t)(query-path) : len;
    size_t seg_len = strlen(encoded);
    int need_slash = (!path_length || path[path_length - 1] != '/');
    if (len + (need_slash ? 1U : 0U) + seg_len + 1U > cap) {
        return -1;
    }
    memmove(path+path_length+(size_t)need_slash+seg_len,path+path_length,len-path_length+1);
    if (need_slash) path[path_length++]='/';
    memcpy(path+path_length,encoded,seg_len);
    return 0;
}

static int xhttp_append_query_param(char *path, size_t cap, const char *key, const char *value) {
    if (path == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    size_t len=strlen(path);
    if (len >= cap) return -1;
    char encoded_key[256],encoded_value[27001];
    if (xhttp_encode_component(key,encoded_key,sizeof(encoded_key)) != 0 || xhttp_encode_component(value,encoded_value,sizeof(encoded_value)) != 0) return -1;
    char *request=malloc(cap); if (!request) return -1;
    const char *query=strchr(path,'?'); size_t used=query ? (size_t)(query-path) : len;
    memcpy(request,path,used); int has_query=0;
    for (const char *part=query ? query+1 : NULL;part && *part;) {
        const char *end=strchr(part,'&'); if (!end) end=path+len;
        const char *equals=memchr(part,'=',(size_t)(end-part)); size_t name_size=(size_t)((equals ? equals : end)-part);
        char raw[256],decoded[256]; int same=0;
        if (name_size < sizeof(raw)) {
            memcpy(raw,part,name_size); raw[name_size]=0;
            same=percent_decode(raw,decoded,sizeof(decoded)) == 0 && !strcmp(decoded,key);
        }
        if (!same && end > part) { request[used++]=has_query ? '&' : '?'; memcpy(request+used,part,(size_t)(end-part)); used+=(size_t)(end-part); has_query=1; }
        part=*end ? end+1 : NULL;
    }
    int written=snprintf(request+used,cap-used,"%c%s=%s",has_query ? '&' : '?',encoded_key,encoded_value);
    int result=written > 0 && (size_t)written < cap-used ? 0 : -1;
    if (!result) memcpy(path,request,used+(size_t)written+1);
    free(request); return result;
}

static int xhttp_append_header_line(char *headers, size_t cap, const char *key, const char *value) {
    if (headers == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    return core_http_header_set(headers,cap,key,value);
}

static int xhttp_append_cookie_pair(char *cookies, size_t cap, const char *key, const char *value) {
    if (cookies == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return 0;
    }
    if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL || strchr(value, '\r') != NULL || strchr(value, '\n') != NULL) {
        return -1;
    }
    size_t len = strlen(cookies);
    size_t avail = cap > len ? cap - len : 0;
    if (avail == 0) {
        return -1;
    }
    int n = snprintf(cookies + len, avail, "%s%s=%s", len > 0 ? "; " : "", key, value);
    return (n > 0 && (size_t)n < avail) ? 0 : -1;
}

static const char *xhttp_meta_key(const char *placement, const char *configured, const char *header_default, const char *other_default) {
    if (configured != NULL && configured[0] != '\0') {
        return configured;
    }
    if (placement != NULL && strcmp(placement, "header") == 0) {
        return header_default;
    }
    if (placement != NULL && (strcmp(placement, "query") == 0 || strcmp(placement, "cookie") == 0)) {
        return other_default;
    }
    return "";
}

static int xhttp_apply_meta_one(char *path, size_t path_cap, char *headers, size_t headers_cap, char *cookies, size_t cookies_cap,
                                const char *placement, const char *key, const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    if (placement == NULL || placement[0] == '\0' || strcmp(placement, "path") == 0) {
        return xhttp_append_path_segment(path, path_cap, value);
    }
    if (strcmp(placement, "query") == 0) {
        return xhttp_append_query_param(path, path_cap, key, value);
    }
    if (strcmp(placement, "header") == 0) {
        return xhttp_append_header_line(headers, headers_cap, key, value);
    }
    if (strcmp(placement, "cookie") == 0) {
        return xhttp_append_cookie_pair(cookies, cookies_cap, key, value);
    }
    return -1;
}

static int xhttp_apply_padding(tls13_conn_t *c, char *path, size_t path_cap, char *headers, size_t headers_cap, char *cookies,
                               size_t cookies_cap) {
    char padding[16384];
    if (random_xpadding_value(c->xhttp_padding_min, c->xhttp_padding_max, c->xhttp_padding_method, padding, sizeof(padding)) != 0) {
        return -1;
    }

    const char *placement = c->xhttp_padding_obfs ? c->xhttp_padding_placement : "queryinheader";
    const char *key = c->xhttp_padding_obfs && c->xhttp_padding_key[0] != '\0' ? c->xhttp_padding_key : "x_padding";
    const char *header = c->xhttp_padding_obfs && c->xhttp_padding_header[0] != '\0' ? c->xhttp_padding_header : "Referer";

    if (strcmp(placement, "header") == 0) {
        return xhttp_append_header_line(headers, headers_cap, header, padding);
    }
    if (strcmp(placement, "query") == 0) {
        return xhttp_append_query_param(path, path_cap, key, padding);
    }
    if (strcmp(placement, "cookie") == 0) {
        return xhttp_append_cookie_pair(cookies, cookies_cap, key, padding);
    }

    char bare_path[1024];
    snprintf(bare_path, sizeof(bare_path), "%s", path);
    char *q = strchr(bare_path, '?');
    if (q != NULL) {
        *q = '\0';
    }

    char referer[16384];
    const char *scheme = c->mode == CONN_MODE_XHTTP_PLAIN ? "http" : "https";
    int n = snprintf(referer, sizeof(referer), "%s://%s%s?%s=%s", scheme, c->xhttp_host, bare_path, key, padding);
    if (n <= 0 || (size_t)n >= sizeof(referer)) {
        return -1;
    }
    return xhttp_append_header_line(headers, headers_cap, header, referer);
}

int xhttp_prepare_request(tls13_conn_t *c, const char *seq_str, char *path, size_t path_cap, char *headers, size_t headers_cap) {
    char cookies[16384];
    cookies[0] = '\0';
    if (strlen(c->xhttp_headers) >= headers_cap) return -1;
    memcpy(headers,c->xhttp_headers,strlen(c->xhttp_headers)+1);
    snprintf(path, path_cap, "%s", c->xhttp_base_path);

    if (xhttp_apply_padding(c, path, path_cap, headers, headers_cap, cookies, sizeof(cookies)) != 0) {
        return -1;
    }

    const char *session_key = xhttp_meta_key(c->xhttp_session_placement, c->xhttp_session_key, "X-Session", "x_session");
    if (xhttp_apply_meta_one(path, path_cap, headers, headers_cap, cookies, sizeof(cookies), c->xhttp_session_placement, session_key,
                             c->xhttp_session_id) != 0) {
        return -1;
    }

    if (seq_str != NULL && seq_str[0] != '\0') {
        const char *seq_key = xhttp_meta_key(c->xhttp_seq_placement, c->xhttp_seq_key, "X-Seq", "x_seq");
        if (xhttp_apply_meta_one(path, path_cap, headers, headers_cap, cookies, sizeof(cookies), c->xhttp_seq_placement, seq_key, seq_str) !=
            0) {
            return -1;
        }
    }

    if (cookies[0] != '\0' && core_http_header_append_cookie(headers,headers_cap,cookies) != 0) {
        return -1;
    }
    return 0;
}

int xhttp_packet_headers(tls13_conn_t *connection, const char *sequence, const uint8_t *data, size_t length, uint32_t header_limit,
                                char path[2048], core_xhttp_payload_t *packet, char *error, size_t capacity) {
    char *prefix=connection->output_memory ? core_buffer_alloc(connection->output_memory,65537) : malloc(65537);
    if (!prefix) { set_err(error,capacity,"XHTTP metadata allocation failed"); return -1; }
    if (xhttp_prepare_request(connection,sequence,path,2048,prefix,65537) != 0) {
        if (connection->output_memory) core_buffer_free(connection->output_memory,prefix,65537); else free(prefix);
        set_err(error,capacity,"failed to build XHTTP packet metadata"); return -1;
    }
    size_t reserve=strlen(path)+strlen(connection->xhttp_host)+strlen(connection->xhttp_uplink_method)+5;
    reserve+=strlen(":method:scheme:authority:path")+4*32;
    reserve+=strlen("user-agent")+strlen(xhttp_user_agent)+32;
    reserve+=strlen("accept")+3+32+strlen("cache-control")+8+32+strlen("pragma")+8+32;
    reserve+=strlen("content-length")+20+32;
    size_t budget=header_limit > reserve ? (size_t)header_limit-reserve : 0;
    core_xhttp_payload_options_t options={.placement=connection->xhttp_uplink_data_placement,.key=connection->xhttp_uplink_data_key,.chunks=connection->xhttp_uplink_chunks,.memory=connection->output_memory};
    int result=core_xhttp_payload_build(&options,data,length,prefix,budget,packet,error,capacity);
    if (connection->output_memory) core_buffer_free(connection->output_memory,prefix,65537); else free(prefix);
    return result;
}

int xhttp_wait_post(tls13_conn_t *connection, char *error, size_t capacity) {
    uint64_t due,now=core_now_ms();
    if (core_xhttp_post_due(connection->xhttp_post_intervals,connection->xhttp_last_post_ms,now,&due) != 0) { set_err(error,capacity,"XHTTP packet interval sampling failed"); return -1; }
    while ((now=core_now_ms()) < due) {
        if ((core_deadline_active() && !core_deadline_remaining()) || core_poll(NULL,0,due-now > INT_MAX ? INT_MAX : (int)(due-now)) < 0) {
            set_err(error,capacity,"XHTTP packet interval wait failed"); return -1;
        }
    }
    connection->xhttp_last_post_ms=now; return 0;
}

static int xhttp_conn_write_all(tls13_conn_t *c, const void *buf, size_t len) {
    if (c->tls_md) return reality_write_app_records(c,buf,len);
    return c->ssl != NULL ? ssl_write_all(c->ssl, buf, len) : write_exact(c->fd, buf, len);
}

static void *xhttp_plain_upload_reader(void *arg) {
    tls13_conn_t *connection=arg; char error[160]={0};
    if (xhttp_read_http1_response(NULL,connection->xhttp_upload_fd,connection->xhttp_uplink_method,error,sizeof(error))) {
        pthread_mutex_lock(&g_tls_state_lock);
        int failed=!connection->xhttp_upload_stopping;
        if (failed) connection->xhttp_upload_failed=1;
        pthread_mutex_unlock(&g_tls_state_lock);
        if (failed) {
            vc_log_error("xhttp","upload response failed: %s",error);
            shutdown(connection->fd,SHUT_RDWR);
        }
    }
    return NULL;
}

static int xhttp_start_plain_upload_reader(tls13_conn_t *c) {
    if (pthread_create(&c->xhttp_upload_reader, NULL, xhttp_plain_upload_reader, c) != 0) {
        return -1;
    }
    c->xhttp_upload_reader_started = 1;
    return 0;
}

int xhttp_http1_headers(tls13_conn_t *connection, const char *method, const char *path, const char *source, int body_mode, size_t body_size,
                               const char *keep_alive, dynbuf_t *request) {
    char line[4096]; int size=snprintf(line,sizeof(line),"%s %s HTTP/1.1\r\nHost: %s\r\n",method,path,connection->xhttp_host);
    if (size < 0 || (size_t)size >= sizeof(line) || db_append(request,line,(size_t)size) != 0) return -1;
    size_t capacity=strlen(source)+1024;
    char *headers=request->memory ? core_buffer_alloc(request->memory,capacity) : malloc(capacity);
    if (!headers) return -1;
    memcpy(headers,source,strlen(source)+1); int result=0;
    if (!core_http_header_get(headers,"User-Agent",NULL)) result=core_http_header_set(headers,capacity,"User-Agent","vless-core/1.0");
    if (!result && !core_http_header_get(headers,"Accept",NULL)) result=core_http_header_set(headers,capacity,"Accept","*/*");
    if (!result && body_mode == 2 && !connection->xhttp_no_grpc_header) result=core_http_header_set(headers,capacity,"Content-Type","application/grpc");
    if (!result && (body_mode == 1 || body_mode == 3) && !core_http_header_get(headers,"Content-Type",NULL)) result=core_http_header_set(headers,capacity,"Content-Type","application/octet-stream");
    if (!result && (body_mode == 2 || body_mode == 3)) result=core_http_header_set(headers,capacity,"Transfer-Encoding","chunked");
    if (!result && body_mode == 1) { snprintf(line,sizeof(line),"%zu",body_size); result=core_http_header_set(headers,capacity,"Content-Length",line); }
    if (!result) result=core_http_header_set(headers,capacity,"Connection",keep_alive);
    if (!result) result=db_append(request,headers,strlen(headers));
    if (!result) result=db_append(request,"\r\n",2);
    if (request->memory) core_buffer_free(request->memory,headers,capacity); else free(headers);
    return result;
}

static int xhttp_send_plain_stream_request(tls13_conn_t *c, int fd, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp stream request");
        return -1;
    }

    dynbuf_t request={0};
    if (xhttp_http1_headers(c,c->xhttp_uplink_method,request_path,extra_headers,2,0,"close",&request) != 0) {
        db_free(&request);
        set_err(err, err_cap, "xhttp stream request too large");
        return -1;
    }
    int result=write_exact(fd,request.data,request.len); db_free(&request);
    if (result != 0) {
        set_err(err, err_cap, "failed to send xhttp stream request");
        return -1;
    }

    c->xhttp_http1_response=(core_http1_response_t){.head_response=!strcmp(c->xhttp_uplink_method,"HEAD")};
    c->xhttp_eof=c->xhttp_wire_eof=0;
    return 0;
}

int xhttp_write_plain_stream(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    int fd = strcmp(c->xhttp_transport_mode, "stream-one") == 0 ? c->fd : c->xhttp_upload_fd;
    if (fd < 0) {
        return -1;
    }

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 16384) {
            chunk = 16384;
        }
        char header[32];
        int header_len = snprintf(header, sizeof(header), "%zx\r\n", chunk);
        if (header_len <= 0 || (size_t)header_len >= sizeof(header) || write_exact(fd, header, (size_t)header_len) != 0 ||
            write_exact(fd, buf + off, chunk) != 0 || write_exact(fd, "\r\n", 2) != 0) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}

static int xhttp_send_download_request(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp GET");
        return -1;
    }

    dynbuf_t request={0};
    if ((!core_http_header_get(extra_headers,"Cache-Control",NULL) && core_http_header_set(extra_headers,sizeof(extra_headers),"Cache-Control","no-cache") != 0) ||
        xhttp_http1_headers(c,"GET",request_path,extra_headers,0,0,"keep-alive",&request) != 0) {
        db_free(&request);
        set_err(err, err_cap, "xhttp GET request too large");
        return -1;
    }

    int result=xhttp_conn_write_all(c,request.data,request.len); db_free(&request);
    if (result != 0) {
        set_err(err, err_cap, "failed to send xhttp GET");
        return -1;
    }

    c->xhttp_http1_response=(core_http1_response_t){0};
    c->xhttp_eof=c->xhttp_wire_eof=0;
    (void)cfg;
    return 0;
}

int xhttp_http1_packet_request(tls13_conn_t *connection, const char *path, const char *headers, size_t body_size, const char *keep_alive, dynbuf_t *request) {
    return xhttp_http1_headers(connection,connection->xhttp_uplink_method,path,headers,1,body_size,keep_alive,request);
}

static int xhttp_post_packet_plain(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap) {
    if (xhttp_wait_post(c,err,err_cap) != 0) return -1;
    int fd = tcp_connect_host(c->remote_host, c->remote_port, c->ip_source);
    if (fd < 0) {
        set_err(err, err_cap, "tcp connect failed");
        return -1;
    }

    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    core_xhttp_payload_t packet;
    if (xhttp_packet_headers(c,seq,buf,*length,8192,request_path,&packet,err,err_cap) != 0) {
        close(fd);
        return -1;
    }
    *length=packet.consumed;

    dynbuf_t request={0};
    if (xhttp_http1_packet_request(c,request_path,packet.headers,packet.body_size,"close",&request) != 0) {
        core_xhttp_payload_clear(&packet); db_free(&request);
        close(fd);
        set_err(err, err_cap, "xhttp POST request too large");
        return -1;
    }

    int rc = 0;
    if (write_exact(fd,request.data,request.len) != 0 || (packet.body_size && write_exact(fd,buf,packet.body_size) != 0)) {
        rc = -1;
        set_err(err, err_cap, "failed to send xhttp POST");
    } else {
        rc=xhttp_read_http1_response(NULL,fd,c->xhttp_uplink_method,err,err_cap);
    }

    core_xhttp_payload_clear(&packet); db_free(&request); close(fd);
    return rc;
}

int xhttp_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap) {
    if (c->mode == CONN_MODE_XHTTP_PLAIN) {
        return xhttp_post_packet_plain(c, buf, length, err, err_cap);
    }
    if (xhttp_wait_post(c,err,err_cap) != 0) return -1;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    tls_verify_mode_t mode = c->tls_verify_policy;
    if (mode == TLS_VERIFY_MODE_TOFU) {
        if (c->xhttp_pin_key[0] == '\0' &&
            xhttp_make_pin_key(c->remote_sni[0] != '\0' ? c->remote_sni : c->remote_host, c->remote_port, c->xhttp_pin_key,
                               sizeof(c->xhttp_pin_key)) != 0) {
            set_err(err, err_cap, "failed to build TOFU pin key");
            return -1;
        }
        if (open_tls_socket(c->ip_source, c->remote_host, c->remote_port, c->remote_sni, 0, NULL, 0, &ctx, &ssl, &fd, &c->tls_use_aes_fallback, err,
                            err_cap) != 0) {
            return -1;
        }
        if (xhttp_tofu_verify_or_store(ssl, c->xhttp_pin_key, 0, err, err_cap) != 0) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            return -1;
        }
        c->xhttp_tls_insecure = 1;
    } else {
        int verify_peer = c->xhttp_tls_insecure ? 0 : tls_verify_peer(mode);
        if (open_tls_socket(c->ip_source, c->remote_host, c->remote_port, c->remote_sni, verify_peer, NULL, 0, &ctx, &ssl, &fd,
                            &c->tls_use_aes_fallback, err, err_cap) != 0) {
            return -1;
        }
    }

    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    core_xhttp_payload_t packet;
    if (xhttp_packet_headers(c,seq,buf,*length,8192,request_path,&packet,err,err_cap) != 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }
    *length=packet.consumed;

    dynbuf_t request={0};
    if (xhttp_http1_packet_request(c,request_path,packet.headers,packet.body_size,"close",&request) != 0) {
        core_xhttp_payload_clear(&packet); db_free(&request);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        set_err(err, err_cap, "xhttp POST request too large");
        return -1;
    }

    int rc = 0;
    if (ssl_write_all(ssl,request.data,request.len) != 0 || (packet.body_size && ssl_write_all(ssl,buf,packet.body_size) != 0)) {
        rc = -1;
        set_err(err, err_cap, "failed to send xhttp POST");
    } else {
        rc=xhttp_read_http1_response(ssl,fd,c->xhttp_uplink_method,err,err_cap);
    }

    core_xhttp_payload_clear(&packet); db_free(&request);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return rc;
}

int xhttp_configure(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->xhttp_seq = 0;

    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);

    if (normalize_xhttp_path(cfg->xhttp_path, c->xhttp_base_path, sizeof(c->xhttp_base_path)) != 0) {
        set_err(err, err_cap, "invalid xhttp path");
        return -1;
    }

    const char *xhost = cfg->xhttp_host[0] != '\0' ? cfg->xhttp_host : c->remote_sni;
    if (http_host(xhost,c->xhttp_host,sizeof(c->xhttp_host))) { set_err(err,err_cap,"invalid xhttp host"); return -1; }
    snprintf(c->xhttp_transport_mode, sizeof(c->xhttp_transport_mode), "%s", cfg->xhttp_mode);
    snprintf(c->xhttp_session_placement, sizeof(c->xhttp_session_placement), "%s",
             cfg->xhttp_session_placement[0] != '\0' ? cfg->xhttp_session_placement : "path");
    snprintf(c->xhttp_session_key, sizeof(c->xhttp_session_key), "%s", cfg->xhttp_session_key);
    snprintf(c->xhttp_seq_placement, sizeof(c->xhttp_seq_placement), "%s",
             cfg->xhttp_seq_placement[0] != '\0' ? cfg->xhttp_seq_placement : "path");
    snprintf(c->xhttp_seq_key, sizeof(c->xhttp_seq_key), "%s", cfg->xhttp_seq_key);
    snprintf(c->xhttp_uplink_method, sizeof(c->xhttp_uplink_method), "%s",
             cfg->xhttp_uplink_method[0] != '\0' ? cfg->xhttp_uplink_method : "POST");
    memcpy(c->xhttp_headers,cfg->xhttp_headers,sizeof(c->xhttp_headers)); c->xhttp_no_grpc_header=cfg->xhttp_no_grpc_header;
    snprintf(c->xhttp_uplink_data_placement,sizeof(c->xhttp_uplink_data_placement),"%s",cfg->xhttp_uplink_data_placement[0] ? cfg->xhttp_uplink_data_placement : "body");
    snprintf(c->xhttp_uplink_data_key,sizeof(c->xhttp_uplink_data_key),"%s",cfg->xhttp_uplink_data_key);
    c->xhttp_uplink_chunks=(core_range_t){cfg->xhttp_uplink_chunk_min,cfg->xhttp_uplink_chunk_max};
    snprintf(c->xhttp_padding_placement, sizeof(c->xhttp_padding_placement), "%s",
             cfg->xhttp_padding_placement[0] != '\0' ? cfg->xhttp_padding_placement : "queryinheader");
    snprintf(c->xhttp_padding_key, sizeof(c->xhttp_padding_key), "%s",
             cfg->xhttp_padding_key[0] != '\0' ? cfg->xhttp_padding_key : "x_padding");
    snprintf(c->xhttp_padding_header, sizeof(c->xhttp_padding_header), "%s",
             cfg->xhttp_padding_header[0] != '\0' ? cfg->xhttp_padding_header : "X-Padding");
    snprintf(c->xhttp_padding_method, sizeof(c->xhttp_padding_method), "%s",
             cfg->xhttp_padding_method[0] != '\0' ? cfg->xhttp_padding_method : "repeat-x");
    c->xhttp_padding_obfs = cfg->xhttp_padding_obfs;
    c->xhttp_padding_min = cfg->xhttp_padding_max ? cfg->xhttp_padding_min : 100;
    c->xhttp_padding_max = cfg->xhttp_padding_max ? cfg->xhttp_padding_max : 1000;
    c->xhttp_max_each_post_bytes=core_xhttp_post_limit(cfg);
    c->xhttp_post_intervals=(core_range_t){cfg->xhttp_min_posts_interval_min,cfg->xhttp_min_posts_interval_max};
    if (c->xhttp_max_each_post_bytes < 0) { set_err(err,err_cap,"XHTTP packet size sampling failed"); return -1; }

    c->xhttp_session_id[0] = '\0';
    if (core_xhttp_session(cfg,c->xhttp_session_id,sizeof(c->xhttp_session_id)) != 0) {
        set_err(err, err_cap, "failed to create xhttp session id");
        return -1;
    }
    return 0;
}

int xhttp_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->xmux_physical = cfg->xhttp_physical_only;
    if (xhttp_configure(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_XHTTP_PLAIN;
        c->fd = tcp_connect_host(c->remote_host, c->remote_port, c->ip_source);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
        vc_log_info("xhttp", "plain mode=%s http=1.1 max_each_post=%d",
                    c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
        if (c->xmux_physical) return 0;
        if (strcmp(c->xhttp_transport_mode, "stream-one") == 0) {
            return xhttp_send_plain_stream_request(c, c->fd, err, err_cap);
        }
        if (xhttp_send_download_request(cfg, c, err, err_cap) != 0) {
            return -1;
        }
        if (strcmp(c->xhttp_transport_mode, "stream-up") == 0) {
            c->xhttp_upload_fd = tcp_connect_host(c->remote_host, c->remote_port, c->ip_source);
            if (c->xhttp_upload_fd < 0) {
                set_err(err, err_cap, "xhttp upload tcp connect failed");
                return -1;
            }
            if (xhttp_send_plain_stream_request(c, c->xhttp_upload_fd, err, err_cap) != 0) {
                return -1;
            }
            if (xhttp_start_plain_upload_reader(c) != 0) {
                set_err(err, err_cap, "failed to start xhttp upload stream");
                return -1;
            }
        }
        return 0;
    }

    if (strcmp(cfg->security, "reality") == 0) {
        c->mode = CONN_MODE_XHTTP_REALITY;
        if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
            return -1;
        }

        vc_log_info("xhttp", "reality mode=%s http=2", c->xhttp_transport_mode);
        if (xhttp_h2_start_mode(c, err, err_cap) != 0) {
            return -1;
        }
        return 0;
    }

    c->mode=CONN_MODE_XHTTP_TLS;
    if (connect_manual_tls(cfg,c,err,err_cap)) return -1;
    c->xhttp_tls_insecure=c->tls_verify_policy != TLS_VERIFY_MODE_STRICT;
    if (!strcmp(c->tls_selected_alpn,"h2")) {
        c->mode=CONN_MODE_XHTTP_REALITY;
        vc_log_info("xhttp","tls mode=%s http=2 max_each_post=%d",c->xhttp_transport_mode,c->xhttp_max_each_post_bytes);
        return xhttp_h2_start_mode(c,err,err_cap);
    }
    if (c->tls_selected_alpn[0] && strcmp(c->tls_selected_alpn,"http/1.1")) { set_err(err,err_cap,"XHTTP requires h2 or http/1.1 ALPN"); return -1; }

    if (!c->xmux_physical && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        set_err(err, err_cap, "xhttp stream-one and stream-up require HTTP/2");
        return -1;
    }
    vc_log_info("xhttp", "tls mode=%s http=1.1 max_each_post=%d",
                c->xhttp_transport_mode, c->xhttp_max_each_post_bytes);
    if (c->xmux_physical) return 0;
    if (xhttp_send_download_request(cfg, c, err, err_cap) != 0) {
        return -1;
    }
    return 0;
}
