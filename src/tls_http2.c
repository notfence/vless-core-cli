#include "tls_transport_internal.h"

static int h2_send_window_update(tls13_conn_t *c, uint32_t stream_id, uint32_t increment);
static h2_response_entry_t *h2_response_get(tls13_conn_t *c, uint32_t id, int create);
static void h2_response_remove(tls13_conn_t *c, uint32_t id);
static unsigned h2_response_active(const tls13_conn_t *c);
static int h2_note_recv_data(tls13_conn_t *c, h2_response_entry_t *entry, size_t payload_len, int delivered);
static int h2_wait_tls_input(tls13_conn_t *c, int want_write);
static int h2_read_exact(tls13_conn_t *c, uint8_t *buf, size_t len);
static int hpack_append_int(dynbuf_t *b, uint32_t value, uint8_t prefix_bits, uint8_t first);
static int hpack_append_string(dynbuf_t *b, const char *s);
static int hpack_append_indexed(dynbuf_t *b, uint32_t index);
static int hpack_append_literal_new_name(dynbuf_t *b, const char *name, const char *value);
static int h2_finish_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *block, size_t len, char *err, size_t err_cap);
static int h2_append_header_block(tls13_conn_t *c, const uint8_t *data, size_t len, char *err, size_t err_cap);
static int h2_process_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t payload_len, char *err,
                              size_t err_cap);
static int h2_add_send_window(int64_t *window, uint32_t increment);
static int h2_process_control_frame(tls13_conn_t *c, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload,
                                    size_t payload_len, char *err, size_t err_cap);
static int h2_send_client_preface(tls13_conn_t *c, char *err, size_t err_cap);
static size_t protobuf_varint_size(size_t value);
static size_t protobuf_write_varint(uint8_t *out, size_t value);
static int grpc_feed_data(tls13_conn_t *c, const uint8_t *data, size_t length);
static int h2_append_regular_header(dynbuf_t *block, const char *name, size_t name_len, const char *value, size_t value_len);
static int h2_append_http1_header_lines(dynbuf_t *block, const char *headers, int omit_content_type);
static int h2_send_xhttp_body(tls13_conn_t *c, uint32_t stream_id, const uint8_t *buf, size_t len, char *err, size_t err_cap);
static int xhttp_h2_begin(tls13_conn_t *c, char *err, size_t err_cap);
static int xhttp_h2_send_download_request(tls13_conn_t *c, char *err, size_t err_cap);
static int xhttp_h2_send_stream_one_request(tls13_conn_t *c, char *err, size_t err_cap);
static int h2_request_capacity(tls13_conn_t *c, char *err, size_t err_cap);
static int xhttp_h2_send_stream_up_request(tls13_conn_t *c, char *err, size_t err_cap);
static int grpc_path_escape(const char *src, char *dst, size_t cap, int keep_slash);
static int grpc_build_request_path(const char *service_name, int multi_mode, char *path, size_t cap);
static int grpc_h2_start(tls13_conn_t *c, char *err, size_t err_cap);
static int grpc_tls_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);

int h2_send_frame(tls13_conn_t *c, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t len) {
    if (len > 0xFFFFFFU) {
        return -1;
    }
    c->h2_send_buf.len = 0;
    if (db_reserve(&c->h2_send_buf, 9 + len) != 0) {
        return -1;
    }
    uint8_t *hdr = c->h2_send_buf.data;
    hdr[0] = (uint8_t)(len >> 16);
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)len;
    hdr[3] = type;
    hdr[4] = flags;
    stream_id &= 0x7FFFFFFFU;
    hdr[5] = (uint8_t)(stream_id >> 24);
    hdr[6] = (uint8_t)(stream_id >> 16);
    hdr[7] = (uint8_t)(stream_id >> 8);
    hdr[8] = (uint8_t)stream_id;
    if (len > 0) {
        memcpy(hdr + 9, payload, len);
    }
    c->h2_send_buf.len = 9 + len;

    if (c->xmux_async) {
        tls13_conn_t *owner = c->xmux_owner ? c->xmux_owner : c;
        if (c->h2_send_buf.len > 256U*1024U - owner->xmux_plain_output.len) return -1;
        int result=db_append(&owner->xmux_plain_output, c->h2_send_buf.data, c->h2_send_buf.len);
        if (!result) owner->xmux_enqueued+=c->h2_send_buf.len;
        return result;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
        if (ssl_write_all(c->ssl, c->h2_send_buf.data, c->h2_send_buf.len) != 0) {
            return -1;
        }
    } else if (c->mode == CONN_MODE_GRPC_PLAIN) {
        if (write_exact(c->fd, c->h2_send_buf.data, c->h2_send_buf.len) != 0) {
            return -1;
        }
    } else {
        if (reality_write_app_records(c, c->h2_send_buf.data, c->h2_send_buf.len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int h2_send_window_update(tls13_conn_t *c, uint32_t stream_id, uint32_t increment) {
    if (increment == 0 || increment > 0x7FFFFFFFU) {
        return -1;
    }
    uint8_t payload[4] = {
        (uint8_t)(increment >> 24),
        (uint8_t)(increment >> 16),
        (uint8_t)(increment >> 8),
        (uint8_t)increment,
    };
    return h2_send_frame(c, H2_FRAME_WINDOW_UPDATE, 0, stream_id, payload, sizeof(payload));
}

static h2_response_entry_t *h2_response_get(tls13_conn_t *c, uint32_t id, int create) {
    for (h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next) if (entry->id == id) return entry;
    if (!create) return NULL;
    if (c->h2_response_count >= 256) { errno=EAGAIN; return NULL; }
    h2_response_entry_t *entry=calloc(1,sizeof(*entry));
    if (!entry) return NULL;
    entry->id=id; entry->receive_window=H2_CLIENT_INITIAL_WINDOW;
    if (id == c->h2_stream_id) entry->response.headers=c->h2_headers_received;
    entry->next=c->h2_responses; c->h2_responses=entry; c->h2_response_count++;
    return entry;
}

static void h2_response_remove(tls13_conn_t *c, uint32_t id) {
    h2_response_entry_t **cursor=&c->h2_responses;
    while (*cursor) {
        if ((*cursor)->id == id) { h2_response_entry_t *entry=*cursor; *cursor=entry->next; c->h2_response_count--; free(entry); return; }
        cursor=&(*cursor)->next;
    }
}

void h2_response_clear(tls13_conn_t *c) {
    while (c->h2_responses) h2_response_remove(c,c->h2_responses->id);
}

static unsigned h2_response_active(const tls13_conn_t *c) {
    unsigned count=0;
    for (const h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next)
        if (!entry->response.ended || !entry->request_ended) count++;
    return count;
}

static int h2_stream_writable(tls13_conn_t *c, uint32_t id) {
    h2_response_entry_t *entry=h2_response_get(c,id,0);
    if (c->grpc_read_failed || (entry && entry->reset)) {
        core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_PROTOCOL,EPROTO)); errno=EPROTO; return 0;
    }
    return 1;
}

static int h2_note_recv_data(tls13_conn_t *c, h2_response_entry_t *entry, size_t payload_len, int delivered) {
    if (payload_len == 0) {
        return 0;
    }
    if ((int64_t)payload_len > c->h2_receive_window || (entry && (int64_t)payload_len > entry->receive_window)) return -1;
    if (!delivered) {
        if (h2_send_window_update(c,0,(uint32_t)payload_len) || (entry && !entry->response.ended && h2_send_window_update(c,entry->id,(uint32_t)payload_len))) return -1;
        return 0;
    }
    c->h2_receive_window-=(int64_t)payload_len;
    if (entry) entry->receive_window-=(int64_t)payload_len;
    if (payload_len > 0x7FFFFFFFU || c->h2_recv_conn_pending > 0x7FFFFFFFU - payload_len ||
        c->h2_recv_stream_pending > 0x7FFFFFFFU - payload_len) {
        return -1;
    }

    c->h2_recv_conn_pending += (uint32_t)payload_len;
    c->h2_recv_stream_pending += (uint32_t)payload_len;
    if (c->h2_recv_conn_pending < H2_WINDOW_UPDATE_THRESHOLD && c->h2_recv_stream_pending < H2_WINDOW_UPDATE_THRESHOLD) {
        return 0;
    }

    uint32_t conn_inc = c->h2_recv_conn_pending;
    uint32_t stream_inc = c->h2_recv_stream_pending;
    c->h2_recv_conn_pending = 0;
    c->h2_recv_stream_pending = 0;
    c->h2_receive_window+=conn_inc;
    if (entry) entry->receive_window+=stream_inc;
    if (h2_send_window_update(c, 0, conn_inc) != 0 || h2_send_window_update(c, c->h2_stream_id, stream_inc) != 0) {
        return -1;
    }
    return 0;
}

int h2_collect_tls_available(tls13_conn_t *c, int *want_write) {
    if (c == NULL || c->ssl == NULL) {
        return -1;
    }
    if (want_write != NULL) {
        *want_write = 0;
    }

    int fd = SSL_get_fd(c->ssl);
    if (fd < 0) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }

    int result = 0;
    uint8_t buf[16384];
    for (int reads = 0; reads < 64; reads++) {
        ERR_clear_error();
        int n = SSL_read(c->ssl, buf, sizeof(buf));
        if (n > 0) {
            if (db_append(&c->h2_net_cache, buf, (size_t)n) != 0) {
                result = -1;
                break;
            }
            result = 1;
            if (h2_cached_frame_ready(c)) {
                break;
            }
            continue;
        }

        int ssl_error = SSL_get_error(c->ssl, n);
        if (ssl_error == SSL_ERROR_WANT_READ) {
            break;
        }
        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            if (want_write != NULL) {
                *want_write = 1;
            }
            break;
        }
        if (result > 0 &&
            (ssl_error == SSL_ERROR_ZERO_RETURN ||
             (ssl_error == SSL_ERROR_SYSCALL && n == 0))) {
            break;
        }
        result = -1;
        break;
    }

    int saved_errno = errno;
    if (fcntl(fd, F_SETFL, flags) != 0) {
        result = -1;
    }
    errno = saved_errno;
    return result;
}

static int h2_wait_tls_input(tls13_conn_t *c, int want_write) {
    int rc = core_wait_socket(c->fd, want_write ? POLLOUT : POLLIN, -1);
    return rc > 0 ? 0 : -1;
}

static int h2_read_exact(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (c->h2_net_cache.len > 0) {
            size_t take = c->h2_net_cache.len;
            if (take > len - off) {
                take = len - off;
            }
            memcpy(buf + off, c->h2_net_cache.data, take);
            db_consume(&c->h2_net_cache, take);
            off += take;
            continue;
        }

        if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
            int want_write = 0;
            int collected = h2_collect_tls_available(c, &want_write);
            if (collected < 0) {
                return -1;
            }
            if (c->h2_net_cache.len == 0 &&
                h2_wait_tls_input(c, want_write) != 0) {
                return -1;
            }
        } else if (c->mode == CONN_MODE_GRPC_PLAIN) {
            if (read_exact(c->fd, buf + off, len - off) != 0) {
                return -1;
            }
            off = len;
        } else {
            if (fill_reality_plain_cache(c, &c->h2_net_cache) != 0) {
                return -1;
            }
            if (c->h2_net_cache.len == 0) {
                return -1;
            }
        }
    }
    return 0;
}

int h2_read_frame(tls13_conn_t *c, uint8_t *type, uint8_t *flags, uint32_t *stream_id, uint8_t **payload, size_t *payload_len) {
    *payload=NULL; *payload_len=0;
    uint8_t hdr[9];
    if (h2_read_exact(c, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    size_t len = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | (size_t)hdr[2];
    if (len > H2_DEFAULT_MAX_FRAME) {
        return -1;
    }

    uint8_t *body = NULL;
    if (len > 0) {
        body = (uint8_t *)malloc(len);
        if (body == NULL) {
            return -1;
        }
        if (h2_read_exact(c, body, len) != 0) {
            free(body);
            return -1;
        }
    }

    *type = hdr[3];
    *flags = hdr[4];
    *stream_id = (((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8]) & 0x7FFFFFFFU;
    if (!c->xmux_async) {
        int validation=core_http2_validate_frame(&c->h2_validation,*type,*flags,*stream_id,body,len);
        if (validation == -1) { free(body); vc_log_error("h2","invalid h2 frame sequence"); return -1; }
        if (validation == -2) {
            uint32_t code=c->h2_validation.error.code;
            const uint8_t reset[]={(uint8_t)(code>>24),(uint8_t)(code>>16),(uint8_t)(code>>8),(uint8_t)code};
            if (h2_send_frame(c,H2_FRAME_RST_STREAM,0,*stream_id,reset,sizeof(reset))) { free(body); return -1; }
            h2_response_entry_t *entry=h2_response_get(c,*stream_id,0);
            if (entry) { entry->reset=1; entry->response.ended=1; if (entry->request_ended) h2_response_remove(c,*stream_id); }
            if (*stream_id == c->h2_stream_id) {
                c->grpc_read_failed=1; core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_PROTOCOL,EPROTO));
            }
            if (*type != H2_FRAME_HEADERS) { free(body); body=NULL; len=0; *type=UINT8_MAX; *flags=0; *stream_id=0; }
        }
    }
    if (!c->xmux_async && (*type == 0 || *type == 1 || *type == 3 || *type == 8) && *stream_id &&
        (!(*stream_id&1) || (*stream_id != c->h2_stream_id && *stream_id != c->h2_upload_stream_id && *stream_id >= c->h2_next_stream_id))) {
        free(body); vc_log_error("h2","h2 frame on idle stream"); return -1;
    }
    *payload = body;
    *payload_len = len;
    return 0;
}

static int hpack_append_int(dynbuf_t *b, uint32_t value, uint8_t prefix_bits, uint8_t first) {
    uint8_t max_first = (uint8_t)((1U << prefix_bits) - 1U);
    if (value < max_first) {
        uint8_t ch = first | (uint8_t)value;
        return db_append(b, &ch, 1);
    }

    uint8_t ch = first | max_first;
    if (db_append(b, &ch, 1) != 0) {
        return -1;
    }
    value -= max_first;
    while (value >= 128) {
        ch = (uint8_t)((value & 0x7F) | 0x80);
        if (db_append(b, &ch, 1) != 0) {
            return -1;
        }
        value >>= 7;
    }
    ch = (uint8_t)value;
    return db_append(b, &ch, 1);
}

static int hpack_append_string(dynbuf_t *b, const char *s) {
    size_t len = strlen(s);
    if (len > 0x7FFFFFFFU) {
        return -1;
    }
    if (hpack_append_int(b, (uint32_t)len, 7, 0x00) != 0) {
        return -1;
    }
    return db_append(b, s, len);
}

static int hpack_append_indexed(dynbuf_t *b, uint32_t index) {
    return hpack_append_int(b, index, 7, 0x80);
}

static int hpack_append_literal_new_name(dynbuf_t *b, const char *name, const char *value) {
    uint8_t literal = 0x00;
    if (db_append(b, &literal, 1) != 0) {
        return -1;
    }
    if (hpack_append_string(b, name) != 0 || hpack_append_string(b, value) != 0) {
        return -1;
    }
    return 0;
}

static int h2_finish_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *block, size_t len, char *err, size_t err_cap) {
    core_hpack_headers_t headers;
    int decoded=core_hpack_decode(&c->hpack,block,len,&headers);
    if (decoded == -1) { core_trace_failure(CORE_TRACE_TRANSPORT); set_err(err,err_cap,"invalid h2 header block"); return -1; }
    h2_response_entry_t *entry=h2_response_get(c,stream_id,stream_id == c->h2_stream_id);
    if (!entry) {
        if (!(stream_id&1) || (stream_id != c->h2_stream_id && stream_id >= c->h2_next_stream_id)) {
            set_err(err,err_cap,"h2 response on idle stream"); return -1;
        }
        return 0;
    }
    int initial=!entry->response.headers;
    if (entry->reset) return 0;
    if (decoded || core_http2_response_headers(&entry->response,&headers,flags&H2_FLAG_END_STREAM)) {
        core_trace_failure(CORE_TRACE_TRANSPORT); set_err(err,err_cap,"invalid h2 response headers"); return -1;
    }
    int status=headers.status;
    if (status >= 100 && status < 200) return 0;
    if (c->grpc_transport && core_grpc_response_headers(&headers,initial,flags&H2_FLAG_END_STREAM,err,err_cap)) {
        core_trace_failure(CORE_TRACE_TRANSPORT); return -1;
    }
    if (status && status != 200) {
        core_trace_failure(CORE_TRACE_TRANSPORT);
        if (err && err_cap) snprintf(err,err_cap,"%s h2 stream %u returned non-200: %d",c->grpc_transport ? "grpc" : "xhttp",stream_id,status);
        return -1;
    }
    if (stream_id == c->h2_stream_id) c->h2_headers_received=entry->response.headers;
    if (entry->response.ended) {
        if (stream_id == c->h2_stream_id) c->h2_stream_eof=1;
        else if (entry->request_ended) h2_response_remove(c,stream_id);
    }
    return 0;
}

static int h2_append_header_block(tls13_conn_t *c, const uint8_t *data, size_t len, char *err, size_t err_cap) {
    if (c->h2_header_block.len > H2_MAX_INBOUND_FRAME || len > H2_MAX_INBOUND_FRAME - c->h2_header_block.len) {
        set_err(err, err_cap, "h2 header block too large");
        return -1;
    }
    if (db_append(&c->h2_header_block, data, len) != 0) {
        set_err(err, err_cap, "failed to buffer h2 headers");
        return -1;
    }
    return 0;
}

static int h2_process_headers(tls13_conn_t *c, uint8_t flags, uint32_t stream_id, const uint8_t *payload, size_t payload_len, char *err,
                              size_t err_cap) {
    if (stream_id == 0 || c->h2_header_stream_id != 0) {
        set_err(err, err_cap, "invalid h2 headers stream");
        return -1;
    }
    size_t off = 0;
    if ((flags & H2_FLAG_PADDED) != 0) {
        if (payload_len == 0) {
            set_err(err, err_cap, "invalid h2 padded headers");
            return -1;
        }
        uint8_t pad = payload[off++];
        if ((size_t)pad > payload_len - off) {
            set_err(err, err_cap, "invalid h2 headers padding");
            return -1;
        }
        payload_len -= (size_t)pad;
    }
    if ((flags & H2_FLAG_PRIORITY) != 0) {
        if (payload_len - off < 5) {
            set_err(err, err_cap, "invalid h2 priority headers");
            return -1;
        }
        off += 5;
    }
    if (off > payload_len) {
        set_err(err, err_cap, "invalid h2 headers");
        return -1;
    }

    const uint8_t *block = off != 0 ? payload + off : payload;
    if ((flags & H2_FLAG_END_HEADERS) != 0) {
        return h2_finish_headers(c, flags, stream_id, block, payload_len - off, err, err_cap);
    }
    if (h2_append_header_block(c, block, payload_len - off, err, err_cap) != 0) {
        return -1;
    }
    c->h2_header_stream_id = stream_id;
    c->h2_header_flags = flags & H2_FLAG_END_STREAM;
    return 0;
}

static int h2_add_send_window(int64_t *window, uint32_t increment) {
    if (window == NULL || increment == 0 || *window > 0x7FFFFFFFLL - (int64_t)increment) {
        return -1;
    }
    *window += (int64_t)increment;
    return 0;
}

static int h2_process_control_frame(tls13_conn_t *c, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload,
                                    size_t payload_len, char *err, size_t err_cap) {
    if (c->h2_header_stream_id != 0 && type != H2_FRAME_CONTINUATION) {
        set_err(err, err_cap, "interleaved h2 header block");
        return -1;
    }
    switch (type) {
    case H2_FRAME_SETTINGS:
        if ((flags & H2_FLAG_ACK) != 0) {
            return 0;
        }
        if (payload_len % 6 != 0) {
            set_err(err, err_cap, "invalid h2 settings");
            return -1;
        }
        for (size_t off = 0; off + 6 <= payload_len; off += 6) {
            uint16_t id = ((uint16_t)payload[off] << 8) | (uint16_t)payload[off + 1];
            uint32_t val = ((uint32_t)payload[off + 2] << 24) | ((uint32_t)payload[off + 3] << 16) | ((uint32_t)payload[off + 4] << 8) |
                           (uint32_t)payload[off + 5];
            if (id == 3) c->h2_peer_concurrency=val;
            else if (id == 4) {
                if (val > 0x7FFFFFFFU) {
                    set_err(err, err_cap, "invalid h2 initial window");
                    return -1;
                }
                int64_t delta = (int64_t)val - (int64_t)c->h2_peer_initial_window;
                if (c->h2_peer_stream_window+delta > INT_MAX || (c->h2_upload_stream_id && c->h2_upload_stream_window+delta > INT_MAX)) return -1;
                c->h2_peer_initial_window = val;
                c->h2_peer_stream_window += delta;
                if (c->h2_upload_stream_id != 0) {
                    c->h2_upload_stream_window += delta;
                }
            } else if (id == 6) c->h2_peer_header_list_size=val;
            else if (id == 5 && val >= 16384 && val <= 16777215) {
                c->h2_peer_max_frame_size = val;
            }
        }
        return h2_send_frame(c, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, NULL, 0);
    case H2_FRAME_WINDOW_UPDATE:
        if (payload_len != 4) {
            set_err(err, err_cap, "invalid h2 window update");
            return -1;
        }
        {
            uint32_t inc = (((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) | ((uint32_t)payload[2] << 8) | (uint32_t)payload[3]) &
                           0x7FFFFFFFU;
            if (inc == 0) {
                set_err(err, err_cap, "invalid h2 window increment");
                return -1;
            }
            if (stream_id == 0) {
                if (h2_add_send_window(&c->h2_peer_conn_window, inc) != 0) {
                    set_err(err, err_cap, "h2 connection window overflow");
                    return -1;
                }
            } else if (stream_id == c->h2_stream_id) {
                if (h2_add_send_window(&c->h2_peer_stream_window, inc) != 0) {
                    set_err(err, err_cap, "h2 stream window overflow");
                    return -1;
                }
            } else if (stream_id == c->h2_upload_stream_id) {
                if (h2_add_send_window(&c->h2_upload_stream_window, inc) != 0) {
                    set_err(err, err_cap, "h2 upload window overflow");
                    return -1;
                }
            }
        }
        return 0;
    case H2_FRAME_PING:
        if ((flags & H2_FLAG_ACK) == 0 && payload_len == 8) {
            return h2_send_frame(c, H2_FRAME_PING, H2_FLAG_ACK, 0, payload, payload_len);
        }
        return 0;
    case H2_FRAME_HEADERS:
        return h2_process_headers(c, flags, stream_id, payload, payload_len, err, err_cap);
    case H2_FRAME_CONTINUATION:
        if (c->h2_header_stream_id == 0 || stream_id != c->h2_header_stream_id) {
            set_err(err, err_cap, "invalid h2 continuation stream");
            return -1;
        }
        if (h2_append_header_block(c, payload, payload_len, err, err_cap) != 0) {
            return -1;
        }
        if ((flags & H2_FLAG_END_HEADERS) != 0) {
            int rc = h2_finish_headers(c, c->h2_header_flags, stream_id, c->h2_header_block.data, c->h2_header_block.len, err, err_cap);
            c->h2_header_stream_id = 0;
            c->h2_header_flags = 0;
            c->h2_header_block.len = 0;
            return rc;
        }
        return 0;
    case H2_FRAME_RST_STREAM:
        if (stream_id == 0 || payload_len != 4) {
            set_err(err, err_cap, "invalid h2 stream reset");
            return -1;
        }
        {
            if (stream_id != c->h2_stream_id && !h2_response_get(c,stream_id,0)) return 0;
            uint32_t code = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                            ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];
            if (code == 0 && stream_id == c->h2_stream_id && c->h2_stream_eof) {
                c->h2_request_cancelled = 1;
                vc_log_debug(c->grpc_transport ? "grpc" : "xhttp", "h2 request closed after response fd=%d stream=%u", c->fd, (unsigned)stream_id);
                return 0;
            }
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "h2 stream reset fd=%d stream=%u code=%u response_complete=%d",
                         c->fd, (unsigned)stream_id, (unsigned)code, c->h2_stream_eof);
            }
        }
        return -1;
    case H2_FRAME_GOAWAY:
        if (stream_id || payload_len < 8) { set_err(err,err_cap,"invalid h2 goaway"); return -1; }
        {
            uint32_t last=(((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)|((uint32_t)payload[2]<<8)|payload[3])&0x7fffffffU;
            uint32_t code=((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|((uint32_t)payload[6]<<8)|payload[7];
            c->h2_goaway=1;
            if (code || c->h2_stream_id > last) { set_err(err,err_cap,"h2 goaway rejected stream"); return -1; }
            for (h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next)
                if (!entry->response.ended && entry->id > last) { set_err(err,err_cap,"h2 goaway rejected stream"); return -1; }
            return 0;
        }
    default:
        return 0;
    }
}

static int h2_send_client_preface(tls13_conn_t *c, char *err, size_t err_cap) {
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    int preface_rc = 0;
    if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
        preface_rc = ssl_write_all(c->ssl, preface, sizeof(preface) - 1);
    } else if (c->mode == CONN_MODE_GRPC_PLAIN) {
        preface_rc = write_exact(c->fd, preface, sizeof(preface) - 1);
    } else {
        preface_rc = reality_write_app_records(c, (const uint8_t *)preface, sizeof(preface) - 1);
    }
    if (preface_rc != 0) {
        set_err(err, err_cap, "failed to send h2 preface");
        return -1;
    }

    uint32_t initial_window = c->grpc_physical_only ? c->grpc_initial_window : c->xmux_physical ? CORE_HTTP2_STREAM_LIMIT : H2_CLIENT_INITIAL_WINDOW;
    uint8_t settings[24] = {
        0x00,
        0x04,
        (uint8_t)(initial_window >> 24),
        (uint8_t)(initial_window >> 16),
        (uint8_t)(initial_window >> 8),
        (uint8_t)initial_window,
        0,1,0,0,0x10,0,
        0,6,0,1,0,0,
        0,2,0,0,0,0,
    };
    if (h2_send_frame(c, H2_FRAME_SETTINGS, 0, 0, settings, sizeof(settings)) != 0 ||
        (!c->xmux_physical && !c->grpc_physical_only && h2_send_window_update(c, 0, H2_CONNECTION_WINDOW_INC) != 0)) {
        set_err(err, err_cap, "failed to send h2 settings");
        return -1;
    }
    c->h2_validation.settings_pending=1;
    return 0;
}

int h2_write_data(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    int stream_up = strcmp(c->xhttp_transport_mode, "stream-up") == 0;
    uint32_t stream_id = stream_up ? c->h2_upload_stream_id : c->h2_stream_id;
    int64_t *stream_window = stream_up ? &c->h2_upload_stream_window : &c->h2_peer_stream_window;
    if (!h2_stream_writable(c,stream_id)) return -1;
    if (stream_id == 0) {
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        if (!h2_stream_writable(c,stream_id)) return -1;
        if (!stream_up && c->h2_request_cancelled) return 0;
        if (c->grpc_transport && tls13_drain_h2_input(c) < 0) {
            return -1;
        }
        while (c->h2_peer_conn_window <= 0 || *stream_window <= 0) {
            if (!stream_up && c->h2_request_cancelled) return 0;
            if (h2_pump_one_frame(c) != 0) {
                vc_log_error(c->grpc_transport ? "grpc" : "xhttp", "failed while waiting for h2 upload window");
                return -1;
            }
            if (!h2_stream_writable(c,stream_id)) return -1;
        }
        if (!h2_stream_writable(c,stream_id)) return -1;
        if (!stream_up && c->h2_request_cancelled) return 0;
        size_t chunk = len - off;
        if (chunk > c->h2_peer_max_frame_size) {
            chunk = c->h2_peer_max_frame_size;
        }
        if ((int64_t)chunk > c->h2_peer_conn_window) {
            chunk = (size_t)c->h2_peer_conn_window;
        }
        if ((int64_t)chunk > *stream_window) {
            chunk = (size_t)*stream_window;
        }
        if (chunk == 0 || h2_send_frame(c, H2_FRAME_DATA, 0, stream_id, buf + off, chunk) != 0) {
            return -1;
        }
        c->h2_peer_conn_window -= (int64_t)chunk;
        *stream_window -= (int64_t)chunk;
        off += chunk;
    }
    return 0;
}

static size_t protobuf_varint_size(size_t value) {
    size_t n = 1;
    while (value >= 0x80) {
        value >>= 7;
        n++;
    }
    return n;
}

static size_t protobuf_write_varint(uint8_t *out, size_t value) {
    size_t n = 0;
    do {
        uint8_t ch = (uint8_t)(value & 0x7f);
        value >>= 7;
        if (value != 0) {
            ch |= 0x80;
        }
        out[n++] = ch;
    } while (value != 0);
    return n;
}

int grpc_fill_app_cache(tls13_conn_t *c) {
    while (!c->app_cache.len) {
        if (core_grpc_pending(&c->grpc_decoder)) {
            uint8_t output[8192]; size_t length=0;
            if (core_grpc_read(&c->grpc_decoder,output,sizeof(output),&length) || (length && db_append(&c->app_cache,output,length))) return -1;
            if (length) return 0;
        }
        if (c->grpc_read_failed) return -1;
        if (!c->grpc_net_cache.len) return 1;
        size_t consumed=0,payload_length=0; const uint8_t *payload=NULL;
        int result=core_grpc_decode(&c->grpc_decoder,c->grpc_net_cache.data,c->grpc_net_cache.len,&consumed,&payload,&payload_length);
        if (result < 0 || (!consumed && !core_grpc_pending(&c->grpc_decoder)) || (payload_length && db_append(&c->app_cache,payload,payload_length))) {
            vc_log_error("grpc",c->grpc_decoder.failed == 2 ? "gRPC message buffering budget exhausted" : c->grpc_decoder.failed == 3 ? "gRPC message buffer allocation failed" : "invalid gRPC protobuf message");
            c->grpc_read_failed=1; return -1;
        }
        db_consume(&c->grpc_net_cache,consumed);
    }
    return 0;
}

static int grpc_feed_data(tls13_conn_t *c, const uint8_t *data, size_t length) {
    c->grpc_net_cache.limit=32768;
    if (db_append(&c->grpc_net_cache,data,length)) return -1;
    return grpc_fill_app_cache(c) < 0 ? -1 : 0;
}

int grpc_pool_read(tls13_conn_t *c, uint8_t *buffer, size_t capacity, size_t *length) {
    *length=0;
    if (!capacity) return 0;
    if (!c->app_cache.len) {
        int pending=grpc_fill_app_cache(c);
        if (pending < 0) return -1;
        if (pending) {
            uint8_t input[8192]; size_t received=0;
            int result=core_http2_read(c->xmux_stream,input,sizeof(input),&received);
            if (result < 0) return -1;
            if (result > 0) return result;
            if (!received) return core_grpc_complete(&c->grpc_decoder) && !c->grpc_net_cache.len ? 0 : -1;
            if (grpc_feed_data(c,input,received)) { c->grpc_read_failed=1; if (!c->app_cache.len) return -1; }
            if (!c->app_cache.len) return 1;
        }
    }
    size_t take=c->app_cache.len < capacity ? c->app_cache.len : capacity;
    memcpy(buffer,c->app_cache.data,take); db_consume(&c->app_cache,take);
    *length=take; return 0;
}

int grpc_write_hunk(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    size_t varint_len = protobuf_varint_size(len);
    if (len > UINT32_MAX - 1U - varint_len) {
        return -1;
    }
    size_t msg_len = 1U + varint_len + len;
    size_t frame_len = 5U + msg_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (frame == NULL) {
        return -1;
    }

    frame[0] = 0;
    frame[1] = (uint8_t)(msg_len >> 24);
    frame[2] = (uint8_t)(msg_len >> 16);
    frame[3] = (uint8_t)(msg_len >> 8);
    frame[4] = (uint8_t)msg_len;
    frame[5] = 0x0a;
    size_t written = protobuf_write_varint(frame + 6, len);
    memcpy(frame + 6 + written, buf, len);

    int rc = c->xmux_stream ? core_http2_write(c->xmux_stream,frame,frame_len) : h2_write_data(c, frame, frame_len);
    free(frame);
    return rc;
}

int h2_pump_one_frame(tls13_conn_t *c) {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    char err[160] = {0};

    if (h2_read_frame(c, &type, &flags, &stream_id, &payload, &payload_len) != 0) {
        free(payload);
        return -1;
    }

    int rc = 0;
    if (type == H2_FRAME_DATA && c->h2_header_stream_id == 0) {
        h2_response_entry_t *entry=h2_response_get(c,stream_id,stream_id == c->h2_stream_id);
        if (!stream_id || !(stream_id&1) || (!entry && stream_id >= c->h2_next_stream_id)) { free(payload); return -1; }
        if (entry && entry->reset) { int result=h2_note_recv_data(c,NULL,payload_len,0); free(payload); return result; }
        size_t off = 0;
        size_t data_len = payload_len;
        if ((flags & H2_FLAG_PADDED) != 0) {
            if (payload_len == 0) {
                rc = -1;
            } else {
                uint8_t pad = payload[0];
                off = 1;
                if ((size_t)pad > payload_len - off) {
                    rc = -1;
                } else {
                    data_len = payload_len - off - (size_t)pad;
                }
            }
        }

        if (rc == 0 && entry && core_http2_response_data(&entry->response,data_len,flags&H2_FLAG_END_STREAM)) rc=-1;
        int delivered=stream_id == c->h2_stream_id;
        if (rc == 0 && h2_note_recv_data(c, entry, payload_len, delivered) != 0) {
            rc = -1;
        }
        if (rc == 0 && delivered && data_len > 0) {
            if (c->grpc_transport) {
                rc = grpc_feed_data(c, payload + off, data_len);
            } else if (db_append(&c->app_cache, payload + off, data_len) != 0) {
                rc = -1;
            }
        }
        if (rc == 0 && (flags & H2_FLAG_END_STREAM) != 0) {
            if (c->grpc_transport) { vc_log_error("grpc","gRPC DATA ended without grpc-status"); rc=-1; }
            else if (delivered) c->h2_stream_eof=1;
            else if (entry && entry->request_ended) h2_response_remove(c,stream_id);
        }
    } else {
        rc = h2_process_control_frame(c, type, flags, stream_id, payload, payload_len, err, sizeof(err));
        if (rc != 0) core_trace_failure(CORE_TRACE_TRANSPORT);
        if (rc != 0 && err[0] != '\0') {
            vc_log_error(c->grpc_transport ? "grpc" : "xhttp", "%s", err);
        }
    }

    free(payload);
    if (rc && c->grpc_transport) c->grpc_read_failed=1;
    return rc;
}

int h2_fill_app_cache(tls13_conn_t *c) {
    if (c->grpc_transport) {
        int result=grpc_fill_app_cache(c);
        if (result <= 0) return result;
    }
    if (c->grpc_read_failed) return -1;
    if (c->h2_stream_eof) {
        return -1;
    }
    if (h2_pump_one_frame(c) != 0) {
        return c->grpc_transport && c->app_cache.len ? 0 : -1;
    }
    if (c->app_cache.len > 0) {
        return 0;
    }
    if (c->h2_stream_eof) {
        return -1;
    }
    return 1;
}

static int h2_append_regular_header(dynbuf_t *block, const char *name, size_t name_len, const char *value, size_t value_len) {
    if (name == NULL || value == NULL || name_len == 0) {
        return 0;
    }
    if (name_len >= 128 || value_len > 65536) {
        return -1;
    }

    char lname[128];
    for (size_t i = 0; i < name_len; i++) {
        unsigned char ch = (unsigned char)name[i];
        if (ch == '\r' || ch == '\n' || ch == ':' || ch == '\0') {
            return -1;
        }
        lname[i] = (char)tolower(ch);
    }
    lname[name_len] = '\0';

    while (value_len > 0 && (*value == ' ' || *value == '\t')) {
        value++;
        value_len--;
    }
    while (value_len > 0 && (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
        value_len--;
    }
    if (strcmp(lname, "connection") == 0 || strcmp(lname, "keep-alive") == 0 || strcmp(lname, "proxy-connection") == 0 ||
        strcmp(lname, "transfer-encoding") == 0 || strcmp(lname, "upgrade") == 0) {
        return 0;
    }
    char *text=block->memory ? core_buffer_alloc(block->memory,value_len+1) : malloc(value_len+1);
    if (!text) return -1;
    memcpy(text,value,value_len); text[value_len]=0;
    int result=hpack_append_literal_new_name(block,lname,text);
    if (block->memory) core_buffer_free(block->memory,text,value_len+1); else free(text);
    return result;
}

static int h2_append_http1_header_lines(dynbuf_t *block, const char *headers, int omit_content_type) {
    const char *p = headers;
    while (p != NULL && *p != '\0') {
        const char *line_end = strstr(p, "\r\n");
        size_t line_len = line_end != NULL ? (size_t)(line_end - p) : strlen(p);
        if (line_len > 0) {
            const char *colon = memchr(p, ':', line_len);
            if (colon == NULL) {
                return -1;
            }
            if (!(omit_content_type && colon-p == 12 && !strncasecmp(p,"content-type",12)) && h2_append_regular_header(block, p, (size_t)(colon - p), colon + 1, line_len - (size_t)(colon - p) - 1) != 0) {
                return -1;
            }
        }
        if (line_end == NULL) {
            break;
        }
        p = line_end + 2;
    }
    return 0;
}

int h2_send_xhttp_request_headers(tls13_conn_t *c, uint32_t stream_id, const char *method, const char *path,
                                         const char *extra_headers, size_t content_len, int has_body, int streaming_body, char *err,
                                         size_t err_cap) {
    if (!c->xmux_async) {
        h2_response_entry_t *entry=h2_response_get(c,stream_id,0);
        if (entry) entry->response.no_body=!strcmp(method,"HEAD");
    }
    dynbuf_t block = {.limit=1024U*1024U,.memory=c->output_memory};
    int rc = 0;

    if (strcmp(method, "GET") == 0) {
        rc = hpack_append_indexed(&block, 2);
    } else if (strcmp(method, "POST") == 0) {
        rc = hpack_append_indexed(&block, 3);
    } else {
        rc = hpack_append_literal_new_name(&block, ":method", method);
    }

    if (rc == 0) {
        rc = hpack_append_indexed(&block, 7);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, ":authority", c->xhttp_host);
    }
    if (rc == 0) {
        rc = (strcmp(path, "/") == 0) ? hpack_append_indexed(&block, 4) : hpack_append_literal_new_name(&block, ":path", path);
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"User-Agent",NULL)) {
        rc = hpack_append_literal_new_name(&block, "user-agent",xhttp_user_agent);
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"Accept",NULL)) {
        rc = hpack_append_literal_new_name(&block, "accept", "*/*");
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"Cache-Control",NULL)) {
        rc = hpack_append_literal_new_name(&block, "cache-control", "no-cache");
    }
    if (rc == 0 && !core_http_header_get(extra_headers,"Pragma",NULL)) {
        rc = hpack_append_literal_new_name(&block, "pragma", "no-cache");
    }
    if (rc == 0 && extra_headers != NULL && extra_headers[0] != '\0') {
        rc = h2_append_http1_header_lines(&block, extra_headers,has_body && streaming_body == 1 && !c->xhttp_no_grpc_header);
    }
    if (rc == 0 && has_body && streaming_body == 1 && !c->xhttp_no_grpc_header) {
        rc = hpack_append_literal_new_name(&block, "content-type", "application/grpc");
    }
    if (rc == 0 && has_body && !streaming_body) {
        char clen[32];
        snprintf(clen, sizeof(clen), "%zu", content_len);
        rc = hpack_append_literal_new_name(&block, "content-length", clen);
    }

    uint8_t flags = H2_FLAG_END_HEADERS;
    if (!has_body) {
        flags |= H2_FLAG_END_STREAM;
    }
    if (rc == 0) {
        size_t offset=0;
        do {
            size_t length=block.len-offset; if (length > 16384) length=16384;
            uint8_t part_flags=offset ? 0 : (uint8_t)(flags&~H2_FLAG_END_HEADERS);
            if (offset+length == block.len) part_flags|=H2_FLAG_END_HEADERS;
            if (h2_send_frame(c,offset ? H2_FRAME_CONTINUATION : H2_FRAME_HEADERS,part_flags,stream_id,block.data+offset,length) != 0) { rc=-1; break; }
            offset+=length;
        } while (offset < block.len);
    }

    db_free(&block);
    if (rc != 0) {
        set_err(err, err_cap, "failed to send xhttp h2 headers");
        return -1;
    }
    return 0;
}

static int h2_send_xhttp_body(tls13_conn_t *c, uint32_t stream_id, const uint8_t *buf, size_t len, char *err, size_t err_cap) {
    if (!h2_stream_writable(c,stream_id)) { set_err(err,err_cap,"h2 upload stream was reset"); return -1; }
    size_t off = 0;
    if (len == 0) {
        if (h2_send_frame(c, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id, NULL, 0) != 0) {
            set_err(err, err_cap, "failed to send xhttp h2 body");
            return -1;
        }
        return 0;
    }

    c->h2_upload_stream_id = stream_id;
    c->h2_upload_stream_window = c->h2_peer_initial_window;
    while (off < len) {
        if (!h2_stream_writable(c,stream_id)) { set_err(err,err_cap,"h2 upload stream was reset"); return -1; }
        while (c->h2_peer_conn_window <= 0 || c->h2_upload_stream_window <= 0) {
            if (h2_pump_one_frame(c) != 0) {
                c->h2_upload_stream_id = 0;
                c->h2_upload_stream_window = 0;
                set_err(err, err_cap, "failed while waiting for xhttp h2 upload window");
                return -1;
            }
            if (!h2_stream_writable(c,stream_id)) { set_err(err,err_cap,"h2 upload stream was reset"); return -1; }
        }

        size_t chunk = len - off;
        if (chunk > c->h2_peer_max_frame_size) {
            chunk = c->h2_peer_max_frame_size;
        }
        if ((int64_t)chunk > c->h2_peer_conn_window) {
            chunk = (size_t)c->h2_peer_conn_window;
        }
        if ((int64_t)chunk > c->h2_upload_stream_window) {
            chunk = (size_t)c->h2_upload_stream_window;
        }
        uint8_t flags = (off + chunk == len) ? H2_FLAG_END_STREAM : 0;
        if (h2_send_frame(c, H2_FRAME_DATA, flags, stream_id, buf + off, chunk) != 0) {
            c->h2_upload_stream_id = 0;
            c->h2_upload_stream_window = 0;
            set_err(err, err_cap, "failed to send xhttp h2 body");
            return -1;
        }
        c->h2_peer_conn_window -= (int64_t)chunk;
        c->h2_upload_stream_window -= (int64_t)chunk;
        off += chunk;
    }
    c->h2_upload_stream_id = 0;
    c->h2_upload_stream_window = 0;
    h2_response_entry_t *entry=h2_response_get(c,stream_id,0);
    if (entry) { entry->request_ended=1; if (entry->response.ended) h2_response_remove(c,stream_id); }
    return 0;
}

static int xhttp_h2_begin(tls13_conn_t *c, char *err, size_t err_cap) {
    c->h2_stream_id = 1;
    c->h2_header_stream_id = 0;
    c->h2_header_flags = 0;
    c->h2_header_block.len = 0;
    c->h2_next_stream_id = 3;
    c->h2_peer_initial_window = H2_DEFAULT_WINDOW;
    c->h2_peer_max_frame_size = H2_DEFAULT_MAX_FRAME;
    c->h2_peer_header_list_size = 8192;
    c->h2_peer_concurrency=UINT32_MAX;
    c->h2_peer_conn_window = H2_DEFAULT_WINDOW;
    c->h2_peer_stream_window = H2_DEFAULT_WINDOW;
    if (c->tls_alps_received && c->tls_alps_settings.received && c->tls_auth_state == 4) {
        c->h2_validation.settings_received=1;
        c->h2_peer_initial_window=c->tls_alps_settings.initial_window;
        c->h2_peer_stream_window=c->h2_peer_initial_window;
        c->h2_peer_max_frame_size=c->tls_alps_settings.max_frame;
        c->h2_peer_header_list_size=c->tls_alps_settings.header_limit;
        c->h2_peer_concurrency=c->tls_alps_settings.concurrency;
    }
    c->h2_upload_stream_id = 0;
    c->h2_upload_stream_window = 0;
    c->h2_recv_conn_pending = 0;
    c->h2_recv_stream_pending = 0;
    c->h2_stream_eof = 0;
    c->h2_request_cancelled = 0;
    c->h2_receive_window=H2_DEFAULT_WINDOW+H2_CONNECTION_WINDOW_INC;
    if (!c->xmux_physical && !c->grpc_physical_only) {
        h2_response_entry_t *entry=h2_response_get(c,c->h2_stream_id,1);
        if (!entry) { set_err(err,err_cap,"failed to allocate h2 response state"); return -1; }
        entry->request_ended=!c->grpc_transport && strcmp(c->xhttp_transport_mode,"stream-one");
    }

    if (h2_send_client_preface(c, err, err_cap) != 0) {
        return -1;
    }
    return 0;
}

static int xhttp_h2_send_download_request(tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 GET");
        return -1;
    }

    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    return h2_send_xhttp_request_headers(c, c->h2_stream_id, "GET", request_path, extra_headers, 0, 0, 0, err, err_cap);
}

static int xhttp_h2_send_stream_one_request(tls13_conn_t *c, char *err, size_t err_cap) {
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 stream-one request");
        return -1;
    }

    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    const char *method = c->xhttp_uplink_method;
    return h2_send_xhttp_request_headers(c, c->h2_stream_id, method, request_path, extra_headers, 0, 1, 1, err, err_cap);
}

static int h2_request_capacity(tls13_conn_t *c, char *err, size_t err_cap) {
    if (c->h2_goaway) { set_err(err,err_cap,"h2 goaway prevents new requests"); return -1; }
    if (!c->h2_next_stream_id || c->h2_next_stream_id > 0x7ffffffdU) { set_err(err,err_cap,"h2 stream identifier exhausted"); return -1; }
    if (tls13_drain_h2_input(c) < 0) { set_err(err,err_cap,"failed to read h2 settings"); return -1; }
    while (!c->h2_goaway && (c->h2_response_count >= 256 || h2_response_active(c) >= c->h2_peer_concurrency))
        if (h2_pump_one_frame(c)) { set_err(err,err_cap,"h2 outstanding response capacity wait failed"); return -1; }
    if (c->h2_goaway) { set_err(err,err_cap,"h2 goaway prevents new requests"); return -1; }
    return 0;
}

static int xhttp_h2_send_stream_up_request(tls13_conn_t *c, char *err, size_t err_cap) {
    if (h2_request_capacity(c,err,err_cap)) return -1;
    char request_path[2048];
    char extra_headers[16384];
    if (xhttp_prepare_request(c, "", request_path, sizeof(request_path), extra_headers, sizeof(extra_headers)) != 0) {
        set_err(err, err_cap, "failed to build xhttp h2 stream-up request");
        return -1;
    }

    uint32_t stream_id = c->h2_next_stream_id;
    c->h2_next_stream_id += 2;
    c->h2_upload_stream_id = stream_id;
    c->h2_upload_stream_window = c->h2_peer_initial_window;
    if (!h2_response_get(c,stream_id,1)) { set_err(err,err_cap,"failed to allocate h2 response state"); return -1; }
    const char *method = c->xhttp_uplink_method;
    return h2_send_xhttp_request_headers(c, stream_id, method, request_path, extra_headers, 0, 1, 1, err, err_cap);
}

int xhttp_h2_post_packet(tls13_conn_t *c, const uint8_t *buf, size_t *length, char *err, size_t err_cap) {
    if (h2_request_capacity(c,err,err_cap)) return -1;
    if (xhttp_wait_post(c,err,err_cap) != 0) return -1;
    char seq[32];
    snprintf(seq, sizeof(seq), "%llu", (unsigned long long)c->xhttp_seq++);

    char request_path[2048];
    core_xhttp_payload_t packet;
    if (xhttp_packet_headers(c,seq,buf,*length,c->h2_peer_header_list_size,request_path,&packet,err,err_cap) != 0) return -1;
    *length=packet.consumed;

    uint32_t stream_id = c->h2_next_stream_id;
    c->h2_next_stream_id += 2;
    h2_response_entry_t *entry=h2_response_get(c,stream_id,1);
    if (!entry) { core_xhttp_payload_clear(&packet); set_err(err,err_cap,"failed to allocate h2 response state"); return -1; }
    entry->request_ended=!packet.body_size;
    const char *method = c->xhttp_uplink_method;
    int result=h2_send_xhttp_request_headers(c,stream_id,method,request_path,packet.headers,packet.body_size,packet.body_size != 0,0,err,err_cap);
    if (!result && packet.body_size) result=h2_send_xhttp_body(c,stream_id,buf,packet.body_size,err,err_cap);
    core_xhttp_payload_clear(&packet); return result;
}

int xhttp_h2_start_mode(tls13_conn_t *c, char *err, size_t err_cap) {
    if (c->xmux_physical) return xhttp_h2_begin(c, err, err_cap);
    if (strcmp(c->xhttp_transport_mode, "stream-one") == 0) {
        return xhttp_h2_send_stream_one_request(c, err, err_cap);
    }
    if (xhttp_h2_send_download_request(c, err, err_cap) != 0) {
        return -1;
    }
    if (strcmp(c->xhttp_transport_mode, "stream-up") == 0) {
        return xhttp_h2_send_stream_up_request(c, err, err_cap);
    }
    return 0;
}

static int grpc_path_escape(const char *src, char *dst, size_t cap, int keep_slash) {
    static const char hex[] = "0123456789ABCDEF";
    size_t out = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p != '\0'; p++) {
        unsigned char ch = *p;
        int safe = (ch >= 'a' && ch <= 'z') ||
                   (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') ||
                   ch == '-' || ch == '_' || ch == '.' || ch == '~' ||
                   ch == '$' || ch == '&' || ch == '+' || ch == ':' ||
                   ch == '=' || ch == '@' || (keep_slash && ch == '/');
        if (safe) {
            if (out + 1 >= cap) {
                return -1;
            }
            dst[out++] = (char)ch;
        } else {
            if (out + 3 >= cap) {
                return -1;
            }
            dst[out++] = '%';
            dst[out++] = hex[ch >> 4];
            dst[out++] = hex[ch & 0x0f];
        }
    }
    if (out >= cap) {
        return -1;
    }
    dst[out] = '\0';
    return 0;
}

static int grpc_build_request_path(const char *service_name, int multi_mode, char *path, size_t cap) {
    char service[512];
    char stream[256];

    if (service_name[0] != '/') {
        if (grpc_path_escape(service_name, service, sizeof(service), 0) != 0) {
            return -1;
        }
        snprintf(stream, sizeof(stream), "%s", multi_mode ? "TunMulti" : "Tun");
    } else {
        const char *last = strrchr(service_name, '/');
        if (last == NULL || last == service_name) {
            service[0] = '\0';
        } else {
            char raw_service[512];
            size_t n = (size_t)(last - service_name - 1);
            if (n >= sizeof(raw_service)) {
                return -1;
            }
            memcpy(raw_service, service_name + 1, n);
            raw_service[n] = '\0';
            if (grpc_path_escape(raw_service, service, sizeof(service), 1) != 0) {
                return -1;
            }
        }

        const char *raw_stream = last != NULL ? last + 1 : "";
        char stream_part[256];
        const char *separator = strchr(raw_stream, '|');
        if (multi_mode && separator != NULL) {
            raw_stream = separator + 1;
        }
        size_t n = strcspn(raw_stream, "|");
        if (n >= sizeof(stream_part)) {
            return -1;
        }
        memcpy(stream_part, raw_stream, n);
        stream_part[n] = '\0';
        if (grpc_path_escape(stream_part, stream, sizeof(stream), 0) != 0) {
            return -1;
        }
    }

    int n = snprintf(path, cap, "/%s/%s", service, stream);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int h2_send_grpc_request_headers(tls13_conn_t *c, char *err, size_t err_cap) {
    char path[1024];
    if (grpc_build_request_path(c->grpc_service_name, c->grpc_multi_mode, path, sizeof(path)) != 0) {
        set_err(err, err_cap, "invalid grpc serviceName");
        return -1;
    }

    dynbuf_t block = {.limit=1024U*1024U,.memory=c->output_memory};
    int rc = hpack_append_indexed(&block, 3);
    if (rc == 0) {
        rc = hpack_append_indexed(&block, c->mode == CONN_MODE_GRPC_PLAIN ? 6 : 7);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, ":authority", c->grpc_authority);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, ":path", path);
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "content-type", "application/grpc");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "user-agent",
                                           c->grpc_user_agent[0] ? c->grpc_user_agent : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                           "Chrome/149.0.0.0 Safari/537.36");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "te", "trailers");
    }
    if (rc == 0) {
        rc = hpack_append_literal_new_name(&block, "grpc-accept-encoding", "identity");
    }
    if (rc == 0 && h2_send_frame(c, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, c->h2_stream_id, block.data, block.len) != 0) {
        rc = -1;
    }
    db_free(&block);

    if (rc != 0) {
        set_err(err, err_cap, "failed to send grpc h2 headers");
        return -1;
    }
    return 0;
}

static int grpc_h2_start(tls13_conn_t *c, char *err, size_t err_cap) {
    if (xhttp_h2_begin(c, err, err_cap) != 0) {
        return -1;
    }
    if (c->grpc_physical_only) c->h2_next_stream_id=1;
    return c->grpc_physical_only ? 0 : h2_send_grpc_request_headers(c, err, err_cap);
}

int h2_cached_frame_ready(const tls13_conn_t *c) {
    if (c->h2_net_cache.len >= 9) {
        size_t frame_len = ((size_t)c->h2_net_cache.data[0] << 16) | ((size_t)c->h2_net_cache.data[1] << 8) |
                           (size_t)c->h2_net_cache.data[2];
        if (frame_len > H2_DEFAULT_MAX_FRAME || c->h2_net_cache.len >= 9 + frame_len) {
            return 1;
        }
    }
    return 0;
}

int h2_input_ready(const tls13_conn_t *c) {
    if (h2_cached_frame_ready(c)) {
        return 1;
    }
    if (c->ssl != NULL && SSL_pending(c->ssl) > 0) {
        return 1;
    }
    if (c->fd < 0) {
        return 0;
    }

    return core_wait_socket(c->fd, POLLIN, 0) > 0;
}

static int grpc_tls_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    if (connect_manual_tls(cfg,c,err,err_cap)) return -1;
    if (strcmp(c->tls_selected_alpn,"h2")) {
        core_trace_error_set(core_connection_error(CORE_TRACE_TRANSPORT,CORE_FAILURE_TLS,EPROTO)); errno=EPROTO;
        set_err(err,err_cap,"grpc requires HTTP/2 ALPN"); return -1;
    }
    c->xhttp_tls_insecure=c->tls_verify_policy != TLS_VERIFY_MODE_STRICT;
    c->mode=CONN_MODE_XHTTP_REALITY;
    return 0;
}

int grpc_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->grpc_transport = 1;
    c->grpc_physical_only=cfg->grpc_physical_only;
    c->grpc_initial_window=cfg->grpc_initial_window ? (unsigned)cfg->grpc_initial_window : 256U*1024U;
    memcpy(c->grpc_user_agent,cfg->grpc_user_agent,sizeof(c->grpc_user_agent));
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);
    snprintf(c->grpc_service_name, sizeof(c->grpc_service_name), "%s", cfg->grpc_service_name);
    c->grpc_multi_mode = strcmp(cfg->xhttp_mode, "multi") == 0;
    c->grpc_decoder.multi=(unsigned)c->grpc_multi_mode;

    if (cfg->grpc_authority[0] != '\0') {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "%s", cfg->grpc_authority);
    } else if (strcmp(cfg->security, "none") != 0 && c->remote_sni[0] != '\0') {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "%s", c->remote_sni);
    } else if (strchr(c->remote_host, ':') != NULL) {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "[%s]:%u", c->remote_host, (unsigned)c->remote_port);
    } else {
        snprintf(c->grpc_authority, sizeof(c->grpc_authority), "%s:%u", c->remote_host, (unsigned)c->remote_port);
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_GRPC_PLAIN;
        c->fd = tcp_connect_host(c->remote_host, c->remote_port, c->ip_source);
        if (c->fd < 0) {
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
    } else if (strcmp(cfg->security, "reality") == 0) {
        c->mode = CONN_MODE_XHTTP_REALITY;
        if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
            return -1;
        }
    } else if (grpc_tls_connect(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    if (grpc_h2_start(c, err, err_cap) != 0) {
        return -1;
    }
    vc_log_info("grpc", "connected service=%s authority=%s security=%s mode=%s",
                c->grpc_service_name, c->grpc_authority,
                cfg->security, c->grpc_multi_mode ? "multi" : "single");
    return 0;
}
