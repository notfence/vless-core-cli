#include "tls_transport_internal.h"

static int tcp_tls_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap);

int tls13_get_fd(const tls13_conn_t *c) {
    return c->fd;
}

int tls13_reality_is_raw_direct(const tls13_conn_t *c) {
    return (c != NULL && c->reality_raw_direct);
}

int tls13_needs_write(const tls13_conn_t *c) {
    if (c && c->relay_async && c->xmux_wire_output.len && !c->xmux_write_wants_read) return 1;
    if (c && c->mode == CONN_MODE_WS) return c->ws_want_write;
    return c != NULL && c->mode == CONN_MODE_XHTTP_TLS && c->ssl != NULL && SSL_want_write(c->ssl);
}

int tls13_idle_timeout(const tls13_conn_t *c) {
    if (!c || c->mode != CONN_MODE_WS || !c->ws_next_heartbeat || c->ws_close_sent || c->ws_decoder.closed) return -1;
    uint64_t now=core_now_ms();
    if (now >= c->ws_next_heartbeat) return 0;
    uint64_t remaining=c->ws_next_heartbeat-now;
    return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

int tls13_tick(tls13_conn_t *c) {
    if (c && c->xhttp_upload_reader_started) {
        pthread_mutex_lock(&g_tls_state_lock); int failed=c->xhttp_upload_failed; pthread_mutex_unlock(&g_tls_state_lock);
        if (failed) return -1;
    }
    if (tls13_idle_timeout(c) == 0) {
        if (ws_write_frame(c,9,NULL,0)) return -1;
        c->ws_next_heartbeat=core_now_ms()+c->ws_heartbeat_ms;
    }
    return 0;
}

int tls13_start_relay(tls13_conn_t *c) {
    if (c && c->xmux_stream) return core_http2_start_relay(c->xmux_stream);
    if (!c || (c->mode != CONN_MODE_PLAIN && c->mode != CONN_MODE_TLS && c->mode != CONN_MODE_REALITY && c->mode != CONN_MODE_WS)) return 0;
    int flags=fcntl(c->fd,F_GETFL,0);
    if (flags < 0 || fcntl(c->fd,F_SETFL,flags|O_NONBLOCK)) return -1;
    if (c->ssl) SSL_set_mode(c->ssl,SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
    c->relay_async=1; return 0;
}

int tls13_flush(tls13_conn_t *c) {
    if (!c || !c->relay_async) return 0;
    if (c->xmux_wire_output.len) {
        ssize_t sent;
        if (c->ssl) {
            if (!c->xmux_ssl_write_length) c->xmux_ssl_write_length=c->xmux_wire_output.len > 16384 ? 16384 : c->xmux_wire_output.len;
            ERR_clear_error(); sent=SSL_write(c->ssl,c->xmux_wire_output.data,(int)c->xmux_ssl_write_length);
            if (sent <= 0) {
                int error=SSL_get_error(c->ssl,(int)sent);
                c->xmux_write_wants_read=error == SSL_ERROR_WANT_READ;
                return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE || (error == SSL_ERROR_SYSCALL && errno == EINTR) ? 0 : -1;
            }
            c->xmux_ssl_write_length=0; c->xmux_write_wants_read=0;
        } else {
            sent=core_send(c->fd,c->xmux_wire_output.data,c->xmux_wire_output.len,MSG_DONTWAIT);
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
            if (sent <= 0) return -1;
        }
        db_consume(&c->xmux_wire_output,(size_t)sent);
    }
    if (c->relay_raw_finish && !c->xmux_wire_output.len) {
        c->relay_raw_finish=0;
        return shutdown(c->fd,SHUT_WR);
    }
    return 0;
}

int tls13_write_raw(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    return !c || c->send_closed ? -1 : relay_write_wire(c,buf,len);
}

int tls13_has_pending_raw(const tls13_conn_t *c) { return c && c->xmux_raw_input.len; }

int tls13_read_raw(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    *out_len=0;
    if (!c || !cap) return c ? 0 : -1;
    if (!c->xmux_raw_input.len) return fd_read_some(c->fd,buf,cap,out_len);
    size_t take=c->xmux_raw_input.len < cap ? c->xmux_raw_input.len : cap;
    memcpy(buf,c->xmux_raw_input.data,take); db_consume(&c->xmux_raw_input,take); *out_len=take; return 0;
}

int tls13_has_pending_app(const tls13_conn_t *c) {
    if (c && c->grpc_transport && (c->grpc_net_cache.len || core_grpc_pending(&c->grpc_decoder) || c->grpc_read_failed)) return 1;
    if (c && c->xmux_stream) return c->app_cache.len || core_xmux_pending(c->xmux_stream);
    if (tls13_uses_h2(c)) {
        return c->app_cache.len > 0 || c->h2_stream_eof || c->grpc_read_failed;
    }
    return tls13_has_pending_input(c);
}

int tls13_has_pending_input(const tls13_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    if (c->grpc_transport && (c->grpc_net_cache.len || core_grpc_pending(&c->grpc_decoder) || c->grpc_read_failed)) return 1;
    if (c->xmux_stream) return c->app_cache.len || core_xmux_pending(c->xmux_stream);
    if (c->app_cache.len > 0) {
        return 1;
    }
    if (c->tls_stream_input.len) return 1;
    if (c->relay_async && c->tls_md) {
        if (c->receive_closed) return 1;
        if (c->xmux_raw_input.len >= 5) {
            size_t length=((size_t)c->xmux_raw_input.data[3]<<8)|c->xmux_raw_input.data[4];
            if (length > 18432 || c->xmux_raw_input.len >= length+5) return 1;
        }
    }
    if (tls13_uses_h2(c) && c->h2_stream_eof) {
        return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
        core_http1_response_t parser=c->xhttp_http1_response; core_http1_event_t event;
        int result=core_http1_next(&parser,c->xhttp_net_cache.data,c->xhttp_net_cache.len,c->xhttp_wire_eof,8192,&event);
        if (result <= 0 || event.consumed || c->xhttp_eof || (c->ssl && SSL_pending(c->ssl) > 0)) return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_TLS_H2 && (h2_cached_frame_ready(c) || (c->ssl && SSL_pending(c->ssl) > 0))) {
        return 1;
    }
    if (c->mode == CONN_MODE_XHTTP_REALITY && c->h2_net_cache.len > 0) {
        return 1;
    }
    if (c->mode == CONN_MODE_GRPC_PLAIN && c->h2_net_cache.len > 0) {
        return 1;
    }
    if (c->mode == CONN_MODE_WS && (c->ws_net_cache.len > 0 || (c->ssl != NULL && SSL_pending(c->ssl) > 0))) {
        return 1;
    }
    return 0;
}

int tls13_drain_h2_input(tls13_conn_t *c) {
    if (c && c->xmux_stream) { core_xmux_drain_notifications(c->xmux_stream); return 0; }
    if (c == NULL ||
        (c->mode != CONN_MODE_XHTTP_TLS_H2 && c->mode != CONN_MODE_XHTTP_REALITY && c->mode != CONN_MODE_GRPC_PLAIN)) {
        return 0;
    }
    if (c->grpc_transport && grpc_fill_app_cache(c) < 0) return c->app_cache.len ? 0 : -1;

    if (c->mode == CONN_MODE_XHTTP_TLS_H2 &&
        c->app_cache.len == 0 &&
        !h2_cached_frame_ready(c)) {
        if (h2_collect_tls_available(c, NULL) < 0) {
            return -1;
        }
    }

    int drain_limit = c->grpc_transport ? H2_GRPC_INPUT_DRAIN_LIMIT : H2_INPUT_DRAIN_LIMIT;
    int drained = 0;
    while (drained < drain_limit && c->app_cache.len == 0 &&
           (c->mode == CONN_MODE_XHTTP_TLS_H2 ?
                h2_cached_frame_ready(c) :
                h2_input_ready(c))) {
        if (h2_pump_one_frame(c) != 0) {
            return c->grpc_transport && c->app_cache.len ? drained : -1;
        }
        drained++;
    }
    return drained;
}

int tls13_uses_h2(const tls13_conn_t *c) {
    return c != NULL &&
           (c->mode == CONN_MODE_XHTTP_TLS_H2 ||
            c->mode == CONN_MODE_XHTTP_REALITY ||
            c->mode == CONN_MODE_GRPC_PLAIN);
}

int tls13_uses_async_io(const tls13_conn_t *c) { return c && c->xmux_stream; }

size_t tls13_write_batch_size(const tls13_conn_t *c) {
    if (c && c->xmux_stream) return 64U*1024U;
    if (c != NULL && c->grpc_transport) {
        return H2_WRITE_BATCH_SIZE;
    }
    if (c != NULL && strcmp(c->xhttp_transport_mode, "packet-up") == 0 &&
        (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_XHTTP_REALITY ||
         c->mode == CONN_MODE_XHTTP_PLAIN) &&
        c->xhttp_max_each_post_bytes > 0) {
        size_t size = (size_t)c->xhttp_max_each_post_bytes;
        return size > 1024U * 1024U ? 1024U * 1024U : size;
    }
    if (c != NULL && strcmp(c->xhttp_transport_mode, "packet-up") != 0 &&
        (c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_XHTTP_REALITY)) {
        return H2_WRITE_BATCH_SIZE;
    }
    return 8192;
}

size_t tls13_write_capacity(const tls13_conn_t *c) {
    if (c && c->relay_async) return c->send_closed ? 0 : 256U*1024U-c->xmux_wire_output.len;
    return c && c->xmux_stream ? core_xmux_write_capacity(c->xmux_stream) : SIZE_MAX;
}

int tls13_reserve_write(tls13_conn_t *c, size_t capacity) {
    return c && c->xmux_stream ? core_xmux_reserve_write(c->xmux_stream, capacity) : 1;
}

void tls13_release_write(tls13_conn_t *c) {
    if (c && c->xmux_stream) core_xmux_release_write(c->xmux_stream);
}

void tls13_mark_raw_direct(tls13_conn_t *c) {
    if (c != NULL) {
        c->reality_raw_direct = 1;
    }
}

static int tcp_tls_connect(const vless_config_t *cfg, tls13_conn_t *c, char *err, size_t err_cap) {
    c->mode = CONN_MODE_TLS;
    snprintf(c->remote_host, sizeof(c->remote_host), "%s", cfg->server_host);
    c->remote_port = cfg->server_port;
    snprintf(c->remote_sni, sizeof(c->remote_sni), "%s", cfg->sni[0] != '\0' ? cfg->sni : cfg->server_host);

    if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
        return -1;
    }

    vc_log_info("tls", "connected mode=vision alpn=%s verify=%s",
                c->tls_selected_alpn[0] ? c->tls_selected_alpn : "none",
                c->tls_verify_mode[0] != '\0' ? c->tls_verify_mode : (cfg->allow_insecure ? "insecure" : "strict"));
    return 0;
}

int tls13_connect_budgeted(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap,
                                  core_buffer_budget_t *output_memory, core_buffer_budget_t *input_memory) {
    *out = NULL;
    tls13_conn_t *c = (tls13_conn_t *)calloc(1, sizeof(*c));
    if (c == NULL) {
        set_err(err, err_cap, "oom");
        return -1;
    }
    c->fd = -1;
    c->ignore_server_ips=cfg->ignore_server_ips;
    c->ip_source=core_config_ip_source(cfg);
    c->xhttp_upload_fd = -1;
    c->mode = CONN_MODE_REALITY;
    c->crypto_reuse=1; c->record_memory.direction=CORE_BUFFER_RELAY;
    c->app_cache.memory=c->tls_stream_input.memory=c->ws_net_cache.memory=&c->record_memory;
    c->xmux_raw_input.memory=c->xmux_wire_output.memory=&c->record_memory;
    c->input_memory=input_memory; c->output_memory=output_memory;
    c->hpack.memory=input_memory;
    if (cfg->xhttp_physical_only || cfg->grpc_physical_only) {
        c->h2_net_cache=(dynbuf_t){.limit=65536,.memory=input_memory};
        c->xmux_raw_input=(dynbuf_t){.limit=65536,.memory=input_memory};
        c->h2_header_block=(dynbuf_t){.limit=1024U*1024U,.memory=input_memory};
        c->app_cache.memory=input_memory; c->app_cache.limit=65536;
        c->xmux_plain_output=(dynbuf_t){.limit=256U*1024U,.memory=output_memory};
        c->xmux_wire_output=(dynbuf_t){.limit=32768,.memory=output_memory};
        c->h2_send_buf=(dynbuf_t){.limit=1024U*1024U,.memory=output_memory};
    }

    if (cfg->transport_mode == TRANSPORT_XHTTP) {
        if (!cfg->xhttp_physical_only) {
            c->xmux_stream = core_xmux_connect(cfg, &xmux_backend, err, err_cap);
            if (!c->xmux_stream) { free(c); return -1; }
            c->fd = core_xmux_fd(c->xmux_stream);
            *out = c; return 0;
        }
        if (xhttp_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (cfg->transport_mode == TRANSPORT_GRPC) {
        if (!cfg->grpc_physical_only) {
            c->grpc_transport=1;
            c->grpc_decoder.multi=strcmp(cfg->xhttp_mode,"multi") == 0;
            c->xmux_stream=core_http2_connect(cfg,&xmux_backend,err,err_cap);
            if (!c->xmux_stream) { free(c); return -1; }
            c->fd=core_http2_fd(c->xmux_stream); *out=c; return 0;
        }
        if (grpc_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (cfg->transport_mode == TRANSPORT_WS) {
        if (ws_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (strcmp(cfg->security, "none") == 0) {
        c->mode = CONN_MODE_PLAIN;
        c->fd = tcp_connect_host(cfg->server_host, cfg->server_port, core_config_ip_source(cfg));
        if (c->fd < 0) {
            tls13_reality_close(c);
            set_err(err, err_cap, "tcp connect failed");
            return -1;
        }
        vc_log_info("tcp", "connected security=none");
        *out = c;
        return 0;
    }

    if (strcmp(cfg->security, "tls") == 0) {
        if (tcp_tls_connect(cfg, c, err, err_cap) != 0) {
            tls13_reality_close(c);
            return -1;
        }
        *out = c;
        return 0;
    }

    if (connect_manual_tls(cfg, c, err, err_cap) != 0) {
        tls13_reality_close(c);
        return -1;
    }

    *out = c;
    return 0;
}

int tls13_reality_connect(const vless_config_t *cfg, tls13_conn_t **out, char *err, size_t err_cap) {
    int result=tls13_connect_budgeted(cfg,out,err,err_cap,NULL,NULL);
    int saved=errno;
    core_connection_error_t failure;
    if (result && !core_trace_error_get(&failure)) {
        core_connection_trace_t trace;
        core_trace_stage_t stage=core_trace_snapshot(&trace) && trace.stage != CORE_TRACE_NONE ? trace.stage : CORE_TRACE_TRANSPORT;
        core_trace_error_set(core_connection_error(stage,CORE_FAILURE_SYSTEM,saved ? saved : EIO));
    }
    errno=saved; return result;
}

void tls13_reality_close(tls13_conn_t *c) {
    if (c == NULL) {
        return;
    }
    int saved=errno;
    core_grpc_clear(&c->grpc_decoder); db_free(&c->grpc_net_cache);
    if (c->xmux_stream) { core_xmux_close(c->xmux_stream); db_free(&c->app_cache); tls_record_work_clear(c); OPENSSL_cleanse(c,sizeof(*c)); free(c); errno=saved; return; }
    h2_response_clear(c);
    if (!c->send_closed && c->mode == CONN_MODE_XHTTP_PLAIN && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        int upload_fd = strcmp(c->xhttp_transport_mode, "stream-one") == 0 ? c->fd : c->xhttp_upload_fd;
        if (upload_fd >= 0) {
            (void)write_exact(upload_fd, "0\r\n\r\n", 5);
        }
    }
    if (!c->send_closed && c->grpc_transport && !c->grpc_physical_only && c->h2_stream_id != 0 && c->fd >= 0) {
        (void)h2_send_frame(c, H2_FRAME_DATA, H2_FLAG_END_STREAM, c->h2_stream_id, NULL, 0);
    }
    if (c->xhttp_upload_fd >= 0) {
        pthread_mutex_lock(&g_tls_state_lock); c->xhttp_upload_stopping=1; pthread_mutex_unlock(&g_tls_state_lock);
        shutdown(c->xhttp_upload_fd, SHUT_RDWR);
        if (c->xhttp_upload_reader_started) {
            pthread_join(c->xhttp_upload_reader, NULL);
        }
        close(c->xhttp_upload_fd);
        c->xhttp_upload_fd = -1;
    }
    if (c->ssl != NULL) {
        if (!c->reality_raw_direct) {
            SSL_shutdown(c->ssl);
        }
        SSL_free(c->ssl);
    }
    if (c->ssl_ctx != NULL) {
        SSL_CTX_free(c->ssl_ctx);
    }
    if (c->fd >= 0) {
        close(c->fd);
    }
    core_hpack_clear(&c->hpack);
    X509_free(c->tls_peer_certificate);
    db_free(&c->tls_certificate_message);
    db_free(&c->tls_post_handshake);
    db_free(&c->tls_stream_input);
    db_free(&c->tls_client_hello); EVP_PKEY_free(c->tls_retry_key);
    db_free(&c->xhttp_net_cache);
    db_free(&c->ws_net_cache);
    db_free(&c->h2_net_cache);
    db_free(&c->h2_send_buf);
    db_free(&c->h2_header_block);
    db_free(&c->transcript);
    db_free(&c->app_cache);
    db_free(&c->xmux_raw_input); db_free(&c->xmux_plain_output); db_free(&c->xmux_wire_output);
    tls_record_work_clear(c);
    OPENSSL_cleanse(c,sizeof(*c));
    free(c);
    errno=saved;
}

int tls13_write_app(tls13_conn_t *c, const uint8_t *buf, size_t len) {
    if (c->send_closed || (c->mode == CONN_MODE_WS && (c->ws_close_sent || c->ws_decoder.closed))) return -1;
    if (c->xmux_stream && !c->grpc_transport) return core_xmux_write(c->xmux_stream, buf, len);
    if (c->grpc_transport) {
        return grpc_write_hunk(c, buf, len);
    }

    if (c->mode == CONN_MODE_PLAIN) {
        return relay_write_wire(c,buf,len);
    }

    if (c->mode == CONN_MODE_WS) {
        if (!c->ws_upgraded) {
            char error[160]="WebSocket upgrade failed";
            int early=len && len <= (size_t)c->ws_early_data;
            if (ws_upgrade(c,early ? buf : NULL,early ? len : 0,error,sizeof(error))) {
                vc_log_error("ws","%s",error); return -1;
            }
            if (early) return 0;
        }
        return ws_write_frame(c, 0x2, buf, len);
    }

    if (c->mode == CONN_MODE_XHTTP_PLAIN && strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
        return xhttp_write_plain_stream(c, buf, len);
    }

    if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
        size_t max_post = c->xhttp_max_each_post_bytes > 0 ? (size_t)c->xhttp_max_each_post_bytes : 1000000U;
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            if (chunk > max_post) {
                chunk = max_post;
            }
            char err[128] = {0};
            if (xhttp_post_packet(c, buf + off, &chunk, err, sizeof(err)) != 0) {
                if (err[0] != '\0') {
                    vc_log_error("xhttp", "upload failed: %s", err);
                }
                return -1;
            }
            off += chunk;
        }
        return 0;
    }

    if (c->mode == CONN_MODE_XHTTP_TLS_H2) {
        if (strcmp(c->xhttp_transport_mode, "packet-up") != 0) {
            return h2_write_data(c, buf, len);
        }
        size_t max_post = c->xhttp_max_each_post_bytes > 0 ? (size_t)c->xhttp_max_each_post_bytes : 1000000U;
        size_t off = 0;
        while (off < len) {
            size_t chunk = len - off;
            if (chunk > max_post) {
                chunk = max_post;
            }
            char err[128] = {0};
            if (xhttp_h2_post_packet(c, buf + off, &chunk, err, sizeof(err)) != 0) {
                if (err[0] != '\0') {
                    vc_log_error("xhttp", "h2 upload failed: %s", err);
                }
                return -1;
            }
            off += chunk;
        }
        return 0;
    }

    if (c->mode == CONN_MODE_XHTTP_REALITY) {
        if (strcmp(c->xhttp_transport_mode, "packet-up") == 0) {
            size_t max_post = c->xhttp_max_each_post_bytes > 0 ? (size_t)c->xhttp_max_each_post_bytes : 1000000U;
            size_t off = 0;
            while (off < len) {
                size_t chunk = len - off;
                if (chunk > max_post) {
                    chunk = max_post;
                }
                char err[128] = {0};
                if (xhttp_h2_post_packet(c, buf + off, &chunk, err, sizeof(err)) != 0) {
                    if (err[0] != '\0') {
                        vc_log_error("xhttp", "h2 upload failed: %s", err);
                    }
                    return -1;
                }
                off += chunk;
            }
            return 0;
        }
        return h2_write_data(c, buf, len);
    }
    return reality_write_app_records(c, buf, len);
}

int tls13_read_app(tls13_conn_t *c, uint8_t *buf, size_t cap, size_t *out_len) {
    if (c->xmux_stream && c->grpc_transport) return grpc_pool_read(c,buf,cap,out_len);
    if (c->xmux_stream) return core_xmux_read(c->xmux_stream, buf, cap, out_len);
    *out_len = 0;
    if (cap == 0) {
        return 0;
    }

    if (c->mode == CONN_MODE_PLAIN) {
        return fd_read_some(c->fd, buf, cap, out_len);
    }

    if (c->app_cache.len == 0) {
        if (c->mode == CONN_MODE_WS) {
            int result=ws_fill_app_cache(c);
            if (result) return result;
        } else if (c->mode == CONN_MODE_XHTTP_TLS || c->mode == CONN_MODE_XHTTP_PLAIN) {
            int rc = xhttp_fill_app_cache(c);
            if (rc < 0) {
                return c->xhttp_eof ? 0 : -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_TLS_H2 || c->mode == CONN_MODE_GRPC_PLAIN) {
            int rc = h2_fill_app_cache(c);
            if (rc < 0) {
                return c->h2_stream_eof && !c->grpc_read_failed && (!c->grpc_transport || core_grpc_complete(&c->grpc_decoder)) ? 0 : -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else if (c->mode == CONN_MODE_XHTTP_REALITY) {
            int rc = h2_fill_app_cache(c);
            if (rc < 0) {
                return c->h2_stream_eof && !c->grpc_read_failed && (!c->grpc_transport || core_grpc_complete(&c->grpc_decoder)) ? 0 : -1;
            }
            if (rc > 0) {
                return 1;
            }
        } else {
            int result=fill_reality_app_cache(c);
            if (result) return result;
        }
    }

    size_t take = c->app_cache.len;
    if (take > cap) {
        take = cap;
    }
    if (take > 0) memcpy(buf, c->app_cache.data, take);
    db_consume(&c->app_cache, take);
    *out_len = take;
    return 0;
}

int tls13_read_exact_or_eof(tls13_conn_t *c, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (core_deadline_active() && !core_deadline_remaining()) return -1;
        size_t got = 0;
        int rc = tls13_read_app(c, buf + off, len - off, &got);
        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            if (tls13_flush(c) || (!tls13_has_pending_input(c) && core_wait_socket(c->fd,tls13_needs_write(c) ? POLLOUT : POLLIN,-1) <= 0)) return -1;
            continue;
        }
        if (got == 0) {
            return off ? -1 : 1;
        }
        off += got;
    }
    return 0;
}

int tls13_read_exact_app(tls13_conn_t *c, uint8_t *buf, size_t len) {
    return tls13_read_exact_or_eof(c,buf,len) == 0 ? 0 : -1;
}

int tls13_finish_pending(const tls13_conn_t *c) {
    if (!c) return -1;
    if (c->xmux_stream) {
        int result=core_http2_finish_pending(c->xmux_stream);
        return result < 0 && (c->app_cache.len || (c->grpc_transport && (c->grpc_net_cache.len || core_grpc_pending(&c->grpc_decoder)))) ? 0 : result;
    }
    return c->send_closed && (c->xmux_wire_output.len || c->relay_raw_finish);
}

int tls13_full_close(const tls13_conn_t *c) {
    return c && c->mode == CONN_MODE_WS && c->ws_decoder.closed;
}

int tls13_finish_write(tls13_conn_t *c, int raw) {
    if (!c) return -1;
    if (c->send_closed) return 0;
    int result=0;
    if (c->xmux_stream) result=core_http2_finish_write(c->xmux_stream);
    else if (c->mode == CONN_MODE_PLAIN || raw) {
        if (c->relay_async) c->relay_raw_finish=1;
        else result=shutdown(c->fd,SHUT_WR);
    }
    else if (c->mode == CONN_MODE_WS) {
        const uint8_t code[]={3,0xe8};
        if (!c->ws_close_sent) result=ws_write_frame(c,8,code,sizeof(code));
        if (!result) c->ws_close_sent=1;
    } else if (c->mode == CONN_MODE_XHTTP_PLAIN) {
        if (strcmp(c->xhttp_transport_mode,"packet-up")) {
            int fd=!strcmp(c->xhttp_transport_mode,"stream-up") ? c->xhttp_upload_fd : c->fd;
            result=fd < 0 ? -1 : write_exact(fd,"0\r\n\r\n",5);
        }
    } else if (c->grpc_transport || tls13_uses_h2(c)) {
        if (strcmp(c->xhttp_transport_mode,"packet-up")) {
            uint32_t stream=!strcmp(c->xhttp_transport_mode,"stream-up") ? c->h2_upload_stream_id : c->h2_stream_id;
            result=stream ? h2_send_frame(c,H2_FRAME_DATA,H2_FLAG_END_STREAM,stream,NULL,0) : -1;
        }
    } else if (c->mode == CONN_MODE_TLS || c->mode == CONN_MODE_REALITY) {
        const uint8_t alert[]={1,0}; uint8_t *record=NULL; size_t length=0;
        result=c->crypto_reuse ? tls_record_seal_owned(c,21,alert,sizeof(alert),&record,&length) :
            encrypt_record(c,c->c_app_key,c->c_app_iv,&c->c_app_seq,21,alert,sizeof(alert),&record,&length);
        if (!result) result=relay_write_wire(c,record,length);
        if (!c->crypto_reuse) free(record);
    }
    if (!result) {
        c->send_closed=1;
        for (h2_response_entry_t *entry=c->h2_responses;entry;entry=entry->next) entry->request_ended=1;
    }
    return result;
}
