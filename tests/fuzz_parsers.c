#define _POSIX_C_SOURCE 200809L
#include "../src/tls13_reality.c"
#include "uri.h"
#include "json.h"
#include "utils.h"
#include "routing.h"
#include "vision.h"
#include "vless.h"
#include "xhttp_download.h"
#include "xhttp_padding.h"
#include "cli_args.h"

static const char *const fuzz_names[] = {"uri", "hpack", "h2", "grpc", "http", "xhttp", "ws", "vision", "tls", "arguments"};
static size_t fuzz_target;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    const char *name = getenv("VC_FUZZ_PARSER");
    for (size_t i = 0; i < sizeof(fuzz_names) / sizeof(fuzz_names[0]); i++) {
        if (name && strcmp(name, fuzz_names[i]) == 0) {
            fuzz_target = i;
            return 0;
        }
    }
    fprintf(stderr, "VC_FUZZ_PARSER must name a supported parser\n");
    exit(2);
}

static void fuzz_clear(tls13_conn_t *c) {
    h2_response_clear(c);
    core_grpc_clear(&c->grpc_decoder); db_free(&c->grpc_net_cache);
    db_free(&c->transcript);
    db_free(&c->tls_post_handshake); db_free(&c->tls_client_hello); db_free(&c->tls_certificate_message);
    X509_free(c->tls_peer_certificate); EVP_PKEY_free(c->tls_retry_key);
    db_free(&c->h2_net_cache);
    db_free(&c->h2_header_block);
    core_hpack_clear(&c->hpack);
    db_free(&c->h2_send_buf);
    db_free(&c->app_cache);
    db_free(&c->ws_net_cache);
    db_free(&c->xhttp_net_cache);
    db_free(&c->xmux_raw_input); db_free(&c->xmux_wire_output); db_free(&c->xmux_plain_output);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;
    char error[160] = {0};
    tls13_conn_t c = {.fd = -1, .mode = CONN_MODE_GRPC_PLAIN, .h2_stream_id = 1,.h2_next_stream_id=3,.h2_receive_window=H2_CLIENT_INITIAL_WINDOW+H2_DEFAULT_WINDOW,
                     .h2_peer_initial_window = H2_DEFAULT_WINDOW, .h2_peer_stream_window = H2_DEFAULT_WINDOW,
                     .h2_peer_conn_window = H2_DEFAULT_WINDOW};
    switch (fuzz_target) {
    case 9: {
        char *input=malloc(size+1);
        if (!input) abort();
        memcpy(input,data,size); input[size]=0;
        char *arguments[64]={"vless-core"}; int count=1;
        for (size_t offset=0;offset<size && count<64;) {
            arguments[count++]=input+offset;
            offset+=strlen(input+offset)+1;
        }
        core_cli_args_t parsed;
        (void)core_cli_args_parse(count,arguments,&parsed,error,sizeof(error));
        core_cli_args_scrub(count,arguments);
        free(input);
        break;
    }
    case 0: {
        char *text = malloc(size + 1);
        if (!text) abort();
        memcpy(text, data, size);
        text[size] = '\0';
        vless_config_t config;
        if (parse_core_uri(text, &config, error, sizeof(error)) == 0 && config.xhttp_download_settings[0]) {
            vless_config_t download;
            (void)core_xhttp_download_config(&config,&download,error,sizeof(error));
        }
        core_json_t *json = core_json_parse(text, error, sizeof(error));
        if (json) {
            core_config_defaults(&config); config.transport_mode=TRANSPORT_XHTTP;
            if (core_xhttp_apply_object(&config,json,"extra",error,sizeof(error)) == 0 && core_xhttp_validate(&config,error,sizeof(error)) == 0) {
                char session[256];
                (void)core_xhttp_session(&config,session,sizeof(session));
            }
            (void)core_xhttp_download_parse(json,&config,error,sizeof(error));
            const core_json_t *headers=core_json_get(json,"headers");
            if (headers) {
                char output[4096];
                if (core_http_headers_parse(headers,output,sizeof(output),error,sizeof(error)) == 0) {
                    (void)core_http_header_get(output,"Cookie",NULL);
                    (void)core_http_header_set(output,sizeof(output),"X-Vless-Core",text);
                    (void)core_http_header_append_cookie(output,sizeof(output),"vless-core=1");
                }
            }
        }
        core_json_free(json);
        uint8_t decoded[256];
        size_t length = 0, capacity = size ? data[0] : 0;
        (void)base64url_decode(text, decoded, capacity, &length);
        char escaped[256];
        (void)percent_decode(text, escaped, capacity);
        (void)core_request_target(text,escaped,capacity);
        (void)core_http_path(text,escaped,capacity,0);
        (void)core_http_path(text,escaped,capacity,1);
        (void)parse_uuid(text, decoded);
        routing_config_t routes;
        if (routing_config_parse(text,&routes,error,sizeof(error)) == 0) {
            (void)routing_decide(&routes,"192.0.2.1",443,NULL,NULL,0,NULL);
            (void)routing_decide(&routes,"2001:db8::1",443,NULL,NULL,0,NULL);
        }
        free(text);
        break;
    }
    case 1: {
        (void)core_hpack_status(data, size);
        core_hpack_decoder_t decoder = {0}; core_hpack_headers_t headers;
        size_t split=size ? data[0] % size : 0;
        (void)core_hpack_decode(&decoder,data,split,&headers);
        (void)core_hpack_decode(&decoder,data+split,size-split,&headers);
        core_hpack_clear(&decoder);
        (void)core_hpack_decode(&decoder,data,size,&headers);
        (void)core_hpack_decode(&decoder,data,size,&headers);
        core_hpack_clear(&decoder);
        (void)core_hpack_huffman_bits(data,size);
        char decoded[256];
        size_t length = 0, capacity = size ? data[0] : 0;
        (void)core_hpack_decode_huffman(data, size, decoded, capacity, &length);
        (void)core_hpack_decode_huffman(data, size, NULL, 0, &length);
        break;
    }
    case 2: {
        if (db_append(&c.h2_net_cache, data, size) != 0) abort();
        while (c.h2_net_cache.len > 0) {
            uint8_t type, flags, *payload = NULL;
            uint32_t stream;
            size_t length = 0;
            if (h2_read_frame(&c, &type, &flags, &stream, &payload, &length) != 0) break;
            int result = type == H2_FRAME_DATA ? grpc_feed_data(&c, payload, length)
                : h2_process_control_frame(&c, type, flags, stream, payload, length, error, sizeof(error));
            free(payload);
            if (result != 0) break;
        }
        break;
    }
    case 3: {
        size_t step = size ? 1 + data[0] % 64 : 1;
        for (unsigned multi=0;multi<2;multi++) {
            core_grpc_clear(&c.grpc_decoder); c.grpc_decoder.multi=multi; c.grpc_read_failed=0;
            db_consume(&c.grpc_net_cache,c.grpc_net_cache.len); db_consume(&c.app_cache,c.app_cache.len);
            for (size_t off = 0; off < size; off += step) {
                size_t length = size - off < step ? size - off : step;
                if (grpc_feed_data(&c, data + off, length) != 0) break;
                while (c.app_cache.len || core_grpc_pending(&c.grpc_decoder) || c.grpc_net_cache.len) {
                    db_consume(&c.app_cache,c.app_cache.len);
                    if (grpc_fill_app_cache(&c) != 0) break;
                }
            }
        }
        break;
    }
    case 4: {
        core_http1_response_t response={0}; core_http1_event_t event; size_t offset=0;
        for (size_t iteration=0;iteration<size+8;iteration++) {
            int result=core_http1_next(&response,data+offset,size-offset,1,4096,&event);
            offset+=event.consumed;
            if (result || event.kind == 3) break;
        }
        if (db_append(&c.xhttp_net_cache, data, size) != 0) abort();
        c.mode = CONN_MODE_WS;
        (void)core_ws_validate_upgrade(data,size,"vless-core","vless-core");
        (void)parse_ws_upgrade_response(&c,&c.xhttp_net_cache,"vless-core","vless-core",error,sizeof(error));
        break;
    }
    case 5: {
        core_xhttp_payload_options_t options={.placement=size && (data[0]&1) ? "header" : "cookie",.key="vless-core",.chunks={64,256}};
        core_xhttp_payload_t packet;
        if (core_xhttp_payload_build(&options,data,size,"X-Session: vless-core\r\n",size && (data[0]&2) ? 8192 : 65536,&packet,error,sizeof(error)) == 0) {
            if (packet.consumed > size || packet.body_size || !packet.headers) abort();
            free(packet.headers);
        }
        char padding[16384];
        core_range_t range={size ? data[0]*16 : 0,size > 1 ? data[1]*32 : 0};
        const char *methods[]={"repeat-x","tokenish","invalid"};
        size_t capacity=size > 2 ? (size_t)data[2]*64 : 0;
        if (core_xhttp_padding(range,methods[size ? data[0]%3 : 0],padding,capacity) == 0 && strlen(padding) >= capacity) abort();
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 || shutdown(pair[1], SHUT_WR) != 0) abort();
        c.fd = pair[0];
        c.mode = CONN_MODE_XHTTP_PLAIN;
        c.xhttp_http1_response=(core_http1_response_t){.state=2,.chunked=1};
        if (db_append(&c.xhttp_net_cache, data, size) != 0) abort();
        while (c.xhttp_net_cache.len > 0) {
            size_t before = c.xhttp_net_cache.len;
            int result = xhttp_fill_app_cache(&c);
            c.app_cache.len = 0;
            if (result != 0 || c.xhttp_net_cache.len == before) break;
        }
        close(pair[0]);
        close(pair[1]);
        break;
    }
    case 6: {
        core_ws_decoder_t decoder={0}; size_t offset=0;
        while (offset < size) {
            size_t chunk=1+(data[offset]%32),consumed=0;
            if (chunk > size-offset) chunk=size-offset;
            core_ws_event_t event;
            int result=core_ws_decode(&decoder,data+offset,chunk,&consumed,&event);
            if (consumed > chunk || event.length > size) abort();
            if (result < 0 || !consumed) break;
            offset+=consumed;
        }
        break;
    }
    case 7: {
        uint8_t uuid[16] = {0};
        vision_unpad_t unpad;
        vision_unpad_init(&unpad, uuid);
        size_t step = size ? 1 + data[size - 1] % 64 : 1;
        for (size_t off = 0; off < size; off += step) {
            uint8_t *plain = NULL;
            size_t length = 0, count = size - off < step ? size - off : step;
            int direct = 0;
            int result = vision_unpad_feed(&unpad, data + off, count, &plain, &length, &direct);
            free(plain);
            if (result != 0) break;
            (void)vision_unpad_complete(&unpad);
        }
        (void)vision_unpad_complete(&unpad);
        vision_unpad_free(&unpad);
        vless_response_t response={0}; size_t offset=0;
        while (offset < size) {
            size_t chunk=size-offset < step ? size-offset : step, consumed=0;
            int result=vless_consume_response(&response,data+offset,chunk,&consumed);
            if (consumed > chunk) abort();
            offset+=consumed;
            if (result || !consumed) break;
        }
        break;
    }
    case 8: {
        uint8_t share[TLS_HYBRID_SERVER_SHARE_SIZE];
        uint16_t cipher;
        size_t share_length = 0;
        (void)parse_server_hello_for_keyshare(data, size, &cipher, share, &share_length);
        const uint8_t *certificate = NULL;
        size_t certificate_length = 0;
        (void)parse_first_cert_der(data, size, &certificate, &certificate_length);
        static uint8_t *hello; static size_t hello_length;
        if (!hello) {
            vless_config_t config; core_config_defaults(&config); strcpy(config.sni,"vless-core.test"); config.fp_mode=FP_FIREFOX;
            uint8_t private_key[32],public_key[32],random[32],auth[32]; size_t sid;
            if (build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private_key,public_key,random,auth,&hello,&hello_length,&sid,NULL,NULL)) abort();
        }
        core_tls_hello_t server;
        if (!core_tls_hello_parse(data,size,hello,hello_length,&server) && server.retry) {
            uint8_t *retry=NULL; size_t retry_length=0; EVP_PKEY *key=NULL;
            (void)core_tls_hello_retry(hello,hello_length,&server,&retry,&retry_length,&key);
            free(retry); EVP_PKEY_free(key);
        }
        configure_tls_cipher(&c,0x1303); c.tls_auth_state=4;
        (void)tls_certificate_request(data,size);
        (void)tls_session_ticket(data,size);
        (void)tls_encrypted_extensions(&c,data,size);
        (void)append_transcript(&c,data,size);
        (void)tls_post_handshake(&c,data,size);
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) abort();
        if (write_exact(pair[1], data, size) != 0 || shutdown(pair[1], SHUT_WR) != 0) abort();
        uint8_t type, *payload = NULL;
        size_t length = 0;
        (void)read_record(pair[0], &type, &payload, &length);
        free(payload);
        close(pair[0]);
        close(pair[1]);
        if (socketpair(AF_UNIX,SOCK_STREAM,0,pair)) abort();
        c.fd=pair[0]; c.mode=CONN_MODE_TLS; c.tls_post_handshake.len=0;
        if (tls13_start_relay(&c)) abort();
        uint8_t *record=NULL; size_t record_length=0; uint64_t sequence=0;
        if (encrypt_record(&c,c.s_app_key,c.s_app_iv,&sequence,size && (data[0]&1) ? 22 : 23,data,size < 16384 ? size : 16384,&record,&record_length)) abort();
        if (size && (data[0]&2)) record[record_length-1]^=1;
        size_t cut=size ? data[0]%record_length : 0;
        if (write_exact(pair[1],record,cut)) abort();
        uint8_t output[256]; size_t received=0;
        (void)tls13_read_app(&c,output,sizeof(output),&received);
        if (write_exact(pair[1],record+cut,record_length-cut) || shutdown(pair[1],SHUT_WR)) abort();
        free(record);
        for (size_t i=0;i<32;i++) {
            int result=tls13_read_app(&c,output,sizeof(output),&received);
            if (result < 0 || (!result && !received)) break;
        }
        (void)tls13_finish_write(&c,0); (void)tls13_flush(&c);
        close(pair[0]); close(pair[1]);
        break;
    }
    }
    fuzz_clear(&c);
    return 0;
}
