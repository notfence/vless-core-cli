#define _POSIX_C_SOURCE 200809L
#include "tls_fixture.h"
#include "uri.h"
#include "json.h"
#include "utils.h"
#include "routing.h"
#include "vision.h"
#include "vless.h"
#include "trojan.h"
#include "../src/vmess_internal.h"
#include "xhttp_download.h"
#include "xhttp_padding.h"
#include "cli_args.h"

static const char *const fuzz_names[] = {"uri", "hpack", "h2", "grpc", "http", "xhttp", "ws", "vision", "tls", "arguments", "vmess"};
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
    db_free(&c->tls_stream_input);
    db_free(&c->xhttp_net_cache);
    db_free(&c->xmux_raw_input); db_free(&c->xmux_wire_output); db_free(&c->xmux_plain_output);
    tls_record_work_clear(c);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65536) return 0;
    char error[160] = {0};
    tls13_conn_t c = {.fd = -1, .mode = CONN_MODE_GRPC_PLAIN, .h2_stream_id = 1,.h2_next_stream_id=3,.h2_receive_window=H2_CLIENT_INITIAL_WINDOW+H2_DEFAULT_WINDOW,
                     .h2_peer_initial_window = H2_DEFAULT_WINDOW, .h2_peer_stream_window = H2_DEFAULT_WINDOW,
                     .h2_peer_conn_window = H2_DEFAULT_WINDOW};
    switch (fuzz_target) {
    case 10: {
        core_vmess_header_t header={.ready=1,.security=(core_vmess_security_t)(3+(size ? data[0]%4 : 0))};
        for (unsigned i=0;i<16;i++) header.request_key[i]=header.response_key[i]=(uint8_t)i,header.request_iv[i]=header.response_iv[i]=(uint8_t)(i+16);
        core_vmess_body_t body={0}; uint8_t plain[256];
        if (core_vmess_body_init(&body,&header,0,NULL)) abort();
        body.counter=size && (data[0]&128) ? 65536U : size && (data[0]&64) ? 65535U : 0;
        size_t offset=size ? 1 : 0;
        while (offset<size || body.plain_length) {
            size_t got=0;
            if (body.plain_length) { if (core_vmess_body_read(&body,plain,sizeof(plain),&got)) break; continue; }
            uint8_t *span=NULL; size_t capacity=0;
            if (core_vmess_body_prepare(&body,&span,&capacity) || !capacity) break;
            size_t take=size-offset;
            if (take > capacity) take=capacity;
            if (take > 1+(size ? data[size-1]%64 : 0)) take=1+data[size-1]%64;
            memcpy(span,data+offset,take); offset+=take;
            if (core_vmess_body_commit(&body,take)) break;
        }
        (void)core_vmess_body_eof(&body); core_vmess_body_clear(&body);
        core_vmess_body_t sender={0}; uint8_t encoded[8192];
        if (core_vmess_body_init(&sender,&header,1,NULL)) abort();
        sender.counter=size && (data[0]&128) ? 65536U : size && (data[0]&64) ? 65535U : 0;
        offset=size ? 1 : 0;
        while (offset<size) {
            size_t consumed=0,written=0;
            if (core_vmess_body_encode(&sender,data+offset,size-offset,&consumed,encoded,sizeof(encoded),&written,0)) break;
            if (!consumed || written > sizeof(encoded)) abort();
            offset+=consumed;
        }
        if (!sender.failed) { size_t consumed=0,written=0; (void)core_vmess_body_encode(&sender,NULL,0,&consumed,encoded,sizeof(encoded),&written,1); }
        core_vmess_body_clear(&sender); OPENSSL_cleanse(encoded,sizeof(encoded));
        const uint8_t key[]={0x57,0x04,0x56,0x79,0x6f,0xf0,0x36,0xc6,0xf2,0xc6,0x19,0x80,0x41,0xa8,0x0b,0xe9};
        const uint8_t iv[]={0x0d,0x3b,0x40,0xf3,0x09,0x67,0xc5,0x89,0x5a,0x48,0x2a,0xef,0x36,0x29,0xa6,0x83};
        memcpy(header.response_key,key,sizeof(key)); memcpy(header.response_iv,iv,sizeof(iv));
        header.response_needed=18; header.authentication=36; offset=size ? 1 : 0;
        while (offset<size) {
            size_t used=0,take=size-offset,fragment=1+data[0]%17;
            if (take > fragment) take=fragment;
            int result=core_vmess_response(&header,data+offset,take,&used);
            if (used > take) abort();
            offset+=used;
            if (result || !used) break;
        }
        core_vmess_header_clear(&header);
        break;
    }
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
        int result=core_cli_args_parse(count,arguments,&parsed,error,sizeof(error));
        if (!result && parsed.xray_version) {
            uint8_t before[3]; memcpy(before,g_xray_version,sizeof(before));
            if (tls13_reality_set_xray_version(parsed.xray_version) && memcmp(before,g_xray_version,sizeof(before))) abort();
        }
        core_cli_args_scrub(count,arguments);
        free(input);
        break;
    }
    case 0: {
        char *text = malloc(size + 1);
        if (!text) abort();
        memcpy(text, data, size);
        text[size] = '\0';
        uint8_t trojan_hash[CORE_TROJAN_HASH_SIZE],request[CORE_TROJAN_HEADER_MAX]; size_t request_length=0;
        size_t request_capacity=size ? data[0] : 0;
        if (!core_trojan_password(data,size,trojan_hash)) {
            (void)core_trojan_request(request,request_capacity,&request_length,trojan_hash,text,size > 1 ? (uint16_t)((data[0]<<8)|data[1]) : 0);
            if (request_length > request_capacity || request_length > sizeof(request)) abort();
        }
        OPENSSL_cleanse(trojan_hash,sizeof(trojan_hash)); OPENSSL_cleanse(request,sizeof(request));
        vless_config_t config;
        if (parse_core_uri(text,&config,error,sizeof(error)) == 0) {
            if (config.protocol == CORE_PROTOCOL_VMESS) {
                core_vmess_header_t header={0}; uint8_t wire[CORE_VMESS_HEADER_MAX]; size_t written=0,capacity=size%(sizeof(wire)+1);
                (void)core_vmess_request(&header,config.uuid,config.server_host,config.server_port,config.vmess_security,wire,capacity,&written);
                if (written > capacity) abort();
                core_vmess_header_clear(&header); OPENSSL_cleanse(wire,sizeof(wire));
            }
            if (config.xhttp_download_settings[0]) {
                vless_config_t download;
                (void)core_xhttp_download_config(&config,&download,error,sizeof(error));
                OPENSSL_cleanse(&download,sizeof(download));
            }
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
        OPENSSL_cleanse(&config,sizeof(config)); OPENSSL_cleanse(text,size); free(text);
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
        core_http2_settings_t settings;
        (void)core_http2_alps_parse(data,size,&settings);
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
        vision_wrap_t whole,fragmented; vision_wrap_init(&whole,uuid); vision_wrap_init(&fragmented,uuid);
        size_t step = size ? 1 + data[size - 1] % 64 : 1;
        for (int server=0;server<2;server++) {
            vision_observe_tls(&whole,server,data,size);
            for (size_t offset=0;offset<size;offset+=step) {
                size_t count=size-offset < step ? size-offset : step;
                vision_observe_tls(&fragmented,server,data+offset,count);
            }
            if (whole.tls_disabled != fragmented.tls_disabled || whole.client_hello_seen != fragmented.client_hello_seen ||
                whole.server_hello_seen != fragmented.server_hello_seen || whole.tls13_confirmed != fragmented.tls13_confirmed) abort();
        }
        vision_unpad_t unpad,accounted;
        vision_unpad_init(&unpad, uuid);
        vision_unpad_init(&accounted,uuid);
        core_relay_memory_t memory={0};
        if (core_relay_memory_init(&memory,8192) != 1) abort();
        accounted.memory=&memory.temporary;
        for (size_t off = 0; off < size; off += step) {
            uint8_t *plain = NULL;
            size_t length = 0, count = size - off < step ? size - off : step;
            int direct = 0;
            int result = vision_unpad_feed(&unpad, data + off, count, &plain, &length, &direct);
            int accounted_direct=0;
            if (core_relay_memory_credit(&memory,vision_unpad_buffer_bound(&accounted,count)) != 1) abort();
            int accounted_result=vision_unpad_feed_buffer(&accounted,data+off,count,&memory.plain,&accounted_direct);
            if (result != accounted_result || direct != accounted_direct || length != memory.plain.length ||
                (length && memcmp(plain,memory.plain.data,length))) abort();
            size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
            if (memory.temporary.allocated > memory.temporary.minimum || bytes+reserved > CORE_BUFFER_TOTAL_LIMIT) abort();
            core_relay_buffer_clear(&memory.plain);
            free(plain);
            if (result != 0) break;
            (void)vision_unpad_complete(&unpad);
        }
        (void)vision_unpad_complete(&unpad);
        vision_unpad_free(&unpad);
        vision_unpad_free(&accounted); core_relay_memory_clear(&memory);
        size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
        if (bytes || reserved) abort();
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
        configure_tls_cipher(&c,0x1303); c.tls_auth_state=4; c.crypto_reuse=size && (data[0]&4);
        (void)tls_certificate_request(data,size);
        (void)tls_session_ticket(data,size);
        (void)tls_encrypted_extensions(&c,data,size);
        tls13_conn_t legacy={0};
        if (db_append(&legacy.tls_client_hello,hello,hello_length)) abort();
        (void)tls12_server_hello(&legacy,data,size);
        (void)tls12_certificate_request(data,size);
        legacy.tls12_suite=core_tls12_suite_at(size ? data[0]%27 : 0);
        uint8_t *opened=NULL; size_t opened_length=0; uint64_t opened_sequence=0;
        (void)core_tls12_record_open(legacy.tls12_suite,size && (data[0]&1),legacy.s_app_key,legacy.s_app_iv,legacy.tls12_s_mac,&opened_sequence,
                                   23,data,size,&opened,&opened_length);
        if (opened) { OPENSSL_cleanse(opened,opened_length); free(opened); }
        opened=NULL; opened_length=0; opened_sequence=0;
        uint8_t *legacy_record=NULL; size_t legacy_length=0; uint64_t legacy_sequence=0;
        int legacy_etm=size && (data[0]&1);
        size_t legacy_plain_length=size < 16384 ? size : 16384;
        if (core_tls12_record_seal(legacy.tls12_suite,legacy_etm,legacy.s_app_key,legacy.s_app_iv,legacy.tls12_s_mac,&legacy_sequence,
                                  23,data,legacy_plain_length,&legacy_record,&legacy_length)) abort();
        int damaged=size && (data[0]&2);
        if (damaged) legacy_record[legacy_length-1]^=1;
        int legacy_result=core_tls12_record_open(legacy.tls12_suite,legacy_etm,legacy.s_app_key,legacy.s_app_iv,legacy.tls12_s_mac,&opened_sequence,
                                               23,legacy_record+5,legacy_length-5,&opened,&opened_length);
        if (damaged ? !legacy_result || opened || opened_length || opened_sequence :
            legacy_result || opened_length != legacy_plain_length || opened_sequence != 1 || memcmp(opened,data,legacy_plain_length)) abort();
        if (opened) { OPENSSL_cleanse(opened,opened_length); free(opened); }
        free(legacy_record);
        fuzz_clear(&legacy);
        (void)append_transcript(&c,data,size);
        (void)tls_post_handshake(&c,data,size);
        tls13_conn_t fragmented={.fd=-1,.tls_auth_state=4,.xmux_async=1,.crypto_reuse=size && (data[0]&8)};
        if (configure_tls_cipher(&fragmented,0x1303)) abort();
        size_t step=size ? 1+data[size-1]%7 : 1;
        for (size_t offset=0;offset<size;offset+=step) {
            size_t count=size-offset < step ? size-offset : step;
            uint8_t secrets[128]; memcpy(secrets,fragmented.s_app_traffic,64); memcpy(secrets+64,fragmented.c_app_traffic,64);
            uint64_t incoming=fragmented.s_app_seq,outgoing=fragmented.c_app_seq;
            errno=0;
            int result=tls_post_handshake(&fragmented,data+offset,count);
            if (result < 0) {
                if (errno == EPROTO && (memcmp(secrets,fragmented.s_app_traffic,64) || memcmp(secrets+64,fragmented.c_app_traffic,64) ||
                    incoming != fragmented.s_app_seq || outgoing != fragmented.c_app_seq)) abort();
                break;
            }
            db_free(&fragmented.xmux_wire_output);
        }
        fuzz_clear(&fragmented);
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
