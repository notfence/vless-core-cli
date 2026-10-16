#include "check.h"
#include "uri.h"
#include "vless.h"
#include "vision.h"

static void response_vectors(void) {
    const uint8_t response[]={0,3,'a','b','c','v','l','e','s','s','-','c','o','r','e'};
    for (size_t split=0;split<=sizeof(response);split++) {
        vless_response_t state={0}; uint8_t payload[10]; size_t total=0;
        size_t offsets[]={0,split,sizeof(response)};
        for (unsigned i=0;i<2;i++) {
            size_t size=offsets[i+1]-offsets[i],consumed=0;
            int result=vless_consume_response(&state,response+offsets[i],size,&consumed);
            REQUIRE("vless/response-header-bounds",result >= 0 && consumed <= size && size-consumed <= sizeof(payload)-total);
            if (result) { memcpy(payload+total,response+offsets[i]+consumed,size-consumed); total+=size-consumed; }
        }
        CHECK("vless/fragmented-response-preserves-tail",state.complete && total == 10 && !memcmp(payload,"vless-core",10));
    }
    for (size_t cut=0;cut<5;cut++) {
        vless_response_t state={0}; size_t consumed=0;
        CHECK("vless/truncated-response-is-incomplete",vless_consume_response(&state,response,cut,&consumed) == 0 && !state.complete);
    }
    vless_response_t state={0}; size_t consumed=0; uint8_t bad[]={1,0};
    CHECK("vless/response-version-rejected",vless_consume_response(&state,bad,2,&consumed) < 0);
    uint8_t wire[26]={0}; wire[16]=0; wire[18]=3; wire[20]=2; memcpy(wire+21,"abc",3);
    for (size_t cut=0;cut<=sizeof(wire);cut++) {
        vision_unpad_t decoder; vision_unpad_init(&decoder,wire);
        uint8_t *output=NULL; size_t length=0; int direct=0;
        REQUIRE("vision/eof-vector",vision_unpad_feed(&decoder,wire,cut,&output,&length,&direct) == 0);
        CHECK("vision/eof-between-complete-blocks",vision_unpad_complete(&decoder) == (cut == 0 || cut == sizeof(wire)));
        free(output); vision_unpad_free(&decoder);
    }
    vision_unpad_t decoder; vision_unpad_init(&decoder,wire);
    uint8_t *output=NULL; size_t length=0; int direct=0;
    CHECK("vision/short-unpadded-tail-preserved",vision_unpad_feed(&decoder,(const uint8_t *)"vless",5,&output,&length,&direct) == 0 && length == 5 && !memcmp(output,"vless",5) && vision_unpad_complete(&decoder));
    free(output); vision_unpad_free(&decoder);
}

static void vision_wire_vectors(const uint8_t uuid[16]) {
    for (int command = 1; command <= 2; command++) {
        uint8_t wire[80]; memcpy(wire, uuid, 16);
        const uint8_t blocks[] = {0,0,3,0,2,'v','l','e',0xaa,0xbb,0,0,0,0,1,0xcc,0,0,7,0,1,'s','s','-','c','o','r','e',0xdd};
        memcpy(wire+16, blocks, sizeof(blocks)); wire[16+16] = (uint8_t)command;
        memcpy(wire+16+sizeof(blocks), "/raw-tail", 9);
        size_t wire_length = 16+sizeof(blocks)+9;
        for (size_t cut = 0; cut <= wire_length; cut++) {
            vision_unpad_t unpad; vision_unpad_init(&unpad, uuid);
            uint8_t recovered[80]; size_t recovered_length = 0; int switched = 0;
            size_t offsets[] = {0,cut,wire_length};
            for (int part = 0; part < 2; part++) {
                uint8_t *plain = NULL; size_t plain_length = 0; int direct = 0;
                REQUIRE("vision/golden-feed", vision_unpad_feed(&unpad, wire+offsets[part], offsets[part+1]-offsets[part], &plain, &plain_length, &direct) == 0);
                REQUIRE("vision/golden-output-bound", plain_length <= sizeof(recovered)-recovered_length);
                if (plain_length) memcpy(recovered+recovered_length, plain, plain_length);
                recovered_length += plain_length; switched += direct; free(plain);
            }
            CHECK(command == 1 ? "vision/end-preserves-coalesced-tail" : "vision/direct-preserves-coalesced-tail", recovered_length == 19 && memcmp(recovered, "vless-core/raw-tail", 19) == 0);
            CHECK("vision/golden-direct-signal", switched == (command == 2));
            vision_unpad_free(&unpad);
        }
    }
    uint8_t end[21] = {0}; memcpy(end,uuid,16); end[16] = 1;
    vision_unpad_t unpad; vision_unpad_init(&unpad,uuid);
    uint8_t *plain = NULL; size_t plain_length = 0; int direct = 0;
    REQUIRE("vision/separate-end-frame", vision_unpad_feed(&unpad,end,sizeof(end),&plain,&plain_length,&direct) == 0);
    CHECK("vision/end-does-not-switch-direct", plain_length == 0 && !direct); free(plain);
    const uint8_t tail[] = "vless-core";
    REQUIRE("vision/separate-tail-feed", vision_unpad_feed(&unpad,tail,sizeof(tail)-1,&plain,&plain_length,&direct) == 0);
    CHECK("vision/end-forwards-short-next-read", plain_length == sizeof(tail)-1 && memcmp(plain,tail,plain_length) == 0 && !direct);
    free(plain); vision_unpad_free(&unpad);
}

static void vision_terminal_reads(const uint8_t uuid[16]) {
    uint8_t raw[64];
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(0x80 + i);
    memcpy(raw, uuid, 16);
    const uint8_t fake_block[] = {0,0,3,0,2,'f','o','o',0xaa,0xbb};
    memcpy(raw + 16, fake_block, sizeof(fake_block));
    for (int command = 1; command <= 2; command++) {
        for (size_t content = 0; content <= 10; content += 10) {
            for (size_t padding = 0; padding <= 3; padding += 3) {
                uint8_t frame[40]; memcpy(frame, uuid, 16);
                frame[16] = (uint8_t)command;
                frame[17] = 0; frame[18] = (uint8_t)content;
                frame[19] = 0; frame[20] = (uint8_t)padding;
                memcpy(frame + 21, "vless-core", content);
                memset(frame + 21 + content, 0xff, padding);
                size_t frame_length = 21 + content + padding;
                vision_unpad_t unpad; vision_unpad_init(&unpad, uuid);
                for (size_t i = 0; i < frame_length; i++) {
                    uint8_t *plain = NULL; size_t plain_length = 0; int direct = 0;
                    REQUIRE("vision/fragmented-terminal-feed", vision_unpad_feed(&unpad, frame + i, 1, &plain, &plain_length, &direct) == 0);
                    int is_content = i >= 21 && i < 21 + content;
                    CHECK("vision/fragmented-terminal-content", plain_length == (size_t)is_content && (!is_content || plain[0] == frame[i]));
                    CHECK("vision/direct-only-after-complete-frame", direct == (command == 2 && i + 1 == frame_length));
                    free(plain);
                }
                for (size_t length = 0; length <= sizeof(raw); length++) {
                    uint8_t *plain = NULL; size_t plain_length = 0; int direct = -1;
                    REQUIRE("vision/terminal-next-feed", vision_unpad_feed(&unpad, raw, length, &plain, &plain_length, &direct) == 0);
                    CHECK("vision/terminal-forwards-next-read", plain_length == length && (length == 0 || memcmp(plain, raw, length) == 0) && direct == 0 && unpad.stash_len == 0);
                    free(plain);
                }
                uint8_t *plain = NULL; size_t plain_length = 0;
                REQUIRE("vision/terminal-feed-without-direct-output", vision_unpad_feed(&unpad, raw, sizeof(raw), &plain, &plain_length, NULL) == 0);
                CHECK("vision/terminal-preserves-uuid-like-data", plain_length == sizeof(raw) && memcmp(plain, raw, sizeof(raw)) == 0 && unpad.stash_len == 0);
                free(plain); vision_unpad_free(&unpad);
                vision_unpad_init(&unpad, uuid);
                int direct = -1;
                REQUIRE("vision/reinitialized-prefix-feed", vision_unpad_feed(&unpad, uuid, 1, &plain, &plain_length, &direct) == 0);
                CHECK("vision/reinitialized-awaits-uuid", plain_length == 0 && direct == 0 && unpad.stash_len == 1);
                free(plain); vision_unpad_free(&unpad);
            }
        }
    }
}

static size_t client_hello_record(uint8_t hello[59]) {
    memset(hello,0,59);
    const uint8_t prefix[]={22,3,3,0,54,1,0,0,50,3,3}; memcpy(hello,prefix,sizeof(prefix));
    const uint8_t tail[]={0,0,2,0x13,3,1,0,0,7,0,43,0,3,2,3,4}; memcpy(hello+43,tail,sizeof(tail));
    return 59;
}

static void vision_unconfirmed_tls(const uint8_t uuid[16]) {
    uint8_t hello[59]; size_t length=client_hello_record(hello);
    const uint8_t app[]={23,3,3,0,1,42}; const size_t fragments[]={1,4,59};
    for (size_t sample=0;sample<sizeof(fragments)/sizeof(fragments[0]);sample++) {
        vision_wrap_t wrap; vision_wrap_init(&wrap,uuid);
        vision_unpad_t receive; vision_unpad_init(&receive,uuid);
        for (size_t offset=0;offset<length;) {
            size_t count=length-offset < fragments[sample] ? length-offset : fragments[sample];
            uint8_t *output=NULL,*plain=NULL; size_t output_length=0,plain_length=0; int direct=0;
            REQUIRE("vision/client-hello-fragment-wrap",vision_wrap_payload(&wrap,hello+offset,count,&output,&output_length) == 0);
            REQUIRE("vision/client-hello-fragment-unpad",vision_unpad_feed(&receive,output,output_length,&plain,&plain_length,&direct) == 0);
            CHECK("vision/client-hello-forwarded-immediately",plain_length == count && !memcmp(plain,hello+offset,count) && !direct);
            free(output); free(plain); offset+=count;
        }
        CHECK("vision/client-hello-recognized-across-writes",wrap.client_hello_seen);
        for (unsigned application=0;application<2;application++) {
            uint8_t *output=NULL; size_t output_length=0;
            REQUIRE("vision/unconfirmed-app-wrap",vision_wrap_payload(&wrap,app,sizeof(app),&output,&output_length) == 0);
            CHECK("vision/no-direct-without-server-hello",!wrap.direct_sent); free(output);
        }
        vision_unpad_free(&receive);
    }
}

static size_t server_hello_record(uint8_t hello[95], unsigned cipher, unsigned version) {
    memset(hello,0,95); hello[0]=22; hello[1]=hello[2]=3; hello[5]=2; hello[9]=hello[10]=3;
    memset(hello+11,0x41,32); hello[44]=(uint8_t)(cipher>>8); hello[45]=(uint8_t)cipher;
    size_t length=49;
    if (version != 0x0303) {
        const uint8_t extension[]={0,43,0,2,(uint8_t)(version>>8),(uint8_t)version,0,51,0,36,0,29,0,32};
        memcpy(hello+length,extension,sizeof(extension)); length+=sizeof(extension);
        for (unsigned i=0;i<32;i++) hello[length++]=(uint8_t)(i+1);
    }
    hello[48]=(uint8_t)(length-49); hello[4]=(uint8_t)(length-5); hello[8]=(uint8_t)(length-9);
    return length;
}

static void vision_confirmed_tls(const uint8_t uuid[16]) {
    uint8_t client[59],server[95],app[37]={23,3,3,0,32}; size_t client_length=client_hello_record(client);
    memset(app+5,0x41,sizeof(app)-5);
    const unsigned ciphers[]={0x1301,0x1302,0x1303,0x1304,0x1305,0xc02f};
    const size_t fragments[]={1,4,95};
    CHECK("vision/small-observer-state",sizeof(vision_wrap_t) <= 512);
    for (unsigned version=0x0303;version<=0x0304;version++) for (size_t cipher=0;cipher<sizeof(ciphers)/sizeof(ciphers[0]);cipher++)
        for (size_t sample=0;sample<sizeof(fragments)/sizeof(fragments[0]);sample++) {
        vision_wrap_t wrap; vision_wrap_init(&wrap,uuid); uint8_t *output=NULL; size_t output_length=0;
        REQUIRE("vision/confirmed-client-hello",vision_wrap_payload(&wrap,client,client_length,&output,&output_length) == 0); free(output);
        size_t server_length=server_hello_record(server,ciphers[cipher],version);
        for (size_t offset=0;offset<server_length;) {
            size_t count=server_length-offset < fragments[sample] ? server_length-offset : fragments[sample];
            vision_observe_tls(&wrap,1,server+offset,count); offset+=count;
            if (offset < server_length) CHECK("vision/server-hello-confirmed-only-when-complete",!wrap.server_hello_seen && !wrap.tls13_confirmed);
        }
        int eligible=version == 0x0304 && ciphers[cipher] <= 0x1304;
        CHECK("vision/server-version-and-cipher",wrap.server_hello_seen && wrap.tls13_confirmed == eligible && !wrap.tls_disabled);
        int packets=wrap.packets_left;
        for (size_t offset=0;offset<sizeof(app);offset++) {
            REQUIRE("vision/fragmented-application-wrap",vision_wrap_payload(&wrap,app+offset,1,&output,&output_length) == 0);
            if (offset+1 < sizeof(app)) CHECK("vision/partial-record-does-not-end-padding",!wrap.direct_sent && wrap.padding_active && wrap.packets_left == packets);
            else CHECK("vision/direct-only-on-application-record-boundary",wrap.direct_sent == eligible && !wrap.padding_active && output[0] == (eligible ? 2 : 1));
            free(output);
        }
    }
    for (unsigned variant=0;variant<3;variant++) {
        vision_wrap_t wrap; vision_wrap_init(&wrap,uuid); uint8_t *output=NULL; size_t output_length=0;
        REQUIRE("vision/incomplete-client-hello",vision_wrap_payload(&wrap,client,client_length,&output,&output_length) == 0); free(output);
        size_t server_length=server_hello_record(server,0x1303,variant ? 0x0303 : 0x0304);
        const uint8_t pattern[]={0,43,0,2,3,4};
        if (variant == 1) memcpy(server+11,pattern,sizeof(pattern));
        if (variant == 2) server[46]=1;
        vision_observe_tls(&wrap,1,server,server_length-(variant ? 0 : 1));
        REQUIRE("vision/incomplete-server-app-wrap",vision_wrap_payload(&wrap,app,sizeof(app),&output,&output_length) == 0); free(output);
        CHECK("vision/no-direct-for-unconfirmed-or-malformed-server",!wrap.direct_sent && !wrap.tls13_confirmed);
        if (!variant) {
            vision_observe_tls(&wrap,1,server+server_length-1,1);
            REQUIRE("vision/completed-server-app-wrap",vision_wrap_payload(&wrap,app,sizeof(app),&output,&output_length) == 0); free(output);
            CHECK("vision/late-server-hello-enables-direct",wrap.direct_sent);
        }
    }
    vision_wrap_t wrap; vision_wrap_init(&wrap,uuid); uint8_t *output=NULL; size_t output_length=0;
    for (size_t offset=5;offset<client_length;offset++) {
        uint8_t record[]={22,3,3,0,1,client[offset]};
        REQUIRE("vision/handshake-fragmented-across-records",vision_wrap_payload(&wrap,record,sizeof(record),&output,&output_length) == 0); free(output);
    }
    CHECK("vision/client-hello-across-records-recognized",wrap.client_hello_seen && !wrap.tls_disabled);
    vision_wrap_init(&wrap,uuid);
    REQUIRE("vision/coalesced-client-hello",vision_wrap_payload(&wrap,client,client_length,&output,&output_length) == 0); free(output);
    size_t server_length=server_hello_record(server,0x1303,0x0304);
    for (size_t offset=5;offset<server_length;offset++) {
        uint8_t record[]={22,3,3,0,1,server[offset]}; vision_observe_tls(&wrap,1,record,sizeof(record));
    }
    CHECK("vision/server-hello-across-records-recognized",wrap.tls13_confirmed && !wrap.tls_disabled);
    uint8_t coalesced[39]; memcpy(coalesced,app,sizeof(app)); memcpy(coalesced+sizeof(app),app,2);
    REQUIRE("vision/coalesced-next-record-header",vision_wrap_payload(&wrap,coalesced,sizeof(coalesced),&output,&output_length) == 0); free(output);
    CHECK("vision/no-direct-before-coalesced-tail",!wrap.direct_sent && wrap.padding_active);
    REQUIRE("vision/coalesced-next-record-complete",vision_wrap_payload(&wrap,app+2,sizeof(app)-2,&output,&output_length) == 0); free(output);
    CHECK("vision/coalesced-tail-direct",wrap.direct_sent);
    vision_wrap_init(&wrap,uuid);
    REQUIRE("vision/retry-client-hello",vision_wrap_payload(&wrap,client,client_length,&output,&output_length) == 0); free(output);
    static const uint8_t retry[]={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    memcpy(server+11,retry,sizeof(retry)); vision_observe_tls(&wrap,1,server,server_length);
    CHECK("vision/retry-is-not-final-server-hello",!wrap.server_hello_seen && !wrap.tls13_confirmed);
    server_length=server_hello_record(server,0x1303,0x0304); vision_observe_tls(&wrap,1,server,server_length);
    CHECK("vision/final-server-hello-after-retry",wrap.server_hello_seen && wrap.tls13_confirmed && !wrap.tls_disabled);
    const size_t record_size=16389,record_count=9,total=record_size*record_count;
    uint8_t *large=malloc(total),*recovered=malloc(total); REQUIRE("vision/large-tls-fixture",large && recovered);
    for (size_t i=0;i<record_count;i++) {
        const uint8_t header[]={23,3,3,0x40,0}; memcpy(large+i*record_size,header,sizeof(header));
        memset(large+i*record_size+5,(int)(i+1),record_size-5);
    }
    vision_unpad_t unpad; vision_unpad_init(&unpad,uuid);
    vision_wrap_init(&wrap,uuid);
    REQUIRE("vision/large-client-hello",vision_wrap_payload(&wrap,client,client_length,&output,&output_length) == 0);
    uint8_t *plain=NULL; size_t plain_length=0; int direct=0;
    REQUIRE("vision/large-client-hello-delivered",vision_unpad_feed(&unpad,output,output_length,&plain,&plain_length,&direct) == 0);
    free(output); free(plain); vision_observe_tls(&wrap,1,server,server_length);
    REQUIRE("vision/large-tls-wrap",vision_wrap_payload(&wrap,large,total,&output,&output_length) == 0);
    size_t received=0; int transitioned=0;
    for (size_t offset=0;offset<output_length;) {
        size_t count=output_length-offset < 8192 ? output_length-offset : 8192;
        REQUIRE("vision/large-tls-unpad",vision_unpad_feed(&unpad,output+offset,count,&plain,&plain_length,&direct) == 0);
        REQUIRE("vision/large-tls-output-bounds",plain_length <= total-received);
        if (plain_length) memcpy(recovered+received,plain,plain_length);
        received+=plain_length; transitioned+=direct; offset+=count; free(plain);
    }
    CHECK("vision/large-tls-direct-preserves-every-byte",wrap.direct_sent && transitioned == 1 && received == total && !memcmp(large,recovered,total) && vision_unpad_complete(&unpad));
    vision_unpad_free(&unpad); free(output); free(large); free(recovered);
}

int main(void) {
    response_vectors();
    vless_config_t cfg; char error[128]; uint8_t packet[2048]; size_t length = 0;
    REQUIRE("packets/config", parse_core_uri("vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443", &cfg, error, sizeof(error)) == 0);
    vision_wire_vectors(cfg.uuid);
    vision_terminal_reads(cfg.uuid);
    vision_unconfirmed_tls(cfg.uuid);
    vision_confirmed_tls(cfg.uuid);
    const uint8_t ipv4[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,1,187,1,127,0,0,1};
    CHECK("packets/vless-ipv4-golden", vless_build_request(packet, sizeof(packet), &length, &cfg, "127.0.0.1", 443) == 0 && length == sizeof(ipv4) && memcmp(packet, ipv4, length) == 0);
    CHECK("packets/vless-capacity", vless_build_request(packet, sizeof(ipv4)-1, &length, &cfg, "127.0.0.1", 443) != 0 && length == 0);
    CHECK("packets/vless-ipv6", vless_build_request(packet, sizeof(packet), &length, &cfg, "::1", 1080) == 0 && length == 38 && packet[21] == 3 && packet[37] == 1);
    CHECK("packets/vless-domain", vless_build_request(packet, sizeof(packet), &length, &cfg, "vless-core.test", 80) == 0 && packet[21] == 2 && packet[22] == 15 && memcmp(packet + 23, "vless-core.test", 15) == 0);
    CHECK("packets/vless-empty-domain", vless_build_request(packet, sizeof(packet), &length, &cfg, "", 80) != 0);
    strcpy(cfg.flow, "xtls-rprx-vision");
    CHECK("packets/vless-flow", vless_build_request(packet, sizeof(packet), &length, &cfg, "127.0.0.1", 443) == 0 && packet[17] == 18 && packet[18] == 10 && packet[19] == 16 && memcmp(packet+20, cfg.flow, 16) == 0);
    for (int pads = 1; pads <= 8; pads++) {
        char value[16]; snprintf(value, sizeof(value), "%d", pads); setenv("VLESS_VISION_PAD_PACKETS", value, 1);
        vision_wrap_t wrap; vision_unpad_t unpad; vision_wrap_init(&wrap, cfg.uuid); vision_unpad_init(&unpad, cfg.uuid);
        uint8_t *block = NULL, *out = NULL; size_t size = 0, out_length = 0; int direct = 0;
        REQUIRE("vision/bootstrap", vision_wrap_bootstrap(&wrap, &block, &size) == 0);
        CHECK("vision/bootstrap-uuid", size >= 21 && memcmp(block, cfg.uuid, 16) == 0 && block[16] == 0);
        for (size_t i = 0; i < size; i++) { REQUIRE("vision/fragmented-bootstrap", vision_unpad_feed(&unpad, block+i, 1, &out, &out_length, &direct) == 0); CHECK("vision/bootstrap-no-payload", out_length == 0); free(out); }
        free(block); CHECK("vision/bootstrap-once", vision_wrap_bootstrap(&wrap, &block, &size) == 0 && block == NULL && size == 0);
        for (int p = 0; p < pads; p++) {
            const uint8_t data[] = "vless-core";
            REQUIRE("vision/wrap", vision_wrap_payload(&wrap, data, sizeof(data), &block, &size) == 0);
            uint8_t recovered[64]; size_t recovered_len = 0;
            for (size_t i = 0; i < size; i++) { REQUIRE("vision/fragmented-payload", vision_unpad_feed(&unpad, block+i, 1, &out, &out_length, &direct) == 0); if (out_length) memcpy(recovered+recovered_len, out, out_length); recovered_len += out_length; free(out); }
            CHECK("vision/roundtrip", recovered_len == sizeof(data) && memcmp(recovered, data, sizeof(data)) == 0);
            free(block);
        }
        vision_unpad_free(&unpad);
    }
    const char *pad_values[] = {"0", "1000", "invalid"}; const int expected[] = {1,32,8};
    for (int i = 0; i < 3; i++) { setenv("VLESS_VISION_PAD_PACKETS", pad_values[i], 1); vision_wrap_t wrap; vision_wrap_init(&wrap, cfg.uuid); CHECK("vision/padding-env", wrap.packets_left == expected[i]); }
    unsetenv("VLESS_VISION_PAD_PACKETS");
    vision_wrap_t wrap; vision_wrap_init(&wrap, cfg.uuid); uint8_t *out; size_t out_length;
    uint8_t hello[59],server[95],app[37]={23,3,3,0,32}; memset(app+5,42,sizeof(app)-5); client_hello_record(hello);
    REQUIRE("vision/hello", vision_wrap_payload(&wrap, hello, sizeof(hello), &out, &out_length) == 0); free(out);
    size_t server_length=server_hello_record(server,0x1303,0x0304); vision_observe_tls(&wrap,1,server,server_length);
    CHECK("vision/not-direct-too-early", !wrap.direct_sent);
    REQUIRE("vision/app-one", vision_wrap_payload(&wrap, app, sizeof(app), &out, &out_length) == 0);
    CHECK("vision/direct-transition", wrap.direct_sent && !wrap.padding_active && out[0] == 2); free(out);
    CHECK("vision/raw-after-direct", vision_wrap_payload(&wrap, app, sizeof(app), &out, &out_length) == 0 && out_length == sizeof(app) && memcmp(out, app, sizeof(app)) == 0); free(out);
    vision_wrap_init(&wrap,cfg.uuid); vision_unpad_t receive; vision_unpad_init(&receive,cfg.uuid);
    const uint8_t *messages[] = {hello,app,app}; const size_t sizes[] = {sizeof(hello),sizeof(app),sizeof(app)};
    for (int i = 0; i < 3; i++) {
        if (i == 1) vision_observe_tls(&wrap,1,server,server_length);
        REQUIRE("vision/direct-wrap", vision_wrap_payload(&wrap,messages[i],sizes[i],&out,&out_length) == 0);
        uint8_t *plain; size_t plain_length; int direct = 0;
        REQUIRE("vision/direct-unpad", vision_unpad_feed(&receive,out,out_length,&plain,&plain_length,&direct) == 0);
        CHECK("vision/direct-integrity", plain_length == sizes[i] && memcmp(plain,messages[i],plain_length) == 0);
        CHECK("vision/downstream-direct-flag", direct == (i == 1)); free(plain); free(out);
    }
    vision_unpad_free(&receive);
    const size_t lengths[] = {65534, 65535, 65536, 98304, 131071, 131072, 131073};
    for (size_t sample = 0; sample < sizeof(lengths) / sizeof(lengths[0]); sample++) {
        size_t input_length = lengths[sample];
        uint8_t *input = malloc(input_length), *recovered = malloc(input_length);
        REQUIRE("vision/large-allocate", input != NULL && recovered != NULL);
        for (size_t i = 0; i < input_length; i++) input[i] = (uint8_t)(i % 251);
        for (int pad_packets = 1; pad_packets <= 3; pad_packets++) {
            vision_wrap_init(&wrap, cfg.uuid); wrap.packets_left = pad_packets;
            vision_unpad_init(&receive, cfg.uuid);
            REQUIRE("vision/large-wrap", vision_wrap_payload(&wrap, input, input_length, &out, &out_length) == 0);
            size_t recovered_length = 0;
            for (size_t offset = 0; offset < out_length;) {
                size_t chunk = out_length - offset;
                if (chunk > 8192) chunk = 8192;
                uint8_t *plain = NULL; size_t plain_length = 0; int direct = 0;
                REQUIRE("vision/large-unpad", vision_unpad_feed(&receive, out + offset, chunk, &plain, &plain_length, &direct) == 0);
                REQUIRE("vision/large-output-bound", plain_length <= input_length - recovered_length);
                if (plain_length > 0) memcpy(recovered + recovered_length, plain, plain_length);
                recovered_length += plain_length; offset += chunk; free(plain);
            }
            CHECK("vision/large-payload-preserved", recovered_length == input_length && memcmp(recovered, input, input_length) == 0);
            free(out); vision_unpad_free(&receive);
        }
        free(input); free(recovered);
    }
    return test_result();
}
