#include "check.h"
#include "uri.h"
#include "vless.h"
#include "vision.h"

static void vision_wire_vectors(const uint8_t uuid[16]) {
    for (int command = 1; command <= 2; command++) {
        uint8_t wire[80]; memcpy(wire, uuid, 16);
        const uint8_t blocks[] = {0,0,3,0,2,'v','l','e',0xaa,0xbb,0,0,0,0,1,0xcc,0,0,7,0,1,'s','s','-','c','o','r','e',0xdd};
        memcpy(wire+16, blocks, sizeof(blocks)); wire[16+16] = (uint8_t)command;
        memcpy(wire+16+sizeof(blocks), "/raw-tail", 9);
        size_t wire_length = 16+sizeof(blocks)+9;
        for (size_t cut = 0; cut < 16+sizeof(blocks); cut++) {
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

int main(void) {
    vless_config_t cfg; char error[128]; uint8_t packet[2048]; size_t length = 0;
    REQUIRE("packets/config", parse_core_uri("vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443", &cfg, error, sizeof(error)) == 0);
    vision_wire_vectors(cfg.uuid);
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
    const uint8_t hello[] = {22,3,3,0,4,1,0,0,0}; const uint8_t app[] = {23,3,3,0,1,42};
    REQUIRE("vision/hello", vision_wrap_payload(&wrap, hello, sizeof(hello), &out, &out_length) == 0); free(out);
    REQUIRE("vision/app-one", vision_wrap_payload(&wrap, app, sizeof(app), &out, &out_length) == 0); free(out);
    CHECK("vision/not-direct-too-early", !wrap.direct_sent);
    REQUIRE("vision/app-two", vision_wrap_payload(&wrap, app, sizeof(app), &out, &out_length) == 0);
    CHECK("vision/direct-transition", wrap.direct_sent && !wrap.padding_active && out[0] == 2); free(out);
    CHECK("vision/raw-after-direct", vision_wrap_payload(&wrap, app, sizeof(app), &out, &out_length) == 0 && out_length == sizeof(app) && memcmp(out, app, sizeof(app)) == 0); free(out);
    vision_wrap_init(&wrap,cfg.uuid); vision_unpad_t receive; vision_unpad_init(&receive,cfg.uuid);
    const uint8_t *messages[] = {hello,app,app}; const size_t sizes[] = {sizeof(hello),sizeof(app),sizeof(app)};
    for (int i = 0; i < 3; i++) {
        REQUIRE("vision/direct-wrap", vision_wrap_payload(&wrap,messages[i],sizes[i],&out,&out_length) == 0);
        uint8_t *plain; size_t plain_length; int direct = 0;
        REQUIRE("vision/direct-unpad", vision_unpad_feed(&receive,out,out_length,&plain,&plain_length,&direct) == 0);
        CHECK("vision/direct-integrity", plain_length == sizes[i] && memcmp(plain,messages[i],plain_length) == 0);
        CHECK("vision/downstream-direct-flag", direct == (i == 2)); free(plain); free(out);
    }
    vision_unpad_free(&receive);
    return test_result();
}
