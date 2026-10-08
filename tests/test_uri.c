#include "check.h"
#include "uri.h"
#include "utils.h"
#include "server_ips.h"
#include <openssl/evp.h>
#include <arpa/inet.h>

#define PREFIX "vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?"
#define PBK "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
static vless_config_t config;
static char error[256];
static int parse(const char *uri) { return parse_core_uri(uri, &config, error, sizeof(error)); }

static void check_base64(void) {
    const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint8_t bytes[8], expected[8];
    size_t length;
    for (unsigned value = 1; value <= 255; value++) {
        if (strchr(alphabet, (int)value) || value == '=') continue;
        for (size_t position = 0; position < 4; position++) {
            char input[] = "AAAA";
            input[position] = (char)value;
            length = sizeof(bytes);
            CHECK("utils/base64-reject-every-nonalphabet-byte", base64url_decode(input, bytes, sizeof(bytes), &length) != 0 && length == sizeof(bytes));
        }
    }
    for (unsigned value = 1; value <= 255; value++) {
        if (value == '=') continue;
        char input[] = "AA==x";
        input[4] = (char)value;
        CHECK("utils/base64-reject-data-after-padding", base64url_decode(input, bytes, sizeof(bytes), &length) != 0);
    }
    for (size_t value = 0; value < 64; value++) {
        for (size_t position = 0; position < 4; position++) {
            char input[] = "AAAA", standard[] = "AAAA";
            input[position] = alphabet[value];
            standard[position] = value == 62 ? '+' : value == 63 ? '/' : alphabet[value];
            int expected_length = EVP_DecodeBlock(expected, (unsigned char *)standard, 4);
            CHECK("utils/base64-preserve-every-alphabet-value", expected_length == 3 && base64url_decode(input, bytes, sizeof(bytes), &length) == 0 && length == 3 && memcmp(bytes, expected, length) == 0);
        }
    }
    const char *encoded[] = {"", "Zg", "Zg==", "Zm8", "Zm8=", "Zm9v"};
    const char *plain[] = {"", "f", "f", "fo", "fo", "foo"};
    for (size_t i = 0; i < sizeof(encoded) / sizeof(*encoded); i++) {
        CHECK("utils/base64-preserve-padded-and-unpadded", base64url_decode(encoded[i], bytes, sizeof(bytes), &length) == 0 && length == strlen(plain[i]) && memcmp(bytes, plain[i], length) == 0);
    }
    CHECK("utils/base64-exact-capacity", base64url_decode("Zm9v", bytes, 3, &length) == 0 && length == 3 && memcmp(bytes, "foo", 3) == 0);
    CHECK("utils/base64-capacity-rejected", base64url_decode("Zm9v", bytes, 2, &length) != 0);
    CHECK("utils/base64-null", base64url_decode(NULL, bytes, sizeof(bytes), &length) != 0 && base64url_decode("AA", NULL, sizeof(bytes), &length) != 0 && base64url_decode("AA", bytes, sizeof(bytes), NULL) != 0);

    const size_t lengths[] = {4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1182, 1183, 1184, 4096};
    uint8_t source[4096], decoded[4096];
    char long_encoded[4 * ((sizeof(source) + 2) / 3) + 1];
    for (unsigned pattern = 0; pattern < 4; pattern++) {
        for (size_t i = 0; i < sizeof(source); i++) {
            source[i] = pattern == 0 ? 0 : pattern == 1 ? 255 : pattern == 2 ? (i % 2 ? 0x55 : 0xaa) : (uint8_t)i;
        }
        for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); i++) {
            int encoded_length = EVP_EncodeBlock((unsigned char *)long_encoded, source, (int)lengths[i]);
            REQUIRE("utils/base64-reference-encoding", encoded_length == (int)(4 * ((lengths[i] + 2) / 3)));
            for (int j = 0; j < encoded_length; j++) {
                if (long_encoded[j] == '+') long_encoded[j] = '-';
                if (long_encoded[j] == '/') long_encoded[j] = '_';
            }
            CHECK("utils/base64-long-padded-roundtrip", base64url_decode(long_encoded, decoded, lengths[i], &length) == 0 && length == lengths[i] && memcmp(decoded, source, length) == 0);
            while (encoded_length > 0 && long_encoded[encoded_length - 1] == '=') long_encoded[--encoded_length] = '\0';
            CHECK("utils/base64-long-unpadded-roundtrip", base64url_decode(long_encoded, decoded, lengths[i], &length) == 0 && length == lengths[i] && memcmp(decoded, source, length) == 0);
            CHECK("utils/base64-long-capacity-rejected", base64url_decode(long_encoded, decoded, lengths[i] - 1, &length) != 0);
        }
    }
}

int main(void) {
    check_base64();
    CHECK("uri/tcp-defaults", parse(PREFIX "type=tcp") == 0 && strcmp(config.security, "none") == 0 && config.flow[0] == 0 && config.fp_mode == FP_CHROME);
    const char *types[] = {"tcp", "ws", "xhttp", "grpc"};
    const char *securities[] = {"none", "tls", "reality"};
    const char *flows[] = {"", "xtls-rprx-vision", "invalid"};
    for (size_t t = 0; t < 4; t++) for (size_t s = 0; s < 3; s++) for (size_t f = 0; f < 3; f++) {
        char uri[1024], name[160];
        snprintf(uri, sizeof(uri), PREFIX "type=%s&security=%s&flow=%s&pbk=" PBK "&sid=01", types[t], securities[s], flows[f]);
        snprintf(name, sizeof(name), "uri/matrix/%s/%s/flow%zu", types[t], securities[s], f);
        int accepted = !(t == 1 && s == 2) && !(t == 0 && ((s == 0 && f != 0) || (s != 0 && f == 2)));
        CHECK(name, (parse(uri) == 0) == accepted);
        if (accepted && t > 0) CHECK("uri/non-tcp-flow-cleared", config.flow[0] == 0);
    }
    const char *invalid[] = {
        "", "http://127.0.0.1", "vless://bad@host:443", "vless://00000000-0000-0000-0000-000000000001@host:0",
        PREFIX "security=reality", PREFIX "security=unknown", PREFIX "flow=xtls-rprx-vision",
        PREFIX "type=tcp&network=ws", PREFIX "allowInsecure=1&insecure=0", PREFIX "TYPE=tcp&%74ype=ws",
        PREFIX "sni=%00", PREFIX "sni=%0a", PREFIX "sni=%ff", PREFIX "sni=%ed%a0%80", PREFIX "sni=%",
        PREFIX "=x", PREFIX "sni=a&", PREFIX "a", PREFIX "type=ws&security=reality",
        PREFIX "type=xhttp&mode=bad", PREFIX "type=grpc&mode=bad", PREFIX "encryption=bad",
        PREFIX "type=xhttp&mode=stream-up&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%7D",
        PREFIX "type=xhttp&extra=%7B%22uplinkDataPlacement%22%3A%22header%22%7D", "socks5://host:0", "socks5://[::1"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        char name[80]; snprintf(name, sizeof(name), "uri/reject/%zu", i); CHECK(name, parse(invalid[i]) != 0);
    }
    CHECK("uri/empty-security", parse(PREFIX "security=") == 0 && strcmp(config.security, "none") == 0);
    CHECK("uri/xhttp-auto-plain", parse(PREFIX "type=xhttp") == 0 && strcmp(config.xhttp_mode, "packet-up") == 0);
    CHECK("uri/xhttp-auto-tls", parse(PREFIX "type=xhttp&security=tls") == 0 && strcmp(config.xhttp_mode, "packet-up") == 0);
    CHECK("uri/xhttp-auto-reality", parse(PREFIX "type=xhttp&security=reality&pbk=" PBK) == 0 && strcmp(config.xhttp_mode, "stream-one") == 0);
    const char *fps[] = {"chrome", "random", "qq", "randomized", "firefox", "edge"};
    for (int i = 0; i < 6; i++) { char uri[512]; snprintf(uri, sizeof(uri), PREFIX "fp=%s", fps[i]); CHECK("uri/fingerprint", parse(uri) == 0 && config.fp_mode == (fingerprint_mode_t)i); }
    CHECK("uri/ipv6", parse("vless://00000000-0000-0000-0000-000000000001@[::1]:443") == 0 && strcmp(config.server_host, "::1") == 0);
    CHECK("uri/socks-default", parse("socks5://127.0.0.1#vless-core") == 0 && config.protocol == CORE_PROTOCOL_SOCKS5 && config.server_port == 1080);
    CHECK("uri/socks-auth", parse("socks5://vless%2Dcore:p%40ss@[::1]:1081#vless-core") == 0 && strcmp(config.socks5_user, "vless-core") == 0 && strcmp(config.socks5_pass, "p@ss") == 0);
    CHECK("uri/extra", parse(PREFIX "type=xhttp&extra=%7B%22sessionPlacement%22%3A%22header%22%2C%22seqKey%22%3A%22X-vless-core%22%2C%22xPaddingBytes%22%3A%2210-20%22%2C%22scMaxEachPostBytes%22%3A%222000%22%7D") == 0 && strcmp(config.xhttp_session_placement, "header") == 0 && strcmp(config.xhttp_seq_key, "X-vless-core") == 0 && config.xhttp_padding_min == 10 && config.xhttp_padding_max == 20 && config.xhttp_max_each_post_min == 2000);
    const char *modes[] = {"native", "xorpub", "random"};
    const char *rtts[] = {"0rtt", "1rtt"};
    for (int m = 0; m < 3; m++) for (int r = 0; r < 2; r++) {
        char uri[1024]; snprintf(uri, sizeof(uri), PREFIX "encryption=mlkem768x25519plus.%s.%s." PBK, modes[m], rtts[r]);
        CHECK("uri/encryption-mode", parse(uri) == 0 && config.encryption_enabled && config.encryption_xor_mode == m && config.encryption_relay_count == 1 && config.encryption_relays[0].key_len == 32);
    }
    uint8_t key[1184] = {1}; char encoded[1600]; EVP_EncodeBlock((unsigned char *)encoded, key, sizeof(key));
    for (size_t i = 0; encoded[i]; i++) { if (encoded[i] == '+') encoded[i] = '-'; if (encoded[i] == '/') encoded[i] = '_'; if (encoded[i] == '=') { encoded[i] = 0; break; } }
    char long_uri[5000]; snprintf(long_uri, sizeof(long_uri), PREFIX "encryption=mlkem768x25519plus.native.1rtt.%s", encoded);
    CHECK("uri/mlkem-relay", parse(long_uri) == 0 && config.encryption_relays[0].key_len == 1184);
    snprintf(long_uri, sizeof(long_uri), PREFIX "encryption=mlkem768x25519plus.native.1rtt." PBK "." PBK "." PBK "." PBK);
    CHECK("uri/four-relays", parse(long_uri) == 0 && config.encryption_relay_count == 4);
    strcat(long_uri, "." PBK); CHECK("uri/too-many-relays", parse(long_uri) != 0);
    memset(long_uri, 'a', CORE_URI_MAX_LENGTH + 1); long_uri[CORE_URI_MAX_LENGTH + 1] = 0;
    CHECK("uri/length-limit", parse(long_uri) != 0);
    CHECK("uri/null", parse_core_uri(NULL, &config, error, sizeof(error)) != 0);
    CHECK("uri/invalid-base64-reality-key", parse(PREFIX "security=reality&pbk=!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") != 0);
    CHECK("uri/invalid-base64-encryption-key", parse(PREFIX "encryption=mlkem768x25519plus.native.1rtt.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") != 0);
    CHECK("server-ips/order-deduplicate", core_set_server_ips(" 127.0.0.2 ,127.0.0.1,127.0.0.2\t") == 0 && core_server_ip_count() == 2);
    struct in_addr ip; inet_pton(AF_INET, "127.0.0.2", &ip);
    CHECK("server-ips/first", core_server_ip_at(0)->s_addr == ip.s_addr && core_server_ip_at(2) == NULL);
    const char *bad_ips[] = {"", "127.0.0.1,", ",127.0.0.1", "127.0.0.1,,127.0.0.2", "host", "[::1]", "999.0.0.1", "127.0.0.1\n"};
    for (size_t i = 0; i < sizeof(bad_ips) / sizeof(*bad_ips); i++) CHECK("server-ips/reject-atomic", core_set_server_ips(bad_ips[i]) != 0 && core_server_ip_count() == 2);
    char maximum_ips[1024] = "";
    for (int i = 0; i < 64; i++) { char value[32]; snprintf(value, sizeof(value), "%s127.0.0.%d", i ? "," : "", i+1); strcat(maximum_ips,value); }
    CHECK("server-ips/maximum", core_set_server_ips(maximum_ips) == 0 && core_server_ip_count() == 64);
    strcat(maximum_ips, ",127.0.0.65"); CHECK("server-ips/overflow-atomic", core_set_server_ips(maximum_ips) != 0 && core_server_ip_count() == 64);
    CHECK("server-ips/ipv6-mixed-deduplicate", core_set_server_ips("::1,127.0.0.1,0:0:0:0:0:0:0:1") == 0 && core_server_ip_count() == 2);
    uint8_t bytes[32]; size_t length = 0; char decoded[64];
    CHECK("utils/uuid", parse_uuid("00000000-0000-0000-0000-000000000001", bytes) == 0 && bytes[15] == 1);
    CHECK("utils/hex", hex_to_bytes("00ff10", bytes, sizeof(bytes), &length) == 0 && length == 3 && bytes[1] == 255);
    CHECK("utils/hex-invalid", hex_to_bytes("0", bytes, sizeof(bytes), &length) != 0 && hex_to_bytes("zz", bytes, sizeof(bytes), &length) != 0);
    CHECK("utils/percent", percent_decode("vless%2Dcore+test", decoded, sizeof(decoded)) == 0 && strcmp(decoded, "vless-core test") == 0);
    CHECK("utils/percent-overflow", percent_decode("1234", decoded, 4) != 0);
    CHECK("utils/base64-invalid", base64url_decode("!!!!", bytes, sizeof(bytes), &length) != 0);
    return test_result();
}
