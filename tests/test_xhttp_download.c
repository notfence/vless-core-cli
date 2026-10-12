#include "xhttp_download.h"
#include "uri.h"
#include "check.h"

static int parse(const char *json, vless_config_t *config, char *error) {
    core_json_t *root=core_json_parse(json,error,256);
    if (!root) return -1;
    int result=core_xhttp_download_parse(root,config,error,256); core_json_free(root); return result;
}

static int parent(const char *extra, const char *parameters, vless_config_t *config, char *error) {
    char encoded[3072],uri[4096]; size_t used=0; const char *hex="0123456789ABCDEF";
    for (const unsigned char *p=(const unsigned char *)extra;*p;p++) {
        if (used+4 > sizeof(encoded)) return -1;
        encoded[used++]='%'; encoded[used++]=hex[*p>>4]; encoded[used++]=hex[*p&15];
    }
    encoded[used]=0;
    int size=snprintf(uri,sizeof(uri),"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:443?type=xhttp&extra=%s%s",encoded,parameters);
    if (size < 0 || (size_t)size >= sizeof(uri)) return -1;
    return parse_core_uri(uri,config,error,256);
}

int main(void) {
    vless_config_t config,download; char error[256];
    CHECK("download/escaped-request-target",parse("{\"address\":\"127.0.0.1\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/vless core?keep=%2F\"}}",&config,error) == 0 && !strcmp(config.xhttp_path,"/vless%20core?keep=%2F"));
    CHECK("download/invalid-escaped-path",parse("{\"address\":\"127.0.0.1\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/bad%00\"}}",&config,error) < 0 && strstr(error,"path"));
    CHECK("download/plain-endpoint",parse("{\"address\":\"127.0.0.2\",\"port\":8080,\"network\":\"xhttp\",\"security\":\"none\",\"xhttpSettings\":{\"path\":\"/download\",\"host\":\"vless-core.test\"}}",&config,error) == 0 && !strcmp(config.server_host,"127.0.0.2") && config.server_port == 8080 && !strcmp(config.xhttp_path,"/download") && config.xhttp_download_only);
    CHECK("download/tls-independent-policy",parse("{\"address\":\"::1\",\"port\":443,\"network\":\"xhttp\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"vless-core.test\",\"allowInsecure\":true,\"alpn\":[\"h2\",\"http/1.1\"]}}",&config,error) == 0 && !strcmp(config.server_host,"::1") && !strcmp(config.sni,"vless-core.test") && config.allow_insecure && !strcmp(config.alpn,"h2,http/1.1"));
    CHECK("download/nested-extra-priority",parse("{\"address\":\"127.0.0.1\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/explicit\",\"extra\":{\"path\":\"/extra\",\"noGRPCHeader\":true}}}",&config,error) == 0 && !strcmp(config.xhttp_path,"/explicit") && config.xhttp_no_grpc_header);
    const char *invalid[]={
        "[]","{}","{\"network\":\"xhttp\",\"address\":\"127.0.0.1\"}","{\"network\":\"xhttp\",\"address\":\"bad host\",\"port\":443}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":0}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":65536}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":\"443\"}",
        "{\"address\":\"host\",\"port\":443,\"network\":\"grpc\"}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"security\":\"quic\"}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"tlsSettings\":{}}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"security\":\"reality\"}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"security\":\"tls\",\"tlsSettings\":{\"alpn\":[\"h3\"]}}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"security\":\"tls\",\"tlsSettings\":{\"allowInsecure\":\"true\"}}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"downloadSettings\":{}}","{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"xhttpSettings\":{\"downloadSettings\":{}}}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"xhttpSettings\":{\"extra\":{\"downloadSettings\":{}}}}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"xhttpSettings\":{\"headers\":{\"Host\":\"injected\"}}}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"Address\":\"different\",\"port\":443}",
        "{\"network\":\"xhttp\",\"address\":\"host\",\"port\":443,\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"first\",\"ServerName\":\"second\"}}",
    };
    for (size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++) CHECK("download/unsupported-or-malformed-settings-rejected",parse(invalid[i],&config,error) != 0 && error[0]);
    CHECK("download/no-implicit-tcp-transport",parse("{\"address\":\"127.0.0.1\",\"port\":443}",&config,error) != 0 && strstr(error,"network"));
    const char *extra="{\"downloadSettings\":{\"address\":\"127.0.0.2\",\"port\":443,\"network\":\"xhttp\"}}";
    REQUIRE("download/parent-uri-parsed",parent(extra,"",&config,error) == 0 && config.xhttp_download_settings[0]);
    CHECK("download/separate-endpoint-excludes-main-ip-override",core_xhttp_download_config(&config,&download,error,sizeof(error)) == 0 && download.ignore_server_ips);
    CHECK("download/stream-one-rejected",parent(extra,"&mode=stream-one",&config,error) != 0 && strstr(error,"stream-one"));
    CHECK("download/reality-auto-selects-stream-up",parent(extra,"&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",&config,error) == 0 && !strcmp(config.xhttp_mode,"stream-up"));
    CHECK("download/explicit-query-overrides-extra",parent(extra,"&downloadSettings=%7B%22address%22%3A%22127.0.0.1%22%2C%22port%22%3A443%2C%22network%22%3A%22xhttp%22%7D",&config,error) == 0 && core_xhttp_download_config(&config,&download,error,sizeof(error)) == 0 && !download.ignore_server_ips);
    return test_result();
}
