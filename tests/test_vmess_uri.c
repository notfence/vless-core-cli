#include "check.h"
#include "uri.h"
#include "vmess.h"
#include <openssl/evp.h>

static int parse_json(const char *json,vless_config_t *config,char error[256]) {
    char uri[8192]="vmess://";
    EVP_EncodeBlock((unsigned char *)uri+8,(const unsigned char *)json,(int)strlen(json));
    return parse_core_uri(uri,config,error,256);
}

int main(void) {
    vless_config_t *config=calloc(1,sizeof(*config)); char error[256];
    REQUIRE("vmess/uri-storage",config);
    const char *modes[]={"auto","aes-128-gcm","chacha20-poly1305","none","zero"};
    const core_vmess_security_t expected[]={CORE_VMESS_AUTO,CORE_VMESS_AES128_GCM,CORE_VMESS_CHACHA20_POLY1305,CORE_VMESS_NONE,CORE_VMESS_ZERO};
    for (size_t i=0;i<5;i++) {
        char uri[512]; snprintf(uri,sizeof(uri),"vmess://00000000-0000-0000-0000-000000000001@127.0.0.1:443?encryption=%s&scy=%s&aid=0&alterId=0",modes[i],modes[i]);
        REQUIRE("vmess/address-form",!parse_core_uri(uri,config,error,sizeof(error)));
        CHECK("vmess/address-effective-config",config->protocol == CORE_PROTOCOL_VMESS && config->server_port == 443 && config->uuid[15] == 1 && config->vmess_security == expected[i] && !strcmp(config->security,"none"));
        char json[512]; snprintf(json,sizeof(json),"{\"v\":\"2\",\"ps\":\"fixture\",\"add\":\"127.0.0.1\",\"port\":443,\"id\":\"00000000-0000-0000-0000-000000000001\",\"aid\":\"0\",\"scy\":\"%s\",\"net\":\"tcp\",\"tls\":\"\",\"type\":\"none\"}",modes[i]);
        REQUIRE("vmess/base64-json-form",!parse_json(json,config,error));
        CHECK("vmess/base64-json-effective-config",config->protocol == CORE_PROTOCOL_VMESS && config->vmess_security == expected[i] && config->server_port == 443 && !strcmp(config->server_host,"127.0.0.1") && !strcmp(config->security,"none"));
    }
    const char *bad[]={"aid=1","aid=-0","alterId=4294967296","encryption=aes-128-cfb","encryption=mlkem768x25519plus.native.0rtt.key","encryption=auto&scy=none","flow=xtls-rprx-vision","type=ws","type=grpc","type=xhttp","security=invalid","authenticatedLength=true"};
    for (size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        char uri[512]; snprintf(uri,sizeof(uri),"vmess://00000000-0000-0000-0000-000000000001@127.0.0.1:443?%s",bad[i]);
        CHECK("vmess/unsupported-setting-rejected",parse_core_uri(uri,config,error,sizeof(error)) < 0);
    }
    const char *fields[]={"\"aid\":1","\"aid\":-0","\"aid\":1e0","\"aid\":0.0","\"v\":3","\"v\":true","\"port\":65536","\"port\":-1","\"port\":1.5","\"port\":184467440737095516160","\"id\":null","\"add\":\"bad\\r\\nHost: injected\"","\"type\":\"http\"","\"scy\":\"aes-128-cfb\"","\"scy\":\"auto\",\"encryption\":\"none\"","\"tls\":\"tls\",\"security\":\"none\""};
    for (size_t i=0;i<sizeof(fields)/sizeof(*fields);i++) {
        char json[1024]; snprintf(json,sizeof(json),"{\"add\":\"127.0.0.1\",\"port\":443,\"id\":\"00000000-0000-0000-0000-000000000001\",%s}",fields[i]);
        CHECK("vmess/json-invalid-setting-rejected",parse_json(json,config,error) < 0);
    }
    const char *certificate_options[]={"vcn","pcs"};
    for (size_t i=0;i<2;i++) {
        char json[512],uri[512];
        snprintf(json,sizeof(json),"{\"add\":\"127.0.0.1\",\"port\":443,\"id\":\"00000000-0000-0000-0000-000000000001\",\"%s\":\"unsupported\"}",certificate_options[i]);
        CHECK("vmess/json-unsupported-certificate-option",parse_json(json,config,error) < 0);
        snprintf(uri,sizeof(uri),"vmess://00000000-0000-0000-0000-000000000001@127.0.0.1:443?%s=unsupported",certificate_options[i]);
        CHECK("vmess/address-unsupported-certificate-option",parse_core_uri(uri,config,error,sizeof(error)) < 0);
    }
    const char *invalid64[]={"e30=garbage","e30===","e30==","e31=","e3=","e3 0=","e3+_",""};
    for (size_t i=0;i<sizeof(invalid64)/sizeof(*invalid64);i++) {
        char uri[256]; snprintf(uri,sizeof(uri),"vmess://%s",invalid64[i]);
        CHECK("vmess/base64-invalid-rejected",parse_core_uri(uri,config,error,sizeof(error)) < 0);
    }
    const char *ports[]={"0","65536","-1","+1","1.0","1e0","4294967296","184467440737095516160","\" 443\"","true","null"};
    for (size_t i=0;i<sizeof(ports)/sizeof(*ports);i++) {
        char json[512]; snprintf(json,sizeof(json),"{\"add\":\"127.0.0.1\",\"port\":%s,\"id\":\"00000000-0000-0000-0000-000000000001\"}",ports[i]);
        CHECK("vmess/json-port-strict-range",parse_json(json,config,error) < 0);
    }
    const char *bad_shapes[]={"{\"add\":\"127.0.0.1\",\"port\":443,\"id\":{}}","{\"add\":\"127.0.0.1\",\"port\":443,\"id\":\"00000000-0000-0000-0000-000000000001\",\"v\":[]}","{\"add\":\"127.0.0.1\",\"port\":443,\"id\":\"00000000-0000-0000-0000-000000000001\",\"aid\":{}}"};
    for (size_t i=0;i<sizeof(bad_shapes)/sizeof(*bad_shapes);i++) CHECK("vmess/json-required-field-types",parse_json(bad_shapes[i],config,error) < 0);
    const char *json="{\"add\":\"127.0.0.1\",\"port\":443,\"id\":\"00000000-0000-0000-0000-000000000001\",\"unknownObject\":{},\"unknownArray\":[],\"unknownNumber\":7,\"ps\":\"\xef\xbf\xbf\xef\xbf\xbf\"}";
    char encoded[4096]="vmess://"; EVP_EncodeBlock((unsigned char *)encoded+8,(const unsigned char *)json,(int)strlen(json));
    for (unsigned variant=0;variant<4;variant++) {
        char uri[sizeof(encoded)]; strcpy(uri,encoded);
        if (variant&1) for (char *p=uri+8;*p;p++) { if (*p == '+') *p='-'; else if (*p == '/') *p='_'; }
        if (variant&2) { size_t length=strlen(uri); while (length && uri[length-1] == '=') uri[--length]=0; }
        CHECK("vmess/base64-alphabets-and-padding",!parse_core_uri(uri,config,error,sizeof(error)));
    }
    free(config); return test_result();
}
