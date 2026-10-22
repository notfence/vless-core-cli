#include "check.h"
#include "uri.h"
#include "shadowsocks.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>

static vless_config_t config,reference;
static char error[256];
static int parse(const char *uri) { return parse_core_uri(uri,&config,error,sizeof(error)); }

static void forms(void) {
    const uint8_t password[]={'A','+','b',':','%','@',0,'Z'}; uint8_t key[32];
    REQUIRE("ss/uri-password-master",!core_ss_master(CORE_SS_AES128_GCM,password,sizeof(password),key));
    REQUIRE("ss/uri-raw-userinfo",!parse("ss://aes-128-gcm:A+b%3A%25%40%00Z@127.0.0.1:443#fixture"));
    CHECK("ss/uri-derived-key-only",config.protocol == CORE_PROTOCOL_SHADOWSOCKS && config.ss.count == 1 && config.ss.method == CORE_SS_AES128_GCM && !memcmp(config.ss.keys,key,16) && !strcmp(config.security,"none") && config.server_port == 443);
    reference=config;
    uint8_t credentials[128]="aes-128-gcm:"; size_t prefix=strlen((char *)credentials);
    memcpy(credentials+prefix,password,sizeof(password));
    char encoded[256],value[1024]; EVP_EncodeBlock((unsigned char *)encoded,credentials,(int)(prefix+sizeof(password)));
    for (unsigned variant=0;variant<4;variant++) {
        char user[256]; strcpy(user,encoded);
        if (variant&1) for (char *p=user;*p;p++) { if (*p == '+') *p='-'; if (*p == '/') *p='_'; }
        if (variant&2) { size_t n=strlen(user); while (n && user[n-1]=='=') user[--n]=0; }
        snprintf(value,sizeof(value),"ss://%s@127.0.0.1:443",user);
        CHECK("ss/uri-base64-userinfo-equivalent",!parse(value) && !memcmp(&config,&reference,sizeof(config)));
        memcpy(credentials+prefix+sizeof(password),"@127.0.0.1:443",strlen("@127.0.0.1:443"));
        EVP_EncodeBlock((unsigned char *)user,credentials,(int)(prefix+sizeof(password)+strlen("@127.0.0.1:443")));
        if (variant&1) for (char *p=user;*p;p++) { if (*p == '+') *p='-'; if (*p == '/') *p='_'; }
        if (variant&2) { size_t n=strlen(user); while (n && user[n-1]=='=') user[--n]=0; }
        snprintf(value,sizeof(value),"ss://%s#fixture",user);
        CHECK("ss/uri-legacy-equivalent",!parse(value) && !memcmp(&config,&reference,sizeof(config)));
    }
    REQUIRE("ss/uri-percent-once-master",!core_ss_master(CORE_SS_AES128_GCM,(const uint8_t *)"%41+",4,key));
    CHECK("ss/uri-percent-decoded-once-plus-preserved",!parse("ss://aes-128-gcm:%2541+@localhost:1") && !memcmp(config.ss.keys,key,16));
    CHECK("ss/uri-ipv6-port-boundary",!parse("ss://chacha20-ietf-poly1305:secret@[::1]:65535/?security=none&encryption=none") && config.ss.method == CORE_SS_CHACHA20_POLY1305 && !strcmp(config.server_host,"::1") && config.server_port == 65535);
}

static void keys(void) {
    const char *methods[]={"2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"};
    uint8_t raw[64]; for (unsigned i=0;i<sizeof(raw);i++) raw[i]=(uint8_t)i;
    for (unsigned method=0;method<3;method++) {
        size_t size=method ? 32 : 16;
        for (unsigned count=1;count<4;count++) {
            char user[512]="",key[128],value[1024];
            for (unsigned i=0;i<count;i++) { EVP_EncodeBlock((unsigned char *)key,raw+i,size); if (i) strcat(user,":"); strcat(user,key); }
            snprintf(value,sizeof(value),"ss://%s:%s@localhost:443",methods[method],user);
            int result=parse(value);
            if (method == 2 && count>1) CHECK("ss/uri-chacha2022-chain-rejected",result<0);
            else {
                REQUIRE("ss/uri-2022-key-chain",!result);
                CHECK("ss/uri-2022-key-count",config.ss.count == count);
                for (unsigned i=0;i<count;i++) CHECK("ss/uri-2022-key-order",!memcmp(config.ss.keys+i*size,raw+i,size));
            }
        }
        char encoded[128],value[1024]; uint8_t normalized[32];
        EVP_EncodeBlock((unsigned char *)encoded,raw,(int)size+1);
        snprintf(value,sizeof(value),"ss://%s:%s@localhost:443",methods[method],encoded);
        REQUIRE("ss/uri-long-psk-normalized",!core_ss_normalize((core_ss_method_t)(CORE_SS_2022_AES128_GCM+method),raw,size+1,normalized) && !parse(value));
        CHECK("ss/uri-long-psk-matches-xray-rule",!memcmp(config.ss.keys,normalized,size));
    }
    CHECK("ss/uri-2022-percent-encoded-psk",!parse("ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@localhost:443") && !memcmp(config.ss.keys,raw,16));
    char longest[CORE_URI_MAX_LENGTH+1]="ss://2022-blake3-aes-128-gcm:";
    for (unsigned i=0;i<150;i++) { if (i) strcat(longest,":"); strcat(longest,"AAECAwQFBgcICQoLDA0ODw=="); }
    strcat(longest,"@localhost:443");
    CHECK("ss/uri-long-chain-not-truncated",!parse(longest) && config.ss.count == 150 && !memcmp(config.ss.keys+149*16,raw,16));
    size_t length=strlen(longest); longest[length++]='#';
    memset(longest+length,'x',CORE_URI_MAX_LENGTH-length); longest[CORE_URI_MAX_LENGTH]=0;
    CHECK("ss/uri-exact-source-length",!parse(longest) && config.ss.count==150);
    CHECK("ss/uri-shared-config-storage-not-expanded",sizeof(config.ss)<=sizeof(config.encryption_relays));
}

static void invalid(void) {
    const char *values[]={
        "ss://","ss://@localhost:1","ss://aes-128-gcm:@localhost:1","ss://:secret@localhost:1",
        "ss://none:secret@localhost:1","ss://plain:secret@localhost:1","ss://aes-128-cfb:secret@localhost:1",
        "ss://aes-128-gcm:secret@localhost","ss://aes-128-gcm:secret@localhost:0","ss://aes-128-gcm:secret@localhost:+1",
        "ss://aes-128-gcm:secret@localhost:65536","ss://aes-128-gcm:secret@localhost:184467440737095516160",
        "ss://aes-128-gcm:secret@localhost:1/path","ss://aes-128-gcm:secret@localhost:1//",
        "ss://aes-128-gcm:secret@[localhost]:1","ss://aes-128-gcm:secret@[::1]extra:1",
        "ss://aes-128-gcm:secret@local host:1","ss://aes-128-gcm:secret@localhost:1@127.0.0.1:1",
        "ss://aes-128-gcm:se%cret@localhost:1","ss://aes-128-gcm:secret%@localhost:1",
        "ss://AA=+_@localhost:1","ss://Zg===@localhost:1","ss://Zh==@localhost:1","ss://AA=@localhost:1",
        "ss://2022-blake3-aes-128-gcm:AA==@localhost:1","ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw@localhost:1",
        "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODx==@localhost:1",
        "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==:@localhost:1",
        "ss://aes-128-gcm:secret@localhost:1?encryption=aes-128-gcm","ss://aes-128-gcm:secret@localhost:1?flow=xtls-rprx-vision",
        "ss://aes-128-gcm:secret@localhost:1?plugin=obfs-local","ss://aes-128-gcm:secret@localhost:1?type=ws&host=bad%0D%0AInjected",
        "ss://aes-128-gcm:secret@localhost:1?security=bad","ss://aes-128-gcm:secret@localhost:1?flow=x&flow="
    };
    for (size_t i=0;i<sizeof(values)/sizeof(*values);i++) {
        memset(&config,0xa5,sizeof(config)); int result=parse(values[i]);
        CHECK("ss/uri-invalid-config-rejected",result<0 && !strstr(error,"secret") && !strstr(error,"ss://") && !strstr(error,"Injected"));
        CHECK("ss/uri-error-clears-derived-keys",!memcmp(&config,&(vless_config_t){0},sizeof(config)));
    }
    for (unsigned old=0;old<2;old++) {
        const char *user="2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==";
        char text[512],encoded[1024],value[1024]; snprintf(text,sizeof(text),"%s%s",user,old ? "@localhost:1" : "");
        EVP_EncodeBlock((unsigned char *)encoded,(const unsigned char *)text,(int)strlen(text));
        snprintf(value,sizeof(value),"ss://%s%s",encoded,old ? "" : "@localhost:1");
        CHECK("ss/uri-2022-base64-userinfo-rejected",parse(value)<0);
    }
    char too_long[CORE_URI_MAX_LENGTH+2]; memset(too_long,'A',sizeof(too_long)); memcpy(too_long,"ss://",5); too_long[sizeof(too_long)-1]=0;
    CHECK("ss/uri-source-limit",parse(too_long)<0);
    const char *unsupported[]={"cert","ca","pinsha256","pinnedPeerCertificateSha256","pinnedPeerCertificateSpkiSha256","verifyCert","peer","vcn","pcs"};
    for (size_t i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++) {
        char value[512]; snprintf(value,sizeof(value),"ss://aes-128-gcm:secret@localhost:443?security=tls&%s=unsupported",unsupported[i]);
        CHECK("ss/uri-unsupported-trust-option-rejected",parse(value)<0 && !strstr(error,"secret") && !strstr(error,"unsupported"));
    }
}

static void websocket(void) {
    REQUIRE("ss/uri-websocket",!parse("ss://aes-128-gcm:secret@localhost:443?type=ws&security=tls&fp=firefox&host=ws.test%3A8443&path=%2Fss&ed=4096&heartbeatPeriod=1&headers=%7B%22X-SS-Fixture%22%3A%22present%22%7D"));
    CHECK("ss/uri-websocket-effective-settings",config.transport_mode==TRANSPORT_WS && config.fp_mode==FP_FIREFOX && !strcmp(config.security,"tls") && !strcmp(config.xhttp_host,"ws.test:8443") && !strcmp(config.xhttp_path,"/ss") && config.ws_early_data==4096 && config.ws_heartbeat_period==1 && strstr(config.ws_headers,"x-ss-fixture: present\r\n"));
    CHECK("ss/uri-websocket-reality-rejected",parse("ss://aes-128-gcm:secret@localhost:443?type=ws&security=reality")<0);
}

int main(void) { forms(); keys(); invalid(); websocket(); OPENSSL_cleanse(&config,sizeof(config)); OPENSSL_cleanse(&reference,sizeof(reference)); return test_result(); }
