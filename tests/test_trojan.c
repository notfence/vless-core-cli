#include "check.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include "trojan.h"
#include "uri.h"
#include "config_inspect.h"

EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
int __real_EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
int __real_EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t);
int __real_EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);
static unsigned fail_at, calls;
static int failing(void) { return fail_at && ++calls == fail_at; }
EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void) { return failing() ? NULL : __real_EVP_MD_CTX_new(); }
int __wrap_EVP_DigestInit_ex(EVP_MD_CTX *c, const EVP_MD *m, ENGINE *e) { return failing() ? 0 : __real_EVP_DigestInit_ex(c,m,e); }
int __wrap_EVP_DigestUpdate(EVP_MD_CTX *c, const void *p, size_t n) { return failing() ? 0 : __real_EVP_DigestUpdate(c,p,n); }
int __wrap_EVP_DigestFinal_ex(EVP_MD_CTX *c, unsigned char *p, unsigned int *n) { return failing() ? 0 : __real_EVP_DigestFinal_ex(c,p,n); }

static void uri_vectors(void) {
    vless_config_t config; char error[256],output[1024]; uint8_t expected[28];
    const uint8_t password[]="A+B:@%\xc3\xa9\0Tail";
    const char *uri="trojan://A+B%3A%40%25%C3%A9%00Tail@offline.invalid:443";
    REQUIRE("trojan/uri-password-vector",!core_trojan_password(password,sizeof(password)-1,expected));
    REQUIRE("trojan/uri-default",!parse_core_uri(uri,&config,error,sizeof(error)));
    CHECK("trojan/uri-defaults-tcp-tls",config.protocol == CORE_PROTOCOL_TROJAN && config.transport_mode == TRANSPORT_VISION && !strcmp(config.security,"tls") && config.fp_mode == FP_CHROME);
    CHECK("trojan/uri-password-exact-bytes",!memcmp(expected,config.trojan_hash,28));
    CHECK("trojan/inspect-offline-endpoints",!core_config_inspect(&config,output,sizeof(output),error,sizeof(error)) && !strcmp(output,"CONFIG\t1\nPRIMARY\toffline.invalid\t443\nEND\n"));
    CHECK("trojan/uri-percent-once",!parse_core_uri("trojan://%252B@127.0.0.1:443",&config,error,sizeof(error)) && !core_trojan_password((const uint8_t *)"%2B",3,expected) && !memcmp(expected,config.trojan_hash,28));
    CHECK("trojan/uri-ipv6",!parse_core_uri("trojan://fixture@[::1]:65535?security=none&type=raw",&config,error,sizeof(error)) && config.server_port == 65535 && !strcmp(config.server_host,"::1"));
    const char *ports[]={"0","65536","4294967296","184467440737095516160","+443","-1","443x"," 443",""};
    char value[256];
    for (size_t i=0;i<sizeof(ports)/sizeof(*ports);i++) {
        snprintf(value,sizeof(value),"trojan://private-fixture@127.0.0.1:%s",ports[i]);
        CHECK("trojan/invalid-port",parse_core_uri(value,&config,error,sizeof(error)) < 0 && !strstr(error,"private-fixture"));
    }
    const char *queries[]={"flow=xtls-rprx-vision","encryption=private-fixture","security=","type=ws","type=grpc","type=xhttp"};
    for (size_t i=0;i<sizeof(queries)/sizeof(*queries);i++) {
        snprintf(value,sizeof(value),"trojan://private-fixture@127.0.0.1:443?%s",queries[i]);
        CHECK("trojan/invalid-combination",parse_core_uri(value,&config,error,sizeof(error)) < 0 && !strstr(error,"private-fixture"));
        uint8_t zero[28]={0}; CHECK("trojan/invalid-config-cleans-credential",!memcmp(config.trojan_hash,zero,28));
    }
    for (unsigned stage=1;stage<=4;stage++) {
        fail_at=stage; calls=0;
        CHECK("trojan/uri-crypto-failure",parse_core_uri(uri,&config,error,sizeof(error)) < 0 && !strstr(error,"A+B"));
        fail_at=0;
        uint8_t zero[28]={0}; CHECK("trojan/uri-crypto-failure-cleans-credential",!memcmp(config.trojan_hash,zero,28));
    }
}

int main(void) {
    uri_vectors();
    uint8_t digest[28], wire[321]; size_t length=999;
    const char *hex="23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    REQUIRE("trojan/sha224-known-vector",!core_trojan_password((const uint8_t *)"abc",3,digest));
    REQUIRE("trojan/ipv4-request",!core_trojan_request(wire,sizeof(wire),&length,digest,"127.0.0.1",443));
    const uint8_t tail[]={13,10,1,1,127,0,0,1,1,187,13,10};
    CHECK("trojan/ipv4-wire",length == 68 && !memcmp(wire,hex,56) && !memcmp(wire+56,tail,sizeof(tail)));
    REQUIRE("trojan/ipv6-request",!core_trojan_request(wire,sizeof(wire),&length,digest,"::1",65535));
    uint8_t ip[16]; inet_pton(AF_INET6,"::1",ip);
    CHECK("trojan/ipv6-wire",length == 80 && wire[59] == 4 && !memcmp(wire+60,ip,16) && wire[76] == 255 && wire[77] == 255 && wire[78] == 13 && wire[79] == 10);
    REQUIRE("trojan/domain-request",!core_trojan_request(wire,sizeof(wire),&length,digest,"example.test",80));
    CHECK("trojan/domain-wire",length == 77 && wire[59] == 3 && wire[60] == 12 && !memcmp(wire+61,"example.test",12) && wire[73] == 0 && wire[74] == 80);
    char host[257]; memset(host,'a',255); host[255]=0;
    CHECK("trojan/maximum-header",!core_trojan_request(wire,320,&length,digest,host,1) && length == 320);
    memset(wire,0xa5,sizeof(wire)); length=999;
    CHECK("trojan/short-output-no-partial-secret",core_trojan_request(wire,319,&length,digest,host,1) < 0 && !length && wire[0] == 0xa5);
    host[255]='a'; host[256]=0;
    CHECK("trojan/oversized-domain",core_trojan_request(wire,sizeof(wire),&length,digest,host,1) < 0 && !length);
    CHECK("trojan/empty-domain",core_trojan_request(wire,sizeof(wire),&length,digest,"",1) < 0);
    CHECK("trojan/zero-port",core_trojan_request(wire,sizeof(wire),&length,digest,"localhost",0) < 0);
    CHECK("trojan/invalid-domain-control",core_trojan_request(wire,sizeof(wire),&length,digest,"a\r\nb",80) < 0);
    CHECK("trojan/empty-password",core_trojan_password((const uint8_t *)"",0,digest) < 0);
    const uint8_t password[]={'A','+',':','@',0,'b'}; uint8_t first[28],second[28];
    REQUIRE("trojan/binary-password",!core_trojan_password(password,sizeof(password),first));
    REQUIRE("trojan/password-explicit-length",!core_trojan_password(password,4,second));
    CHECK("trojan/password-not-truncated",memcmp(first,second,sizeof(first)) != 0);
    for (unsigned stage=1;stage<=4;stage++) {
        fail_at=stage; calls=0; memset(digest,0xa5,sizeof(digest));
        CHECK("trojan/digest-failure",core_trojan_password(password,sizeof(password),digest) < 0);
        uint8_t zero[28]={0}; CHECK("trojan/digest-failure-cleans-output",!memcmp(digest,zero,sizeof(digest)));
        fail_at=0;
        CHECK("trojan/digest-recovers",!core_trojan_password(password,sizeof(password),digest));
    }
    return test_result();
}
