#include "check.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include "trojan.h"

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

int main(void) {
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
