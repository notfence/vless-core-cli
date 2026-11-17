#ifndef CORE_TEST_TLS_FIXTURE_H
#define CORE_TEST_TLS_FIXTURE_H
#include "../src/tls_records.c"
#include "../src/tls_certificate_compression.c"
#include "../src/tls_client_hello.c"
#include "../src/tls_certificate.c"
#include "../src/tls_handshake.c"
#include "../src/tls_transport.c"
#include "../src/tls_websocket.c"
#include "../src/tls_httpupgrade.c"
#include "../src/tls_xhttp.c"
#include "../src/tls_http2.c"
#include "../src/tls13_reality.c"

static inline int test_build_client_hello(const vless_config_t *config,int reality,tls_cipher_offer_t offer,
                                 uint8_t private_key[32],uint8_t public_key[32],uint8_t random[32],uint8_t auth[32],
                                 uint8_t **hello,size_t *length,size_t *session,const uint8_t *hybrid,EVP_PKEY **retained) {
    static const uint8_t fixture_hybrid[TLS_MLKEM768_PUBLIC_KEY_SIZE]={0};
    return build_client_hello(config,reality,offer,private_key,public_key,random,auth,hello,length,session,
                              hybrid ? hybrid : fixture_hybrid,retained);
}
#define build_client_hello test_build_client_hello
#endif
