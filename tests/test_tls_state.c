#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "../src/tls13_reality.c"
#include "uri.h"

static int hello_extension(const uint8_t *hello, size_t length, unsigned kind, const uint8_t **body, size_t *size) {
    if (length < 40) return -1;
    size_t offset=39+hello[38];
    if (offset+2 > length) return -1;
    offset+=2+((size_t)hello[offset]<<8)+hello[offset+1];
    if (offset >= length) return -1;
    offset+=1+hello[offset];
    if (offset+2 > length) return -1;
    offset+=2;
    while (offset+4 <= length) {
        unsigned type=((unsigned)hello[offset]<<8)|hello[offset+1];
        size_t count=((size_t)hello[offset+2]<<8)|hello[offset+3]; offset+=4;
        if (count > length-offset) return -1;
        if (type == kind) { *body=hello+offset; *size=count; return 0; }
        offset+=count;
    }
    return -1;
}

static void retry_vectors(const uint8_t *client,size_t length) {
    static const uint8_t random[]={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    uint8_t hello[96]={2,0,0,92,3,3}; memcpy(hello+6,random,32); hello[38]=32; memcpy(hello+39,client+39,32);
    const uint8_t tail[]={0x13,3,0,0,19,0,43,0,2,3,4,0,51,0,2,0,23,0,44,0,3,0,1,65};
    memcpy(hello+71,tail,sizeof(tail)); hello[3]=(uint8_t)(71+sizeof(tail)-4); size_t size=71+sizeof(tail);
    core_tls_hello_t parsed;
    CHECK("tls/retry-cookie-and-group",core_tls_hello_parse(hello,size,client,length,&parsed) == 0 && parsed.retry && parsed.group == 23 && parsed.cookie_length == 3);
    uint8_t *retry=NULL; size_t retry_length=0; EVP_PKEY *key=NULL;
    REQUIRE("tls/retry-clienthello",core_tls_hello_retry(client,length,&parsed,&retry,&retry_length,&key) == 0 && key);
    const uint8_t *value=NULL; size_t count=0;
    CHECK("tls/retry-cookie-preserved",hello_extension(retry,retry_length,44,&value,&count) == 0 && count == 3 && !memcmp(value,"\x00\x01" "A",3));
    CHECK("tls/retry-share-changed",hello_extension(retry,retry_length,51,&value,&count) == 0 && count == 71 && value[3] == 23);
    free(retry); EVP_PKEY_free(key);
    hello[87]=29; CHECK("tls/retry-already-offered-group",core_tls_hello_parse(hello,size,client,length,&parsed) != 0);
    hello[87]=25; CHECK("tls/retry-unadvertised-group",core_tls_hello_parse(hello,size,client,length,&parsed) != 0);
    hello[87]=23; hello[39]^=1; CHECK("tls/retry-wrong-session",core_tls_hello_parse(hello,size,client,length,&parsed) != 0); hello[39]^=1;
    for (size_t cut=0;cut<size;cut++) CHECK("tls/retry-truncation",core_tls_hello_parse(hello,cut,client,length,&parsed) != 0);
}

static void initial_share_vectors(void) {
    vless_config_t config; core_config_defaults(&config); strcpy(config.security,"tls"); strcpy(config.sni,"vless-core.test"); config.fp_mode=FP_FIREFOX;
    EVP_PKEY *key=NULL,*peer=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
    uint8_t private_key[32],public_key[32],random[32],auth[32],*hello=NULL,peer_public[65],shared[96],expected[96];
    size_t length=0,sid=0,public_length=0,shared_length=sizeof(shared),expected_length=sizeof(expected),count=0; const uint8_t *extension=NULL;
    REQUIRE("tls/initial-p256-clienthello",build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private_key,public_key,random,auth,&hello,&length,&sid,NULL,&key) == 0 && key && peer);
    REQUIRE("tls/initial-p256-extension",hello_extension(hello,length,51,&extension,&count) == 0);
    const uint8_t *offered=NULL;
    for (size_t offset=2;offset+4 <= count;) {
        size_t size=((size_t)extension[offset+2]<<8)|extension[offset+3];
        REQUIRE("tls/initial-p256-share-bound",size <= count-offset-4);
        if (extension[offset] == 0 && extension[offset+1] == 23 && size == 65) offered=extension+offset+4;
        offset+=size+4;
    }
    REQUIRE("tls/initial-p256-public-key",offered && EVP_PKEY_get_octet_string_param(peer,OSSL_PKEY_PARAM_PUB_KEY,peer_public,sizeof(peer_public),&public_length) == 1);
    CHECK("tls/initial-p256-private-key-matches-wire",core_tls_ecdh(key,23,peer_public,public_length,shared,&shared_length) == 0 && core_tls_ecdh(peer,23,offered,65,expected,&expected_length) == 0 && shared_length == expected_length && !memcmp(shared,expected,shared_length));
    free(hello); EVP_PKEY_free(key); EVP_PKEY_free(peer);
}

int main(int argc, char **argv) {
    if (argc == 2) {
        vless_config_t config; char error[256]={0}; tls13_conn_t *connection=NULL;
        REQUIRE("tls/live-config",parse_core_uri(argv[1],&config,error,sizeof(error)) == 0);
        int result=tls13_reality_connect(&config,&connection,error,sizeof(error));
        if (result) fprintf(stderr,"handshake: %s\n",error);
        CHECK("tls/live-retry-handshake",result == 0); tls13_reality_close(connection); return test_result();
    }
    vless_config_t config; core_config_defaults(&config); strcpy(config.security,"tls"); strcpy(config.sni,"vless-core.test"); strcpy(config.alpn,"http/1.1");
    uint8_t private_key[32],public_key[32],random[32],auth[32],*hello=NULL;
    size_t length=0,sid=0,extension_length=0; const uint8_t *extension=NULL;
    REQUIRE("tls/alpn-build",build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private_key,public_key,random,auth,&hello,&length,&sid,NULL,NULL) == 0);
    CHECK("tls/alpn-explicit-on-wire",hello_extension(hello,length,16,&extension,&extension_length) == 0 && extension_length == 11 && !memcmp(extension,"\x00\x09\x08http/1.1",11));
    retry_vectors(hello,length);
    initial_share_vectors();
    free(hello);
    for (unsigned fingerprint=0;fingerprint<3;fingerprint++) {
        config.fp_mode=(fingerprint_mode_t[]){FP_CHROME,FP_FIREFOX,FP_QQ}[fingerprint]; hello=NULL;
        REQUIRE("tls/advertised-certificate-capabilities-build",build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private_key,public_key,random,auth,&hello,&length,&sid,NULL,NULL) == 0);
        CHECK("tls/no-unsupported-certificate-compression",hello_extension(hello,length,27,&extension,&extension_length) != 0);
        CHECK("tls/no-unsupported-delegated-credentials",hello_extension(hello,length,34,&extension,&extension_length) != 0);
        free(hello);
    }
    tls13_conn_t negotiated={.tls_h2_required=1}; strcpy(negotiated.tls_offered_alpn,"h2,http/1.1");
    const uint8_t h2[]={0,9,0,16,0,5,0,3,2,'h','2'},none[]={0,0};
    CHECK("tls/alpn-h2-negotiated",tls_encrypted_extensions(&negotiated,h2,sizeof(h2)) == 0);
    negotiated.tls_selected_alpn[0]=0;
    CHECK("tls/alpn-missing-h2-rejected",tls_encrypted_extensions(&negotiated,none,sizeof(none)) != 0);
    negotiated.tls_is_reality=1;
    CHECK("tls/alpn-reality-implicit-h2",tls_encrypted_extensions(&negotiated,none,sizeof(none)) == 0);
    for (int request=0;request<2;request++) {
        int pair[2]; REQUIRE("tls/update-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t receiver={.fd=pair[0],.mode=CONN_MODE_TLS,.tls_auth_state=4},peer={0};
        REQUIRE("tls/update-ciphers",configure_tls_cipher(&receiver,0x1303) == 0 && configure_tls_cipher(&peer,0x1303) == 0);
        memset(receiver.s_app_traffic,7,32); memset(receiver.c_app_traffic,8,32); memcpy(peer.s_app_traffic,receiver.s_app_traffic,32);
        REQUIRE("tls/update-initial-keys",derive_key_iv_md(receiver.tls_md,receiver.s_app_traffic,32,32,receiver.s_app_key,receiver.s_app_iv) == 0 &&
            derive_key_iv_md(receiver.tls_md,receiver.c_app_traffic,32,32,receiver.c_app_key,receiver.c_app_iv) == 0);
        memcpy(peer.s_app_key,receiver.s_app_key,32); memcpy(peer.s_app_iv,receiver.s_app_iv,12);
        uint8_t control[]={24,0,0,1,(uint8_t)request},*record=NULL; size_t record_length=0;
        for (size_t part=0;part<sizeof(control);part++) {
            REQUIRE("tls/update-fragment-encrypt",encrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,22,control+part,1,&record,&record_length) == 0);
            REQUIRE("tls/update-fragment-write",write_exact(pair[1],record,record_length) == 0); free(record);
        }
        uint8_t secret[32];
        REQUIRE("tls/update-peer-secret",hkdf_expand_label_md(peer.tls_md,peer.s_app_traffic,32,"traffic upd",NULL,0,secret,32) == 0);
        REQUIRE("tls/update-peer-keys",derive_key_iv_md(peer.tls_md,secret,32,32,peer.s_app_key,peer.s_app_iv) == 0); peer.s_app_seq=0;
        REQUIRE("tls/update-payload-encrypt",encrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,23,(const uint8_t *)"vless-core",10,&record,&record_length) == 0);
        REQUIRE("tls/update-payload-write",write_exact(pair[1],record,record_length) == 0); free(record); shutdown(pair[1],SHUT_WR);
        uint8_t payload[80]; size_t size=0;
        CHECK("tls/update-fragmented-delivery",tls13_read_app(&receiver,payload,sizeof(payload),&size) == 0 && size == 10 && !memcmp(payload,"vless-core",10));
        CHECK("tls/update-no-raw-fallback",!receiver.reality_raw_direct);
        if (request) {
            core_set_socket_io_timeout(pair[1],100);
            uint8_t type,*response=NULL; size_t response_length=0;
            CHECK("tls/update-response",read_record(pair[1],&type,&response,&response_length) == 0 && type == 23); free(response);
        }
        close(pair[0]); close(pair[1]); db_free(&receiver.app_cache); db_free(&receiver.tls_post_handshake);
    }
    return test_result();
}
