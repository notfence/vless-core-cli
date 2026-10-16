#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "tls_fixture.h"
#include "uri.h"
#include <openssl/pem.h>

typedef struct {
    int fd, variant;
    EVP_PKEY *key;
    uint8_t *certificate;
    size_t certificate_length;
    int empty_certificate, client_finished;
} peer_t;

static int peer_message(dynbuf_t *buffer, uint8_t type, const uint8_t *body, size_t length) {
    uint8_t header[4]={type,(uint8_t)(length>>16),(uint8_t)(length>>8),(uint8_t)length};
    return db_append(buffer,header,4) || db_append(buffer,body,length);
}

static void certificate_identity_cases(void) {
    const char *root=getenv("TEST_PRIVATE_ROOT");
    EVP_PKEY *key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","P-256");
    REQUIRE("identity/private-key",root && key);
    static const struct { const char *san,*purpose,*host; int accepted; } cases[]={
        {"DNS:vless-core.test","serverAuth","vless-core.test",1},
        {"DNS:vless-core.test","clientAuth","vless-core.test",0},
        {"IP:127.0.0.1","serverAuth","127.0.0.1",1},
        {"IP:::1","serverAuth","::1",1},
        {"IP:127.0.0.2","serverAuth","127.0.0.1",0},
        {"DNS:vless-core.test","serverAuth","wrong.test",0},
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        X509 *certificate=X509_new(); REQUIRE("identity/certificate",certificate);
        X509_set_version(certificate,2); ASN1_INTEGER_set(X509_get_serialNumber(certificate),(long)i+1);
        X509_gmtime_adj(X509_getm_notBefore(certificate),-60); X509_gmtime_adj(X509_getm_notAfter(certificate),3600);
        X509_NAME *name=X509_get_subject_name(certificate);
        X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"wrong-cn.test",-1,-1,0);
        X509_set_issuer_name(certificate,name); X509_set_pubkey(certificate,key);
        const int types[]={NID_subject_alt_name,NID_ext_key_usage,NID_key_usage};
        const char *values[]={cases[i].san,cases[i].purpose,"digitalSignature"};
        for (unsigned extension=0;extension<3;extension++) {
            X509_EXTENSION *value=X509V3_EXT_conf_nid(NULL,NULL,types[extension],(char *)values[extension]);
            REQUIRE("identity/certificate-extension",value && X509_add_ext(certificate,value,-1)); X509_EXTENSION_free(value);
        }
        REQUIRE("identity/certificate-signature",X509_sign(certificate,key,EVP_sha256()) > 0);
        char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/identity-ca.pem",root);
        FILE *file=fopen(path,"w"); REQUIRE("identity/ca-file",file && PEM_write_X509(file,certificate)); fclose(file);
        setenv("VLESS_CA_BUNDLE",path,1);
        unsigned char *der=NULL; int size=i2d_X509(certificate,&der); REQUIRE("identity/der",size > 0);
        size_t list_size=(size_t)size+5;
        uint8_t header[]={0,(uint8_t)(list_size>>16),(uint8_t)(list_size>>8),(uint8_t)list_size,(uint8_t)(size>>16),(uint8_t)(size>>8),(uint8_t)size};
        dynbuf_t body={0},message={0}; uint8_t empty[]={0,0};
        REQUIRE("identity/certificate-message",!db_append(&body,header,sizeof(header)) && !db_append(&body,der,(size_t)size) && !db_append(&body,empty,2) && !peer_message(&message,11,body.data,body.len));
        char error[256]={0}; int result=verify_tls_cert_message(cases[i].host,message.data,message.len,error,sizeof(error));
        CHECK("identity/server-certificate-purpose-and-san",cases[i].accepted ? result == 0 : result != 0);
        OPENSSL_free(der); db_free(&body); db_free(&message); X509_free(certificate);
    }
    for (unsigned i=0;i<3;i++) {
        dynbuf_t extensions={0}; const char *host=(const char *[]){"127.0.0.1","::1","vless-core.test"}[i];
        CHECK("identity/numeric-sni-omitted",ext_server_name(&extensions,host) == 0 && (i == 2 ? extensions.len > 0 : extensions.len == 0));
        db_free(&extensions);
    }
    EVP_PKEY_free(key);
}

static void *peer_run(void *opaque) {
    peer_t *peer=opaque;
    tls13_conn_t server={.fd=peer->fd};
    uint8_t type,*hello=NULL; size_t hello_length=0;
    dynbuf_t flight={0},certificate={0},server_hello={0};
    if (read_record(peer->fd,&type,&hello,&hello_length) != 0 || hello_length < 44) goto done;
    size_t sid_length=hello[38],offset=39+sid_length;
    if (offset+2 > hello_length) goto done;
    offset+=2+((size_t)hello[offset]<<8)+hello[offset+1];
    if (offset >= hello_length) goto done;
    offset+=1+hello[offset];
    if (offset+2 > hello_length) goto done;
    size_t end=offset+2+((size_t)hello[offset]<<8)+hello[offset+1]; offset+=2;
    uint8_t client_public[32]; int found=0;
    while (offset+4 <= end && end <= hello_length) {
        unsigned kind=((unsigned)hello[offset]<<8)+hello[offset+1];
        size_t length=((size_t)hello[offset+2]<<8)+hello[offset+3]; offset+=4;
        if (length > end-offset) goto done;
        if (kind == 51 && length >= 2) {
            for (size_t at=offset+2;at+4 <= offset+length;) {
                unsigned group=((unsigned)hello[at]<<8)+hello[at+1];
                size_t count=((size_t)hello[at+2]<<8)+hello[at+3]; at+=4;
                if (count > offset+length-at) goto done;
                if (group == 29 && count == 32) { memcpy(client_public,hello+at,32); found=1; }
                at+=count;
            }
        }
        offset+=length;
    }
    uint8_t private_key[32],public_key[32],shared[32],body[160];
    if (!found || x25519_generate(private_key,public_key) != 0 || x25519_shared(private_key,client_public,shared) != 0) goto done;
    size_t used=0; body[used++]=3; body[used++]=3;
    if (RAND_bytes(body+used,32) != 1) goto done;
    used+=32; body[used++]=(uint8_t)sid_length; memcpy(body+used,hello+39,sid_length); used+=sid_length;
    const uint8_t extensions[]={0x13,3,0,0,46,0,43,0,2,3,4,0,51,0,36,0,29,0,32};
    memcpy(body+used,extensions,sizeof(extensions)); used+=sizeof(extensions);
    memcpy(body+used,public_key,32); used+=32;
    if (peer_message(&server_hello,2,body,used) || configure_tls_cipher(&server,0x1303) != 0 ||
        db_append(&server.transcript,hello,hello_length) || db_append(&server.transcript,server_hello.data,server_hello.len)) goto done;
    uint8_t record_header[]={22,3,3,(uint8_t)(server_hello.len>>8),(uint8_t)server_hello.len};
    if (write_exact(peer->fd,record_header,5) || write_exact(peer->fd,server_hello.data,server_hello.len) || derive_handshake_keys(&server,shared,32)) goto done;
    const uint8_t empty_extensions[]={0,0};
    if (peer_message(&flight,8,empty_extensions,2)) goto done;
    const uint8_t request[]={0,0,8,0,13,0,4,0,2,8,7};
    if (peer->variant == 7 || peer->variant == 8) {
        if (peer_message(&flight,13,request,sizeof(request))) goto done;
        if (peer->variant == 8 && peer_message(&flight,13,request,sizeof(request))) goto done;
    }
    if (peer->variant == 10 && peer_message(&flight,13,(const uint8_t *)"\x01\x00\x00\x00",4)) goto done;
    if (peer->variant == 11 && peer_message(&flight,13,(const uint8_t *)"\x00\x00\x00",3)) goto done;
    uint8_t cert_header[]={0,(uint8_t)((peer->certificate_length+5)>>16),(uint8_t)((peer->certificate_length+5)>>8),(uint8_t)(peer->certificate_length+5),
        (uint8_t)(peer->certificate_length>>16),(uint8_t)(peer->certificate_length>>8),(uint8_t)peer->certificate_length};
    if (db_append(&certificate,cert_header,sizeof(cert_header)) || db_append(&certificate,peer->certificate,peer->certificate_length) || db_append(&certificate,empty_extensions,2)) goto done;
    if (peer->variant == 3 && peer_message(&flight,15,(const uint8_t *)"\x08\x07\x00\x01x",5)) goto done;
    if (peer_message(&flight,11,certificate.data,certificate.len)) goto done;
    if (peer->variant == 9 && peer_message(&flight,13,request,sizeof(request))) goto done;
    if (peer->variant == 4 && peer_message(&flight,11,certificate.data,certificate.len)) goto done;
    if (db_append(&server.transcript,flight.data,flight.len)) goto done;
    if (peer->variant != 1 && peer->variant != 3) {
        uint8_t transcript[64],signed_data[160],signature[512],verify[516]; size_t signature_length=sizeof(signature);
        memset(signed_data,32,64);
        const char context[]="TLS 1.3, server CertificateVerify";
        memcpy(signed_data+64,context,sizeof(context));
        if (transcript_hash(&server,transcript)) goto done;
        memcpy(signed_data+64+sizeof(context),transcript,32);
        EVP_MD_CTX *sign=EVP_MD_CTX_new(); EVP_PKEY_CTX *parameters=NULL;
        int ed=EVP_PKEY_base_id(peer->key) == EVP_PKEY_ED25519;
        int rsa=EVP_PKEY_base_id(peer->key) == EVP_PKEY_RSA;
        int ok=sign && EVP_DigestSignInit(sign,&parameters,ed ? NULL : EVP_sha256(),NULL,peer->key) == 1;
        if (ok && rsa) ok=EVP_PKEY_CTX_set_rsa_padding(parameters,RSA_PKCS1_PSS_PADDING) == 1 && EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters,32) == 1;
        if (ok) ok=EVP_DigestSign(sign,signature,&signature_length,signed_data,64+sizeof(context)+32) == 1;
        EVP_MD_CTX_free(sign);
        if (!ok) goto done;
        if (peer->variant == 2) signature[signature_length-1]^=1;
        verify[0]=ed || rsa ? 8 : 4; verify[1]=ed ? 7 : rsa ? 4 : 3;
        verify[2]=(uint8_t)(signature_length>>8); verify[3]=(uint8_t)signature_length; memcpy(verify+4,signature,signature_length);
        size_t before=flight.len;
        if (peer_message(&flight,15,verify,signature_length+4) || db_append(&server.transcript,flight.data+before,flight.len-before)) goto done;
        if (peer->variant == 5) {
            before=flight.len;
            if (peer_message(&flight,15,verify,signature_length+4) || db_append(&server.transcript,flight.data+before,flight.len-before)) goto done;
        }
    }
    uint8_t transcript[64],finished[64];
    if (transcript_hash(&server,transcript) || calc_finished_verify(&server,server.s_hs_traffic,transcript,finished)) goto done;
    if (peer->variant == 6) finished[0]^=1;
    if (peer_message(&flight,20,finished,32)) goto done;
    uint8_t *encrypted=NULL; size_t encrypted_length=0;
    if (encrypt_record(&server,server.s_hs_key,server.s_hs_iv,&server.s_hs_seq,22,flight.data,flight.len,&encrypted,&encrypted_length)) goto done;
    (void)write_exact(peer->fd,encrypted,encrypted_length); free(encrypted);
    if (peer->variant == 7) {
        uint8_t *record=NULL,*plain=NULL,inner=0; size_t record_size=0,plain_size=0;
        if (peer_message(&server.transcript,20,finished,32) || read_record(peer->fd,&type,&record,&record_size)) goto done;
        if (type == 20) { free(record); record=NULL; if (read_record(peer->fd,&type,&record,&record_size)) goto done; }
        int result=decrypt_record(&server,server.c_hs_key,server.c_hs_iv,&server.c_hs_seq,type,record,record_size,&plain,&plain_size,&inner);
        free(record);
        if (!result && inner == 22 && plain_size == 44 && !memcmp(plain,"\x0b\x00\x00\x04\x00\x00\x00\x00",8)) {
            peer->empty_certificate=1;
            if (!db_append(&server.transcript,plain,8) && !transcript_hash(&server,transcript) && !calc_finished_verify(&server,server.c_hs_traffic,transcript,finished))
                peer->client_finished=!memcmp(plain+8,"\x14\x00\x00\x20",4) && !CRYPTO_memcmp(plain+12,finished,32);
        }
        free(plain);
    }
    shutdown(peer->fd,SHUT_WR);
    uint8_t remaining[512]; while (recv(peer->fd,remaining,sizeof(remaining),0) > 0) {}
done:
    free(hello); db_free(&flight); db_free(&certificate); db_free(&server_hello); db_free(&server.transcript); close(peer->fd); return NULL;
}

int main(void) {
    const char *root=getenv("TEST_PRIVATE_ROOT"); REQUIRE("auth/private-root",root != NULL);
    certificate_identity_cases();
    for (int kind=0;kind<3;kind++) {
        int ed=kind == 1;
        EVP_PKEY *key=kind == 2 ? EVP_PKEY_Q_keygen(NULL,NULL,"RSA",2048) : ed ? EVP_PKEY_Q_keygen(NULL,NULL,"ED25519") : EVP_PKEY_Q_keygen(NULL,NULL,"EC","P-256");
        X509 *certificate=X509_new(); REQUIRE("auth/key-certificate",key && certificate);
        X509_set_version(certificate,2); ASN1_INTEGER_set(X509_get_serialNumber(certificate),1);
        X509_gmtime_adj(X509_getm_notBefore(certificate),-60); X509_gmtime_adj(X509_getm_notAfter(certificate),3600);
        X509_NAME *name=X509_get_subject_name(certificate);
        X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"vless-core.test",-1,-1,0);
        X509_set_issuer_name(certificate,name); X509_set_pubkey(certificate,key);
        REQUIRE("auth/certificate-sign",X509_sign(certificate,key,ed ? NULL : EVP_sha256()) > 0);
        unsigned char *der=NULL; int length=i2d_X509(certificate,&der); REQUIRE("auth/certificate-der",length > 0);
        char ca[PATH_MAX],pins[PATH_MAX]; snprintf(ca,sizeof(ca),"%s/auth-ca.pem",root); snprintf(pins,sizeof(pins),"%s/auth-pins",root);
        FILE *file=fopen(ca,"w"); REQUIRE("auth/ca-write",file && PEM_write_X509(file,certificate)); fclose(file);
        setenv("VLESS_CA_BUNDLE",ca,1); setenv("VLESS_XHTTP_PIN_FILE",pins,1);
        const char *modes[]={"strict","insecure","tofu"};
        for (size_t mode=0;mode<3;mode++) for (int variant=0;variant<12;variant++) {
            unlink(pins); int pair[2]; REQUIRE("auth/socketpair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
            peer_t peer={.fd=pair[1],.variant=variant,.key=key,.certificate=der,.certificate_length=(size_t)length}; pthread_t thread;
            REQUIRE("auth/peer-thread",pthread_create(&thread,NULL,peer_run,&peer) == 0);
            vless_config_t config; core_config_defaults(&config); strcpy(config.security,"tls"); strcpy(config.sni,"vless-core.test"); config.server_port=443; config.fp_mode=FP_QQ;
            setenv("VLESS_TLS_MODE",modes[mode],1);
            tls13_conn_t connection={.fd=pair[0]}; char error[256]={0};
            core_set_socket_io_timeout(pair[0],1000);
            int result=run_tls_handshake(&config,&connection,TLS_CIPHER_OFFER_CHACHA,error,sizeof(error));
            CHECK("auth/handshake-memory-released",connection.tls_handshake_bytes == 0);
            if (!variant && result) fprintf(stderr,"valid handshake %d/%s: %s\n",kind,modes[mode],error);
            if (variant == 0 || variant == 7) CHECK("auth/valid-signature",result == 0);
            else CHECK("auth/malformed-handshake-rejected",result != 0);
            if (variant && variant != 7 && mode == 2) CHECK("auth/failed-handshake-no-tofu-pin",access(pins,F_OK) != 0);
            shutdown(pair[0],SHUT_RDWR); close(pair[0]); pthread_join(thread,NULL); db_free(&connection.transcript);
            if (variant == 7) {
                CHECK("auth/requested-empty-client-certificate",peer.empty_certificate);
                CHECK("auth/requested-client-finished-transcript",peer.client_finished);
            }
            X509_free(connection.tls_peer_certificate); db_free(&connection.tls_certificate_message);
            db_free(&connection.tls_client_hello); EVP_PKEY_free(connection.tls_retry_key); db_free(&connection.tls_post_handshake);
        }
        OPENSSL_free(der); X509_free(certificate); EVP_PKEY_free(key);
    }
    CHECK("auth/global-handshake-memory-released",tls_buffer_bytes == 0);
    return test_result();
}
