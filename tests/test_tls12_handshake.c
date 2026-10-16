#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "tls_fixture.h"
#include "uri.h"
#include <openssl/pem.h>
#include <signal.h>

typedef struct {
    int fd,variant,ems,client_finished,empty_certificate;
    EVP_PKEY *key;
    const uint8_t *certificate;
    size_t certificate_length;
} peer12_t;

static int message12(dynbuf_t *buffer,unsigned type,const uint8_t *body,size_t length) {
    uint8_t header[]={(uint8_t)type,(uint8_t)(length>>16),(uint8_t)(length>>8),(uint8_t)length};
    return db_append(buffer,header,4) || db_append(buffer,body,length);
}
static int send12(int fd,const uint8_t *data,size_t length,size_t fragment) {
    for (size_t offset=0;offset<length;) {
        size_t count=length-offset; if (count > fragment) count=fragment;
        uint8_t header[]={22,3,3,(uint8_t)(count>>8),(uint8_t)count};
        if (write_exact(fd,header,5) || write_exact(fd,data+offset,count)) return -1;
        offset+=count;
    }
    return 0;
}
static void *peer12_run(void *opaque) {
    peer12_t *peer=opaque;
    tls13_conn_t state={.fd=peer->fd,.tls12_suite=core_tls12_suite(0xcca9),.tls_md=EVP_sha256(),.tls_hash_len=32,.tls_key_len=32};
    dynbuf_t flight={0},certificate={0};
    EVP_PKEY *exchange=NULL;
    uint8_t type=0,*hello=NULL,*record=NULL,*plain=NULL; size_t hello_length=0,record_length=0,plain_length=0;
    uint8_t random[32],public[32],shared[96],master[48],block[88],seed[64],hash[64],finished[12];
    if (read_record(peer->fd,&type,&hello,&hello_length) || type != 22 || hello_length < 42) goto cleanup;
    if (RAND_bytes(random,32) != 1) goto cleanup;
    uint8_t body[48]={3,3}; memcpy(body+2,random,32); body[35]=0xcc; body[36]=0xa9;
    size_t body_length=38;
    if (peer->ems) { body[39]=4; body[41]=23; body_length=44; }
    if (peer->variant == 15) memcpy(body+26,"DOWNGRD\x01",8);
    if (message12(&flight,2,body,body_length)) goto cleanup;
    size_t list_length=peer->certificate_length+3;
    uint8_t prefix[]={(uint8_t)(list_length>>16),(uint8_t)(list_length>>8),(uint8_t)list_length,
        (uint8_t)(peer->certificate_length>>16),(uint8_t)(peer->certificate_length>>8),(uint8_t)peer->certificate_length};
    if (db_append(&certificate,prefix,6) || db_append(&certificate,peer->certificate,peer->certificate_length)) goto cleanup;
    exchange=EVP_PKEY_Q_keygen(NULL,NULL,"X25519"); size_t public_length=32;
    if (!exchange || EVP_PKEY_get_raw_public_key(exchange,public,&public_length) != 1 || public_length != 32) goto cleanup;
    uint8_t parameters[36]={3,0,29,32}; memcpy(parameters+4,public,32);
    uint8_t signed_data[100],signature[128],key_message[168]; size_t signature_length=sizeof(signature);
    memcpy(signed_data,hello+6,32); memcpy(signed_data+32,random,32); memcpy(signed_data+64,parameters,sizeof(parameters));
    EVP_MD_CTX *sign=EVP_MD_CTX_new();
    int signed_ok=sign && EVP_DigestSignInit(sign,NULL,EVP_sha256(),NULL,peer->key) == 1 && EVP_DigestSign(sign,signature,&signature_length,signed_data,sizeof(signed_data)) == 1;
    EVP_MD_CTX_free(sign); if (!signed_ok) goto cleanup;
    if (peer->variant == 1) signature[signature_length-1]^=1;
    memcpy(key_message,parameters,36); key_message[36]=4; key_message[37]=3;
    key_message[38]=(uint8_t)(signature_length>>8); key_message[39]=(uint8_t)signature_length; memcpy(key_message+40,signature,signature_length);
    if (peer->variant == 3 && message12(&flight,12,key_message,40+signature_length)) goto cleanup;
    if (message12(&flight,11,certificate.data,certificate.len)) goto cleanup;
    if (peer->variant == 4 && message12(&flight,11,certificate.data,certificate.len)) goto cleanup;
    if (peer->variant != 2 && peer->variant != 3 && message12(&flight,12,key_message,40+signature_length)) goto cleanup;
    const uint8_t request[]={1,64,0,2,4,3,0,0};
    if (peer->variant == 5 || peer->variant == 11) {
        if (message12(&flight,13,request,sizeof(request))) goto cleanup;
        if (peer->variant == 5 && message12(&flight,13,request,sizeof(request))) goto cleanup;
    }
    if (peer->variant == 6 && message12(&flight,13,(const uint8_t *)"\x00\x00\x00\x00\x00\x00",6)) goto cleanup;
    if (peer->variant == 9 && message12(&flight,8,NULL,0)) goto cleanup;
    if (message12(&flight,14,NULL,0) || db_append(&state.transcript,hello,hello_length) || db_append(&state.transcript,flight.data,flight.len) ||
        send12(peer->fd,flight.data,flight.len,peer->variant == 10 ? 1 : 16384)) goto cleanup;
    if (read_record(peer->fd,&type,&record,&record_length) || type != 22) goto cleanup;
    if (peer->variant == 11) {
        peer->empty_certificate=record_length == 7 && !memcmp(record,"\x0b\x00\x00\x03\x00\x00\x00",7);
        if (!peer->empty_certificate || db_append(&state.transcript,record,record_length)) goto cleanup;
        free(record); record=NULL;
        if (read_record(peer->fd,&type,&record,&record_length) || type != 22) goto cleanup;
    }
    size_t shared_length=sizeof(shared);
    if (record_length != 37 || record[0] != 16 || record[4] != 32 || core_tls_ecdh(exchange,29,record+5,32,shared,&shared_length) ||
        db_append(&state.transcript,record,record_length)) goto cleanup;
    free(record); record=NULL;
    memcpy(seed,hello+6,32); memcpy(seed+32,random,32);
    if (peer->ems) {
        if (transcript_hash(&state,hash) || core_tls12_prf(EVP_sha256(),shared,shared_length,"extended master secret",hash,32,master,48)) goto cleanup;
    } else if (core_tls12_prf(EVP_sha256(),shared,shared_length,"master secret",seed,64,master,48)) goto cleanup;
    memcpy(seed,random,32); memcpy(seed+32,hello+6,32);
    if (core_tls12_prf(EVP_sha256(),master,48,"key expansion",seed,64,block,sizeof(block))) goto cleanup;
    memcpy(state.c_app_key,block,32); memcpy(state.s_app_key,block+32,32); memcpy(state.c_app_iv,block+64,12); memcpy(state.s_app_iv,block+76,12);
    if (read_record(peer->fd,&type,&record,&record_length) || type != 20 || record_length != 1 || record[0] != 1) goto cleanup;
    free(record); record=NULL;
    if (read_record_bounded(peer->fd,&type,&record,&record_length,1) || type != 22 ||
        core_tls12_record_open(state.tls12_suite,0,state.c_app_key,state.c_app_iv,state.tls12_c_mac,&state.c_app_seq,type,record,record_length,&plain,&plain_length) ||
        plain_length != 16 || plain[0] != 20 || transcript_hash(&state,hash) ||
        core_tls12_prf(EVP_sha256(),master,48,"client finished",hash,32,finished,12) || CRYPTO_memcmp(finished,plain+4,12)) goto cleanup;
    peer->client_finished=1;
    if (db_append(&state.transcript,plain,plain_length)) goto cleanup;
    OPENSSL_cleanse(plain,plain_length); free(plain); plain=NULL; free(record); record=NULL;
    if (peer->variant == 14) {
        const uint8_t invalid_ticket[]={4,0,0,6,0,0,0,60,0,1};
        if (send12(peer->fd,invalid_ticket,sizeof(invalid_ticket),16384)) goto cleanup;
    }
    uint8_t ccs[]={20,3,3,0,1,1}; if (peer->variant == 8) ccs[5]=2;
    if (write_exact(peer->fd,ccs,sizeof(ccs)) || transcript_hash(&state,hash) || core_tls12_prf(EVP_sha256(),master,48,"server finished",hash,32,finished,12)) goto cleanup;
    if (peer->variant == 7 || peer->variant == 12) finished[11]^=1;
    uint8_t message[16]={20,0,0,12}; memcpy(message+4,finished,12);
    size_t count=peer->variant == 13 ? 15 : sizeof(message);
    if (core_tls12_record_seal(state.tls12_suite,0,state.s_app_key,state.s_app_iv,state.tls12_s_mac,&state.s_app_seq,22,message,count,&record,&record_length) ||
        write_exact(peer->fd,record,record_length)) goto cleanup;
cleanup:
    free(hello); free(record); if (plain) { OPENSSL_cleanse(plain,plain_length); free(plain); }
    EVP_PKEY_free(exchange); db_free(&flight); db_free(&certificate); db_free(&state.transcript);
    OPENSSL_cleanse(shared,sizeof(shared)); OPENSSL_cleanse(master,sizeof(master)); OPENSSL_cleanse(block,sizeof(block)); OPENSSL_cleanse(&state,sizeof(state));
    close(peer->fd); return NULL;
}
static void key_usage_cases(const char *root, unsigned usage) {
    EVP_PKEY *key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","P-256"); X509 *certificate=X509_new();
    REQUIRE("tls12/fixture-certificate",key && certificate);
    X509_set_version(certificate,2); ASN1_INTEGER_set(X509_get_serialNumber(certificate),1);
    X509_gmtime_adj(X509_getm_notBefore(certificate),-60); X509_gmtime_adj(X509_getm_notAfter(certificate),3600);
    X509_NAME *name=X509_get_subject_name(certificate); X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"vless-core.test",-1,-1,0);
    X509_set_issuer_name(certificate,name); X509_set_pubkey(certificate,key);
    if (usage) {
        X509_EXTENSION *extension=X509V3_EXT_conf_nid(NULL,NULL,NID_key_usage,usage == 1 ? "critical,digitalSignature" : "critical,keyEncipherment");
        REQUIRE("tls12/key-usage-extension",extension && X509_add_ext(certificate,extension,-1)); X509_EXTENSION_free(extension);
    }
    REQUIRE("tls12/fixture-sign",X509_sign(certificate,key,EVP_sha256()) > 0);
    unsigned char *der=NULL; int length=i2d_X509(certificate,&der); REQUIRE("tls12/fixture-der",length > 0);
    char ca[PATH_MAX],pins[PATH_MAX]; snprintf(ca,sizeof(ca),"%s/tls12-ca.pem",root); snprintf(pins,sizeof(pins),"%s/tls12-pins",root);
    FILE *file=fopen(ca,"w"); REQUIRE("tls12/ca-file",file && PEM_write_X509(file,certificate)); fclose(file);
    setenv("VLESS_CA_BUNDLE",ca,1); setenv("VLESS_XHTTP_PIN_FILE",pins,1);
    const char *modes[]={"strict","insecure","tofu"};
    for (unsigned mode=0;mode<3;mode++) for (int ems=0;ems<2;ems++) for (int variant=0;variant<(usage ? 1 : 16);variant++) {
        unlink(pins); int pair[2]; REQUIRE("tls12/fixture-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        peer12_t peer={.fd=pair[1],.variant=variant,.ems=ems,.key=key,.certificate=der,.certificate_length=(size_t)length}; pthread_t thread;
        REQUIRE("tls12/fixture-thread",pthread_create(&thread,NULL,peer12_run,&peer) == 0);
        core_deadline_t deadline; REQUIRE("tls12/deadline-attached",core_deadline_attach(&deadline) == 0); core_deadline_begin(1000);
        vless_config_t config; core_config_defaults(&config); strcpy(config.security,"tls"); strcpy(config.sni,"vless-core.test"); config.server_port=443;
        setenv("VLESS_TLS_MODE",modes[mode],1);
        tls13_conn_t connection={.fd=pair[0]}; char error[256]={0};
        int result=run_tls_handshake(&config,&connection,TLS_CIPHER_OFFER_CHACHA,error,sizeof(error));
        int accepted=usage != 2 && (variant == 0 || variant == 10 || variant == 11);
        if (accepted && result) fprintf(stderr,"TLS 1.2 fixture %s/%d/%d: %s\n",modes[mode],ems,variant,error);
        CHECK("tls12/strict-handshake-state-and-proof",accepted ? !result : result != 0);
        CHECK("tls12/handshake-budget-released",!connection.tls_handshake_bytes && !tls_buffer_bytes);
        if (mode == 2) CHECK("tls12/tofu-after-authenticated-finished",accepted ? access(pins,F_OK) == 0 : access(pins,F_OK) != 0);
        core_deadline_end(); core_deadline_detach(); shutdown(pair[0],SHUT_RDWR); close(pair[0]); pthread_join(thread,NULL);
        if (accepted) CHECK("tls12/client-finished-authenticated",peer.client_finished);
        if (variant == 11) CHECK("tls12/optional-client-certificate-empty",peer.empty_certificate);
        X509_free(connection.tls_peer_certificate); db_free(&connection.tls_client_hello); db_free(&connection.tls_certificate_message);
        db_free(&connection.transcript); db_free(&connection.tls_post_handshake); EVP_PKEY_free(connection.tls_retry_key); OPENSSL_cleanse(&connection,sizeof(connection));
    }
    OPENSSL_free(der); X509_free(certificate); EVP_PKEY_free(key);
}
int main(void) {
    REQUIRE("tls12/ignore-sigpipe",signal(SIGPIPE,SIG_IGN) != SIG_ERR);
    const char *root=getenv("TEST_PRIVATE_ROOT"); REQUIRE("tls12/private-root",root != NULL);
    for (unsigned usage=0;usage<3;usage++) key_usage_cases(root,usage);
    return test_result();
}
