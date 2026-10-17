#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "tls_fixture.h"
#include "uri.h"

static int allocation_failure;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) { if (allocation_failure) { allocation_failure=0; errno=ENOMEM; return NULL; } return __real_malloc(size); }

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

static void record_limit_vectors(void) {
    for (int etm=0;etm<2;etm++) {
        tls13_conn_t legacy={.tls12_suite=core_tls12_suite(0xc013),.tls_receive_record_limit=64,.tls12_etm=etm};
        uint8_t payload[128]={0},*plain=NULL,inner=0; size_t length=0; uint64_t sequence=0;
        CHECK("tls12/negotiated-cbc-expansion-rejected",decrypt_record(&legacy,legacy.s_app_key,legacy.s_app_iv,&sequence,23,payload,sizeof(payload),&plain,&length,&inner) < 0 && errno == EMSGSIZE && !sequence && !plain);
        CHECK("tls12/pool-retained-below-key-threshold",!xmux_transport_retire(&legacy));
        legacy.c_app_seq=TLS_RECORD_REKEY_LIMIT;
        CHECK("tls12/pool-retired-before-send-key-limit",xmux_transport_retire(&legacy));
        legacy.c_app_seq=0; legacy.s_app_seq=TLS_RECORD_REKEY_LIMIT;
        CHECK("tls12/pool-retired-before-receive-key-limit",xmux_transport_retire(&legacy));
        legacy.tls12_suite=NULL;
        CHECK("tls13/pool-uses-key-update-not-rotation",!xmux_transport_retire(&legacy));
    }
    tls13_conn_t connection={.tls_auth_state=4};
    REQUIRE("tls/record-limit-cipher",configure_tls_cipher(&connection,0x1303) == 0);
    uint8_t *data=calloc(1,16385),*record=NULL; size_t size=0;
    REQUIRE("tls/record-limit-payload",data);
    uint64_t sequence=0;
    CHECK("tls/oversized-plaintext-rejected",encrypt_record(&connection,connection.c_app_key,connection.c_app_iv,&sequence,23,data,16385,&record,&size) != 0);
    free(record); record=NULL; sequence=UINT64_MAX;
    CHECK("tls/sequence-cannot-wrap",encrypt_record(&connection,connection.c_app_key,connection.c_app_iv,&sequence,23,data,1,&record,&size) != 0 && sequence == UINT64_MAX);
    free(record); free(data);
    const uint8_t ticket[]={4,0,0,0};
    CHECK("tls/empty-session-ticket-rejected",tls_post_handshake(&connection,ticket,sizeof(ticket)) != 0);
    db_free(&connection.tls_post_handshake);
    const uint8_t valid_ticket[]={4,0,0,14,0,0,0,60,0,0,0,0,0,0,1,'x',0,0};
    CHECK("tls/session-ticket-structure-accepted",tls_post_handshake(&connection,valid_ticket,sizeof(valid_ticket)) == 0);
    db_free(&connection.tls_post_handshake);
    const uint8_t bad_extensions[]={0,6,0,51,0,2,0,29};
    CHECK("tls/key-share-forbidden-in-encrypted-extensions",tls_encrypted_extensions(&connection,bad_extensions,sizeof(bad_extensions)) != 0);
    const uint8_t unoffered[]={0,4,0xab,0xcd,0,0};
    CHECK("tls/unoffered-encrypted-extension-rejected",tls_encrypted_extensions(&connection,unoffered,sizeof(unoffered)) != 0);
    dynbuf_t cache={0};
    CHECK("tls/unexpected-inner-record-rejected",tls_application_plain(&connection,20,(const uint8_t *)"\x01",1,&cache) != 0);
    const uint8_t fatal[]={2,40};
    CHECK("tls/fatal-alert-is-not-ignored",tls_application_plain(&connection,21,fatal,sizeof(fatal),&cache) < 0);
    db_free(&cache);
    uint8_t *transcript=calloc(1,1024U*1024U+1);
    REQUIRE("tls/transcript-limit-payload",transcript);
    CHECK("tls/handshake-accumulation-limited",append_transcript(&connection,transcript,1024U*1024U+1) != 0);
    db_free(&connection.transcript);
    tls13_conn_t *connections=calloc(9,sizeof(*connections)); REQUIRE("tls/global-handshake-budget-fixture",connections);
    for (unsigned i=0;i<8;i++) REQUIRE("tls/global-handshake-budget-within-limit",append_transcript(connections+i,transcript,1024U*1024U) == 0);
    CHECK("tls/global-handshake-budget-enforced",append_transcript(connections+8,transcript,1024U*1024U) != 0);
    for (unsigned i=0;i<9;i++) db_free(&connections[i].transcript);
    CHECK("tls/global-handshake-budget-recovered",append_transcript(&connection,transcript,1024U*1024U) == 0);
    db_free(&connection.transcript); free(connections); free(transcript);
    CHECK("tls/global-handshake-budget-no-leak",tls_buffer_bytes == 0);
    allocation_failure=1;
    CHECK("tls/handshake-allocation-reservation-rollback",append_transcript(&connection,(const uint8_t *)"vless-core",10) != 0 && !tls_buffer_bytes && !connection.tls_handshake_bytes);
    REQUIRE("tls/handshake-allocation-recovery",append_transcript(&connection,(const uint8_t *)"vless-core",10) == 0);
    size_t accounted=tls_buffer_bytes; uint8_t block[1024]={0}; allocation_failure=1;
    CHECK("tls/handshake-resize-reservation-rollback",append_transcript(&connection,block,sizeof(block)) != 0 && tls_buffer_bytes == accounted && connection.transcript.len == 10 && !memcmp(connection.transcript.data,"vless-core",10));
    db_free(&connection.transcript); CHECK("tls/handshake-allocation-cleanup",tls_buffer_bytes == 0);
}
static void physical_tls_close_notify(void) {
    for (int legacy=0;legacy<2;legacy++) {
        int pair[2]; REQUIRE("tls/physical-close-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t *connection=calloc(1,sizeof(*connection)),peer={0};
        REQUIRE("tls/physical-close-state",connection != NULL);
        connection->fd=pair[0]; connection->xhttp_upload_fd=-1; connection->tls_auth_state=4; connection->xmux_async=1;
        if (legacy) { connection->tls12_suite=peer.tls12_suite=core_tls12_suite(0xcca8); connection->tls_md=EVP_sha256(); }
        else REQUIRE("tls/physical-close-ciphers",!configure_tls_cipher(connection,0x1303) && !configure_tls_cipher(&peer,0x1303));
        xmux_transport_close(connection);
        uint8_t type=0,*record=NULL,*plain=NULL,inner=0; size_t record_length=0,plain_length=0; uint64_t sequence=0;
        int result=read_record_bounded(pair[1],&type,&record,&record_length,legacy);
        CHECK("tls/physical-close-emits-close-notify",!result && !decrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&sequence,type,record,record_length,&plain,&plain_length,&inner) && inner == 21 && plain_length == 2 && plain[1] == 0);
        free(plain); free(record); close(pair[1]);
    }
}

static void automatic_update_vectors(void) {
    for (unsigned pooled=0;pooled<2;pooled++) {
        int pair[2]; REQUIRE("tls/automatic-update-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t sender={.fd=pair[0],.mode=CONN_MODE_TLS,.tls_auth_state=4,.xmux_async=(int)pooled},peer={0};
        REQUIRE("tls/automatic-update-ciphers",configure_tls_cipher(&sender,0x1303) == 0 && configure_tls_cipher(&peer,0x1303) == 0);
        memset(sender.c_app_traffic,7,32); memcpy(peer.s_app_traffic,sender.c_app_traffic,32);
        REQUIRE("tls/automatic-update-keys",derive_key_iv_md(sender.tls_md,sender.c_app_traffic,32,32,sender.c_app_key,sender.c_app_iv) == 0);
        memcpy(peer.s_app_key,sender.c_app_key,32); memcpy(peer.s_app_iv,sender.c_app_iv,12);
        sender.c_app_seq=peer.s_app_seq=TLS_RECORD_REKEY_LIMIT;
        if (pooled) {
            REQUIRE("tls/automatic-pooled-update-queue",db_append(&sender.xmux_plain_output,"vless-core",10) == 0);
            REQUIRE("tls/automatic-pooled-update-flush",xmux_transport_flush(&sender) == 0 && xmux_transport_flush(&sender) == 0 && xmux_transport_flush(&sender) == 0);
            CHECK("tls/control-record-not-counted-as-upload",sender.xmux_flushed == 10);
        } else REQUIRE("tls/automatic-single-update-write",reality_write_app_records(&sender,(const uint8_t *)"vless-core",10) == 0);
        uint8_t type,*record=NULL,*plain=NULL,inner=0; size_t size=0,length=0;
        REQUIRE("tls/automatic-update-wire",read_record(pair[1],&type,&record,&size) == 0 && decrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,type,record,size,&plain,&length,&inner) == 0);
        CHECK("tls/automatic-update-precedes-payload",inner == 22 && length == 5 && !memcmp(plain,"\x18\x00\x00\x01\x00",5)); free(record); free(plain);
        REQUIRE("tls/automatic-update-peer-rotate",tls_update_keys(&peer,0) == 0);
        REQUIRE("tls/automatic-update-new-key-wire",read_record(pair[1],&type,&record,&size) == 0 && decrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,type,record,size,&plain,&length,&inner) == 0);
        CHECK("tls/automatic-update-new-key-payload",inner == 23 && length == 10 && !memcmp(plain,"vless-core",10) && sender.c_app_seq == 1);
        free(record); free(plain); db_free(&sender.xmux_plain_output); db_free(&sender.xmux_wire_output); close(pair[0]); close(pair[1]);
    }
    int pair[2]; REQUIRE("tls/receive-update-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    tls13_conn_t receiver={.fd=pair[0],.mode=CONN_MODE_TLS,.tls_auth_state=4,.s_app_seq=TLS_RECORD_REKEY_LIMIT},peer={0};
    REQUIRE("tls/receive-update-cipher",configure_tls_cipher(&receiver,0x1303) == 0 && configure_tls_cipher(&peer,0x1303) == 0);
    memset(receiver.c_app_traffic,7,32);
    REQUIRE("tls/receive-update-keys",derive_key_iv_md(receiver.tls_md,receiver.c_app_traffic,32,32,receiver.c_app_key,receiver.c_app_iv) == 0);
    memcpy(peer.s_app_key,receiver.c_app_key,32); memcpy(peer.s_app_iv,receiver.c_app_iv,12);
    dynbuf_t cache={0};
    REQUIRE("tls/receive-update-request",tls_application_plain(&receiver,23,(const uint8_t *)"vless-core",10,&cache) == 0);
    uint8_t type,*record=NULL,*plain=NULL,inner=0; size_t size=0,length=0;
    REQUIRE("tls/receive-update-request-wire",read_record(pair[1],&type,&record,&size) == 0 && decrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,type,record,size,&plain,&length,&inner) == 0);
    CHECK("tls/receive-update-requested-once",inner == 22 && length == 5 && plain[4] == 1 && receiver.tls_receive_update_requested);
    free(record); free(plain);
    REQUIRE("tls/receive-update-second-payload",tls_application_plain(&receiver,23,(const uint8_t *)"x",1,&cache) == 0);
    uint8_t byte; CHECK("tls/receive-update-not-repeated",recv(pair[1],&byte,1,MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK("tls/receive-update-request-cleared",tls_update_keys(&receiver,0) == 0 && !receiver.tls_receive_update_requested && !receiver.s_app_seq);
    db_free(&cache); close(pair[0]); close(pair[1]);
}

static void key_update_record_boundaries(void) {
    static const uint8_t update[]={24,0,0,1,1};
    static const uint8_t ticket[]={4,0,0,14,0,0,0,60,0,0,0,0,0,0,1,'x',0,0};
    for (unsigned pooled=0;pooled<2;pooled++) for (unsigned variant=0;variant<7;variant++) for (unsigned split=0;split<2;split++) {
        int pair[2]; REQUIRE("tls/boundary-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t receiver={.fd=pair[0],.mode=CONN_MODE_TLS,.tls_auth_state=4,.xmux_async=(int)pooled,.s_app_seq=TLS_RECORD_REKEY_LIMIT,.c_app_seq=7};
        REQUIRE("tls/boundary-cipher",configure_tls_cipher(&receiver,0x1303) == 0);
        memset(receiver.s_app_traffic,7,32); memset(receiver.c_app_traffic,8,32);
        REQUIRE("tls/boundary-keys",derive_key_iv_md(receiver.tls_md,receiver.s_app_traffic,32,32,receiver.s_app_key,receiver.s_app_iv) == 0 &&
            derive_key_iv_md(receiver.tls_md,receiver.c_app_traffic,32,32,receiver.c_app_key,receiver.c_app_iv) == 0);
        uint8_t secrets[128]; memcpy(secrets,receiver.s_app_traffic,64); memcpy(secrets+64,receiver.c_app_traffic,64);
        uint8_t keys[88]; memcpy(keys,receiver.s_app_key,32); memcpy(keys+32,receiver.s_app_iv,12);
        memcpy(keys+44,receiver.c_app_key,32); memcpy(keys+76,receiver.c_app_iv,12);
        uint8_t record[64]; size_t length=0;
        if (variant == 1 || variant == 6) { memcpy(record,ticket,sizeof(ticket)); length=sizeof(ticket); }
        if (variant != 5) { memcpy(record+length,update,sizeof(update)); length+=sizeof(update); }
        if (variant == 2) { memcpy(record+length,ticket,sizeof(ticket)); length+=sizeof(ticket); }
        if (variant == 3) { memcpy(record+length,update,sizeof(update)); length+=sizeof(update); }
        if (variant == 4 || variant == 6) record[length++]=0;
        dynbuf_t cache={0}; int result=0; size_t prefix=split && length ? (variant < 2 ? length-1 : 4) : 0;
        if (prefix) {
            result=tls_application_plain(&receiver,22,record,prefix,&cache);
            if (variant == 0 || variant == 1) {
                CHECK("tls/incomplete-update-does-not-change-keys",result == 0 && receiver.s_app_seq == TLS_RECORD_REKEY_LIMIT && receiver.c_app_seq == 7 &&
                    !memcmp(secrets,receiver.s_app_traffic,64) && !memcmp(secrets+64,receiver.c_app_traffic,64) && !receiver.xmux_wire_output.len && !receiver.tls_receive_update_requested);
            }
        }
        if (!result) result=tls_application_plain(&receiver,22,length ? record+prefix : NULL,length-prefix,&cache);
        int accepted=variant == 0 || variant == 1;
        CHECK("tls/key-update-record-boundary",accepted ? result == 0 && !receiver.s_app_seq : result < 0);
        if (!accepted) {
            CHECK("tls/invalid-update-preserves-keys-and-sequences",receiver.s_app_seq == TLS_RECORD_REKEY_LIMIT && receiver.c_app_seq == 7 &&
                !memcmp(secrets,receiver.s_app_traffic,64) && !memcmp(secrets+64,receiver.c_app_traffic,64) &&
                !memcmp(keys,receiver.s_app_key,32) && !memcmp(keys+32,receiver.s_app_iv,12) &&
                !memcmp(keys+44,receiver.c_app_key,32) && !memcmp(keys+76,receiver.c_app_iv,12));
            uint8_t byte;
            CHECK("tls/invalid-update-has-no-response",!receiver.xmux_wire_output.len && !receiver.tls_receive_update_requested &&
                recv(pair[1],&byte,1,MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        }
        db_free(&receiver.tls_post_handshake); db_free(&receiver.xmux_wire_output); db_free(&cache); close(pair[0]); close(pair[1]);
    }
    for (unsigned pooled=0;pooled<2;pooled++) for (unsigned empty=0;empty<3;empty++) {
        int pair[2]; REQUIRE("tls/boundary-wire-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
        tls13_conn_t receiver={.fd=pair[0],.mode=CONN_MODE_TLS,.tls_auth_state=4,.xmux_async=(int)pooled},peer={0};
        REQUIRE("tls/boundary-wire-ciphers",configure_tls_cipher(&receiver,0x1303) == 0 && configure_tls_cipher(&peer,0x1303) == 0);
        uint8_t payload[32]; size_t length=0;
        if (!empty) { memcpy(payload,update,sizeof(update)); memcpy(payload+sizeof(update),ticket,sizeof(ticket)); length=sizeof(update)+sizeof(ticket); }
        uint8_t *record=NULL; size_t record_length=0; unsigned type=empty == 2 ? 23 : 22;
        REQUIRE("tls/boundary-wire-encrypt",encrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,(uint8_t)type,payload,length,&record,&record_length) == 0 &&
            write_exact(pair[1],record,record_length) == 0); free(record);
        REQUIRE("tls/boundary-wire-following-data",encrypt_record(&peer,peer.s_app_key,peer.s_app_iv,&peer.s_app_seq,23,(const uint8_t *)"vless-core",10,&record,&record_length) == 0 &&
            write_exact(pair[1],record,record_length) == 0); free(record);
        uint8_t output[16]; size_t count=0; int result=pooled ? xmux_transport_collect(&receiver) : tls13_read_app(&receiver,output,sizeof(output),&count);
        CHECK("tls/physical-record-boundaries-enforced",empty == 2 ? result >= 0 && (pooled ? receiver.h2_net_cache.len == 10 : count == 10) : result < 0);
        if (empty != 2) CHECK("tls/invalid-physical-record-does-not-rotate",receiver.s_app_seq == 1 && !receiver.c_app_seq && !receiver.xmux_wire_output.len);
        db_free(&receiver.tls_post_handshake); db_free(&receiver.xmux_raw_input); db_free(&receiver.xmux_wire_output);
        db_free(&receiver.app_cache); db_free(&receiver.h2_net_cache); close(pair[0]); close(pair[1]);
    }
}

static void incoming_record_vectors(void) {
    tls13_conn_t connection={0}; REQUIRE("tls/incoming-record-cipher",configure_tls_cipher(&connection,0x1303) == 0);
    static const struct { size_t content,padding; unsigned limit; int accepted; } cases[]={
        {16384,0,0,1},{16385,0,0,0},{16384,239,0,1},{16384,240,0,0},{16384,239,16385,0},
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        size_t inner_size=cases[i].content+1+cases[i].padding,encrypted_size=inner_size+16;
        uint8_t *inner=calloc(1,inner_size),*encrypted=malloc(encrypted_size); REQUIRE("tls/incoming-record-fixture",inner && encrypted);
        memset(inner,'A',cases[i].content); inner[cases[i].content]=23;
        uint8_t header[]={23,3,3,(uint8_t)(encrypted_size>>8),(uint8_t)encrypted_size};
        EVP_CIPHER_CTX *cipher=EVP_CIPHER_CTX_new(); int written=0,final=0;
        REQUIRE("tls/independent-peer-record",cipher && EVP_EncryptInit_ex(cipher,EVP_chacha20_poly1305(),NULL,connection.s_app_key,connection.s_app_iv) == 1 &&
            EVP_EncryptUpdate(cipher,NULL,&written,header,5) == 1 && EVP_EncryptUpdate(cipher,encrypted,&written,inner,(int)inner_size) == 1 &&
            EVP_EncryptFinal_ex(cipher,encrypted+written,&final) == 1 && EVP_CIPHER_CTX_ctrl(cipher,EVP_CTRL_AEAD_GET_TAG,16,encrypted+inner_size) == 1);
        EVP_CIPHER_CTX_free(cipher); free(inner); connection.tls_receive_record_limit=cases[i].limit;
        uint8_t *plain=NULL,type=0; size_t length=0; uint64_t sequence=0;
        int result=decrypt_record(&connection,connection.s_app_key,connection.s_app_iv,&sequence,23,encrypted,encrypted_size,&plain,&length,&type);
        CHECK("tls/incoming-record-size-and-padding",cases[i].accepted ? result == 0 && length == cases[i].content && type == 23 && sequence == 1 : result < 0 && !sequence);
        free(plain); free(encrypted);
    }
    int pair[2]; REQUIRE("tls/oversized-wire-record-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    uint8_t oversized[]={23,3,3,0x41,0x01,'A'};
    REQUIRE("tls/oversized-wire-record-feed",write_exact(pair[1],oversized,sizeof(oversized)) == 0 && shutdown(pair[1],SHUT_WR) == 0);
    uint8_t type,*payload=NULL,byte=0; size_t length=0;
    CHECK("tls/oversized-wire-record-rejected-before-payload",read_record(pair[0],&type,&payload,&length) != 0 && recv(pair[0],&byte,1,MSG_DONTWAIT) == 1 && byte == 'A');
    free(payload); close(pair[0]); close(pair[1]);
    REQUIRE("tls/unprotected-app-record-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    connection=(tls13_conn_t){.fd=pair[0],.mode=CONN_MODE_TLS,.tls_auth_state=4}; REQUIRE("tls/unprotected-app-record-cipher",configure_tls_cipher(&connection,0x1303) == 0);
    uint8_t *record=NULL; uint64_t sequence=0; const uint8_t ccs[]={20,3,3,0,1,1};
    REQUIRE("tls/unprotected-app-record-feed",encrypt_record(&connection,connection.s_app_key,connection.s_app_iv,&sequence,23,(const uint8_t *)"vless-core",10,&record,&length) == 0 &&
        write_exact(pair[1],ccs,sizeof(ccs)) == 0 && write_exact(pair[1],record,length) == 0 && shutdown(pair[1],SHUT_WR) == 0);
    uint8_t output[32]; size_t received=0;
    CHECK("tls/unprotected-app-record-is-not-skipped",tls13_read_app(&connection,output,sizeof(output),&received) < 0 && !received);
    free(record); db_free(&connection.app_cache); close(pair[0]); close(pair[1]);
    const uint8_t valid_certificate[]={11,0,0,10,0,0,0,6,0,0,1,'x',0,0};
    const uint8_t context_certificate[]={11,0,0,11,1,'x',0,0,6,0,0,1,'x',0,0};
    const uint8_t *der=NULL; size_t der_length=0;
    CHECK("tls/certificate-container-valid",parse_first_cert_der(valid_certificate,sizeof(valid_certificate),&der,&der_length) == 0 && der_length == 1);
    CHECK("tls/server-certificate-context-must-be-empty",parse_first_cert_der(context_certificate,sizeof(context_certificate),&der,&der_length) != 0);
    uint8_t trailing[sizeof(valid_certificate)+1]; memcpy(trailing,valid_certificate,sizeof(valid_certificate)); trailing[3]++; trailing[sizeof(valid_certificate)]=0;
    CHECK("tls/certificate-list-cannot-have-trailing-data",parse_first_cert_der(trailing,sizeof(trailing),&der,&der_length) != 0);
    for (size_t cut=0;cut<sizeof(valid_certificate);cut++) CHECK("tls/certificate-container-truncation",parse_first_cert_der(valid_certificate,cut,&der,&der_length) != 0);
    vless_config_t config; core_config_defaults(&config); config.fp_mode=FP_FIREFOX; strcpy(config.sni,"vless-core.test");
    uint8_t private_key[32],public_key[32],random[32],auth[32],*hello=NULL; size_t hello_size=0,sid=0;
    REQUIRE("tls/record-limit-clienthello",build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private_key,public_key,random,auth,&hello,&hello_size,&sid,NULL,NULL) == 0);
    connection=(tls13_conn_t){0}; REQUIRE("tls/record-limit-clienthello-cache",db_append(&connection.tls_client_hello,hello,hello_size) == 0); free(hello);
    const uint8_t limits[]={0,6,0,28,0,2,0,64};
    CHECK("tls/record-size-limit-negotiated",tls_encrypted_extensions(&connection,limits,sizeof(limits)) == 0 && connection.tls_send_record_limit == 64 && connection.tls_receive_record_limit == 16385);
    db_free(&connection.tls_client_hello);
}

static void address_cipher_cache_vectors(void) {
    struct sockaddr_in first={.sin_family=AF_INET,.sin_port=htons(443)},second=first;
    REQUIRE("tls/address-cipher-cache-fixture",inet_pton(AF_INET,"127.0.0.1",&first.sin_addr) == 1 && inet_pton(AF_INET,"127.0.0.2",&second.sin_addr) == 1);
    REQUIRE("tls/address-cipher-cache-isolated",g_tls_aes_fallback_count == 0);
    cache_tls_address_aes("vless-core.test",443,"vless-core.test",(const struct sockaddr *)&first,sizeof(first));
    CHECK("tls/address-cipher-cache-successful-address",tls_address_aes_cached("vless-core.test",443,"vless-core.test",(const struct sockaddr *)&first,sizeof(first)));
    CHECK("tls/address-cipher-cache-other-address-unaffected",!tls_address_aes_cached("vless-core.test",443,"vless-core.test",(const struct sockaddr *)&second,sizeof(second)));
    CHECK("tls/address-cipher-cache-sni-isolated",!tls_address_aes_cached("vless-core.test",443,"other.test",(const struct sockaddr *)&first,sizeof(first)));
    CHECK("tls/address-cipher-cache-does-not-change-manual-policy",!tls_aes_fallback_cached("vless-core.test",443,"vless-core.test"));
    cache_tls_aes_fallback("vless-core.test",443,"vless-core.test");
    CHECK("tls/manual-cipher-cache-retained",tls_aes_fallback_cached("vless-core.test",443,"vless-core.test"));
    CHECK("tls/manual-cipher-cache-does-not-poison-other-address",!tls_address_aes_cached("vless-core.test",443,"vless-core.test",(const struct sockaddr *)&second,sizeof(second)));
    memset(g_tls_aes_fallback_cache,0,sizeof(g_tls_aes_fallback_cache)); g_tls_aes_fallback_count=0;
}

static void buffered_http_progress(void) {
    int pair[2]; REQUIRE("h1/buffered-progress-pair",!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    REQUIRE("h1/buffered-progress-nonblocking",!fcntl(pair[0],F_SETFL,O_NONBLOCK));
    tls13_conn_t sender={0},receiver={.fd=pair[0],.mode=CONN_MODE_XHTTP_TLS,.xmux_async=1,.tls_auth_state=4,.xmux_http1_id=1};
    REQUIRE("h1/buffered-progress-ciphers",!configure_tls_cipher(&sender,0x1303) && !configure_tls_cipher(&receiver,0x1303));
    const uint8_t response[]="HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvless-core";
    for (unsigned fragment=0;fragment<2;fragment++) {
        size_t offset=fragment ? 7 : 0,length=fragment ? sizeof(response)-1-7 : 7,size=0; uint8_t *record=NULL;
        REQUIRE("h1/buffered-progress-record",!encrypt_record(&sender,sender.c_app_key,sender.c_app_iv,&sender.c_app_seq,23,response+offset,length,&record,&size));
        REQUIRE("h1/buffered-progress-cache",!db_append(&receiver.xmux_raw_input,record,size)); free(record);
    }
    CHECK("h1/buffered-progress-without-socket-readiness",core_wait_socket(pair[0],POLLIN,0) == 0);
    CHECK("h1/buffered-progress-is-runnable",xmux_transport_collect(&receiver) == CORE_HTTP2_INPUT_PROGRESS);
    core_http2_frame_t frame;
    CHECK("h1/partial-http-header-has-no-event",xmux_transport_read_frame(&receiver,&frame,65535) == 1 && receiver.xmux_raw_input.len > 5 && receiver.h2_net_cache.len == 7);
    CHECK("h1/buffered-next-record-is-runnable",xmux_transport_collect(&receiver) == CORE_HTTP2_INPUT_PROGRESS);
    REQUIRE("h1/buffered-header-event",!xmux_transport_read_frame(&receiver,&frame,65535) && frame.event == 1 && frame.status == 200);
    CHECK("h1/blocked-payload-is-not-runnable",xmux_transport_read_frame(&receiver,&frame,0) == CORE_HTTP2_INPUT_BLOCKED && receiver.h2_net_cache.len == 10);
    REQUIRE("h1/buffered-payload-event",!xmux_transport_read_frame(&receiver,&frame,65535) && frame.event == 2 && frame.length == 10 && !memcmp(frame.data,"vless-core",10)); xmux_transport_release_frame(&receiver,&frame);
    REQUIRE("h1/buffered-end-event",!xmux_transport_read_frame(&receiver,&frame,65535) && frame.event == 3);
    CHECK("h1/no-buffered-progress-no-active-loop",xmux_transport_collect(&receiver) == 0);
    db_free(&receiver.h2_net_cache); db_free(&receiver.xmux_raw_input); close(pair[0]); close(pair[1]);
}

static void alps_vectors(void) {
    const uint8_t frame[]={0,0,30,4,0,0,0,0,0,0,1,0,0,0,0,0,3,0,0,0,2,0,4,0,0,4,0,0,5,0,0,128,0,0,6,0,1,0,0};
    core_http2_settings_t settings={0};
    REQUIRE("alps/http2-settings",core_http2_alps_parse(frame,sizeof(frame),&settings) == 0);
    CHECK("alps/settings-values",settings.received && !settings.table_size && settings.concurrency == 2 && settings.initial_window == 1024 && settings.max_frame == 32768 && settings.header_limit == 65536);
    const uint8_t unknown[]={0,0,1,0xff,7,0,0,0,0,1},hints[]={0,0,6,0x89,0,0,0,0,0,0,1,'x',0,1,'y'};
    CHECK("alps/extension-frames",core_http2_alps_parse(unknown,sizeof(unknown),&settings) == 0 && !settings.received && core_http2_alps_parse(hints,sizeof(hints),&settings) == 0);
    uint8_t invalid[sizeof(frame)];
    for (unsigned type=0;type<10;type++) if (type != 4) {
        memcpy(invalid,frame,sizeof(frame)); invalid[3]=(uint8_t)type;
        CHECK("alps/forbidden-frames",core_http2_alps_parse(invalid,sizeof(invalid),&settings) < 0);
    }
    for (size_t cut=1;cut<sizeof(frame);cut++) CHECK("alps/truncated-frame",core_http2_alps_parse(frame,cut,&settings) < 0);
    memcpy(invalid,frame,sizeof(frame)); invalid[4]=1;
    CHECK("alps/settings-ack-forbidden",core_http2_alps_parse(invalid,sizeof(invalid),&settings) < 0);
    invalid[4]=0; invalid[8]=1;
    CHECK("alps/settings-stream-forbidden",core_http2_alps_parse(invalid,sizeof(invalid),&settings) < 0);
    invalid[8]=0; invalid[23]=128;
    CHECK("alps/settings-window-overflow",core_http2_alps_parse(invalid,sizeof(invalid),&settings) < 0);
    uint8_t bad_hints[sizeof(hints)]; memcpy(bad_hints,hints,sizeof(hints)); bad_hints[10]=9;
    CHECK("alps/malformed-accept-ch",core_http2_alps_parse(bad_hints,sizeof(bad_hints),&settings) < 0);
    REQUIRE("alps/settings-restored",core_http2_alps_parse(frame,sizeof(frame),&settings) == 0);
    vless_config_t config; core_config_defaults(&config); strcpy(config.sni,"vless-core.test"); config.fp_mode=FP_QQ;
    for (unsigned h2=0;h2<2;h2++) {
        strcpy(config.alpn,h2 ? "h2,http/1.1" : "http/1.1");
        uint8_t private[32],public[32],random[32],auth[32],*hello=NULL; size_t size=0,sid=0;
        REQUIRE("alps/profile-clienthello",!build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private,public,random,auth,&hello,&size,&sid,NULL,NULL));
        size_t extension_length=0; const uint8_t *extension=core_tls_hello_extension(hello,size,0x4469,&extension_length);
        CHECK("alps/advertisement-follows-alpn",h2 ? extension && extension_length == 5 : !extension);
        tls13_conn_t negotiated={0}; negotiated.tls_client_hello.data=hello; negotiated.tls_client_hello.len=size;
        strcpy(negotiated.tls_offered_alpn,config.alpn);
        const uint8_t valid[]={0,13,0x44,0x69,0,0,0,16,0,5,0,3,2,'h','2'};
        CHECK("alps/selection-must-be-offered",(tls_encrypted_extensions(&negotiated,valid,sizeof(valid)) == 0) == h2);
        negotiated.tls_selected_alpn[0]=0; negotiated.tls_alps_received=0;
        const uint8_t absent[]={0,4,0x44,0x69,0,0};
        CHECK("alps/selection-requires-alpn",tls_encrypted_extensions(&negotiated,absent,sizeof(absent)) < 0 && !negotiated.tls_alps_received);
        const uint8_t duplicate[]={0,17,0x44,0x69,0,0,0,16,0,5,0,3,2,'h','2',0x44,0x69,0,0};
        CHECK("alps/duplicate-extension",tls_encrypted_extensions(&negotiated,duplicate,sizeof(duplicate)) < 0 && !negotiated.tls_alps_received);
        const uint8_t wrong_alpn[]={0,19,0x44,0x69,0,0,0,16,0,11,0,9,8,'h','t','t','p','/','1','.','1'};
        CHECK("alps/http1-selection-forbidden",tls_encrypted_extensions(&negotiated,wrong_alpn,sizeof(wrong_alpn)) < 0 && !negotiated.tls_alps_received);
        negotiated.tls12_suite=core_tls12_suite(0xc02f);
        CHECK("alps/tls12-selection-forbidden",tls_encrypted_extensions(&negotiated,valid,sizeof(valid)) < 0 && !negotiated.tls_alps_received);
        free(hello);
    }
    for (unsigned pooled=0;pooled<2;pooled++) {
        int pair[2]; REQUIRE("alps/preface-pair",!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
        tls13_conn_t *connection=calloc(1,sizeof(*connection)); REQUIRE("alps/preface-connection",connection != NULL);
        connection->fd=pair[0]; connection->xhttp_upload_fd=-1; connection->mode=CONN_MODE_GRPC_PLAIN;
        connection->xmux_physical=connection->xmux_async=(int)pooled;
        connection->tls_alps_received=1; connection->tls_auth_state=4; connection->tls_alps_settings=settings;
        char error[128]; REQUIRE("alps/initial-settings-applied",!xhttp_h2_begin(connection,error,sizeof(error)));
        CHECK("alps/initial-window-before-request",connection->h2_peer_initial_window == 1024 && connection->h2_peer_stream_window == 1024 && connection->h2_peer_max_frame_size == 32768 && connection->h2_peer_concurrency == 2);
        core_http2_settings_t snapshot; core_http2_validation_t validation;
        REQUIRE("alps/physical-settings-snapshot",xmux_backend.initial_settings(connection,&snapshot,&validation) == 1);
        CHECK("alps/server-settings-already-acknowledged",validation.settings_received && validation.settings_pending == 1);
        CHECK("alps/client-wire-settings-ack",core_http2_validate_frame(&validation,4,1,0,NULL,0) == 0 && validation.settings_pending == 0);
        const uint8_t status[]={0x88};
        CHECK("alps/response-without-wire-server-settings",core_http2_validate_frame(&validation,1,4,1,status,sizeof(status)) == 0);
        CHECK("alps/later-wire-settings",core_http2_validate_frame(&validation,4,0,0,frame+9,sizeof(frame)-9) == 0);
        connection->tls_auth_state=3;
        CHECK("alps/settings-not-exposed-before-auth",xmux_backend.initial_settings(connection,&snapshot,&validation) == 0);
        tls13_reality_close(connection); close(pair[1]);
    }
    int pair[2]; REQUIRE("alps/fragmented-flight-pair",!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    tls13_conn_t sender={.fd=pair[0],.tls_alps_received=1,.tls_client_certificate_requested=1,.tls_send_record_limit=64},peer={0};
    REQUIRE("alps/fragmented-flight-cipher",!configure_tls_cipher(&sender,0x1302) && !configure_tls_cipher(&peer,0x1302));
    REQUIRE("alps/fragmented-flight-transcript",!db_append(&sender.transcript,"vless-core server Finished",26));
    char error[128]; REQUIRE("alps/fragmented-client-flight",!tls_send_client_finished(&sender,error,sizeof(error)));
    uint8_t type,*record=NULL,*plain=NULL,inner=0,combined[86]; size_t size=0,length=0,total=0,records=0;
    REQUIRE("alps/fragmented-flight-ccs",!read_record(pair[1],&type,&record,&size) && type == 20 && size == 1); free(record);
    while (records<2) {
        REQUIRE("alps/fragmented-flight-record",!read_record(pair[1],&type,&record,&size));
        REQUIRE("alps/fragmented-flight-decrypt",!decrypt_record(&peer,peer.c_hs_key,peer.c_hs_iv,&peer.c_hs_seq,type,record,size,&plain,&length,&inner)); free(record);
        CHECK("alps/fragmented-flight-record-size",inner == 22 && length <= 63 && total+length <= sizeof(combined));
        memcpy(combined+total,plain,length); total+=length; free(plain); records++;
    }
    const uint8_t prefix[]={8,0,0,6,0,4,0x44,0x69,0,0,11,0,0,4,0,0,0,0,20,0,0,48};
    CHECK("alps/fragmented-flight-order-and-last-boundary",total == 70 && sender.c_hs_seq == 2 && !memcmp(combined,prefix,sizeof(prefix)));
    tls_handshake_material_clear(&sender); close(pair[0]); close(pair[1]);
}

int main(int argc, char **argv) {
    if (argc == 2 || (argc == 3 && !strcmp(argv[1],"--http"))) {
        vless_config_t config; char error[256]={0}; tls13_conn_t *connection=NULL;
        REQUIRE("tls/live-config",parse_core_uri(argv[argc-1],&config,error,sizeof(error)) == 0);
        int result=tls13_reality_connect(&config,&connection,error,sizeof(error));
        if (result) fprintf(stderr,"handshake: %s\n",error);
        CHECK("tls/live-retry-handshake",result == 0);
        if (!result && argc == 3) {
            const uint8_t request[]="GET / HTTP/1.0\r\n\r\n";
            CHECK("tls/live-http-send",!tls13_write_app(connection,request,sizeof(request)-1));
            uint8_t response[16384]; size_t total=0;
            for (;;) {
                size_t count=0; int received=tls13_read_app(connection,response+total,sizeof(response)-total,&count);
                CHECK("tls/live-http-read",received >= 0);
                if (received < 0 || (!received && !count)) break;
                if (received > 0) continue;
                total+=count;
                REQUIRE("tls/live-http-response-capacity",total < sizeof(response));
            }
            CHECK("tls/live-http-response",total > 12 && !memcmp(response,"HTTP/1.0 200 ",13));
        }
        tls13_reality_close(connection); return test_result();
    }
    record_limit_vectors();
    alps_vectors();
    buffered_http_progress();
    physical_tls_close_notify();
    automatic_update_vectors();
    key_update_record_boundaries();
    incoming_record_vectors();
    address_cipher_cache_vectors();
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
