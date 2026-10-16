#include "tls_internal.h"

static int tls_encrypted_extensions(tls13_conn_t *c, const uint8_t *data, size_t length) {
    if (length < 2 || (((size_t)data[0]<<8)|data[1]) != length-2) return -1;
    unsigned seen[32]; size_t count=0;
    for (size_t offset=2;offset < length;) {
        if (length-offset < 4 || count == 32) return -1;
        unsigned type=((unsigned)data[offset]<<8)|data[offset+1]; size_t size=((size_t)data[offset+2]<<8)|data[offset+3]; offset+=4;
        if (size > length-offset) return -1;
        for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
        seen[count++]=type;
        if (type != 0 && type != 1 && type != 10 && type != 16 && type != 28 && type != 0x4469) return -1;
        size_t offered_size=0;
        const uint8_t *offered=core_tls_hello_extension(c->tls_client_hello.data,c->tls_client_hello.len,type,&offered_size);
        if (!offered && (type != 16 || c->tls_client_hello.len)) return -1;
        if (type == 0 && size) return -1;
        if (type == 28) {
            if (size != 2) return -1;
            unsigned limit=((unsigned)data[offset]<<8)|data[offset+1];
            if (limit < 64 || limit > 16385) return -1;
            c->tls_send_record_limit=limit;
            if (offered_size != 2) return -1;
            c->tls_receive_record_limit=((unsigned)offered[0]<<8)|offered[1];
        }
        if (type == 1) {
            if (size != 1 || offered_size != 1 || data[offset] != offered[0] || data[offset] < 1 || data[offset] > 4) return -1;
            c->tls_send_record_limit=(1U<<(8+data[offset]))+1;
        }
        if (type == 10) {
            if (size < 4 || (size&1) || (((size_t)data[offset]<<8)|data[offset+1]) != size-2) return -1;
        }
        if (type == 16) {
            if (size < 3 || (((size_t)data[offset]<<8)|data[offset+1]) != size-2 || data[offset+2] != size-3 || size-3 >= sizeof(c->tls_selected_alpn)) return -1;
            memcpy(c->tls_selected_alpn,data+offset+3,size-3); c->tls_selected_alpn[size-3]=0;
            if (strlen(c->tls_selected_alpn) != size-3 || !alpn_csv_has_token(c->tls_offered_alpn,c->tls_selected_alpn)) return -1;
        }
        offset+=size;
    }
    return c->tls_h2_required && strcmp(c->tls_selected_alpn,"h2") &&
        !(c->tls_is_reality && !c->tls_selected_alpn[0]) ? -1 : 0;
}

static int verify_server_signature(tls13_conn_t *c, const uint8_t *body, size_t length) {
    if (tls_certificate_key_usage(c->tls_peer_certificate,1) || length < 4 || (((size_t)body[2]<<8)|body[3]) != length-4) return -1;
    unsigned scheme=((unsigned)body[0]<<8)|body[1];
    const EVP_MD *digest=NULL;
    int expected_type=0,curve=0,pss=0;
    switch (scheme) {
    case 0x0403: digest=EVP_sha256(); expected_type=EVP_PKEY_EC; curve=NID_X9_62_prime256v1; break;
    case 0x0503: digest=EVP_sha384(); expected_type=EVP_PKEY_EC; curve=NID_secp384r1; break;
    case 0x0603: digest=EVP_sha512(); expected_type=EVP_PKEY_EC; curve=NID_secp521r1; break;
    case 0x0804: digest=EVP_sha256(); expected_type=EVP_PKEY_RSA; pss=1; break;
    case 0x0805: digest=EVP_sha384(); expected_type=EVP_PKEY_RSA; pss=1; break;
    case 0x0806: digest=EVP_sha512(); expected_type=EVP_PKEY_RSA; pss=1; break;
    case 0x0809: digest=EVP_sha256(); expected_type=EVP_PKEY_RSA_PSS; pss=1; break;
    case 0x080a: digest=EVP_sha384(); expected_type=EVP_PKEY_RSA_PSS; pss=1; break;
    case 0x080b: digest=EVP_sha512(); expected_type=EVP_PKEY_RSA_PSS; pss=1; break;
    case 0x0807: expected_type=EVP_PKEY_ED25519; break;
    default: return -1;
    }
    EVP_PKEY *key=X509_get_pubkey(c->tls_peer_certificate);
    if (!key || EVP_PKEY_base_id(key) != expected_type) { EVP_PKEY_free(key); return -1; }
    if (curve) {
        char group[80]; size_t size=0;
        if (EVP_PKEY_get_utf8_string_param(key,OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&size) != 1 ||
            OBJ_txt2nid(group) != curve) { EVP_PKEY_free(key); return -1; }
    }
    uint8_t transcript[64],input[164];
    const char context[]="TLS 1.3, server CertificateVerify";
    memset(input,32,64); memcpy(input+64,context,sizeof(context));
    if (transcript_hash(c,transcript)) { EVP_PKEY_free(key); return -1; }
    memcpy(input+64+sizeof(context),transcript,c->tls_hash_len);
    EVP_MD_CTX *verify=EVP_MD_CTX_new(); EVP_PKEY_CTX *parameters=NULL;
    int ok=verify && EVP_DigestVerifyInit(verify,&parameters,digest,NULL,key) == 1;
    if (ok && pss) ok=EVP_PKEY_CTX_set_rsa_padding(parameters,RSA_PKCS1_PSS_PADDING) == 1 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(parameters,EVP_MD_get_size(digest)) == 1 && EVP_PKEY_CTX_set_rsa_mgf1_md(parameters,digest) == 1;
    if (ok) ok=EVP_DigestVerify(verify,body+4,length-4,input,64+sizeof(context)+c->tls_hash_len) == 1;
    EVP_MD_CTX_free(verify); EVP_PKEY_free(key); return ok ? 0 : -1;
}

static int tls_certificate_request(const uint8_t *body, size_t length) {
    if (length < 3 || body[0] || (((size_t)body[1]<<8)|body[2]) != length-3) return -1;
    unsigned seen[256]; size_t count=0; int signatures=0;
    for (size_t offset=3;offset<length;) {
        if (length-offset < 4 || count == sizeof(seen)/sizeof(seen[0])) return -1;
        unsigned type=((unsigned)body[offset]<<8)|body[offset+1];
        size_t size=((size_t)body[offset+2]<<8)|body[offset+3]; offset+=4;
        if (size > length-offset) return -1;
        for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
        seen[count++]=type;
        if (type == 13 || type == 50) {
            if (size < 4 || (size&1) || (((size_t)body[offset]<<8)|body[offset+1]) != size-2) return -1;
            if (type == 13) signatures=1;
        }
        offset+=size;
    }
    return signatures ? 0 : -1;
}

static int server_handshake_message(const vless_config_t *cfg, tls13_conn_t *c, const uint8_t *message, size_t length, char *err, size_t err_cap) {
    if (length < 4) return -1;
    unsigned type=message[0]; size_t body_length=length-4;
    if (type == 13) {
        if (c->tls_auth_state != 1 || c->tls_client_certificate_requested || tls_certificate_request(message+4,body_length)) {
            set_err(err,err_cap,"invalid or unexpected TLS CertificateRequest"); return -1;
        }
        if (append_transcript(c,message,length)) return -1;
        c->tls_client_certificate_requested=1; return 0;
    }
    static const unsigned expected[]={8,11,15,20};
    if (c->tls_auth_state >= 4 || type != expected[c->tls_auth_state]) {
        set_err(err,err_cap,"unexpected TLS server handshake message"); return -1;
    }
    if (type == 8) {
        if (tls_encrypted_extensions(c,message+4,body_length)) {
            set_err(err,err_cap,"invalid TLS EncryptedExtensions"); return -1;
        }
    } else if (type == 11) {
        const uint8_t *der=NULL; size_t der_length=0;
        if (parse_first_cert_der(message,length,&der,&der_length)) { set_err(err,err_cap,"invalid TLS Certificate"); return -1; }
        const unsigned char *cursor=der;
        c->tls_peer_certificate=d2i_X509(NULL,&cursor,(long)der_length);
        if (!c->tls_peer_certificate || cursor != der+der_length) { set_err(err,err_cap,"invalid TLS leaf certificate"); return -1; }
        if (tls_certificate_key_usage(c->tls_peer_certificate,1)) { set_err(err,err_cap,"TLS certificate KeyUsage forbids signing"); return -1; }
        if (!strcmp(cfg->security,"reality")) {
            if (verify_reality_cert(c->auth_key,der,der_length)) { set_err(err,err_cap,"REALITY cert verify failed"); return -1; }
        } else if (c->tls_verify_policy == TLS_VERIFY_MODE_STRICT &&
            verify_tls_cert_message(cfg->sni[0] ? cfg->sni : cfg->server_host,message,length,err,err_cap)) return -1;
        if (db_append(&c->tls_certificate_message,message,length)) return -1;
    } else if (type == 15) {
        if (verify_server_signature(c,message+4,body_length)) { set_err(err,err_cap,"TLS CertificateVerify signature failed"); return -1; }
    } else {
        uint8_t transcript[64],finished[64];
        if (body_length != c->tls_hash_len || transcript_hash(c,transcript) ||
            calc_finished_verify(c,c->s_hs_traffic,transcript,finished) || CRYPTO_memcmp(finished,message+4,body_length)) {
            set_err(err,err_cap,"server Finished mismatch"); return -1;
        }
        if (strcmp(cfg->security,"reality") && c->tls_verify_policy == TLS_VERIFY_MODE_TOFU &&
            tcp_tls_tofu_verify_or_store(cfg,c->tls_certificate_message.data,c->tls_certificate_message.len,err,err_cap)) return -1;
    }
    if (append_transcript(c,message,length)) return -1;
    c->tls_auth_state++; return type == 20 ? 1 : 0;
}

static unsigned tls12_word(const uint8_t *data) { return ((unsigned)data[0]<<8)|data[1]; }
static int tls12_server_hello(tls13_conn_t *c,const uint8_t *message,size_t length) {
    if (length < 42 || message[0] != 2 || tls12_word(message+4) != 0x0303 || message[38] > 32 ||
        (((size_t)message[1]<<16)|((size_t)message[2]<<8)|message[3]) != length-4 ||
        !memcmp(message+30,"DOWNGRD\x01",8) || !memcmp(message+30,"DOWNGRD\x00",8)) return -1;
    size_t offset=39+message[38];
    if (offset+3 > length || message[offset+2]) return -1;
    unsigned suite=tls12_word(message+offset);
    const uint8_t *client=c->tls_client_hello.data; size_t client_length=c->tls_client_hello.len;
    if (client_length < 42) return -1;
    if (message[38] && message[38] == client[38] && !memcmp(message+39,client+39,message[38])) return -1;
    size_t offered=39+client[38],count=offered+2 <= client_length ? tls12_word(client+offered) : 0;
    if (!count || count > client_length-offered-2) return -1;
    int present=0;
    for (size_t i=offered+2;i<offered+2+count;i+=2) if (tls12_word(client+i) == suite) present=1;
    if (!present || !(c->tls12_suite=core_tls12_suite(suite))) return -1;
    c->tls_cipher_suite=(uint16_t)suite; c->tls_key_len=c->tls12_suite->key_length;
    c->tls_md=core_tls12_digest(c->tls12_suite->prf_hash); c->tls_hash_len=(size_t)EVP_MD_get_size(c->tls_md);
    offset+=3;
    if (offset == length) return c->tls_h2_required ? -1 : 0;
    if (length-offset < 2 || tls12_word(message+offset) != length-offset-2) return -1;
    offset+=2; unsigned seen[64]; size_t used=0;
    while (offset < length) {
        if (length-offset < 4 || used == 64) return -1;
        unsigned type=tls12_word(message+offset); size_t size=tls12_word(message+offset+2); offset+=4;
        if (size > length-offset) return -1;
        for (size_t i=0;i<used;i++) if (seen[i] == type) return -1;
        seen[used++]=type; size_t offered_size=0;
        const uint8_t *offered_value=core_tls_hello_extension(client,client_length,type,&offered_size);
        if (!offered_value) return -1;
        const uint8_t *value=message+offset;
        if (type == 23 || type == 22 || type == 35 || type == 0 || type == 5) {
            if (size || (type == 22 && c->tls12_suite->cipher != CORE_TLS12_CBC)) return -1;
            if (type == 23) c->tls12_ems=1;
            if (type == 22) c->tls12_etm=1;
            if (type == 35) c->tls12_ticket=1;
            if (type == 5) c->tls12_status=1;
        } else if (type == 16) {
            if (size < 3 || tls12_word(value) != size-2 || value[2] != size-3 || size-3 >= sizeof(c->tls_selected_alpn)) return -1;
            memcpy(c->tls_selected_alpn,value+3,size-3); c->tls_selected_alpn[size-3]=0;
            if (strlen(c->tls_selected_alpn) != size-3 || !alpn_csv_has_token(c->tls_offered_alpn,c->tls_selected_alpn)) return -1;
        } else if (type == 0xff01) { if (size != 1 || value[0]) return -1; }
        else if (type == 11) {
            if (size < 2 || value[0] != size-1) return -1;
            int uncompressed=0; for (size_t i=1;i<size;i++) if (!value[i]) uncompressed=1;
            if (!uncompressed) return -1;
        } else if (type == 28) {
            if (size != 2 || offered_size != 2 || tls12_word(value) < 64 || tls12_word(value) > 16384) return -1;
            c->tls_send_record_limit=tls12_word(value); c->tls_receive_record_limit=tls12_word(offered_value);
            if (c->tls_receive_record_limit > 16384) c->tls_receive_record_limit=16384;
        } else if (type == 1) {
            if (size != 1 || offered_size != 1 || value[0] != offered_value[0] || value[0] < 1 || value[0] > 4) return -1;
            c->tls_send_record_limit=c->tls_receive_record_limit=1U<<(8+value[0]);
        } else if (type == 18) {
            if (size < 2 || tls12_word(value) != size-2) return -1;
            for (size_t i=2;i<size;) { if (size-i < 2 || !tls12_word(value+i) || tls12_word(value+i) > size-i-2) return -1; i+=2+tls12_word(value+i); }
        } else return -1;
        offset+=size;
    }
    return c->tls_h2_required && strcmp(c->tls_selected_alpn,"h2") ? -1 : 0;
}
static int tls12_certificate(const vless_config_t *config,tls13_conn_t *c,const uint8_t *message,size_t length,char *error,size_t capacity) {
    if (length < 7 || message[0] != 11 ||
        (((size_t)message[4]<<16)|((size_t)message[5]<<8)|message[6]) != length-7) return -1;
    dynbuf_t converted={0}; if (tls_buffer_init(&converted,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) return -1;
    const uint8_t prefix[]={11,0,0,0,0,0,0,0}; int result=-1;
    if (db_append(&converted,prefix,sizeof(prefix))) goto cleanup;
    for (size_t offset=7;offset<length;) {
        if (length-offset < 3) goto cleanup;
        size_t count=((size_t)message[offset]<<16)|((size_t)message[offset+1]<<8)|message[offset+2];
        if (!count || count > length-offset-3 || db_append(&converted,message+offset,count+3)) goto cleanup;
        const uint8_t extensions[]={0,0};
        if (db_append(&converted,extensions,sizeof(extensions))) goto cleanup;
        offset+=count+3;
    }
    size_t body=converted.len-4,list=converted.len-8;
    converted.data[1]=(uint8_t)(body>>16); converted.data[2]=(uint8_t)(body>>8); converted.data[3]=(uint8_t)body;
    converted.data[5]=(uint8_t)(list>>16); converted.data[6]=(uint8_t)(list>>8); converted.data[7]=(uint8_t)list;
    const uint8_t *der=NULL; size_t der_length=0;
    if (parse_first_cert_der(converted.data,converted.len,&der,&der_length)) goto cleanup;
    const unsigned char *cursor=der; c->tls_peer_certificate=d2i_X509(NULL,&cursor,(long)der_length);
    if (!c->tls_peer_certificate || cursor != der+der_length) goto cleanup;
    if (!c->tls12_suite || tls_certificate_key_usage(c->tls_peer_certificate,c->tls12_suite->exchange != CORE_TLS12_RSA)) {
        set_err(error,capacity,"TLS certificate KeyUsage forbids key exchange"); goto cleanup;
    }
    if (c->tls_verify_policy == TLS_VERIFY_MODE_STRICT &&
        verify_tls_cert_message(config->sni[0] ? config->sni : config->server_host,converted.data,converted.len,error,capacity)) goto cleanup;
    c->tls_certificate_message=converted; memset(&converted,0,sizeof(converted)); result=0;
cleanup:
    db_free(&converted); return result;
}
static int tls12_signature(tls13_conn_t *c,const uint8_t client_random[32],const uint8_t server_random[32],
                            const uint8_t *parameters,size_t parameters_length,const uint8_t *signature,size_t length) {
    if (tls_certificate_key_usage(c->tls_peer_certificate,1) || length < 4 || tls12_word(signature+2) != length-4) return -1;
    unsigned scheme=tls12_word(signature); size_t offered_size=0;
    const uint8_t *offered=core_tls_hello_extension(c->tls_client_hello.data,c->tls_client_hello.len,13,&offered_size);
    if (!offered || offered_size < 4 || tls12_word(offered) != offered_size-2) return -1;
    int present=0; for (size_t i=2;i+2 <= offered_size;i+=2) if (tls12_word(offered+i) == scheme) present=1;
    if (!present) return -1;
    const EVP_MD *digest=NULL; int expected=0,pss=0;
    switch (scheme) {
    case 0x0201: digest=EVP_sha1(); expected=EVP_PKEY_RSA; break;
    case 0x0401: digest=EVP_sha256(); expected=EVP_PKEY_RSA; break;
    case 0x0501: digest=EVP_sha384(); expected=EVP_PKEY_RSA; break;
    case 0x0601: digest=EVP_sha512(); expected=EVP_PKEY_RSA; break;
    case 0x0203: digest=EVP_sha1(); expected=EVP_PKEY_EC; break;
    case 0x0403: digest=EVP_sha256(); expected=EVP_PKEY_EC; break;
    case 0x0503: digest=EVP_sha384(); expected=EVP_PKEY_EC; break;
    case 0x0603: digest=EVP_sha512(); expected=EVP_PKEY_EC; break;
    case 0x0804: digest=EVP_sha256(); expected=EVP_PKEY_RSA; pss=1; break;
    case 0x0805: digest=EVP_sha384(); expected=EVP_PKEY_RSA; pss=1; break;
    case 0x0806: digest=EVP_sha512(); expected=EVP_PKEY_RSA; pss=1; break;
    case 0x0809: digest=EVP_sha256(); expected=EVP_PKEY_RSA_PSS; pss=1; break;
    case 0x080a: digest=EVP_sha384(); expected=EVP_PKEY_RSA_PSS; pss=1; break;
    case 0x080b: digest=EVP_sha512(); expected=EVP_PKEY_RSA_PSS; pss=1; break;
    case 0x0807: expected=EVP_PKEY_ED25519; break;
    default: return -1;
    }
    if ((expected == EVP_PKEY_EC || expected == EVP_PKEY_ED25519) != !!c->tls12_suite->ecdsa) return -1;
    EVP_PKEY *key=X509_get_pubkey(c->tls_peer_certificate); EVP_MD_CTX *context=EVP_MD_CTX_new(); EVP_PKEY_CTX *options=NULL;
    int ok=key && EVP_PKEY_base_id(key) == expected && context && EVP_DigestVerifyInit(context,&options,digest,NULL,key) == 1;
    if (ok && pss) ok=EVP_PKEY_CTX_set_rsa_padding(options,RSA_PKCS1_PSS_PADDING) == 1 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(options,EVP_MD_get_size(digest)) == 1 && EVP_PKEY_CTX_set_rsa_mgf1_md(options,digest) == 1;
    if (ok && expected == EVP_PKEY_ED25519) {
        uint8_t input[256];
        if (parameters_length > sizeof(input)-64) ok=0;
        else { memcpy(input,client_random,32); memcpy(input+32,server_random,32); memcpy(input+64,parameters,parameters_length);
            ok=EVP_DigestVerify(context,signature+4,length-4,input,64+parameters_length) == 1; }
    } else if (ok) ok=EVP_DigestVerifyUpdate(context,client_random,32) == 1 && EVP_DigestVerifyUpdate(context,server_random,32) == 1 &&
        EVP_DigestVerifyUpdate(context,parameters,parameters_length) == 1 && EVP_DigestVerifyFinal(context,signature+4,length-4) == 1;
    EVP_MD_CTX_free(context); EVP_PKEY_free(key); return ok ? 0 : -1;
}
static int tls12_vector(const uint8_t *data,size_t length,size_t *offset,const uint8_t **value,size_t *size) {
    if (length-*offset < 2) return -1;
    *size=tls12_word(data+*offset); *offset+=2;
    if (!*size || *size > length-*offset) return -1;
    *value=data+*offset; *offset+=*size; return 0;
}
static int tls12_key_exchange(tls13_conn_t *c,const uint8_t client_random[32],const uint8_t server_random[32],
                               const uint8_t *body,size_t length,dynbuf_t *premaster,dynbuf_t *client) {
    EVP_PKEY *local=NULL,*peer=NULL; EVP_PKEY_CTX *generate=NULL,*derive=NULL; DH *parameters=NULL,*generated=NULL;
    BIGNUM *prime=NULL,*generator=NULL,*public=NULL; int result=-1;
    if (c->tls12_suite->exchange == CORE_TLS12_ECDHE) {
        if (length < 4 || body[0] != 3 || body[3] > length-4) goto cleanup;
        unsigned group=tls12_word(body+1); size_t offered_size=0;
        const uint8_t *offered=core_tls_hello_extension(c->tls_client_hello.data,c->tls_client_hello.len,10,&offered_size);
        if (!offered || offered_size < 4 || tls12_word(offered) != offered_size-2) goto cleanup;
        int present=0; for (size_t i=2;i+2<=offered_size;i+=2) if (tls12_word(offered+i) == group) present=1;
        size_t public_length=body[3],expected=group == 29 ? 32 : group == 23 ? 65 : group == 24 ? 97 : group == 25 ? 133 : 0;
        if (!present || !expected || expected != public_length || tls12_signature(c,client_random,server_random,body,public_length+4,body+public_length+4,length-public_length-4)) goto cleanup;
        const char *curve=group == 23 ? "prime256v1" : group == 24 ? "secp384r1" : "secp521r1";
        local=group == 29 ? EVP_PKEY_Q_keygen(NULL,NULL,"X25519") : EVP_PKEY_Q_keygen(NULL,NULL,"EC",curve);
        if (!local || db_reserve(premaster,96)) goto cleanup;
        size_t secret_length=premaster->cap;
        if (core_tls_ecdh(local,(uint16_t)group,body+4,public_length,premaster->data,&secret_length)) goto cleanup;
        premaster->len=secret_length;
        uint8_t client_public[133]; size_t client_length=sizeof(client_public);
        if ((group == 29 ? EVP_PKEY_get_raw_public_key(local,client_public,&client_length) :
            EVP_PKEY_get_octet_string_param(local,OSSL_PKEY_PARAM_PUB_KEY,client_public,sizeof(client_public),&client_length)) != 1) goto cleanup;
        uint8_t prefix=(uint8_t)client_length;
        if (db_append(client,&prefix,1) || db_append(client,client_public,client_length)) goto cleanup;
    } else {
        size_t offset=0,p_size=0,g_size=0,y_size=0; const uint8_t *p=NULL,*g=NULL,*y=NULL;
        if (tls12_vector(body,length,&offset,&p,&p_size) || tls12_vector(body,length,&offset,&g,&g_size) ||
            tls12_vector(body,length,&offset,&y,&y_size) || p_size > 1024 || g_size > p_size || y_size > p_size ||
            tls12_signature(c,client_random,server_random,body,offset,body+offset,length-offset)) goto cleanup;
        prime=BN_bin2bn(p,(int)p_size,NULL); generator=BN_bin2bn(g,(int)g_size,NULL); public=BN_bin2bn(y,(int)y_size,NULL);
        if (!prime || !generator || !public || BN_num_bits(prime) < 2048 || !(parameters=DH_new()) || DH_set0_pqg(parameters,prime,NULL,generator) != 1) goto cleanup;
        prime=generator=NULL;
        if (DH_set0_key(parameters,public,NULL) != 1) goto cleanup;
        public=NULL; peer=EVP_PKEY_new();
        if (!peer || EVP_PKEY_assign_DH(peer,parameters) != 1) goto cleanup;
        parameters=NULL; generate=EVP_PKEY_CTX_new(peer,NULL);
        if (!generate || EVP_PKEY_param_check(generate) != 1 || EVP_PKEY_public_check(generate) != 1 ||
            EVP_PKEY_keygen_init(generate) != 1 || EVP_PKEY_keygen(generate,&local) != 1) goto cleanup;
        derive=EVP_PKEY_CTX_new(local,NULL); size_t secret_length=0;
        if (!derive || EVP_PKEY_derive_init(derive) != 1 || EVP_PKEY_derive_set_peer(derive,peer) != 1 ||
            EVP_PKEY_derive(derive,NULL,&secret_length) != 1 || db_reserve(premaster,secret_length) ||
            EVP_PKEY_derive(derive,premaster->data,&secret_length) != 1) goto cleanup;
        premaster->len=secret_length; generated=EVP_PKEY_get1_DH(local); const BIGNUM *client_public=NULL;
        if (!generated) goto cleanup;
        DH_get0_key(generated,&client_public,NULL); size_t public_length=client_public ? (size_t)BN_num_bytes(client_public) : 0;
        if (!public_length || public_length > 65535 || db_reserve(client,public_length+2)) goto cleanup;
        uint8_t prefix[]={(uint8_t)(public_length>>8),(uint8_t)public_length};
        if (db_append(client,prefix,2) || BN_bn2bin(client_public,client->data+client->len) != (int)public_length) goto cleanup;
        client->len+=public_length;
    }
    result=0;
cleanup:
    BN_free(prime); BN_free(generator); BN_free(public); DH_free(parameters); DH_free(generated);
    EVP_PKEY_CTX_free(generate); EVP_PKEY_CTX_free(derive); EVP_PKEY_free(local); EVP_PKEY_free(peer); return result;
}
static int tls12_rsa_exchange(tls13_conn_t *c,dynbuf_t *premaster,dynbuf_t *client) {
    if (tls_certificate_key_usage(c->tls_peer_certificate,0)) return -1;
    EVP_PKEY *key=X509_get_pubkey(c->tls_peer_certificate); EVP_PKEY_CTX *context=key ? EVP_PKEY_CTX_new(key,NULL) : NULL; int result=-1;
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA || !context || db_reserve(premaster,48)) goto cleanup;
    premaster->len=48;
    if (RAND_bytes(premaster->data,48) != 1) goto cleanup;
    premaster->data[0]=3; premaster->data[1]=3; size_t encrypted_length=0;
    if (EVP_PKEY_encrypt_init(context) != 1 || EVP_PKEY_CTX_set_rsa_padding(context,RSA_PKCS1_PADDING) != 1 ||
        EVP_PKEY_encrypt(context,NULL,&encrypted_length,premaster->data,premaster->len) != 1 || encrypted_length > 65535 ||
        db_reserve(client,encrypted_length+2)) goto cleanup;
    client->data[0]=(uint8_t)(encrypted_length>>8); client->data[1]=(uint8_t)encrypted_length;
    if (EVP_PKEY_encrypt(context,client->data+2,&encrypted_length,premaster->data,premaster->len) != 1) goto cleanup;
    client->len=encrypted_length+2; result=0;
cleanup:
    EVP_PKEY_CTX_free(context); EVP_PKEY_free(key); return result;
}
static int tls12_certificate_request(const uint8_t *body,size_t length) {
    if (length < 6 || !body[0] || body[0] > length-1) return -1;
    size_t offset=1+body[0]; if (length-offset < 2) return -1;
    size_t signatures=tls12_word(body+offset); offset+=2;
    if (signatures < 2 || (signatures&1) || signatures > length-offset) return -1;
    offset+=signatures;
    if (length-offset < 2 || tls12_word(body+offset) != length-offset-2) return -1;
    offset+=2;
    while (offset < length) { if (length-offset < 2 || tls12_word(body+offset) > length-offset-2) return -1; offset+=2+tls12_word(body+offset); }
    return 0;
}
static int tls12_send_handshake(tls13_conn_t *c,const uint8_t *message,size_t length) {
    for (size_t offset=0;offset<length;) {
        size_t size=length-offset; if (size > 16384) size=16384;
        uint8_t header[]={22,3,3,(uint8_t)(size>>8),(uint8_t)size};
        if (write_exact(c->fd,header,5) || write_exact(c->fd,message+offset,size)) return -1;
        offset+=size;
    }
    return append_transcript(c,message,length);
}
static int run_tls12_handshake(const vless_config_t *config,tls13_conn_t *c,dynbuf_t *pending,char *error,size_t capacity) {
    struct {
        uint8_t client_random[32],server_random[32],master[48],block[256],hash[64],finished[12];
        dynbuf_t premaster,client;
        uint8_t *record,*decoded;
        size_t record_size,decoded_size;
    } state={0};
    int result=-1,certificate=0,key_exchange=0,status=0,request=0,done=0;
    memcpy(state.client_random,c->tls_client_hello.data+6,32);
    if (tls_buffer_init(&state.premaster,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes) ||
        tls_buffer_init(&state.client,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) goto cleanup;
    if (pending->len < 4) goto cleanup;
    size_t hello_length=4+((size_t)pending->data[1]<<16)+((size_t)pending->data[2]<<8)+pending->data[3];
    if (hello_length > pending->len || tls12_server_hello(c,pending->data,hello_length)) {
        set_err(error,capacity,"invalid TLS 1.2 ServerHello or downgrade marker"); goto cleanup;
    }
    if ((config->transport_mode == TRANSPORT_XHTTP || config->transport_mode == TRANSPORT_GRPC) && !strcmp(c->tls_selected_alpn,"h2") &&
        (c->tls12_suite->exchange == CORE_TLS12_RSA || c->tls12_suite->cipher == CORE_TLS12_CBC)) {
        set_err(error,capacity,"HTTP/2 selected an inadequate TLS 1.2 cipher"); goto cleanup;
    }
    memcpy(state.server_random,pending->data+6,32);
    if (append_transcript(c,pending->data,hello_length)) goto cleanup;
    db_consume(pending,hello_length);
    while (!done) {
        while (pending->len >= 4) {
            size_t body_length=((size_t)pending->data[1]<<16)|((size_t)pending->data[2]<<8)|pending->data[3];
            if (body_length > TLS_HANDSHAKE_LIMIT-4) goto cleanup;
            if (body_length > pending->len-4) break;
            unsigned type=pending->data[0]; const uint8_t *body=pending->data+4;
            if (type == 11 && !certificate && !key_exchange && !request) {
                if (tls12_certificate(config,c,pending->data,body_length+4,error,capacity)) goto cleanup;
                certificate=1;
            } else if (type == 22 && certificate && c->tls12_status && !status && !key_exchange && !request) {
                if (body_length < 4 || body[0] != 1 || (((size_t)body[1]<<16)|((size_t)body[2]<<8)|body[3]) != body_length-4) goto cleanup;
                status=1;
            } else if (type == 12 && certificate && !key_exchange && !request && c->tls12_suite->exchange != CORE_TLS12_RSA) {
                if (c->tls12_status && !status) goto cleanup;
                if (tls12_key_exchange(c,state.client_random,state.server_random,body,body_length,&state.premaster,&state.client)) {
                    set_err(error,capacity,"TLS 1.2 ServerKeyExchange signature or parameters failed"); goto cleanup;
                }
                key_exchange=1;
            } else if (type == 13 && certificate && !request && (key_exchange || c->tls12_suite->exchange == CORE_TLS12_RSA)) {
                if (tls12_certificate_request(body,body_length)) goto cleanup;
                request=1; c->tls_client_certificate_requested=1;
            } else if (type == 14 && !body_length && certificate && (key_exchange || c->tls12_suite->exchange == CORE_TLS12_RSA)) {
                if (c->tls12_status && !status) goto cleanup;
                done=1;
            } else { set_err(error,capacity,"unexpected TLS 1.2 server handshake message"); goto cleanup; }
            if (append_transcript(c,pending->data,body_length+4)) goto cleanup;
            db_consume(pending,body_length+4);
            if (done) break;
        }
        if (done) break;
        uint8_t type=0;
        if (read_record(c->fd,&type,&state.record,&state.record_size) || type != 22 || !state.record_size ||
            db_append(pending,state.record,state.record_size)) goto cleanup;
        free(state.record); state.record=NULL;
    }
    if (pending->len) { set_err(error,capacity,"unexpected data after TLS 1.2 ServerHelloDone"); goto cleanup; }
    if (c->tls12_suite->exchange == CORE_TLS12_RSA && tls12_rsa_exchange(c,&state.premaster,&state.client)) {
        set_err(error,capacity,"TLS 1.2 RSA key exchange failed"); goto cleanup;
    }
    const uint8_t empty_certificate[]={11,0,0,3,0,0,0};
    if (request && tls12_send_handshake(c,empty_certificate,sizeof(empty_certificate))) goto cleanup;
    uint8_t header[]={16,(uint8_t)(state.client.len>>16),(uint8_t)(state.client.len>>8),(uint8_t)state.client.len};
    dynbuf_t flight={0};
    if (tls_buffer_init(&flight,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes) || db_append(&flight,header,sizeof(header)) ||
        db_append(&flight,state.client.data,state.client.len)) { db_free(&flight); goto cleanup; }
    int sent=tls12_send_handshake(c,flight.data,flight.len); db_free(&flight);
    if (sent) goto cleanup;
    if (c->tls12_ems) {
        if (transcript_hash(c,state.hash) || core_tls12_prf(c->tls_md,state.premaster.data,state.premaster.len,"extended master secret",
            state.hash,c->tls_hash_len,state.master,sizeof(state.master))) goto cleanup;
    } else {
        uint8_t seed[64]; memcpy(seed,state.client_random,32); memcpy(seed+32,state.server_random,32);
        if (core_tls12_prf(c->tls_md,state.premaster.data,state.premaster.len,"master secret",seed,sizeof(seed),state.master,sizeof(state.master))) goto cleanup;
    }
    size_t mac_length=c->tls12_suite->mac_hash ? (size_t)EVP_MD_get_size(core_tls12_digest(c->tls12_suite->mac_hash)) : 0;
    size_t iv_length=c->tls12_suite->cipher == CORE_TLS12_GCM ? 4 : c->tls12_suite->cipher == CORE_TLS12_CHACHA ? 12 : 0;
    uint8_t seed[64]; memcpy(seed,state.server_random,32); memcpy(seed+32,state.client_random,32);
    if (core_tls12_prf(c->tls_md,state.master,sizeof(state.master),"key expansion",seed,sizeof(seed),state.block,2*(mac_length+c->tls_key_len+iv_length))) goto cleanup;
    size_t at=0; memcpy(c->tls12_c_mac,state.block+at,mac_length); at+=mac_length;
    memcpy(c->tls12_s_mac,state.block+at,mac_length); at+=mac_length;
    memcpy(c->c_app_key,state.block+at,c->tls_key_len); at+=c->tls_key_len;
    memcpy(c->s_app_key,state.block+at,c->tls_key_len); at+=c->tls_key_len;
    memcpy(c->c_app_iv,state.block+at,iv_length); at+=iv_length; memcpy(c->s_app_iv,state.block+at,iv_length);
    if (transcript_hash(c,state.hash) || core_tls12_prf(c->tls_md,state.master,sizeof(state.master),"client finished",state.hash,c->tls_hash_len,state.finished,12)) goto cleanup;
    uint8_t finished[]={20,0,0,12,0,0,0,0,0,0,0,0,0,0,0,0}; memcpy(finished+4,state.finished,12);
    const uint8_t ccs[]={20,3,3,0,1,1};
    if (encrypt_record(c,c->c_app_key,c->c_app_iv,&c->c_app_seq,22,finished,sizeof(finished),&state.record,&state.record_size) ||
        write_exact(c->fd,ccs,sizeof(ccs)) || write_exact(c->fd,state.record,state.record_size) || append_transcript(c,finished,sizeof(finished))) goto cleanup;
    free(state.record); state.record=NULL;
    int changed=0,ticket=0,complete=0;
    while (!complete) {
        uint8_t type=0;
        if (read_record_bounded(c->fd,&type,&state.record,&state.record_size,changed)) goto cleanup;
        if (type == 20 && !changed && state.record_size == 1 && state.record[0] == 1 && !pending->len) changed=1;
        else if (type == 22 && state.record_size) {
            const uint8_t *bytes=state.record; size_t count=state.record_size;
            if (changed) {
                uint8_t inner=0;
                if (decrypt_record(c,c->s_app_key,c->s_app_iv,&c->s_app_seq,type,state.record,state.record_size,&state.decoded,&state.decoded_size,&inner)) goto cleanup;
                bytes=state.decoded; count=state.decoded_size;
            }
            if (db_append(pending,bytes,count)) goto cleanup;
            while (pending->len >= 4) {
                size_t body_length=((size_t)pending->data[1]<<16)|((size_t)pending->data[2]<<8)|pending->data[3];
                if (body_length > TLS_HANDSHAKE_LIMIT-4) goto cleanup;
                if (body_length > pending->len-4) break;
                if (!changed && pending->data[0] == 4 && c->tls12_ticket && !ticket && body_length >= 6 &&
                    tls12_word(pending->data+8) == body_length-6) ticket=1;
                else if (changed && pending->data[0] == 20 && body_length == 12) {
                    if (transcript_hash(c,state.hash) || core_tls12_prf(c->tls_md,state.master,sizeof(state.master),"server finished",
                        state.hash,c->tls_hash_len,state.finished,12) || CRYPTO_memcmp(state.finished,pending->data+4,12)) {
                        set_err(error,capacity,"TLS 1.2 server Finished mismatch"); goto cleanup;
                    }
                    complete=1;
                } else { set_err(error,capacity,"unexpected TLS 1.2 server final flight"); goto cleanup; }
                if (append_transcript(c,pending->data,body_length+4)) goto cleanup;
                db_consume(pending,body_length+4);
                if (complete) break;
            }
        } else { set_err(error,capacity,"unexpected TLS 1.2 record during handshake"); goto cleanup; }
        free(state.record); state.record=NULL;
        if (state.decoded) { OPENSSL_cleanse(state.decoded,state.decoded_size); free(state.decoded); state.decoded=NULL; }
    }
    if (pending->len || (core_deadline_active() && !core_deadline_remaining())) goto cleanup;
    if (c->tls_verify_policy == TLS_VERIFY_MODE_TOFU && tcp_tls_tofu_verify_or_store(config,c->tls_certificate_message.data,c->tls_certificate_message.len,error,capacity)) goto cleanup;
    c->tls_auth_state=4; result=0;
cleanup: {
    int saved=errno;
    if (result && error && capacity && !*error) set_err(error,capacity,"TLS 1.2 handshake failed");
    free(state.record);
    if (state.decoded) { OPENSSL_cleanse(state.decoded,state.decoded_size); free(state.decoded); }
    db_free(&state.premaster); db_free(&state.client); OPENSSL_cleanse(&state,sizeof(state));
    errno=saved; return result;
}
}

static int run_tls_handshake_with_key(const vless_config_t *cfg, tls13_conn_t *c, tls_cipher_offer_t cipher_offer, EVP_PKEY *hybrid_key, const uint8_t *hybrid_pub, char *err, size_t err_cap) {
    uint8_t client_priv[32]={0},shared[96]={0};
    int use_reality = (strcmp(cfg->security, "reality") == 0);
    tls_verify_mode_t verify_mode = tls_verify_mode_for_config(cfg);
    c->tls_verify_policy = verify_mode;
    snprintf(c->tls_verify_mode, sizeof(c->tls_verify_mode), "%s",
             use_reality ? "reality" : tls_verify_mode_name(verify_mode));
    snprintf(c->tls_offered_alpn,sizeof(c->tls_offered_alpn),"%s",cfg->alpn[0] ? cfg->alpn :
        (cfg->fp_mode == FP_RANDOM || cfg->fp_mode == FP_RANDOMIZED ? "http/1.1,h2" : "h2,http/1.1"));
    c->tls_h2_required=cfg->transport_mode == TRANSPORT_GRPC || (cfg->transport_mode == TRANSPORT_XHTTP && use_reality);
    c->tls_is_reality=use_reality;
    c->tls_receive_record_limit=c->tls_send_record_limit=0; c->tls_receive_update_requested=0;
    if (tls_buffer_init(&c->tls_client_hello,65536,&c->tls_handshake_bytes) ||
        tls_buffer_init(&c->tls_certificate_message,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) {
        set_err(err,err_cap,"TLS handshake memory budget exhausted"); goto handshake_failure;
    }
    if (c->tls_h2_required && !alpn_csv_has_token(c->tls_offered_alpn,"h2")) { set_err(err,err_cap,"HTTP/2 transport requires h2 ALPN"); goto handshake_failure; }

    uint8_t client_pub[32];
    uint8_t client_random[32];
    uint8_t *ch = NULL;
    size_t ch_len = 0;
    size_t sid_pos = 0;

    EVP_PKEY_free(c->tls_retry_key); c->tls_retry_key=NULL;
    if (build_client_hello(cfg, use_reality, cipher_offer, client_priv, client_pub, client_random, c->auth_key, &ch, &ch_len, &sid_pos, hybrid_pub,&c->tls_retry_key) !=
        0) {
        set_err(err, err_cap, "failed to build ClientHello");
        goto handshake_failure;
    }
    if (c->tls_retry_key) c->tls_exchange_group=23;

    uint8_t *ch_record = (uint8_t *)malloc(5 + ch_len);
    if (ch_record == NULL) {
        free(ch);
        set_err(err, err_cap, "failed to allocate ClientHello record");
        goto handshake_failure;
    }
    ch_record[0] = 0x16;
    ch_record[1] = 0x03;
    ch_record[2] = 0x01;
    ch_record[3] = (uint8_t)(ch_len >> 8);
    ch_record[4] = (uint8_t)(ch_len & 0xFF);
    memcpy(ch_record + 5, ch, ch_len);
    if (write_exact(c->fd, ch_record, 5 + ch_len) != 0) {
        free(ch_record);
        free(ch);
        set_err(err, err_cap, "failed to send ClientHello");
        goto handshake_failure;
    }
    free(ch_record);

    if (append_transcript(c, ch, ch_len) != 0 || db_append(&c->tls_client_hello,ch,ch_len)) {
        free(ch);
        set_err(err, err_cap, "transcript append failed");
        goto handshake_failure;
    }
    free(ch);

    dynbuf_t plain_hs = {0};
    if (tls_buffer_init(&plain_hs,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) goto handshake_failure;
    uint8_t server_share[TLS_HYBRID_SERVER_SHARE_SIZE];
    size_t share_len = 0;
    uint16_t server_cipher = 0;
    uint16_t server_group = 0;
    int got_server_hello = 0;

    while (!got_server_hello) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            db_free(&plain_hs);
            set_err(err, err_cap, "failed to read ServerHello record");
            goto handshake_failure;
        }

        if (rtype == 0x16) {
            if (!pl_len) {
                free(pl); db_free(&plain_hs); set_err(err,err_cap,"empty TLS handshake record before ServerHello"); goto handshake_failure;
            }
            if (db_append(&plain_hs, pl, pl_len) != 0) {
                free(pl);
                db_free(&plain_hs);
                goto handshake_failure;
            }
            free(pl);

            while (plain_hs.len >= 4) {
                size_t mlen = ((size_t)plain_hs.data[1] << 16) | ((size_t)plain_hs.data[2] << 8) | plain_hs.data[3];
                if (mlen > TLS_HANDSHAKE_LIMIT-4) { db_free(&plain_hs); set_err(err,err_cap,"TLS ServerHello exceeds handshake limit"); goto handshake_failure; }
                if (plain_hs.len < 4 + mlen) {
                    break;
                }
                if (plain_hs.data[0] == 0x02) {
                    size_t cipher_position=plain_hs.len >= 39 ? 39U+plain_hs.data[38] : SIZE_MAX;
                    if (!use_reality && cipher_position < 4+mlen && 4+mlen-cipher_position >= 3 && core_tls12_suite(tls12_word(plain_hs.data+cipher_position))) {
                        int result=run_tls12_handshake(cfg,c,&plain_hs,err,err_cap);
                        db_free(&plain_hs);
                        if (result) goto handshake_failure;
                        goto handshake_complete;
                    }
                    core_tls_hello_t server;
                    if (core_tls_hello_parse(plain_hs.data,4+mlen,c->tls_client_hello.data,c->tls_client_hello.len,&server)) {
                        db_free(&plain_hs); set_err(err,err_cap,"invalid TLS ServerHello parameters"); goto handshake_failure;
                    }
                    if (server.retry) {
                        if (c->tls_retry_seen || use_reality) { db_free(&plain_hs); set_err(err,err_cap,c->tls_retry_seen ? "repeated TLS HelloRetryRequest" : "REALITY HelloRetryRequest is unsupported"); goto handshake_failure; }
                        uint8_t hash[64],*retry=NULL; size_t retry_length=0;
                        EVP_PKEY *retry_key=NULL;
                        if (configure_tls_cipher(c,server.cipher) || transcript_hash(c,hash) ||
                            core_tls_hello_retry(c->tls_client_hello.data,c->tls_client_hello.len,&server,&retry,&retry_length,&retry_key)) {
                            db_free(&plain_hs); set_err(err,err_cap,"unsupported TLS HelloRetryRequest"); goto handshake_failure;
                        }
                        if (retry_key) { EVP_PKEY_free(c->tls_retry_key); c->tls_retry_key=retry_key; c->tls_exchange_group=server.group; }
                        c->transcript.len=0; uint8_t message_hash[]={254,0,0,(uint8_t)c->tls_hash_len};
                        int result=append_transcript(c,message_hash,4) || append_transcript(c,hash,c->tls_hash_len) ||
                            append_transcript(c,plain_hs.data,4+mlen) || append_transcript(c,retry,retry_length);
                        db_free(&c->tls_client_hello);
                        if (!result) result=tls_buffer_init(&c->tls_client_hello,65536,&c->tls_handshake_bytes) || db_append(&c->tls_client_hello,retry,retry_length);
                        uint8_t header[]={22,3,3,(uint8_t)(retry_length>>8),(uint8_t)retry_length};
                        if (!result) result=write_exact(c->fd,header,5) || write_exact(c->fd,retry,retry_length);
                        free(retry); c->tls_retry_seen=1; c->tls_retry_group=server.group;
                        if (result) { db_free(&plain_hs); set_err(err,err_cap,"failed to send retry ClientHello"); goto handshake_failure; }
                        db_consume(&plain_hs,4+mlen); break;
                    }
                    if (c->tls_retry_seen && (server.cipher != c->tls_cipher_suite || (c->tls_retry_group && server.group != c->tls_retry_group))) {
                        db_free(&plain_hs); set_err(err,err_cap,"ServerHello changed HelloRetryRequest parameters"); goto handshake_failure;
                    }
                    if (parse_server_hello_for_keyshare(plain_hs.data, 4 + mlen, &server_cipher, server_share, &share_len) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "invalid ServerHello");
                        goto handshake_failure;
                    }
                    if (configure_tls_cipher(c, server_cipher) != 0) {
                        db_free(&plain_hs);
                        set_err(err, err_cap, "unsupported TLS cipher suite");
                        goto handshake_failure;
                    }
                    if (append_transcript(c, plain_hs.data, 4 + mlen) != 0) {
                        db_free(&plain_hs);
                        goto handshake_failure;
                    }
                    server_group=server.group;
                    got_server_hello = 1;
                    db_consume(&plain_hs, 4 + mlen);
                    break;
                }
                db_free(&plain_hs); set_err(err,err_cap,"unexpected message before ServerHello"); goto handshake_failure;
            }
        } else if (rtype == 20 && pl_len == 1 && pl[0] == 1) {
            free(pl);
        } else {
            free(pl); db_free(&plain_hs); set_err(err,err_cap,"unexpected TLS record before ServerHello"); goto handshake_failure;
        }
    }

    if (plain_hs.len) { db_free(&plain_hs); set_err(err,err_cap,"unexpected plaintext after ServerHello"); goto handshake_failure; }
    db_free(&plain_hs);

    if (!got_server_hello) {
        set_err(err, err_cap, "ServerHello not received");
        goto handshake_failure;
    }

    size_t shared_len = 32;
    if (share_len == TLS_HYBRID_SERVER_SHARE_SIZE) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
        EVP_PKEY_CTX *kem = hybrid_key != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, hybrid_key, NULL) : NULL;
        size_t kem_len = 32;
        int ok = kem != NULL && EVP_PKEY_decapsulate_init(kem, NULL) == 1 &&
                 EVP_PKEY_decapsulate(kem, shared, &kem_len, server_share, TLS_MLKEM768_CIPHERTEXT_SIZE) == 1 && kem_len == 32;
        EVP_PKEY_CTX_free(kem);
        if (!ok) {
            set_err(err, err_cap, "TLS ML-KEM decapsulation failed");
            goto handshake_failure;
        }
        shared_len = 64;
#else
        (void)hybrid_key;
        set_err(err, err_cap, "TLS X25519MLKEM768 requires OpenSSL 3.5 or newer");
        goto handshake_failure;
#endif
    }
    int exchange_result;
    if (c->tls_retry_key && server_group == c->tls_exchange_group) {
        shared_len=sizeof(shared);
        exchange_result=core_tls_ecdh(c->tls_retry_key,server_group,server_share,share_len,shared,&shared_len);
    } else exchange_result=x25519_shared(client_priv, server_share + share_len - 32, shared + shared_len - 32);
    if (exchange_result != 0) {
        set_err(err, err_cap, "ECDH failed");
        goto handshake_failure;
    }

    if (derive_handshake_keys(c, shared, shared_len) != 0) {
        set_err(err, err_cap, "failed to derive handshake keys");
        goto handshake_failure;
    }
    vc_log_debug("tls", "selected key exchange=%s",server_group == 23 ? "P-256" : server_group == 24 ? "P-384" :
        server_group == 25 ? "P-521" : shared_len == 64 ? "X25519MLKEM768" : "X25519");

    dynbuf_t enc_hs = {0};
    if (tls_buffer_init(&enc_hs,TLS_HANDSHAKE_LIMIT,&c->tls_handshake_bytes)) goto handshake_failure;
    int got_finished = 0;

    while (!got_finished) {
        uint8_t rtype = 0;
        uint8_t *pl = NULL;
        size_t pl_len = 0;
        if (read_record(c->fd, &rtype, &pl, &pl_len) != 0) {
            db_free(&enc_hs);
            set_err(err, err_cap, "failed to read encrypted handshake");
            goto handshake_failure;
        }

        if (rtype != 0x17) {
            int compatibility=rtype == 20 && pl_len == 1 && pl[0] == 1;
            free(pl);
            if (compatibility) continue;
            db_free(&enc_hs); set_err(err,err_cap,"unexpected TLS record during server handshake"); goto handshake_failure;
        }

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        uint8_t inner_type = 0;
        if (decrypt_record(c, c->s_hs_key, c->s_hs_iv, &c->s_hs_seq, rtype, pl, pl_len, &dec, &dec_len, &inner_type) != 0) {
            free(pl);
            db_free(&enc_hs);
            set_err(err, err_cap, "failed to decrypt handshake record");
            goto handshake_failure;
        }
        free(pl);

        if (inner_type == 0x16) {
            if (db_append(&enc_hs, dec, dec_len) != 0) {
                free(dec);
                db_free(&enc_hs);
                goto handshake_failure;
            }
            free(dec);

            while (enc_hs.len >= 4) {
                size_t hlen = ((size_t)enc_hs.data[1] << 16) | ((size_t)enc_hs.data[2] << 8) | enc_hs.data[3];
                if (hlen > TLS_HANDSHAKE_LIMIT-4) { db_free(&enc_hs); set_err(err,err_cap,"TLS message exceeds handshake limit"); goto handshake_failure; }
                if (enc_hs.len < 4 + hlen) {
                    break;
                }
                int result=server_handshake_message(cfg,c,enc_hs.data,4+hlen,err,err_cap);
                if (result < 0) {
                    db_free(&enc_hs);
                    goto handshake_failure;
                }
                db_consume(&enc_hs, 4 + hlen);
                if (result > 0) { got_finished=1; break; }
            }
        } else {
            free(dec);
            db_free(&enc_hs); set_err(err,err_cap,"unexpected TLS inner record during handshake"); goto handshake_failure;
        }
    }

    if (enc_hs.len) { db_free(&enc_hs); set_err(err,err_cap,"unexpected handshake data after server Finished"); goto handshake_failure; }
    db_free(&enc_hs);

    // TLS 1.3 traffic_secret_0 is derived from transcript up to server Finished.
    if (derive_app_keys(c) != 0) {
        set_err(err, err_cap, "failed to derive application keys");
        goto handshake_failure;
    }

    static const uint8_t empty_certificate[]={11,0,0,4,0,0,0,0};
    if (c->tls_client_certificate_requested && append_transcript(c,empty_certificate,sizeof(empty_certificate))) goto handshake_failure;
    uint8_t thash[64],client_verify[64];
    if (transcript_hash(c,thash) || calc_finished_verify(c,c->c_hs_traffic,thash,client_verify)) {
        set_err(err,err_cap,"failed to create client Finished"); goto handshake_failure;
    }

    uint8_t flight[76],*fin_msg=flight+(c->tls_client_certificate_requested ? sizeof(empty_certificate) : 0);
    if (c->tls_client_certificate_requested) memcpy(flight,empty_certificate,sizeof(empty_certificate));
    size_t fin_msg_len = 4 + c->tls_hash_len;
    fin_msg[0] = 0x14;
    fin_msg[1] = 0x00;
    fin_msg[2] = 0x00;
    fin_msg[3] = (uint8_t)c->tls_hash_len;
    memcpy(fin_msg + 4, client_verify, c->tls_hash_len);

    uint8_t *enc_fin = NULL;
    size_t enc_fin_len = 0;
    if (encrypt_record(c, c->c_hs_key, c->c_hs_iv, &c->c_hs_seq, 0x16, flight, (size_t)(fin_msg-flight)+fin_msg_len, &enc_fin, &enc_fin_len) != 0) {
        set_err(err, err_cap, "failed to encrypt client Finished");
        goto handshake_failure;
    }

    /*
     * uTLS/Go middlebox-compat TLS 1.3 sends ChangeCipherSpec after the server
     * handshake flight and immediately before the encrypted Client Finished.
     * It is not included in the handshake transcript.
     */
    uint8_t ccs_rec[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    uint8_t *client_last_flight = (uint8_t *)malloc(sizeof(ccs_rec) + enc_fin_len);
    if (client_last_flight == NULL) {
        free(enc_fin);
        set_err(err, err_cap, "failed to allocate client Finished flight");
        goto handshake_failure;
    }
    memcpy(client_last_flight, ccs_rec, sizeof(ccs_rec));
    memcpy(client_last_flight + sizeof(ccs_rec), enc_fin, enc_fin_len);
    if (write_exact(c->fd, client_last_flight, sizeof(ccs_rec) + enc_fin_len) != 0) {
        free(client_last_flight);
        free(enc_fin);
        set_err(err, err_cap, "failed to send client Finished");
        goto handshake_failure;
    }
    free(client_last_flight);
    free(enc_fin);

    if (append_transcript(c, fin_msg, fin_msg_len) != 0) {
        goto handshake_failure;
    }

handshake_complete:
    OPENSSL_cleanse(client_priv,sizeof(client_priv)); OPENSSL_cleanse(shared,sizeof(shared));
    tls_handshake_material_clear(c);
    return 0;
handshake_failure: {
    int saved=errno;
    OPENSSL_cleanse(client_priv,sizeof(client_priv)); OPENSSL_cleanse(shared,sizeof(shared));
    tls_handshake_material_clear(c);
    OPENSSL_cleanse(c->c_app_traffic,sizeof(c->c_app_traffic)); OPENSSL_cleanse(c->s_app_traffic,sizeof(c->s_app_traffic));
    OPENSSL_cleanse(c->c_app_key,sizeof(c->c_app_key)); OPENSSL_cleanse(c->s_app_key,sizeof(c->s_app_key));
    OPENSSL_cleanse(c->c_app_iv,sizeof(c->c_app_iv)); OPENSSL_cleanse(c->s_app_iv,sizeof(c->s_app_iv));
    OPENSSL_cleanse(c->tls12_c_mac,sizeof(c->tls12_c_mac)); OPENSSL_cleanse(c->tls12_s_mac,sizeof(c->tls12_s_mac));
    if (err && err_cap && !*err) set_err(err,err_cap,errno == ENOBUFS || errno == EMSGSIZE ? "TLS handshake memory or message limit exceeded" : "TLS handshake failed");
    errno=saved; return -1;
}
}

int run_tls_handshake(const vless_config_t *cfg, tls13_conn_t *c, tls_cipher_offer_t cipher_offer, char *err, size_t err_cap) {
    EVP_PKEY *hybrid_key = NULL;
    uint8_t hybrid_pub[TLS_MLKEM768_PUBLIC_KEY_SIZE];
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    if (strcmp(cfg->security, "reality") == 0 &&
        (cfg->fp_mode == FP_CHROME || cfg->fp_mode == FP_EDGE || cfg->fp_mode == FP_FIREFOX)) {
        hybrid_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
        unsigned char *encoded = NULL;
        size_t encoded_len = hybrid_key != NULL ? EVP_PKEY_get1_encoded_public_key(hybrid_key, &encoded) : 0;
        if (encoded_len != sizeof(hybrid_pub)) {
            OPENSSL_free(encoded);
            EVP_PKEY_free(hybrid_key);
            set_err(err, err_cap, "TLS ML-KEM key generation failed");
            return -1;
        }
        memcpy(hybrid_pub, encoded, encoded_len);
        OPENSSL_free(encoded);
    }
#endif
    int result = run_tls_handshake_with_key(cfg, c, cipher_offer, hybrid_key,
                                          hybrid_key != NULL ? hybrid_pub : NULL, err, err_cap);
    int saved=errno;
    EVP_PKEY_free(hybrid_key);
    errno=saved; return result;
}
