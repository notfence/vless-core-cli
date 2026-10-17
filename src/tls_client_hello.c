#include "tls_internal.h"

static uint8_t g_xray_version[3] = {
    XRAY_DEFAULT_VERSION_X,
    XRAY_DEFAULT_VERSION_Y,
    XRAY_DEFAULT_VERSION_Z,
};

int tls13_reality_set_xray_version(const char *value) {
    if (!value) return -1;
    uint8_t parsed[3];
    for (unsigned component=0;component<3;component++) {
        unsigned number=0;
        if (*value < '0' || *value > '9') return -1;
        do {
            unsigned digit=(unsigned)(*value-'0');
            if (number > (255U-digit)/10U) return -1;
            number=number*10U+digit; value++;
        } while (*value >= '0' && *value <= '9');
        parsed[component]=(uint8_t)number;
        if (*value != (component == 2 ? '\0' : '.')) return -1;
        if (component != 2) value++;
    }
    memcpy(g_xray_version,parsed,sizeof(parsed));
    return 0;
}

static int x25519_generate(uint8_t priv[32], uint8_t pub[32]) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (kctx == NULL) {
        return -1;
    }
    EVP_PKEY *pkey = NULL;
    int ok = EVP_PKEY_keygen_init(kctx) == 1 && EVP_PKEY_keygen(kctx, &pkey) == 1;
    EVP_PKEY_CTX_free(kctx);
    if (!ok || pkey == NULL) {
        if (pkey != NULL) {
            EVP_PKEY_free(pkey);
        }
        return -1;
    }

    size_t priv_len = 32;
    size_t pub_len = 32;
    ok = EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) == 1 && priv_len == 32 &&
         EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) == 1 && pub_len == 32;
    EVP_PKEY_free(pkey);
    return ok ? 0 : -1;
}

int x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]) {
    EVP_PKEY *sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (sk == NULL || pk == NULL) {
        if (sk != NULL) {
            EVP_PKEY_free(sk);
        }
        if (pk != NULL) {
            EVP_PKEY_free(pk);
        }
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(sk);
        EVP_PKEY_free(pk);
        return -1;
    }

    size_t out_len = 32;
    int ok = EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, pk) == 1 &&
             EVP_PKEY_derive(ctx, out, &out_len) == 1 && out_len == 32;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 3
static int p256_generate_public_legacy(uint8_t pub[65], EVP_PKEY **retained) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL) {
        return -1;
    }
    int ok = EC_KEY_generate_key(key) == 1;
    if (ok) {
        const EC_GROUP *group = EC_KEY_get0_group(key);
        const EC_POINT *point = EC_KEY_get0_public_key(key);
        ok = group != NULL && point != NULL &&
             EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pub, 65, NULL) == 65;
    }
    if (ok && retained) {
        *retained=EVP_PKEY_new();
        if (!*retained || EVP_PKEY_assign_EC_KEY(*retained,key) != 1) { EVP_PKEY_free(*retained); *retained=NULL; ok=0; }
        else key=NULL;
    }
    EC_KEY_free(key);
    return ok ? 0 : -1;
}
#endif

static int p256_generate_public(uint8_t pub[65], EVP_PKEY **retained) {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    int ok = 0;

    if (ctx == NULL) {
        return -1;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
        EVP_PKEY_generate(ctx, &key) == 1 &&
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, 65, NULL) == 1) {
        ok = 1;
    }

    if (ok && retained) { *retained=key; key=NULL; }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
#else
    return p256_generate_public_legacy(pub,retained);
#endif
}

static int random_grease_values(uint16_t values[4]) {
    static const uint16_t vals[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                                    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
    uint8_t bytes[4],available[16];
    if (RAND_bytes(bytes,sizeof(bytes)) != 1) { errno=EIO; return -1; }
    values[0]=vals[bytes[0]%16];
    for (unsigned i=0;i<16;i++) available[i]=(uint8_t)i;
    for (unsigned i=1;i<4;i++) {
        unsigned count=17-i,index=bytes[i]%count;
        values[i]=vals[available[index]]; available[index]=available[count-1];
    }
    return 0;
}

static int add_ext(dynbuf_t *b, uint16_t etype, const uint8_t *edata, size_t elen) {
    uint8_t hdr[4] = {(uint8_t)(etype >> 8), (uint8_t)(etype & 0xFF), (uint8_t)(elen >> 8), (uint8_t)(elen & 0xFF)};
    if (db_append(b, hdr, 4) != 0) {
        return -1;
    }
    return db_append(b, edata, elen);
}

static int ext_server_name(dynbuf_t *exts, const char *sni) {
    if (tls_identity_is_ip(sni)) return 0;
    uint8_t data[512];
    size_t sni_len = strlen(sni);
    if (sni_len == 0 || sni_len > 255) {
        return -1;
    }

    size_t off = 0;
    size_t list_len = 1 + 2 + sni_len;
    data[off++] = (uint8_t)(list_len >> 8);
    data[off++] = (uint8_t)(list_len & 0xFF);
    data[off++] = 0x00;
    data[off++] = (uint8_t)(sni_len >> 8);
    data[off++] = (uint8_t)(sni_len & 0xFF);
    memcpy(data + off, sni, sni_len);
    off += sni_len;
    return add_ext(exts, 0x0000, data, off);
}

static int ext_supported_groups(dynbuf_t *exts, uint16_t grease, int random_mode, int hybrid) {
    uint8_t data[32];
    uint16_t groups[5];
    size_t gcount = 0;
    if (!random_mode) groups[gcount++] = grease;
    if (hybrid) groups[gcount++] = TLS_GROUP_X25519MLKEM768;
    groups[gcount++] = 0x001d;
    groups[gcount++] = 0x0017;
    if (!random_mode) groups[gcount++] = 0x0018;

    size_t off = 0;
    size_t glen = gcount * 2;
    data[off++] = (uint8_t)(glen >> 8);
    data[off++] = (uint8_t)(glen & 0xFF);
    for (size_t i = 0; i < gcount; i++) {
        data[off++] = (uint8_t)(groups[i] >> 8);
        data[off++] = (uint8_t)(groups[i] & 0xFF);
    }

    return add_ext(exts, 0x000a, data, off);
}

static int ext_supported_groups_firefox(dynbuf_t *exts, int hybrid) {
    uint16_t groups[] = {TLS_GROUP_X25519MLKEM768, 0x001d, 0x0017, 0x0018, 0x0019};
    uint8_t data[32];
    size_t off = 0;
    size_t start = hybrid ? 0 : 1;
    size_t glen = sizeof(groups) - start * sizeof(groups[0]);
    data[off++] = (uint8_t)(glen >> 8);
    data[off++] = (uint8_t)(glen & 0xFF);
    for (size_t i = start; i < sizeof(groups) / sizeof(groups[0]); i++) {
        data[off++] = (uint8_t)(groups[i] >> 8);
        data[off++] = (uint8_t)(groups[i] & 0xFF);
    }
    return add_ext(exts, 0x000a, data, off);
}

static int ext_ec_point_formats(dynbuf_t *exts) {
    uint8_t data[] = {0x01, 0x00};
    return add_ext(exts, 0x000b, data, sizeof(data));
}

static int ext_sig_algs(dynbuf_t *exts) {
    uint16_t sigs[] = {0x0403, 0x0804, 0x0503, 0x0805, 0x0806, 0x0807, 0x0601, 0x0501, 0x0401, 0x0809, 0x080a, 0x080b, 0x0603};
    uint8_t data[64];
    size_t off = 0;
    size_t slen = sizeof(sigs);
    data[off++] = (uint8_t)(slen >> 8);
    data[off++] = (uint8_t)(slen & 0xFF);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        data[off++] = (uint8_t)(sigs[i] >> 8);
        data[off++] = (uint8_t)(sigs[i] & 0xFF);
    }
    return add_ext(exts, 0x000d, data, off);
}

static int ext_sig_algs_qq(dynbuf_t *exts) {
    uint16_t sigs[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0807, 0x0601, 0x0809, 0x080a, 0x080b, 0x0603};
    uint8_t data[64];
    size_t off = 0;
    size_t slen = sizeof(sigs);
    data[off++] = (uint8_t)(slen >> 8);
    data[off++] = (uint8_t)(slen & 0xFF);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        data[off++] = (uint8_t)(sigs[i] >> 8);
        data[off++] = (uint8_t)(sigs[i] & 0xFF);
    }
    return add_ext(exts, 0x000d, data, off);
}

static int ext_sig_algs_firefox(dynbuf_t *exts) {
    uint16_t sigs[] = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0809, 0x080a, 0x080b};
    uint8_t data[64];
    size_t off = 0;
    size_t slen = sizeof(sigs);
    data[off++] = (uint8_t)(slen >> 8);
    data[off++] = (uint8_t)(slen & 0xFF);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        data[off++] = (uint8_t)(sigs[i] >> 8);
        data[off++] = (uint8_t)(sigs[i] & 0xFF);
    }
    return add_ext(exts, 0x000d, data, off);
}

static int ext_alpn(dynbuf_t *exts, int random_mode) {
    const char *p1 = random_mode ? "http/1.1" : "h2";
    const char *p2 = random_mode ? "h2" : "http/1.1";
    size_t l1 = strlen(p1);
    size_t l2 = strlen(p2);

    uint8_t data[64];
    size_t off = 0;
    size_t list_len = 1 + l1 + 1 + l2;
    data[off++] = (uint8_t)(list_len >> 8);
    data[off++] = (uint8_t)(list_len & 0xFF);
    data[off++] = (uint8_t)l1;
    memcpy(data + off, p1, l1);
    off += l1;
    data[off++] = (uint8_t)l2;
    memcpy(data + off, p2, l2);
    off += l2;

    return add_ext(exts, 0x0010, data, off);
}

static int ext_supported_versions(dynbuf_t *exts, uint16_t grease, int random_mode) {
    uint8_t data[8];
    size_t off = 0;
    if (random_mode) {
        data[off++] = 0x04;
        data[off++] = 0x03;
        data[off++] = 0x04;
        data[off++] = 0x03;
        data[off++] = 0x03;
    } else {
        data[off++] = 0x06;
        data[off++] = (uint8_t)(grease >> 8);
        data[off++] = (uint8_t)(grease & 0xFF);
        data[off++] = 0x03;
        data[off++] = 0x04;
        data[off++] = 0x03;
        data[off++] = 0x03;
    }
    return add_ext(exts, 0x002b, data, off);
}

static int ext_supported_versions_qq(dynbuf_t *exts, uint16_t grease) {
    uint8_t data[] = {0x06, (uint8_t)(grease >> 8), (uint8_t)(grease & 0xFF), 0x03, 0x04, 0x03, 0x03};
    return add_ext(exts, 0x002b, data, sizeof(data));
}

static int ext_supported_versions_firefox(dynbuf_t *exts) {
    uint8_t data[] = {0x04, 0x03, 0x04, 0x03, 0x03};
    return add_ext(exts, 0x002b, data, sizeof(data));
}

static int ext_psk_modes(dynbuf_t *exts) {
    uint8_t data[] = {0x01, 0x01};
    return add_ext(exts, 0x002d, data, sizeof(data));
}

static size_t append_x25519_key_shares(uint8_t *data, size_t off, const uint8_t pubkey[32], const uint8_t *hybrid_pub) {
    if (hybrid_pub != NULL) {
        data[off++] = (uint8_t)(TLS_GROUP_X25519MLKEM768 >> 8);
        data[off++] = (uint8_t)TLS_GROUP_X25519MLKEM768;
        data[off++] = (uint8_t)(TLS_HYBRID_CLIENT_SHARE_SIZE >> 8);
        data[off++] = (uint8_t)TLS_HYBRID_CLIENT_SHARE_SIZE;
        memcpy(data + off, hybrid_pub, TLS_MLKEM768_PUBLIC_KEY_SIZE);
        off += TLS_MLKEM768_PUBLIC_KEY_SIZE;
        memcpy(data + off, pubkey, 32);
        off += 32;
    }

    data[off++] = 0x00;
    data[off++] = 0x1d;
    data[off++] = 0x00;
    data[off++] = 0x20;
    memcpy(data + off, pubkey, 32);
    off += 32;
    return off;
}

static int ext_key_share(dynbuf_t *exts, uint16_t grease, const uint8_t pubkey[32], int random_mode, const uint8_t *hybrid_pub) {
    uint8_t data[2 + 5 + 4 + TLS_HYBRID_CLIENT_SHARE_SIZE + 4 + 32];
    size_t off = 2;

    if (!random_mode) {
        data[off++] = (uint8_t)(grease >> 8);
        data[off++] = (uint8_t)(grease & 0xFF);
        data[off++] = 0x00;
        data[off++] = 0x01;
        data[off++] = 0x00;
    }
    off = append_x25519_key_shares(data, off, pubkey, hybrid_pub);

    size_t list_len = off - 2;
    data[0] = (uint8_t)(list_len >> 8);
    data[1] = (uint8_t)(list_len & 0xFF);

    return add_ext(exts, 0x0033, data, off);
}

static int ext_key_share_firefox(dynbuf_t *exts, const uint8_t x25519_pub[32], const uint8_t *hybrid_pub, EVP_PKEY **retained) {
    uint8_t p256_pub[65];
    if (p256_generate_public(p256_pub,retained) != 0) {
        return -1;
    }

    uint8_t data[2 + 4 + TLS_HYBRID_CLIENT_SHARE_SIZE + 4 + 32 + 4 + 65];
    size_t off = append_x25519_key_shares(data, 2, x25519_pub, hybrid_pub);

    data[off++] = 0x00;
    data[off++] = 0x17;
    data[off++] = 0x00;
    data[off++] = 0x41;
    memcpy(data + off, p256_pub, sizeof(p256_pub));
    off += sizeof(p256_pub);

    size_t list_len = off - 2;
    data[0] = (uint8_t)(list_len >> 8);
    data[1] = (uint8_t)(list_len & 0xFF);
    return add_ext(exts, 0x0033, data, off);
}

static int ext_padding(dynbuf_t *exts, size_t pad_len) {
    uint8_t *z = (uint8_t *)calloc(1, pad_len);
    if (z == NULL) {
        return -1;
    }
    int rc = add_ext(exts, 0x0015, z, pad_len);
    free(z);
    return rc;
}

static int ext_grease(dynbuf_t *exts, uint16_t grease) {
    return add_ext(exts, grease, NULL, 0);
}

static int ext_grease_1byte_zero(dynbuf_t *exts, uint16_t grease) {
    uint8_t zero = 0;
    return add_ext(exts, grease, &zero, 1);
}

static int ext_extended_master_secret(dynbuf_t *exts) {
    return add_ext(exts, 0x0017, NULL, 0);
}

static int ext_renegotiation_info(dynbuf_t *exts) {
    uint8_t data[] = {0x00};
    return add_ext(exts, 0xff01, data, sizeof(data));
}

static int ext_session_ticket(dynbuf_t *exts) {
    return add_ext(exts, 0x0023, NULL, 0);
}

static int ext_status_request(dynbuf_t *exts) {
    /* status_type=ocsp, empty responder_id_list and request_extensions */
    uint8_t data[] = {0x01, 0x00, 0x00, 0x00, 0x00};
    return add_ext(exts, 0x0005, data, sizeof(data));
}

static int ext_sct(dynbuf_t *exts) {
    return add_ext(exts, 0x0012, NULL, 0);
}

static int ext_record_size_limit_firefox(dynbuf_t *exts) {
    uint8_t data[] = {0x40, 0x01};
    return add_ext(exts, 0x001c, data, sizeof(data));
}

static int ext_ech_grease_firefox(dynbuf_t *exts) {
    enum { ECH_PAYLOAD_LEN = 239 };
    uint8_t data[1 + 2 + 2 + 1 + 2 + 32 + 2 + ECH_PAYLOAD_LEN];
    size_t off = 0;

    data[off++] = 0x00;
    data[off++] = 0x00;
    data[off++] = 0x01;
    data[off++] = 0x00;
    data[off++] = 0x01;
    if (RAND_bytes(data + off, 1) != 1) {
        return -1;
    }
    off += 1;
    data[off++] = 0x00;
    data[off++] = 0x20;
    if (RAND_bytes(data + off, 32) != 1) {
        return -1;
    }
    off += 32;
    data[off++] = (uint8_t)(ECH_PAYLOAD_LEN >> 8);
    data[off++] = (uint8_t)(ECH_PAYLOAD_LEN & 0xFF);
    if (RAND_bytes(data + off, ECH_PAYLOAD_LEN) != 1) {
        return -1;
    }
    off += ECH_PAYLOAD_LEN;

    return add_ext(exts, 0xfe0d, data, off);
}

static int ext_application_settings_h2(dynbuf_t *exts,const char *alpn) {
    if (alpn && *alpn && !alpn_csv_has_token(alpn,"h2")) return 0;
    /* ALPS (0x4469): protocol_name_list with single entry "h2". */
    uint8_t data[] = {0x00, 0x03, 0x02, 'h', '2'};
    return add_ext(exts, 0x4469, data, sizeof(data));
}

static size_t boring_padding_len(size_t unpadded_client_hello_len) {
    if (unpadded_client_hello_len > 0xff && unpadded_client_hello_len < 0x200) {
        size_t pad_len = 0x200 - unpadded_client_hello_len;
        if (pad_len >= 5) {
            pad_len -= 4;
        } else {
            pad_len = 1;
        }
        return pad_len;
    }
    return 0;
}

static int shuffle_indices(size_t *idx, size_t n) {
    for (size_t i = 0; i < n; i++) {
        idx[i] = i;
    }
    for (size_t i = n; i > 1; i--) {
        uint8_t r = 0;
        if (RAND_bytes(&r, 1) != 1) { errno=EIO; return -1; }
        size_t j = r % i;
        size_t tmp = idx[i - 1];
        idx[i - 1] = idx[j];
        idx[j] = tmp;
    }
    return 0;
}

static int build_client_hello_impl(const vless_config_t *cfg, int use_reality, tls_cipher_offer_t cipher_offer, uint8_t client_priv[32],
                              uint8_t client_pub[32], uint8_t client_random[32], uint8_t auth_key[32], uint8_t **out, size_t *out_len,
                              size_t *sid_pos, const uint8_t *hybrid_pub, EVP_PKEY **retained) {
    dynbuf_t hs = {0};

    if (x25519_generate(client_priv, client_pub) != 0) {
        return -1;
    }
    if (RAND_bytes(client_random, 32) != 1) {
        return -1;
    }

    uint8_t head4[4] = {0x01, 0x00, 0x00, 0x00};
    if (db_append(&hs, head4, 4) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t legacy_ver[] = {0x03, 0x03};
    if (db_append(&hs, legacy_ver, sizeof(legacy_ver)) != 0 || db_append(&hs, client_random, 32) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t sid_len = 32;
    if (db_append(&hs, &sid_len, 1) != 0) {
        db_free(&hs);
        return -1;
    }

    *sid_pos = hs.len;
    uint8_t session_id[32] = {0};
    if (!use_reality && RAND_bytes(session_id, sizeof(session_id)) != 1) {
        db_free(&hs);
        return -1;
    }
    if (db_append(&hs, session_id, sizeof(session_id)) != 0) {
        db_free(&hs);
        return -1;
    }

    uint16_t grease_values[4];
    if (random_grease_values(grease_values) != 0) { db_free(&hs); return -1; }
    uint16_t grease=grease_values[0],boring_grease_cipher=grease_values[1];
    uint16_t boring_grease_group=grease_values[2],boring_grease_vers=grease_values[3];
    uint16_t boring_grease_ext1 = boring_grease_cipher;
    uint16_t boring_grease_ext2 = boring_grease_vers;
    uint8_t suites[128];
    size_t soff = 0;
    if (cfg->fp_mode == FP_QQ || cfg->fp_mode == FP_CHROME || cfg->fp_mode == FP_EDGE) {
        suites[soff++] = (uint8_t)(boring_grease_cipher >> 8);
        suites[soff++] = (uint8_t)(boring_grease_cipher & 0xFF);
    }
    if (cipher_offer == TLS_CIPHER_OFFER_CHACHA) {
        suites[soff++] = 0x13;
        suites[soff++] = 0x03;
    } else {
        suites[soff++] = 0x13;
        suites[soff++] = 0x01;
        suites[soff++] = 0x13;
        suites[soff++] = 0x02;
    }
    if (!use_reality) for (size_t index=0;core_tls12_suite_at(index);index++) {
        const core_tls12_suite_t *suite=core_tls12_suite_at(index);
        if ((suite->cipher == CORE_TLS12_CHACHA) != (cipher_offer == TLS_CIPHER_OFFER_CHACHA)) continue;
        suites[soff++]=(uint8_t)(suite->id>>8); suites[soff++]=(uint8_t)suite->id;
    }

    uint8_t slen[2] = {(uint8_t)(soff >> 8), (uint8_t)(soff & 0xFF)};
    if (db_append(&hs, slen, 2) != 0 || db_append(&hs, suites, soff) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t comp[] = {0x01, 0x00};
    if (db_append(&hs, comp, sizeof(comp)) != 0) {
        db_free(&hs);
        return -1;
    }

    dynbuf_t exts = {0};

    if (cfg->fp_mode == FP_QQ) {
        size_t header_len = hs.len - 4;
        if (ext_grease(&exts, boring_grease_ext1) != 0 || ext_server_name(&exts, cfg->sni) != 0 ||
            ext_extended_master_secret(&exts) != 0 || ext_renegotiation_info(&exts) != 0 ||
            ext_supported_groups(&exts, boring_grease_group, 0, hybrid_pub != NULL) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_status_request(&exts) != 0 ||
            ext_sig_algs_qq(&exts) != 0 || ext_sct(&exts) != 0 || ext_key_share(&exts, boring_grease_group, client_pub, 0, hybrid_pub) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_supported_versions_qq(&exts, boring_grease_vers) != 0 ||
            ext_application_settings_h2(&exts,cfg->alpn) != 0 ||
            ext_grease_1byte_zero(&exts, boring_grease_ext2) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
        size_t unpadded_len = header_len + 4 + exts.len + 2;
        size_t pad_len = boring_padding_len(unpadded_len);
        if (pad_len > 0 && ext_padding(&exts, pad_len) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
    } else if (cfg->fp_mode == FP_CHROME || cfg->fp_mode == FP_EDGE) {
        size_t header_len = hs.len - 4;
        if (ext_grease(&exts, boring_grease_ext1) != 0 || ext_server_name(&exts, cfg->sni) != 0 ||
            ext_extended_master_secret(&exts) != 0 || ext_renegotiation_info(&exts) != 0 ||
            ext_supported_groups(&exts, boring_grease_group, 0, hybrid_pub != NULL) != 0 || ext_ec_point_formats(&exts) != 0 ||
            ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 || ext_status_request(&exts) != 0 ||
            ext_sig_algs_qq(&exts) != 0 || ext_sct(&exts) != 0 || ext_key_share(&exts, boring_grease_group, client_pub, 0, hybrid_pub) != 0 ||
            ext_psk_modes(&exts) != 0 || ext_supported_versions_qq(&exts, boring_grease_vers) != 0 ||
            ext_grease_1byte_zero(&exts, boring_grease_ext2) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
        size_t unpadded_len = header_len + 4 + exts.len + 2;
        size_t pad_len = boring_padding_len(unpadded_len);
        if (pad_len > 0 && ext_padding(&exts, pad_len) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
    } else if (cfg->fp_mode == FP_FIREFOX) {
        if (ext_server_name(&exts, cfg->sni) != 0 || ext_extended_master_secret(&exts) != 0 ||
            ext_renegotiation_info(&exts) != 0 || ext_supported_groups_firefox(&exts, hybrid_pub != NULL) != 0 ||
            ext_ec_point_formats(&exts) != 0 || ext_session_ticket(&exts) != 0 || ext_alpn(&exts, 0) != 0 ||
            ext_status_request(&exts) != 0 ||
            ext_key_share_firefox(&exts, client_pub, hybrid_pub,retained) != 0 || ext_supported_versions_firefox(&exts) != 0 ||
            ext_sig_algs_firefox(&exts) != 0 || ext_psk_modes(&exts) != 0 || ext_record_size_limit_firefox(&exts) != 0 ||
            ext_ech_grease_firefox(&exts) != 0) {
            db_free(&exts);
            db_free(&hs);
            return -1;
        }
    } else {
        enum { EX_SNI, EX_GROUPS, EX_SIGS, EX_ALPN, EX_VERS, EX_PSK, EX_KEYSHARE, EX_ECPF, EX_COUNT };
        size_t order[EX_COUNT];
        if (shuffle_indices(order, EX_COUNT) != 0) { db_free(&exts); db_free(&hs); return -1; }
        for (size_t i = 0; i < EX_COUNT; i++) {
            switch (order[i]) {
                case EX_SNI:
                    if (ext_server_name(&exts, cfg->sni) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_GROUPS:
                    if (ext_supported_groups(&exts, grease, 1, 0) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_SIGS:
                    if (ext_sig_algs(&exts) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_ALPN:
                    if (ext_alpn(&exts, 1) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_VERS:
                    if (ext_supported_versions(&exts, grease, 1) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_PSK:
                    if (ext_psk_modes(&exts) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_KEYSHARE:
                    if (ext_key_share(&exts, grease, client_pub, 1, NULL) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                case EX_ECPF:
                    if (ext_ec_point_formats(&exts) != 0) {
                        db_free(&exts);
                        db_free(&hs);
                        return -1;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    if (!use_reality) {
        int present=0;
        for (size_t offset=0;offset+4 <= exts.len;) {
            unsigned type=((unsigned)exts.data[offset]<<8)|exts.data[offset+1];
            if (type == 23) present=1;
            offset+=4+((size_t)exts.data[offset+2]<<8)+exts.data[offset+3];
        }
        if (!present && ext_extended_master_secret(&exts)) { db_free(&exts); db_free(&hs); return -1; }
        if (add_ext(&exts,22,NULL,0)) { db_free(&exts); db_free(&hs); return -1; }
    }
    if (cfg->alpn[0]) {
        dynbuf_t replaced={0}; unsigned char protocols[128]; unsigned int protocol_length=0;
        if (build_xhttp_tls_alpn(cfg->alpn,protocols,sizeof(protocols),&protocol_length) != 0) { db_free(&exts); db_free(&hs); return -1; }
        for (size_t offset=0;offset+4 <= exts.len;) {
            unsigned type=((unsigned)exts.data[offset]<<8)|exts.data[offset+1];
            size_t count=4+((size_t)exts.data[offset+2]<<8)+exts.data[offset+3];
            if (count > exts.len-offset) { db_free(&replaced); db_free(&exts); db_free(&hs); return -1; }
            int result;
            if (type == 16) {
                uint8_t value[130]={(uint8_t)(protocol_length>>8),(uint8_t)protocol_length};
                memcpy(value+2,protocols,protocol_length); result=add_ext(&replaced,16,value,protocol_length+2);
            } else result=db_append(&replaced,exts.data+offset,count);
            if (result) { db_free(&replaced); db_free(&exts); db_free(&hs); return -1; }
            offset+=count;
        }
        db_free(&exts); exts=replaced;
    }
    uint8_t elen[2] = {(uint8_t)(exts.len >> 8), (uint8_t)(exts.len & 0xFF)};
    if (db_append(&hs, elen, 2) != 0 || db_append(&hs, exts.data, exts.len) != 0) {
        db_free(&exts);
        db_free(&hs);
        return -1;
    }
    db_free(&exts);

    size_t body_len = hs.len - 4;
    hs.data[1] = (uint8_t)((body_len >> 16) & 0xFF);
    hs.data[2] = (uint8_t)((body_len >> 8) & 0xFF);
    hs.data[3] = (uint8_t)(body_len & 0xFF);

    if (!use_reality) {
        *out = hs.data;
        *out_len = hs.len;
        return 0;
    }

    uint8_t sid_plain[16] = {0};
    sid_plain[0] = g_xray_version[0];
    sid_plain[1] = g_xray_version[1];
    sid_plain[2] = g_xray_version[2];
    sid_plain[3] = 0;

    uint32_t now = (uint32_t)time(NULL);
    sid_plain[4] = (uint8_t)(now >> 24);
    sid_plain[5] = (uint8_t)(now >> 16);
    sid_plain[6] = (uint8_t)(now >> 8);
    sid_plain[7] = (uint8_t)(now & 0xFF);

    if (cfg->short_id_len > 0) {
        size_t n = cfg->short_id_len;
        if (n > 8) {
            n = 8;
        }
        memcpy(sid_plain + 8, cfg->short_id, n);
    }

    uint8_t shared[32];
    if (x25519_shared(client_priv, cfg->pbk, shared) != 0) {
        db_free(&hs);
        return -1;
    }

    uint8_t prk[32];
    if (hkdf_extract_md(EVP_sha256(), client_random, 20, shared, 32, prk, sizeof(prk)) != 0 ||
        hkdf_expand_md(EVP_sha256(), prk, sizeof(prk), (const uint8_t *)"REALITY", 7, auth_key, 32) != 0) {
        db_free(&hs);
        return -1;
    }

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    if (ectx == NULL) {
        db_free(&hs);
        return -1;
    }

    uint8_t ct[16];
    uint8_t tag[16];
    int outl = 0;
    int ok = EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_EncryptInit_ex(ectx, NULL, NULL, auth_key, client_random + 20) == 1 &&
             EVP_EncryptUpdate(ectx, NULL, &outl, hs.data, (int)hs.len) == 1 &&
             EVP_EncryptUpdate(ectx, ct, &outl, sid_plain, sizeof(sid_plain)) == 1;

    int finl = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ectx, ct + outl, &finl) == 1 &&
             EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    }
    EVP_CIPHER_CTX_free(ectx);

    if (!ok) {
        db_free(&hs);
        return -1;
    }

    memcpy(hs.data + *sid_pos, ct, 16);
    memcpy(hs.data + *sid_pos + 16, tag, 16);

    *out = hs.data;
    *out_len = hs.len;
    return 0;
}

int build_client_hello(const vless_config_t *cfg, int use_reality, tls_cipher_offer_t cipher_offer, uint8_t client_priv[32],
                      uint8_t client_pub[32], uint8_t client_random[32], uint8_t auth_key[32], uint8_t **out, size_t *out_len,
                      size_t *sid_pos, const uint8_t *hybrid_pub, EVP_PKEY **retained) {
    *out=NULL; *out_len=0; *sid_pos=0;
    if (retained) *retained=NULL;
    int result=build_client_hello_impl(cfg,use_reality,cipher_offer,client_priv,client_pub,client_random,auth_key,out,out_len,sid_pos,hybrid_pub,retained);
    if (result) {
        int saved=errno;
        OPENSSL_cleanse(client_priv,32); OPENSSL_cleanse(client_pub,32);
        OPENSSL_cleanse(client_random,32); OPENSSL_cleanse(auth_key,32);
        if (retained) { EVP_PKEY_free(*retained); *retained=NULL; }
        *sid_pos=0; errno=saved ? saved : EIO;
    }
    return result;
}
