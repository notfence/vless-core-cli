#include "tls_hello.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdlib.h>
#include <string.h>

static unsigned word(const uint8_t *bytes) { return ((unsigned)bytes[0]<<8)|bytes[1]; }
static void put_word(uint8_t *bytes,size_t value) { bytes[0]=(uint8_t)(value>>8); bytes[1]=(uint8_t)value; }
static int client_fields(const uint8_t *hello,size_t length,size_t *ciphers,size_t *extensions) {
    if (length < 42 || hello[0] != 1 || (((size_t)hello[1]<<16)|((size_t)hello[2]<<8)|hello[3]) != length-4 || hello[38] > 32) return -1;
    size_t offset=39+hello[38];
    if (offset+2 > length || word(hello+offset) > length-offset-2) return -1;
    *ciphers=offset; offset+=2+word(hello+offset);
    if (offset >= length || hello[offset] > length-offset-1) return -1;
    offset+=1+hello[offset];
    if (offset+2 > length || word(hello+offset) != length-offset-2) return -1;
    *extensions=offset; return 0;
}
static const uint8_t *extension(const uint8_t *hello,size_t length,size_t start,unsigned type,size_t *size) {
    for (size_t offset=start+2;offset+4 <= length;) {
        unsigned kind=word(hello+offset); size_t count=word(hello+offset+2); offset+=4;
        if (count > length-offset) return NULL;
        if (kind == type) { *size=count; return hello+offset; }
        offset+=count;
    }
    return NULL;
}
static int client_group(const uint8_t *hello,size_t length,size_t start,unsigned group,int sent) {
    size_t size=0; const uint8_t *value=extension(hello,length,start,sent ? 51 : 10,&size);
    if (!value || size < 2 || word(value) != size-2) return 0;
    for (size_t offset=2;offset+2 <= size;) {
        unsigned kind=word(value+offset); offset+=2;
        if (kind == group) return 1;
        if (sent) { if (offset+2 > size || word(value+offset) > size-offset-2) return 0; offset+=2+word(value+offset); }
    }
    return 0;
}
const uint8_t *core_tls_hello_extension(const uint8_t *hello,size_t length,unsigned type,size_t *size) {
    size_t ciphers,start;
    if (!hello || !size || client_fields(hello,length,&ciphers,&start)) return NULL;
    *size=0; return extension(hello,length,start,type,size);
}
int core_tls_hello_parse(const uint8_t *message,size_t length,const uint8_t *client,size_t client_length,core_tls_hello_t *result) {
    static const uint8_t retry_random[]={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    size_t ciphers,start;
    if (!message || !client || !result || client_fields(client,client_length,&ciphers,&start) || length < 44 || message[0] != 2 ||
        (((size_t)message[1]<<16)|((size_t)message[2]<<8)|message[3]) != length-4 || word(message+4) != 0x0303 || message[38] != client[38]) return -1;
    size_t offset=39+message[38];
    if (offset+5 > length || memcmp(message+39,client+39,message[38])) return -1;
    memset(result,0,sizeof(*result)); result->retry=!memcmp(message+6,retry_random,32); result->cipher=(uint16_t)word(message+offset);
    int offered=0;
    for (size_t at=ciphers+2;at+2 <= ciphers+2+word(client+ciphers);at+=2) if (word(client+at) == result->cipher) offered=1;
    if (!offered || (result->cipher != 0x1301 && result->cipher != 0x1302 && result->cipher != 0x1303) || message[offset+2] || word(message+offset+3) != length-offset-5) return -1;
    offset+=5; unsigned seen[4]={0}; size_t count=0; int version=0;
    while (offset < length) {
        if (length-offset < 4 || count == 4) return -1;
        unsigned type=word(message+offset); size_t size=word(message+offset+2); offset+=4;
        if (size > length-offset) return -1;
        for (size_t i=0;i<count;i++) if (seen[i] == type) return -1;
        seen[count++]=type;
        if (type == 43) { if (size != 2 || word(message+offset) != 0x0304) return -1; version=1; }
        else if (type == 44 && result->retry) {
            if (size < 3 || word(message+offset) != size-2) return -1;
            result->cookie=message+offset; result->cookie_length=size;
        } else if (type == 51) {
            if (size < 2 || (result->retry ? size != 2 : size < 4 || word(message+offset+2) != size-4)) return -1;
            result->group=(uint16_t)word(message+offset);
            if (!client_group(client,client_length,start,result->group,0) || (result->retry && client_group(client,client_length,start,result->group,1))) return -1;
            if (!result->retry) { result->share=message+offset+4; result->share_length=size-4; }
        } else return -1;
        offset+=size;
    }
    if (!version || (result->retry ? !result->group && !result->cookie : !result->share)) return -1;
    if (!result->retry) {
        size_t expected=result->group == 29 ? 32 : result->group == 23 ? 65 : result->group == 24 ? 97 : result->group == 25 ? 133 : result->group == 0x11ec ? 1120 : 0;
        if (!expected || result->share_length != expected || !client_group(client,client_length,start,result->group,1)) return -1;
    }
    return 0;
}
static const char *curve_name(unsigned group) {
    return group == 23 ? "prime256v1" : group == 24 ? "secp384r1" : group == 25 ? "secp521r1" : NULL;
}
int core_tls_hello_retry(const uint8_t *client,size_t length,const core_tls_hello_t *retry,uint8_t **out,size_t *out_length,EVP_PKEY **key) {
    size_t ciphers,start;
    if (!out || !out_length || !key || !retry || !retry->retry || client_fields(client,length,&ciphers,&start)) return -1;
    *out=NULL; *out_length=0; *key=NULL;
    uint8_t public_key[133]; size_t public_length=sizeof(public_key);
    if (retry->group) {
        const char *curve=curve_name(retry->group);
        if (retry->group != 29 && !curve) return -1;
        *key=retry->group == 29 ? EVP_PKEY_Q_keygen(NULL,NULL,"X25519") : EVP_PKEY_Q_keygen(NULL,NULL,"EC",curve);
        if (!*key || (retry->group == 29 ? EVP_PKEY_get_raw_public_key(*key,public_key,&public_length) :
            EVP_PKEY_get_octet_string_param(*key,OSSL_PKEY_PARAM_PUB_KEY,public_key,sizeof(public_key),&public_length)) != 1) goto fail;
    }
    if (length > 65535-200 || retry->cookie_length > 65535-length-200) goto fail;
    uint8_t *hello=malloc(length+retry->cookie_length+200); if (!hello) goto fail;
    memcpy(hello,client,start+2); size_t used=start+2;
    for (size_t offset=start+2;offset < length;) {
        if (length-offset < 4) { free(hello); goto fail; }
        unsigned type=word(client+offset); size_t count=4+word(client+offset+2);
        if (count > length-offset) { free(hello); goto fail; }
        if (type == 51 && retry->group) {
            put_word(hello+used,51); put_word(hello+used+2,public_length+6); put_word(hello+used+4,public_length+4);
            put_word(hello+used+6,retry->group); put_word(hello+used+8,public_length); memcpy(hello+used+10,public_key,public_length); used+=10+public_length;
        } else if (type != 44) { memcpy(hello+used,client+offset,count); used+=count; }
        offset+=count;
    }
    if (retry->cookie) { put_word(hello+used,44); put_word(hello+used+2,retry->cookie_length); memcpy(hello+used+4,retry->cookie,retry->cookie_length); used+=4+retry->cookie_length; }
    put_word(hello+start,used-start-2); hello[1]=(uint8_t)((used-4)>>16); hello[2]=(uint8_t)((used-4)>>8); hello[3]=(uint8_t)(used-4);
    *out=hello; *out_length=used; return 0;
fail:
    EVP_PKEY_free(*key); *key=NULL; return -1;
}
int core_tls_ecdh(EVP_PKEY *key,uint16_t group,const uint8_t *public_key,size_t length,uint8_t *secret,size_t *secret_length) {
    EVP_PKEY *peer=NULL; EVP_PKEY_CTX *reader=NULL,*derive=NULL;
    const char *curve=curve_name(group);
    if (group == 29) peer=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,public_key,length);
    else if (curve) {
        OSSL_PARAM parameters[]={OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,(char *)curve,0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,(void *)public_key,length),OSSL_PARAM_construct_end()};
        reader=EVP_PKEY_CTX_new_from_name(NULL,"EC",NULL);
        if (!reader || EVP_PKEY_fromdata_init(reader) != 1 || EVP_PKEY_fromdata(reader,&peer,EVP_PKEY_PUBLIC_KEY,parameters) != 1) goto done;
    }
    derive=peer ? EVP_PKEY_CTX_new(key,NULL) : NULL;
    int ok=derive && EVP_PKEY_derive_init(derive) == 1 && EVP_PKEY_derive_set_peer(derive,peer) == 1 && EVP_PKEY_derive(derive,secret,secret_length) == 1;
    EVP_PKEY_CTX_free(reader); EVP_PKEY_CTX_free(derive); EVP_PKEY_free(peer); return ok ? 0 : -1;
done:
    EVP_PKEY_CTX_free(reader); EVP_PKEY_free(peer); return -1;
}
