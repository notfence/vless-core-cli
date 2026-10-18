#include "trojan.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

int core_trojan_password(const uint8_t *password, size_t length, uint8_t hash[CORE_TROJAN_HASH_SIZE]) {
    if (!hash) { errno=EINVAL; return -1; }
    memset(hash,0,CORE_TROJAN_HASH_SIZE);
    if (!password || !length) { errno=EINVAL; return -1; }
    EVP_MD_CTX *context=EVP_MD_CTX_new();
    unsigned size=0;
    int ok=context && EVP_DigestInit_ex(context,EVP_sha224(),NULL) == 1 &&
        EVP_DigestUpdate(context,password,length) == 1 && EVP_DigestFinal_ex(context,hash,&size) == 1 && size == CORE_TROJAN_HASH_SIZE;
    EVP_MD_CTX_free(context);
    if (!ok) { OPENSSL_cleanse(hash,CORE_TROJAN_HASH_SIZE); errno=EIO; return -1; }
    return 0;
}

int core_trojan_request(uint8_t *output, size_t capacity, size_t *length,
                       const uint8_t hash[CORE_TROJAN_HASH_SIZE], const char *host, uint16_t port) {
    if (!length) { errno=EINVAL; return -1; }
    *length=0;
    if (!output || !hash || !host || !*host || !port) { errno=EINVAL; return -1; }
    uint8_t address[16]; size_t size; unsigned type;
    if (inet_pton(AF_INET,host,address) == 1) { size=4; type=1; }
    else if (inet_pton(AF_INET6,host,address) == 1) { size=16; type=4; }
    else {
        size=strlen(host); type=3;
        if (size > 255) { errno=EINVAL; return -1; }
        for (size_t i=0;i<size;i++) if ((unsigned char)host[i] <= 0x20 || (unsigned char)host[i] == 0x7f || strchr("/:?#@[]\\",host[i])) {
            errno=EINVAL; return -1;
        }
    }
    size_t needed=64+size+(type == 3);
    if (needed > capacity) { errno=ENOBUFS; return -1; }
    static const char hex[]="0123456789abcdef";
    for (size_t i=0;i<CORE_TROJAN_HASH_SIZE;i++) { output[2*i]=(uint8_t)hex[hash[i]>>4]; output[2*i+1]=(uint8_t)hex[hash[i]&15]; }
    output[56]=13; output[57]=10; output[58]=1; output[59]=(uint8_t)type;
    size_t offset=60;
    if (type == 3) output[offset++]=(uint8_t)size;
    memcpy(output+offset,type == 3 ? (const void *)host : (const void *)address,size); offset+=size;
    output[offset++]=(uint8_t)(port>>8); output[offset++]=(uint8_t)port;
    output[offset++]=13; output[offset++]=10;
    *length=offset; return 0;
}
