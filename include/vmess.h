#ifndef CORE_VMESS_H
#define CORE_VMESS_H
#include <stddef.h>
#include <stdint.h>

#define CORE_VMESS_HEADER_MAX 384U
#define CORE_VMESS_RESPONSE_MAX 293U
typedef enum {
    CORE_VMESS_AUTO=0,
    CORE_VMESS_AES128_GCM=3,
    CORE_VMESS_CHACHA20_POLY1305=4,
    CORE_VMESS_NONE=5,
    CORE_VMESS_ZERO=6
} core_vmess_security_t;
typedef struct {
    uint8_t request_key[16],request_iv[16],response_key[16],response_iv[16],authentication;
    uint8_t response[CORE_VMESS_RESPONSE_MAX];
    size_t response_used,response_needed;
    int ready,response_ready,failed;
    core_vmess_security_t security;
} core_vmess_header_t;

int core_vmess_request(core_vmess_header_t *,const uint8_t [16],const char *,uint16_t,core_vmess_security_t,uint8_t *,size_t,size_t *);
int core_vmess_response(core_vmess_header_t *,const uint8_t *,size_t,size_t *);
void core_vmess_header_clear(core_vmess_header_t *);
core_vmess_security_t core_vmess_auto_security(void);
#endif
