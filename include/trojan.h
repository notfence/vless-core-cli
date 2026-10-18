#ifndef VLESS_CORE_TROJAN_H
#define VLESS_CORE_TROJAN_H
#include <stddef.h>
#include <stdint.h>

#define CORE_TROJAN_HASH_SIZE 28
#define CORE_TROJAN_HEADER_MAX 320

int core_trojan_password(const uint8_t *, size_t, uint8_t [CORE_TROJAN_HASH_SIZE]);
int core_trojan_request(uint8_t *, size_t, size_t *, const uint8_t [CORE_TROJAN_HASH_SIZE], const char *, uint16_t);
#endif
