#include "utils.h"

#include <ctype.h>
#include <string.h>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    return -1;
}

int parse_uuid(const char *s, uint8_t out[16]) {
    if (s == NULL || out == NULL) {
        return -1;
    }

    char compact[33];
    size_t j = 0;
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (s[i] == '-') {
            continue;
        }
        if (!isxdigit((unsigned char)s[i]) || j >= 32) {
            return -1;
        }
        compact[j++] = s[i];
    }
    if (j != 32) {
        return -1;
    }
    compact[32] = '\0';

    for (size_t i = 0; i < 16; i++) {
        int hi = hex_value(compact[i * 2]);
        int lo = hex_value(compact[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (hex == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    size_t n = strlen(hex);
    if ((n % 2) != 0) {
        return -1;
    }
    size_t need = n / 2;
    if (need > out_cap) {
        return -1;
    }

    for (size_t i = 0; i < need; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = need;
    return 0;
}

int base64url_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    static const int8_t table[256] = {
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,
        ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13,
        ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20,
        ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24, ['Z'] = 25,
        ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31, ['g'] = 32,
        ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39,
        ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46,
        ['v'] = 47, ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51,
        ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58,
        ['7'] = 59, ['8'] = 60, ['9'] = 61,
        ['-'] = 62, ['_'] = 63
    };

    size_t length=strlen(in),data_length=length;
    while (data_length && in[data_length-1] == '=') data_length--;
    size_t padding=length-data_length,remainder=data_length%4;
    if (padding > 2 || remainder == 1 || (padding && (!data_length || length%4 || padding != 4-remainder))) return -1;
    for (size_t i=0;i<data_length;i++) {
        unsigned char byte=(unsigned char)in[i];
        if ((table[byte] == 0 && byte != 'A') || byte == '=') return -1;
    }
    if ((remainder == 2 && (table[(unsigned char)in[data_length-1]]&15)) ||
        (remainder == 3 && (table[(unsigned char)in[data_length-1]]&3))) return -1;
    size_t required=data_length/4*3+(remainder ? remainder-1 : 0);
    if (required > out_cap) return -1;
    size_t olen = 0;
    uint32_t val = 0;
    int valb = -8;

    for (size_t i = 0; i < data_length; i++) {
        unsigned char c = (unsigned char)in[i];
        int8_t d = table[c];
        val = (val << 6) | (uint32_t)d;
        valb += 6;
        if (valb >= 0) {
            out[olen++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    *out_len = olen;
    return 0;
}

int percent_decode(const char *in, char *out, size_t out_cap) {
    if (in == NULL || out == NULL || out_cap == 0) {
        return -1;
    }

    size_t oi = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        if (oi + 1 >= out_cap) {
            return -1;
        }
        if (in[i] == '%') {
            if (in[i + 1] == '\0' || in[i + 2] == '\0' ||
                !isxdigit((unsigned char)in[i + 1]) || !isxdigit((unsigned char)in[i + 2])) {
                return -1;
            }
            int hi = hex_value(in[i + 1]);
            int lo = hex_value(in[i + 2]);
            int decoded = (hi << 4) | lo;
            if (decoded == 0) return -1;
            out[oi++] = (char)decoded;
            i += 2;
        } else if (in[i] == '+') {
            out[oi++] = ' ';
        } else {
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
    return 0;
}

static int request_byte(unsigned byte) {
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') ||
        (byte && strchr("-._~!$&'()*+,;=:@/?",(int)byte));
}

int core_request_target(const char *input, char *output, size_t capacity) {
    if (!input || !output || !capacity) return -1;
    size_t size=0;
    for (size_t i=0;input[i];i++) {
        unsigned byte=(unsigned char)input[i]; size_t required=request_byte(byte) ? 1 : 3;
        if (byte == '\r' || byte == '\n') return -1;
        if (byte == '%') {
            if (!input[i+1] || !input[i+2]) return -1;
            int high=hex_value(input[i+1]),low=hex_value(input[i+2]);
            if (high < 0 || low < 0 || !(high|low) || (high == 0 && (low == 10 || low == 13))) return -1;
            i+=2; required=3;
        }
        if (required > capacity-1-size) return -1;
        size+=required;
    }
    static const char hex[]="0123456789ABCDEF"; size_t offset=0;
    for (size_t i=0;input[i];i++) {
        unsigned byte=(unsigned char)input[i];
        if (byte == '%') { memcpy(output+offset,input+i,3); offset+=3; i+=2; }
        else if (request_byte(byte)) output[offset++]=(char)byte;
        else { output[offset++]='%'; output[offset++]=hex[byte>>4]; output[offset++]=hex[byte&15]; }
    }
    output[offset]=0; return 0;
}

int core_http_path(const char *input, char *output, size_t capacity, int trailing) {
    if (!input || !*input) input="/";
    if (!output || capacity < 2) return -1;
    if (*input == '/') { if (core_request_target(input,output,capacity)) return -1; }
    else { output[0]='/'; if (core_request_target(input,output+1,capacity-1)) return -1; }
    if (trailing) {
        char *query=strchr(output,'?'); size_t size=strlen(output),path=query ? (size_t)(query-output) : size;
        if (output[path-1] != '/') {
            if (size+1 >= capacity) return -1;
            memmove(output+path+1,output+path,size-path+1); output[path]='/';
        }
    }
    return 0;
}
