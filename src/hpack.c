#define _POSIX_C_SOURCE 200809L
#include "hpack.h"
#include "grpc.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static const struct { const char *name, *value; } static_table[] = {
    {":authority",""},{":method","GET"},{":method","POST"},{":path","/"},{":path","/index.html"},
    {":scheme","http"},{":scheme","https"},{":status","200"},{":status","204"},{":status","206"},
    {":status","304"},{":status","400"},{":status","404"},{":status","500"},{"accept-charset",""},
    {"accept-encoding","gzip, deflate"},{"accept-language",""},{"accept-ranges",""},{"accept",""},
    {"access-control-allow-origin",""},{"age",""},{"allow",""},{"authorization",""},{"cache-control",""},
    {"content-disposition",""},{"content-encoding",""},{"content-language",""},{"content-length",""},
    {"content-location",""},{"content-range",""},{"content-type",""},{"cookie",""},{"date",""},{"etag",""},
    {"expect",""},{"expires",""},{"from",""},{"host",""},{"if-match",""},{"if-modified-since",""},
    {"if-none-match",""},{"if-range",""},{"if-unmodified-since",""},{"last-modified",""},{"link",""},
    {"location",""},{"max-forwards",""},{"proxy-authenticate",""},{"proxy-authorization",""},{"range",""},
    {"referer",""},{"refresh",""},{"retry-after",""},{"server",""},{"set-cookie",""},
    {"strict-transport-security",""},{"transfer-encoding",""},{"user-agent",""},{"vary",""},
    {"via",""},{"www-authenticate",""},
};

void core_hpack_init(core_hpack_decoder_t *decoder) {
    memset(decoder, 0, sizeof(*decoder));
    decoder->maximum = CORE_HPACK_TABLE_LIMIT;
    decoder->initialized = 1;
}

static void *hpack_alloc(core_hpack_decoder_t *decoder, size_t length) {
    return decoder->memory ? core_buffer_alloc(decoder->memory,length) : malloc(length);
}

static void hpack_free(core_hpack_decoder_t *decoder, void *data, size_t length) {
    if (decoder->memory) core_buffer_free(decoder->memory,data,length);
    else free(data);
}

void core_hpack_clear(core_hpack_decoder_t *decoder) {
    if (!decoder) return;
    for (size_t i = 0; i < decoder->count; i++) {
        hpack_free(decoder,decoder->entries[i].name,decoder->entries[i].name_length+1);
        hpack_free(decoder,decoder->entries[i].value,decoder->entries[i].value_length+1);
    }
    memset(decoder, 0, sizeof(*decoder));
}

static void evict_to(core_hpack_decoder_t *decoder, size_t size) {
    while (decoder->count && decoder->size > size) {
        core_hpack_entry_t *entry = &decoder->entries[--decoder->count];
        decoder->size -= entry->size;
        hpack_free(decoder,entry->name,entry->name_length+1); hpack_free(decoder,entry->value,entry->value_length+1); memset(entry, 0, sizeof(*entry));
    }
}

static int lookup(const core_hpack_decoder_t *decoder, uint32_t index, const char **name, size_t *name_length, const char **value, size_t *value_length) {
    if (!index) return -1;
    if (index <= sizeof(static_table)/sizeof(*static_table)) {
        *name=static_table[index-1].name; *value=static_table[index-1].value;
        *name_length=strlen(*name); *value_length=strlen(*value); return 0;
    }
    index-=(uint32_t)(sizeof(static_table)/sizeof(*static_table))+1;
    if (index >= decoder->count) return -1;
    const core_hpack_entry_t *entry=decoder->entries+index;
    *name=entry->name; *value=entry->value; *name_length=entry->name_length; *value_length=entry->value_length; return 0;
}

static int insert(core_hpack_decoder_t *decoder, const char *name, size_t name_length, const char *value, size_t value_length) {
    size_t size=name_length+value_length+32;
    if (size > decoder->maximum) { evict_to(decoder,0); return 0; }
    char *name_copy=hpack_alloc(decoder,name_length+1),*value_copy=hpack_alloc(decoder,value_length+1);
    if (!name_copy || !value_copy) { hpack_free(decoder,name_copy,name_length+1); hpack_free(decoder,value_copy,value_length+1); return -1; }
    memcpy(name_copy,name,name_length); name_copy[name_length]=0;
    memcpy(value_copy,value,value_length); value_copy[value_length]=0;
    evict_to(decoder,decoder->maximum-size);
    if (decoder->count >= sizeof(decoder->entries)/sizeof(*decoder->entries)) { hpack_free(decoder,name_copy,name_length+1); hpack_free(decoder,value_copy,value_length+1); return -1; }
    memmove(decoder->entries+1,decoder->entries,decoder->count*sizeof(*decoder->entries));
    decoder->entries[0]=(core_hpack_entry_t){.name=name_copy,.value=value_copy,.size=size,.name_length=name_length,.value_length=value_length};
    decoder->count++; decoder->size+=size; return 0;
}

static int read_allocated_string(core_hpack_decoder_t *decoder, const uint8_t *block, size_t length, size_t *offset, char **text, size_t *decoded_length) {
    size_t start=*offset,decoded=0;
    if (core_hpack_read_string(block,length,offset,NULL,0,&decoded) || decoded > CORE_HPACK_HEADER_LIMIT) return -1;
    *text=hpack_alloc(decoder,decoded+1);
    if (!*text) return -1;
    size_t verify=start,actual=0;
    if (core_hpack_read_string(block,length,&verify,*text,decoded+1,&actual) || actual != decoded) { hpack_free(decoder,*text,decoded+1); *text=NULL; return -1; }
    *decoded_length=decoded; return 0;
}

static int field_is(const char *field, size_t length, const char *expected) { return length == strlen(expected) && !memcmp(field,expected,length); }

static int emit_header(core_hpack_headers_t *headers, const char *name, size_t name_length, const char *value, size_t value_length) {
    int invalid=0;
    size_t size=name_length+value_length+32;
    if (headers->decoded_size > CORE_HPACK_HEADER_LIMIT || size > CORE_HPACK_HEADER_LIMIT-headers->decoded_size) {
        headers->decoded_size=CORE_HPACK_HEADER_LIMIT+1; invalid=1;
    } else headers->decoded_size+=size;
    if (!name_length) invalid=1;
    for (size_t i=0;i<name_length;i++) {
        unsigned byte=(unsigned char)name[i];
        if (byte == ':' && !i) continue;
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || (byte && strchr("!#$%&'*+-.^_`|~",(int)byte)))) invalid=1;
    }
    if (name_length && name[0] == ':') {
        if (headers->regular_seen || name_length == 1) invalid=1;
        if (!field_is(name,name_length,":status")) {
            const char *pseudos[]={":method",":scheme",":authority",":path",":protocol"}; unsigned flag=0;
            for (size_t i=0;i<sizeof(pseudos)/sizeof(*pseudos);i++) if (field_is(name,name_length,pseudos[i])) flag=1U<<i;
            if (!flag || (headers->other_pseudo&flag)) invalid=1;
            headers->other_pseudo|=flag ? flag : 0x80000000U;
        }
    } else headers->regular_seen=1;
    for (size_t i=0;i<value_length;i++) if (((unsigned char)value[i] < 0x20 && value[i] != '\t') || (unsigned char)value[i] == 0x7f) invalid=1;
    if (value_length && (value[0] == ' ' || value[0] == '\t' || value[value_length-1] == ' ' || value[value_length-1] == '\t')) invalid=1;
    const char *forbidden[]={"connection","proxy-connection","keep-alive","transfer-encoding","upgrade"};
    for (size_t i=0;i<sizeof(forbidden)/sizeof(*forbidden);i++) if (field_is(name,name_length,forbidden[i])) invalid=1;
    if (field_is(name,name_length,"te")) { headers->has_te=1; if (!field_is(value,value_length,"trailers")) invalid=1; }
    if (field_is(name,name_length,"content-type")) { headers->content_type_seen++; headers->grpc_content_type=core_grpc_content_type(value,value_length); }
    if (field_is(name,name_length,":status")) {
        if (headers->status_seen++ || value_length != 3 || value[0] < '1' || value[0] > '5' || value[1] < '0' || value[1] > '9' || value[2] < '0' || value[2] > '9') invalid=1;
        else headers->status=(value[0]-'0')*100+(value[1]-'0')*10+value[2]-'0';
    }
    if (field_is(name,name_length,"content-length")) {
        uint64_t parsed=0; int valid=value_length != 0;
        for (size_t i=0;i<value_length;i++) {
            unsigned digit=(unsigned char)value[i]-'0';
            if (digit > 9 || parsed > (UINT64_MAX-digit)/10) { valid=0; break; }
            parsed=parsed*10+digit;
        }
        if (!valid || (headers->has_content_length && headers->content_length != parsed)) invalid=1;
        headers->has_content_length=1; headers->content_length=parsed;
    }
    if (field_is(name,name_length,"grpc-status")) {
        if (headers->has_grpc_status || !value_length) invalid=1;
        unsigned status=0; int valid=value_length != 0 && (value_length == 1 || value[0] != '0');
        for (size_t i=0;i<value_length;i++) {
            if (value[i] < '0' || value[i] > '9') { valid=0; break; }
            if (status <= 16) status=status*10+(unsigned)(value[i]-'0');
        }
        if (!valid) invalid=1;
        headers->has_grpc_status=1; headers->grpc_status=valid ? status > 16 ? 2 : (int)status : -1;
    }
    return invalid ? -2 : 0;
}

int core_hpack_decode(core_hpack_decoder_t *decoder, const uint8_t *block, size_t length, core_hpack_headers_t *headers) {
    if (!decoder || !headers || (!block && length)) return -1;
    if (!decoder->initialized) {
        core_buffer_budget_t *memory=decoder->memory;
        core_hpack_init(decoder); decoder->memory=memory;
    }
    memset(headers,0,sizeof(*headers));
    size_t offset=0; int saw_header=0,invalid=0;
    while (offset < length) {
        uint8_t first=block[offset]; uint32_t index=0;
        if ((first&0xe0) == 0x20) {
            if (saw_header || core_hpack_decode_int(block,length,&offset,5,&index) || index > CORE_HPACK_TABLE_LIMIT) return -1;
            decoder->maximum=index; evict_to(decoder,index); continue;
        }
        saw_header=1;
        const char *name=NULL,*value=NULL; size_t name_length=0,value_length=0;
        char *owned_name=NULL,*owned_value=NULL;
        if (first&0x80) {
            if (core_hpack_decode_int(block,length,&offset,7,&index) || lookup(decoder,index,&name,&name_length,&value,&value_length)) return -1;
            if (emit_header(headers,name,name_length,value,value_length)) invalid=1;
            continue;
        }
        if (core_hpack_decode_int(block,length,&offset,first&0x40 ? 6 : 4,&index)) return -1;
        if (index) {
            if (lookup(decoder,index,&name,&name_length,&value,&value_length)) return -1;
        } else {
            if (read_allocated_string(decoder,block,length,&offset,&owned_name,&name_length)) return -1;
            name=owned_name;
        }
        if (read_allocated_string(decoder,block,length,&offset,&owned_value,&value_length)) { hpack_free(decoder,owned_name,name_length+1); return -1; }
        value=owned_value;
        if (emit_header(headers,name,name_length,value,value_length)) invalid=1;
        int result=first&0x40 ? insert(decoder,name,name_length,value,value_length) : 0;
        hpack_free(decoder,owned_name,name_length+1); hpack_free(decoder,owned_value,value_length+1);
        if (result) return -1;
    }
    return invalid ? -2 : 0;
}

int core_hpack_status(const uint8_t *block, size_t length) {
    core_hpack_decoder_t decoder = {0}; core_hpack_headers_t headers;
    int result = core_hpack_decode(&decoder,block,length,&headers);
    core_hpack_clear(&decoder);
    return result == 0 ? headers.status : -1;
}

int core_hpack_decode_int(const uint8_t *buf, size_t len, size_t *off, uint8_t prefix_bits, uint32_t *value) {
    if (*off >= len || prefix_bits == 0 || prefix_bits > 8) {
        return -1;
    }
    uint8_t first = buf[*off];
    (*off)++;
    uint32_t mask = (1U << prefix_bits) - 1U;
    uint32_t v = first & mask;
    if (v != mask) {
        *value = v;
        return 0;
    }

    uint32_t m = 0;
    for (;;) {
        if (*off >= len || m > 28) {
            return -1;
        }
        uint8_t b = buf[*off];
        (*off)++;
        if ((uint32_t)(b & 0x7F) > (UINT32_MAX - v) >> m) {
            return -1;
        }
        v += (uint32_t)(b & 0x7F) << m;
        if ((b & 0x80) == 0) {
            *value = v;
            return 0;
        }
        m += 7;
    }
}

static const uint8_t counts[31] = {
    0,0,0,0,0,10,26,32,6,0,5,3,2,6,2,3,0,0,0,3,8,13,26,29,12,4,15,19,29,0,4,
};
static const uint16_t symbols[257] = {
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51,
    52, 53, 54, 55, 56, 57, 61, 65, 95, 98, 100, 102, 103, 104, 108, 109,
    110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118,
    119, 120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39,
    43, 124, 35, 62, 0, 36, 64, 91, 93, 126, 94, 125, 60, 96, 123, 92,
    195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161, 167, 172, 176, 177,
    179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156, 160,
    163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232,
    233, 1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157,
    158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142,
    144, 145, 148, 159, 171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193,
    200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211,
    212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254,
    2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20,
    21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127, 220, 249, 10, 13, 22,
    256,
};

size_t core_hpack_huffman_bits(const uint8_t *data, size_t length) {
    if (!data && length) return SIZE_MAX;
    size_t total=0;
    for (size_t i=0;i<length;i++) {
        size_t index=0; unsigned bits=0;
        for (unsigned width=1;width<=30 && !bits;width++) {
            for (unsigned count=0;count<counts[width];count++,index++) if (symbols[index] == data[i]) { bits=width; break; }
        }
        if (!bits || total > SIZE_MAX-bits) return SIZE_MAX;
        total+=bits;
    }
    return total;
}

int core_hpack_decode_huffman(const uint8_t *buf, size_t len, char *out, size_t out_cap, size_t *out_len) {
    uint32_t code = 0, first = 0;
    size_t base = 0, written = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            code = (code << 1) | ((buf[i] >> bit) & 1U);
            bits++;
            if (code >= first && code - first < counts[bits]) {
                uint16_t symbol = symbols[base + code - first];
                if (symbol == 256) {
                    return -1;
                }
                if (out_cap > 0 && written < out_cap - 1) {
                    out[written] = (char)symbol;
                }
                written++;
                code = first = 0;
                bits = 0;
                base = 0;
            } else {
                if (bits == 30) {
                    return -1;
                }
                base += counts[bits];
                first = (first + counts[bits]) << 1;
            }
        }
    }
    if (bits > 7 || code != (1U << bits) - 1U) {
        return -1;
    }
    if (out_cap > 0) {
        out[written < out_cap ? written : out_cap - 1] = '\0';
    }
    *out_len = written;
    return 0;
}

int core_hpack_read_string(const uint8_t *buf, size_t len, size_t *off, char *out, size_t out_cap, size_t *out_len) {
    if (*off >= len) {
        return -1;
    }
    int huffman = (buf[*off] & 0x80) != 0;
    uint32_t slen = 0;
    if (core_hpack_decode_int(buf, len, off, 7, &slen) != 0 || (size_t)slen > len - *off) {
        return -1;
    }
    if (huffman) {
        if (core_hpack_decode_huffman(buf + *off, slen, out, out_cap, out_len) != 0) {
            return -1;
        }
    } else {
        if (out_cap > 0) {
            size_t copy = slen < out_cap ? slen : out_cap - 1;
            memcpy(out, buf + *off, copy);
            out[copy] = '\0';
        }
        *out_len = slen;
    }
    *off += (size_t)slen;
    return 0;
}
