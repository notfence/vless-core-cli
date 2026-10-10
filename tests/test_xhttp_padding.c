#include "xhttp_padding.h"
#include "hpack.h"
#include "check.h"

int main(void) {
    char value[16384];
    CHECK("hpack/huffman-padding-x-code-size",core_hpack_huffman_bits((uint8_t *)"XZ",2) == 16);
    CHECK("hpack/huffman-rfc-host-code-size",(core_hpack_huffman_bits((uint8_t *)"www.example.com",15)+7)/8 == 12);
    CHECK("hpack/huffman-length-null-rejected",core_hpack_huffman_bits(NULL,1) == SIZE_MAX && !core_hpack_huffman_bits(NULL,0));
    const int lengths[]={1,2,3,10,100,1000,8192};
    for (size_t i=0;i<sizeof(lengths)/sizeof(*lengths);i++) {
        int size=lengths[i];
        REQUIRE("xhttp/repeat-padding-generated",core_xhttp_padding((core_range_t){size,size},"repeat-x",value,sizeof(value)) == 0);
        CHECK("xhttp/repeat-padding-exact",strlen(value) == (size_t)size && strspn(value,"X") == (size_t)size);
        REQUIRE("xhttp/tokenish-padding-generated",core_xhttp_padding((core_range_t){size,size},"tokenish",value,sizeof(value)) == 0);
        CHECK("xhttp/tokenish-padding-exact-huffman-cost",(core_hpack_huffman_bits((uint8_t *)value,strlen(value))+7)/8 == (size_t)size);
        CHECK("xhttp/tokenish-padding-base62",strspn(value,"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == strlen(value));
    }
    CHECK("xhttp/padding-capacity-not-truncated",core_xhttp_padding((core_range_t){100,100},"repeat-x",value,100) != 0 && !value[0]);
    CHECK("xhttp/tokenish-capacity-not-truncated",core_xhttp_padding((core_range_t){100,100},"tokenish",value,100) != 0 && !value[0]);
    CHECK("xhttp/padding-invalid-method",core_xhttp_padding((core_range_t){100,100},"invalid",value,sizeof(value)) != 0);
    CHECK("xhttp/padding-invalid-range",core_xhttp_padding((core_range_t){-1,100},"repeat-x",value,sizeof(value)) != 0);
    return test_result();
}
