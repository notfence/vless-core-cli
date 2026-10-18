#include "xhttp_padding.h"
#include "hpack.h"
#include "check.h"
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int __real_RAND_bytes(unsigned char *,int);
static int controlled_random;
int __wrap_RAND_bytes(unsigned char *data,int length) {
    if (!controlled_random) return __real_RAND_bytes(data,length);
    if (controlled_random < 0) { errno=EIO; return 0; }
    memset(data,255,(size_t)length); return 1;
}

static void tokenish_random_bound(void) {
    pid_t child=fork(); REQUIRE("xhttp/tokenish-rejection-child",child >= 0);
    if (!child) {
        alarm(1); controlled_random=1; char output[16384];
        _exit(core_xhttp_padding((core_range_t){100,100},"tokenish",output,sizeof(output)) < 0 && !output[0] ? 0 : 1);
    }
    int status; REQUIRE("xhttp/tokenish-rejection-wait",waitpid(child,&status,0) == child);
    CHECK("xhttp/tokenish-rejection-has-finite-bound",WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    tokenish_random_bound();
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
