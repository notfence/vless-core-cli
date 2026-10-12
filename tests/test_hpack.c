#include "check.h"
#include "hpack.h"
#include <stdlib.h>

static void standard_sequence(const char *const blocks[3]) {
    core_hpack_decoder_t decoder = {0}; core_hpack_headers_t headers;
    const uint8_t overflow_status[]="\x00\x0b" "grpc-status\x19" "9999999999999999999999999";
    CHECK("hpack/unknown-numeric-grpc-status",core_hpack_decode(&decoder,overflow_status,sizeof(overflow_status)-1,&headers) == 0 && headers.has_grpc_status && headers.grpc_status == 2);
    const uint8_t leading_zero[]="\x00\x0b" "grpc-status\x02" "00";
    CHECK("hpack/grpc-status-not-canonical",core_hpack_decode(&decoder,leading_zero,sizeof(leading_zero)-1,&headers) == -2);
    const uint8_t limit[] = {0x3f,0xe1,1};
    REQUIRE("hpack/rfc-table-limit", core_hpack_decode(&decoder,limit,sizeof(limit),&headers) == 0 && decoder.maximum == 256);
    const int statuses[] = {302,307,200};
    const size_t sizes[] = {222,222,215};
    for (size_t i=0;i<3;i++) {
        uint8_t data[256]; size_t length=strlen(blocks[i])/2;
        REQUIRE("hpack/rfc-vector-size", length <= sizeof(data));
        for (size_t j=0;j<length;j++) { unsigned byte; REQUIRE("hpack/rfc-vector-hex", sscanf(blocks[i]+j*2,"%2x",&byte) == 1); data[j]=(uint8_t)byte; }
        CHECK("hpack/rfc-response-sequence", core_hpack_decode(&decoder,data,length,&headers) == 0 && headers.status == statuses[i] && decoder.size == sizes[i]);
    }
    CHECK("hpack/rfc-evicted-table", decoder.count == 3 && !strcmp(decoder.entries[0].name,"set-cookie") && !strcmp(decoder.entries[1].value,"gzip") && !strcmp(decoder.entries[2].name,"date"));
    core_hpack_clear(&decoder);
}

int main(void) {
    core_hpack_decoder_t retained={0}; core_hpack_headers_t retained_headers;
    const uint8_t malformed[]={0x40,1,'X',1,'v',0x40,1,'x',1,'n'};
    CHECK("hpack/malformed-http-retains-compression-state",core_hpack_decode(&retained,malformed,sizeof(malformed),&retained_headers) != 0 && retained.count == 2);
    const uint8_t following[]={0x88,0xbe};
    CHECK("hpack/healthy-stream-after-malformed-http",core_hpack_decode(&retained,following,sizeof(following),&retained_headers) == 0 && retained_headers.status == 200);
    core_hpack_clear(&retained);
    const uint8_t nul_name[]={0x40,3,'x',0,'y',1,'v',0x40,1,'x',1,'n'};
    CHECK("hpack/nul-http-retains-compression-state",core_hpack_decode(&retained,nul_name,sizeof(nul_name),&retained_headers) != 0 && retained.count == 2);
    CHECK("hpack/healthy-stream-after-nul-http",core_hpack_decode(&retained,following,sizeof(following),&retained_headers) == 0 && retained_headers.status == 200);
    core_hpack_clear(&retained);
    const uint8_t wrong_order[]={0,1,'x',1,'v',0x88},wrong_status[]={0x48,3,'9','0','0'};
    CHECK("hpack/pseudo-after-regular-field",core_hpack_decode(&retained,wrong_order,sizeof(wrong_order),&retained_headers) != 0);
    CHECK("hpack/status-outside-http-range",core_hpack_decode(&retained,wrong_status,sizeof(wrong_status),&retained_headers) != 0);
    core_hpack_clear(&retained);
    standard_sequence((const char *const[]){
        "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        "4803333037c1c0bf",
        "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
    });
    standard_sequence((const char *const[]){
        "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        "4883640effc1c0bf",
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
    });
    core_hpack_decoder_t decoder = {0}; core_hpack_headers_t headers;
    const uint8_t first[] = {0x48,3,'2','0','0',0x40,11,'g','r','p','c','-','s','t','a','t','u','s',1,'0'};
    CHECK("hpack/insert-response", core_hpack_decode(&decoder,first,sizeof(first),&headers) == 0 && headers.status == 200 && headers.grpc_status == 0 && headers.has_grpc_status && decoder.count == 2);
    const uint8_t response[] = {0xbf};
    CHECK("hpack/index-across-blocks", core_hpack_decode(&decoder,response,sizeof(response),&headers) == 0 && headers.status == 200);
    const uint8_t trailer[] = {0xbe};
    CHECK("hpack/dynamic-trailer", core_hpack_decode(&decoder,trailer,sizeof(trailer),&headers) == 0 && headers.status == 0 && headers.has_grpc_status && headers.grpc_status == 0);
    const uint8_t name[] = {0x7e,2,'1','3'};
    CHECK("hpack/dynamic-name", core_hpack_decode(&decoder,name,sizeof(name),&headers) == 0 && headers.grpc_status == 13 && decoder.count == 3);
    const uint8_t duplicate[] = {0xbe,0xbe};
    CHECK("hpack/duplicate-trailer-rejected", core_hpack_decode(&decoder,duplicate,sizeof(duplicate),&headers) != 0);
    const uint8_t reset[] = {0x20};
    CHECK("hpack/resize-zero", core_hpack_decode(&decoder,reset,sizeof(reset),&headers) == 0 && decoder.count == 0 && decoder.maximum == 0);
    CHECK("hpack/evicted-reference-rejected", core_hpack_decode(&decoder,response,sizeof(response),&headers) != 0);
    CHECK("hpack/zero-size-no-retention", core_hpack_decode(&decoder,first,sizeof(first),&headers) == 0 && headers.status == 200 && decoder.count == 0);
    const uint8_t restore[] = {0x3f,0xe1,0x1f};
    CHECK("hpack/resize-restore", core_hpack_decode(&decoder,restore,sizeof(restore),&headers) == 0 && decoder.maximum == 4096);
    const uint8_t small[] = {0x3f,39};
    CHECK("hpack/small-table", core_hpack_decode(&decoder,small,sizeof(small),&headers) == 0 && decoder.maximum == 70);
    CHECK("hpack/entry-eviction", core_hpack_decode(&decoder,first,sizeof(first),&headers) == 0 && decoder.count == 1 && decoder.size == 44 && !strcmp(decoder.entries[0].name,"grpc-status"));
    const uint8_t oversize[] = {0x3f,0xe2,0x1f};
    CHECK("hpack/resize-limit", core_hpack_decode(&decoder,oversize,sizeof(oversize),&headers) != 0);
    const uint8_t late_update[] = {0x88,0x20};
    CHECK("hpack/late-table-update", core_hpack_decode(&decoder,late_update,sizeof(late_update),&headers) != 0);
    const uint8_t unknown[] = {0xbf};
    CHECK("hpack/index-outside-table", core_hpack_decode(&decoder,unknown,sizeof(unknown),&headers) != 0);
    const uint8_t uppercase[] = {0,1,'X',1,'v'};
    CHECK("hpack/uppercase-name", core_hpack_decode(&decoder,uppercase,sizeof(uppercase),&headers) != 0);
    const uint8_t injection[] = {0,1,'x',2,'v','\n'};
    CHECK("hpack/response-injection", core_hpack_decode(&decoder,injection,sizeof(injection),&headers) != 0);
    uint8_t repeated[1725]; memset(repeated,0x93,sizeof(repeated));
    CHECK("hpack/header-list-under-limit", core_hpack_decode(&decoder,repeated,1724,&headers) == 0 && headers.decoded_size == 65512);
    CHECK("hpack/header-list-over-limit", core_hpack_decode(&decoder,repeated,sizeof(repeated),&headers) != 0);
    core_hpack_clear(&decoder);
    CHECK("hpack/clear", decoder.count == 0 && decoder.size == 0 && !decoder.initialized);
    for (size_t cut=1;cut<sizeof(first);cut++) {
        core_hpack_decode(&decoder,first,cut,&headers);
        core_hpack_clear(&decoder);
    }
    return test_result();
}
