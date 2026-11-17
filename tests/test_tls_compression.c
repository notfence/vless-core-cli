#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "tls_fixture.h"

static const struct { unsigned algorithm; const char *encoded; } vectors[] = {
    {1,"789c0af10956484e2d2ac94ccb4c4e2c495548cbac28292d4a553030343236313533b7b0e41a5532aa6454c9a812b29400020000ffff563e5e90"},
    {2,"1b5f0400c4cf1bdfafa417e27d7d42d708954d3536054e8565718ed6d150f7b1f6bfef4cb0a879a45c2a31"},
    {3,"28b52ffd6460036d01003402544c53206365727469666963617465206669787475726520303132333435363738390a015416052ed3c104f27e4fa1"},
};

static void set_length(uint8_t *message,size_t length,size_t plain) {
    message[0]=25; message[1]=(uint8_t)((length-4)>>16); message[2]=(uint8_t)((length-4)>>8); message[3]=(uint8_t)(length-4);
    message[6]=(uint8_t)(plain>>16); message[7]=(uint8_t)(plain>>8); message[8]=(uint8_t)plain;
    message[9]=(uint8_t)((length-12)>>16); message[10]=(uint8_t)((length-12)>>8); message[11]=(uint8_t)(length-12);
}

int main(void) {
    vless_config_t config; core_config_defaults(&config); config.fp_mode=FP_FIREFOX; strcpy(config.sni,"vless-core.test");
    uint8_t private[32],public[32],random[32],auth[32],*hello=NULL; size_t hello_size=0,sid=0;
    REQUIRE("compression/client-hello",!build_client_hello(&config,0,TLS_CIPHER_OFFER_CHACHA,private,public,random,auth,&hello,&hello_size,&sid,NULL,NULL));
    tls13_conn_t connection={0};
    REQUIRE("compression/hello-budget",!tls_buffer_init(&connection.tls_client_hello,65536,&connection.tls_handshake_bytes) &&
        !db_append(&connection.tls_client_hello,hello,hello_size));
    free(hello);
    static const uint8_t phrase[]="TLS certificate fixture 0123456789\n";
    uint8_t expected[32*(sizeof(phrase)-1)];
    for (size_t i=0;i<32;i++) memcpy(expected+i*(sizeof(phrase)-1),phrase,sizeof(phrase)-1);
    size_t baseline=connection.tls_handshake_bytes,global_baseline=tls_buffer_bytes;
    for (size_t i=0;i<sizeof(vectors)/sizeof(*vectors);i++) {
        uint8_t message[2048]={0}; size_t encoded=0;
        REQUIRE("compression/independent-vector",!hex_to_bytes(vectors[i].encoded,message+12,sizeof(message)-12,&encoded));
        size_t length=encoded+12;
        message[4]=0; message[5]=(uint8_t)vectors[i].algorithm;
        set_length(message,length,sizeof(expected));
        dynbuf_t output={0};
        REQUIRE("compression/three-algorithm-decode",!tls_certificate_decompress(&connection,message,length,&output));
        CHECK("compression/exact-plaintext",output.len==sizeof(expected)+4 && output.data[0]==11 && !memcmp(output.data+4,expected,sizeof(expected)));
        db_free(&output);
        CHECK("compression/decoder-memory-released",connection.tls_handshake_bytes==baseline && tls_buffer_bytes==global_baseline);
        for (size_t cut=0;cut<length;cut++) {
            CHECK("compression/truncated-message",tls_certificate_decompress(&connection,message,cut,&output)<0);
            db_free(&output);
        }
        set_length(message,length,sizeof(expected)-1);
        CHECK("compression/decoded-output-overflow",tls_certificate_decompress(&connection,message,length,&output)<0); db_free(&output);
        set_length(message,length,sizeof(expected)+1);
        CHECK("compression/decoded-length-mismatch",tls_certificate_decompress(&connection,message,length,&output)<0); db_free(&output);
        set_length(message,length-1,sizeof(expected));
        CHECK("compression/truncated-stream",tls_certificate_decompress(&connection,message,length-1,&output)<0); db_free(&output);
        set_length(message,length,TLS_HANDSHAKE_LIMIT);
        CHECK("compression/declared-size-limit",tls_certificate_decompress(&connection,message,length,&output)<0); db_free(&output);
        set_length(message,length,sizeof(expected));
        message[length]=0;
        set_length(message,length+1,sizeof(expected));
        CHECK("compression/trailing-data",tls_certificate_decompress(&connection,message,length+1,&output)<0); db_free(&output);
        set_length(message,length,sizeof(expected));
        for (size_t offset=12;offset<length;offset++) {
            message[offset]^=0x80;
            (void)tls_certificate_decompress(&connection,message,length,&output); db_free(&output);
            message[offset]^=0x80;
            CHECK("compression/mutated-stream-releases-memory",connection.tls_handshake_bytes==baseline && tls_buffer_bytes==global_baseline);
        }
        message[5]=4;
        CHECK("compression/unknown-algorithm",tls_certificate_decompress(&connection,message,length,&output)<0); db_free(&output);
        message[5]=(uint8_t)vectors[i].algorithm;
        connection.tls_handshake_bytes=TLS_HANDSHAKE_LIMIT-128;
        CHECK("compression/allocation-budget",tls_certificate_decompress(&connection,message,length,&output)<0); db_free(&output);
        connection.tls_handshake_bytes=baseline;
        CHECK("compression/failure-memory-released",tls_buffer_bytes==global_baseline);
    }
    db_free(&connection.tls_client_hello);
    CHECK("compression/no-retained-memory",!connection.tls_handshake_bytes && !tls_buffer_bytes);
    return test_result();
}
