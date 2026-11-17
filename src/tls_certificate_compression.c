#include "tls_internal.h"
#include "tls_decode_namespace.h"
#include "../third_party/brotli-1.2.1/c/include/brotli/decode.h"
#define ZSTD_STATIC_LINKING_ONLY
#include "../third_party/zstd-1.5.7/lib/zstd.h"
#include <zlib.h>

static voidpf zlib_allocate(voidpf context,uInt count,uInt size) {
    if (size && count > SIZE_MAX/size) { errno=EOVERFLOW; return NULL; }
    return tls_handshake_allocate(context,(size_t)count*size);
}

static int decompress_zlib(tls13_conn_t *connection,const uint8_t *input,size_t input_length,uint8_t *output,size_t length) {
    if (input_length > UINT_MAX || length > UINT_MAX) return -1;
    z_stream stream={0}; stream.zalloc=zlib_allocate; stream.zfree=tls_handshake_deallocate; stream.opaque=connection;
    if (inflateInit(&stream) != Z_OK) return -1;
    stream.next_in=(Bytef *)input; stream.avail_in=(uInt)input_length;
    stream.next_out=output; stream.avail_out=(uInt)length;
    int status=inflate(&stream,Z_FINISH);
    int result=status == Z_STREAM_END && stream.total_out == length && stream.total_in == input_length ? 0 : -1;
    inflateEnd(&stream); return result;
}

static int decompress_brotli(tls13_conn_t *connection,const uint8_t *input,size_t input_length,uint8_t *output,size_t length) {
    BrotliDecoderState *state=BrotliDecoderCreateInstance(tls_handshake_allocate,tls_handshake_deallocate,connection);
    if (!state) return -1;
    size_t available_input=input_length,available_output=length;
    BrotliDecoderResult status=BrotliDecoderDecompressStream(state,&available_input,&input,&available_output,&output,NULL);
    int result=status == BROTLI_DECODER_RESULT_SUCCESS && !available_input && !available_output ? 0 : -1;
    BrotliDecoderDestroyInstance(state); return result;
}

static int decompress_zstd(tls13_conn_t *connection,const uint8_t *input,size_t input_length,uint8_t *output,size_t length) {
    ZSTD_customMem memory={tls_handshake_allocate,tls_handshake_deallocate,connection};
    ZSTD_DCtx *state=ZSTD_createDCtx_advanced(memory);
    if (!state) return -1;
    size_t result=ZSTD_DCtx_setMaxWindowSize(state,TLS_HANDSHAKE_LIMIT);
    if (!ZSTD_isError(result)) result=ZSTD_decompressDCtx(state,output,length,input,input_length);
    ZSTD_freeDCtx(state); return !ZSTD_isError(result) && result == length ? 0 : -1;
}

int tls_certificate_decompress(tls13_conn_t *connection,const uint8_t *message,size_t length,dynbuf_t *output) {
    if (!connection || !message || !output || length < 13 || message[0] != 25 ||
        (((size_t)message[1]<<16)|((size_t)message[2]<<8)|message[3]) != length-4) return -1;
    unsigned algorithm=((unsigned)message[4]<<8)|message[5];
    size_t expected=((size_t)message[6]<<16)|((size_t)message[7]<<8)|message[8];
    size_t encoded=((size_t)message[9]<<16)|((size_t)message[10]<<8)|message[11];
    if (!expected || expected > TLS_HANDSHAKE_LIMIT-4 || encoded != length-12) return -1;
    size_t offered_length=0;
    const uint8_t *offered=core_tls_hello_extension(connection->tls_client_hello.data,connection->tls_client_hello.len,27,&offered_length);
    if (!offered || offered_length < 3 || offered[0] != offered_length-1 || (offered[0]&1)) return -1;
    int found=0;
    for (size_t i=1;i+2<=offered_length;i+=2) if ((((unsigned)offered[i]<<8)|offered[i+1]) == algorithm) found=1;
    if (!found || algorithm < 1 || algorithm > 3 || tls_buffer_init(output,TLS_HANDSHAKE_LIMIT,&connection->tls_handshake_bytes) || db_reserve(output,expected+4)) return -1;
    output->len=expected+4; output->data[0]=11;
    output->data[1]=(uint8_t)(expected>>16); output->data[2]=(uint8_t)(expected>>8); output->data[3]=(uint8_t)expected;
    int result=algorithm == 1 ? decompress_zlib(connection,message+12,encoded,output->data+4,expected) :
        algorithm == 2 ? decompress_brotli(connection,message+12,encoded,output->data+4,expected) :
        decompress_zstd(connection,message+12,encoded,output->data+4,expected);
    if (result) db_free(output);
    return result;
}
