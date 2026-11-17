DECODER_SRC := $(addprefix third_party/brotli-1.2.1/c/common/,constants.c context.c dictionary.c platform.c shared_dictionary.c transform.c)
DECODER_SRC += $(addprefix third_party/brotli-1.2.1/c/dec/,bit_reader.c decode.c huffman.c prefix.c state.c static_init.c)
DECODER_SRC += $(addprefix third_party/zstd-1.5.7/lib/common/,debug.c entropy_common.c error_private.c fse_decompress.c xxhash.c zstd_common.c)
DECODER_SRC += $(addprefix third_party/zstd-1.5.7/lib/decompress/,huf_decompress.c zstd_ddict.c zstd_decompress.c zstd_decompress_block.c)
DECODER_FLAGS := -DZSTD_DISABLE_ASM -DZSTD_LEGACY_SUPPORT=0 -DBROTLI_BUILD_PORTABLE -I$(ROOT_DIR)/third_party/brotli-1.2.1/c/include -include $(ROOT_DIR)/src/tls_decode_namespace.h
DECODER_HEADERS := $(patsubst $(ROOT_DIR)/%,%,$(wildcard $(ROOT_DIR)/third_party/brotli-1.2.1/c/common/*.h $(ROOT_DIR)/third_party/brotli-1.2.1/c/dec/*.h $(ROOT_DIR)/third_party/brotli-1.2.1/c/include/brotli/*.h $(ROOT_DIR)/third_party/zstd-1.5.7/lib/common/*.h $(ROOT_DIR)/third_party/zstd-1.5.7/lib/decompress/*.h $(ROOT_DIR)/third_party/zstd-1.5.7/lib/*.h)) src/tls_decode_namespace.h
