CC ?= cc

COMMON_CFLAGS ?= -O2 -Wall -Wextra -std=c11
INCLUDES := -Iinclude

SRC := $(wildcard src/*.c)
OBJ_LINUX := $(patsubst src/%.c,build/linux/%.o,$(SRC))
OBJ_IOS := $(patsubst src/%.c,build/ios/%.o,$(SRC))

BIN_LINUX ?= vless-core-linux-amd64
BIN_IOS ?= vless-core-darwin-armv7

LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto -lpthread

IOS_TOOLCHAIN ?= $(HOME)/toolchains/ios6
IOS_SDK ?= $(IOS_TOOLCHAIN)/SDK/iPhoneOS6.1.sdk
IOS_OPENSSL_PREFIX ?= third_party/openssl-ios6-armv7
IOS_ZLIB_PREFIX ?= third_party/zlib-ios6-armv7
IOS_CC ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-clang
IOS_AR ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-ar
IOS_RANLIB ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-ranlib
IOS_STRIP ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-strip
IOS_BLOCKS_RUNTIME_LIB ?= libBlocksRuntime.so
IOS_BLOCKS_RUNTIME_DIR ?= $(shell \
	if [ -f "$(IOS_TOOLCHAIN)/lib/$(IOS_BLOCKS_RUNTIME_LIB)" ]; then \
		echo "$(IOS_TOOLCHAIN)/lib"; \
	elif [ -f "$(IOS_TOOLCHAIN)/lib64/$(IOS_BLOCKS_RUNTIME_LIB)" ]; then \
		echo "$(IOS_TOOLCHAIN)/lib64"; \
	else \
		find "$(IOS_TOOLCHAIN)" -maxdepth 5 -type f -name "$(IOS_BLOCKS_RUNTIME_LIB)" -print -quit 2>/dev/null | sed 's#/$(IOS_BLOCKS_RUNTIME_LIB)$$##'; \
	fi)
IOS_RUNTIME_ENV = LD_LIBRARY_PATH="$(IOS_BLOCKS_RUNTIME_DIR)$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}"
IOS_OPENSSL_PATCH_STATUS_FILE ?= $(IOS_OPENSSL_PREFIX)/VLESS_OPENSSL_PATCH_STATUS
IOS_OPENSSL_PATCH_STATUS ?= $(shell cat "$(IOS_OPENSSL_PATCH_STATUS_FILE)" 2>/dev/null || echo unpatched)
IOS_CFLAGS ?= $(COMMON_CFLAGS) $(INCLUDES) -I$(IOS_OPENSSL_PREFIX)/include -arch armv7 -isysroot $(IOS_SDK) -miphoneos-version-min=6.0 -DVLESS_OPENSSL_PATCH_STATUS=\"$(IOS_OPENSSL_PATCH_STATUS)\"
IOS_LDFLAGS ?= -arch armv7 -isysroot $(IOS_SDK) -miphoneos-version-min=6.0
IOS_LDLIBS ?= $(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a -lpthread
CA_BUNDLE ?= third_party/cacert.pem
CURL_IOS_BIN ?= third_party/curl-ios6-armv7/bin/curl

all: linux ios

linux: $(BIN_LINUX)

ios: check-ios-toolchain $(BIN_IOS)

check-ios-toolchain:
	@test -x "$(IOS_CC)" || (echo "Missing iOS compiler: $(IOS_CC)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_AR)" || (echo "Missing iOS archiver: $(IOS_AR)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_RANLIB)" || (echo "Missing iOS ranlib: $(IOS_RANLIB)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_STRIP)" || (echo "Missing iOS strip: $(IOS_STRIP)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -d "$(IOS_SDK)" || (echo "Missing iOS SDK: $(IOS_SDK)"; echo "Set IOS_SDK=/path/to/iPhoneOS6.1.sdk"; exit 1)
	@test -n "$(IOS_BLOCKS_RUNTIME_DIR)" || (echo "Missing $(IOS_BLOCKS_RUNTIME_LIB) under $(IOS_TOOLCHAIN)"; echo "Add it to the toolchain or set IOS_BLOCKS_RUNTIME_DIR=/path/to/runtime/lib"; exit 1)

$(BIN_LINUX): $(OBJ_LINUX)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_LINUX) $(LDLIBS)

$(BIN_IOS): $(OBJ_IOS) $(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a
	PATH="$(IOS_TOOLCHAIN)/bin:$$PATH" $(IOS_RUNTIME_ENV) $(IOS_CC) $(IOS_LDFLAGS) -o $@ $(OBJ_IOS) $(IOS_LDLIBS)

build/linux/%.o: src/%.c | build/linux
	$(CC) $(COMMON_CFLAGS) $(INCLUDES) -c $< -o $@

build/ios/%.o: src/%.c | build/ios
	PATH="$(IOS_TOOLCHAIN)/bin:$$PATH" $(IOS_RUNTIME_ENV) $(IOS_CC) $(IOS_CFLAGS) -c $< -o $@

build/ios/main.o: $(IOS_OPENSSL_PATCH_STATUS_FILE)

$(IOS_OPENSSL_PATCH_STATUS_FILE):
	mkdir -p $(dir $@)
	printf '%s\n' unpatched > $@

build/linux:
	mkdir -p $@

build/ios:
	mkdir -p $@

$(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a:
	@echo "Missing $@"
	@echo "Run: make openssl-ios6"
	@echo "If the private asm patch lives elsewhere, set OPENSSL_IOS6_ASM_PATCH=/path/to/openssl-ios6-armv7-asm.patch"
	@false

openssl-ios6:
	./scripts/build_openssl_ios6.sh

$(IOS_ZLIB_PREFIX)/lib/libz.a:
	@echo "Missing $(IOS_ZLIB_PREFIX)/lib/libz.a"
	@echo "Run: make zlib-ios6"
	@false

zlib-ios6:
	./scripts/build_zlib_ios6.sh

$(CURL_IOS_BIN): $(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a $(IOS_ZLIB_PREFIX)/lib/libz.a
	./scripts/build_curl_ios6.sh

curl-ios6: $(CURL_IOS_BIN)

$(CA_BUNDLE):
	curl -fL -o $@ https://curl.se/ca/cacert.pem

curl-ios6-package: $(CURL_IOS_BIN) $(CA_BUNDLE)
	tar -czf third_party/curl-ios6-with-ca.tar.gz -C $(abspath third_party/curl-ios6-armv7/bin) curl -C $(abspath third_party) cacert.pem
	@echo "Packed third_party/curl-ios6-with-ca.tar.gz"

clean:
	rm -rf build $(BIN_LINUX) $(BIN_IOS)

.PHONY: all linux ios check-ios-toolchain clean openssl-ios6 zlib-ios6 curl-ios6 curl-ios6-package
