CC ?= cc

ROOT_DIR := $(abspath .)

COMMON_CFLAGS ?= -O2 -Wall -Wextra -std=c11
DEPFLAGS := -MMD -MP
INCLUDES := -Iinclude

SRC := $(wildcard src/*.c)
OBJ_LINUX := $(patsubst src/%.c,build/linux/%.o,$(SRC))
OBJ_IOS := $(patsubst src/%.c,build/ios/%.o,$(SRC))
OBJ_IOS_ARM64 := $(patsubst src/%.c,build/ios-arm64/%.o,$(SRC))

BIN_LINUX ?= vless-core-linux-amd64
BIN_IOS ?= vless-core-darwin-armv7
BIN_IOS_ARM64 ?= vless-core-darwin-arm64
RELEASE_DIR ?= build/release
RELEASE_LINUX_ARCHIVE := $(RELEASE_DIR)/vless-core-linux-amd64.tar.gz
RELEASE_IOS_ARMV7_ARCHIVE := $(RELEASE_DIR)/vless-core-darwin-armv7.tar.gz
RELEASE_IOS_ARM64_ARCHIVE := $(RELEASE_DIR)/vless-core-darwin-arm64.tar.gz

LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto -lpthread

IOS_TOOLCHAIN ?= $(abspath ../toolchains/ios6)
IOS_SDK ?= $(IOS_TOOLCHAIN)/SDK/iPhoneOS6.1.sdk
IOS_OPENSSL_PREFIX ?= third_party/openssl-ios6-armv7
IOS_ZLIB_PREFIX ?= third_party/zlib-ios6-armv7
IOS_CC ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-clang
IOS_AR ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-ar
IOS_RANLIB ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-ranlib
IOS_STRIP ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-strip
IOS_OTOOL ?= $(IOS_TOOLCHAIN)/bin/arm-apple-darwin11-otool
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
IOS_LDFLAGS ?= -arch armv7 -isysroot $(IOS_SDK) -miphoneos-version-min=6.0 -Wl,-pie
IOS_LDLIBS ?= $(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a -lpthread
IOS_ARM64_SDK ?= $(abspath ../toolchains/sdks/iPhoneOS11.4.sdk)
IOS_ARM64_MIN_VERSION ?= 11.0
IOS_ARM64_OPENSSL_PREFIX ?= third_party/openssl-ios-arm64
IOS_ARM64_ZLIB_PREFIX ?= third_party/zlib-ios-arm64
IOS_ARM64_OPENSSL_PATCH_STATUS_FILE ?= $(IOS_ARM64_OPENSSL_PREFIX)/VLESS_OPENSSL_PATCH_STATUS
IOS_ARM64_OPENSSL_PATCH_STATUS ?= $(shell cat "$(IOS_ARM64_OPENSSL_PATCH_STATUS_FILE)" 2>/dev/null || echo unpatched)
IOS_ARM64_CFLAGS ?= $(COMMON_CFLAGS) $(INCLUDES) -I$(IOS_ARM64_OPENSSL_PREFIX)/include -arch arm64 -isysroot $(IOS_ARM64_SDK) -miphoneos-version-min=$(IOS_ARM64_MIN_VERSION) -DVLESS_OPENSSL_PATCH_STATUS=\"$(IOS_ARM64_OPENSSL_PATCH_STATUS)\"
IOS_ARM64_LDFLAGS ?= -arch arm64 -isysroot $(IOS_ARM64_SDK) -miphoneos-version-min=$(IOS_ARM64_MIN_VERSION) -Wl,-pie
IOS_ARM64_LDLIBS ?= $(IOS_ARM64_OPENSSL_PREFIX)/lib/libssl.a $(IOS_ARM64_OPENSSL_PREFIX)/lib/libcrypto.a -lpthread
CA_BUNDLE ?= third_party/cacert.pem
CURL_IOS_BIN ?= third_party/curl-ios6-armv7/bin/curl
CURL_IOS_ARM64_PREFIX ?= third_party/curl-ios-arm64
CURL_IOS_ARM64_BIN ?= $(CURL_IOS_ARM64_PREFIX)/bin/curl
THIRD_PARTY_LICENSES := THIRD_PARTY_LICENSES.txt

all: linux ios

linux: $(BIN_LINUX)

ios: check-ios-toolchain $(BIN_IOS)

ios-arm64: check-ios-arm64-toolchain $(BIN_IOS_ARM64)

check-ios-toolchain:
	@test -x "$(IOS_CC)" || (echo "Missing iOS compiler: $(IOS_CC)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_AR)" || (echo "Missing iOS archiver: $(IOS_AR)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_RANLIB)" || (echo "Missing iOS ranlib: $(IOS_RANLIB)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_STRIP)" || (echo "Missing iOS strip: $(IOS_STRIP)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -x "$(IOS_OTOOL)" || (echo "Missing iOS otool: $(IOS_OTOOL)"; echo "Set IOS_TOOLCHAIN=/path/to/ios6/toolchain"; exit 1)
	@test -d "$(IOS_SDK)" || (echo "Missing iOS SDK: $(IOS_SDK)"; echo "Set IOS_SDK=/path/to/iPhoneOS6.1.sdk"; exit 1)
	@test -n "$(IOS_BLOCKS_RUNTIME_DIR)" || (echo "Missing $(IOS_BLOCKS_RUNTIME_LIB) under $(IOS_TOOLCHAIN)"; echo "Add it to the toolchain or set IOS_BLOCKS_RUNTIME_DIR=/path/to/runtime/lib"; exit 1)

check-ios-arm64-toolchain: check-ios-toolchain
	@test -d "$(IOS_ARM64_SDK)" || (echo "Missing arm64 iOS SDK: $(IOS_ARM64_SDK)"; echo "Set IOS_ARM64_SDK=/path/to/iPhoneOS.sdk"; exit 1)

$(BIN_LINUX): $(OBJ_LINUX)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_LINUX) $(LDLIBS)

$(BIN_IOS): $(OBJ_IOS) $(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a
	PATH="$(IOS_TOOLCHAIN)/bin:$$PATH" $(IOS_RUNTIME_ENV) $(IOS_CC) $(IOS_LDFLAGS) -o $@ $(OBJ_IOS) $(IOS_LDLIBS)
	@$(IOS_OTOOL) -hv $@ | grep -qw PIE || (echo "Refusing non-PIE iOS binary: $@"; exit 1)

$(BIN_IOS_ARM64): $(OBJ_IOS_ARM64) $(IOS_ARM64_OPENSSL_PREFIX)/lib/libssl.a $(IOS_ARM64_OPENSSL_PREFIX)/lib/libcrypto.a
	PATH="$(IOS_TOOLCHAIN)/bin:$$PATH" $(IOS_RUNTIME_ENV) $(IOS_CC) $(IOS_ARM64_LDFLAGS) -o $@ $(OBJ_IOS_ARM64) $(IOS_ARM64_LDLIBS)
	@$(IOS_OTOOL) -hv $@ | grep -qw PIE || (echo "Refusing non-PIE iOS binary: $@"; exit 1)

build/linux/%.o: src/%.c | build/linux
	$(CC) $(COMMON_CFLAGS) $(DEPFLAGS) $(INCLUDES) -c $< -o $@

build/ios/%.o: src/%.c | build/ios
	PATH="$(IOS_TOOLCHAIN)/bin:$$PATH" $(IOS_RUNTIME_ENV) $(IOS_CC) $(IOS_CFLAGS) $(DEPFLAGS) -c $< -o $@

build/ios-arm64/%.o: src/%.c | build/ios-arm64
	PATH="$(IOS_TOOLCHAIN)/bin:$$PATH" $(IOS_RUNTIME_ENV) $(IOS_CC) $(IOS_ARM64_CFLAGS) $(DEPFLAGS) -c $< -o $@

build/ios/main.o: $(IOS_OPENSSL_PATCH_STATUS_FILE)
build/ios-arm64/main.o: $(IOS_ARM64_OPENSSL_PATCH_STATUS_FILE)

$(IOS_OPENSSL_PATCH_STATUS_FILE):
	@echo "Missing $@"
	@echo "Run: make openssl-ios6"
	@false

$(IOS_ARM64_OPENSSL_PATCH_STATUS_FILE):
	@echo "Missing $@"
	@echo "Run: make openssl-ios-arm64"
	@false

build/linux:
	mkdir -p $@

build/ios:
	mkdir -p $@

build/ios-arm64:
	mkdir -p $@

$(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a:
	@echo "Missing $@"
	@echo "Run: make openssl-ios6"
	@echo "If the private asm patch lives elsewhere, set OPENSSL_IOS6_ASM_PATCH=/path/to/openssl-ios6-armv7-asm.patch"
	@false

openssl-ios6:
	IOS_TOOLCHAIN="$(IOS_TOOLCHAIN)" IOS_SDK="$(IOS_SDK)" ./scripts/build_openssl_ios6.sh

$(IOS_ARM64_OPENSSL_PREFIX)/lib/libssl.a $(IOS_ARM64_OPENSSL_PREFIX)/lib/libcrypto.a:
	@echo "Missing $@"
	@echo "Run: make openssl-ios-arm64"
	@false

openssl-ios-arm64:
	IOS_ARCH=arm64 IOS_MIN_VERSION=$(IOS_ARM64_MIN_VERSION) IOS_SDK="$(IOS_ARM64_SDK)" \
	IOS_TOOLCHAIN="$(IOS_TOOLCHAIN)" \
	OPENSSL_TARGET=ios64-cross OPENSSL_INSTALL_DIR="$(abspath $(IOS_ARM64_OPENSSL_PREFIX))" \
	OPENSSL_APPLY_LEGACY_PATCHES=0 ./scripts/build_openssl_ios6.sh

$(IOS_ZLIB_PREFIX)/lib/libz.a:
	@echo "Missing $(IOS_ZLIB_PREFIX)/lib/libz.a"
	@echo "Run: make zlib-ios6"
	@false

zlib-ios6:
	IOS_TOOLCHAIN="$(IOS_TOOLCHAIN)" IOS_SDK="$(IOS_SDK)" ./scripts/build_zlib_ios6.sh

$(IOS_ARM64_ZLIB_PREFIX)/lib/libz.a:
	@echo "Missing $(IOS_ARM64_ZLIB_PREFIX)/lib/libz.a"
	@echo "Run: make zlib-ios-arm64"
	@false

zlib-ios-arm64:
	IOS_ARCH=arm64 IOS_MIN_VERSION=$(IOS_ARM64_MIN_VERSION) IOS_SDK="$(IOS_ARM64_SDK)" \
	IOS_TOOLCHAIN="$(IOS_TOOLCHAIN)" \
	ZLIB_INSTALL_DIR="$(abspath $(IOS_ARM64_ZLIB_PREFIX))" ./scripts/build_zlib_ios6.sh

$(CURL_IOS_BIN): $(IOS_OPENSSL_PREFIX)/lib/libssl.a $(IOS_OPENSSL_PREFIX)/lib/libcrypto.a $(IOS_ZLIB_PREFIX)/lib/libz.a
	IOS_TOOLCHAIN="$(IOS_TOOLCHAIN)" IOS_SDK="$(IOS_SDK)" ./scripts/build_curl_ios6.sh

curl-ios6: $(CURL_IOS_BIN)

$(CURL_IOS_ARM64_BIN): $(IOS_ARM64_OPENSSL_PREFIX)/lib/libssl.a $(IOS_ARM64_OPENSSL_PREFIX)/lib/libcrypto.a $(IOS_ARM64_ZLIB_PREFIX)/lib/libz.a
	IOS_ARCH=arm64 IOS_MIN_VERSION=$(IOS_ARM64_MIN_VERSION) IOS_SDK="$(IOS_ARM64_SDK)" \
	IOS_TOOLCHAIN="$(IOS_TOOLCHAIN)" \
	OPENSSL_PREFIX="$(abspath $(IOS_ARM64_OPENSSL_PREFIX))" ZLIB_PREFIX="$(abspath $(IOS_ARM64_ZLIB_PREFIX))" \
	CURL_INSTALL_DIR="$(abspath $(CURL_IOS_ARM64_PREFIX))" ./scripts/build_curl_ios6.sh

curl-ios-arm64: $(CURL_IOS_ARM64_BIN)

$(CA_BUNDLE):
	curl -fL -o $@ https://curl.se/ca/cacert.pem

curl-ios6-package: $(CURL_IOS_BIN) $(CA_BUNDLE) $(THIRD_PARTY_LICENSES)
	tar -czf third_party/curl-ios6-with-ca.tar.gz \
		-C $(abspath third_party/curl-ios6-armv7/bin) curl \
		-C $(abspath third_party) cacert.pem \
		-C $(ROOT_DIR) $(THIRD_PARTY_LICENSES)
	@echo "Packed third_party/curl-ios6-with-ca.tar.gz"

$(RELEASE_LINUX_ARCHIVE): $(BIN_LINUX) $(THIRD_PARTY_LICENSES)
	mkdir -p $(RELEASE_DIR)
	tar -czf $@ -C $(ROOT_DIR) $(BIN_LINUX) $(THIRD_PARTY_LICENSES)

$(RELEASE_IOS_ARMV7_ARCHIVE): $(BIN_IOS) $(THIRD_PARTY_LICENSES)
	mkdir -p $(RELEASE_DIR)
	tar -czf $@ -C $(ROOT_DIR) $(BIN_IOS) $(THIRD_PARTY_LICENSES)

$(RELEASE_IOS_ARM64_ARCHIVE): $(BIN_IOS_ARM64) $(THIRD_PARTY_LICENSES)
	mkdir -p $(RELEASE_DIR)
	tar -czf $@ -C $(ROOT_DIR) $(BIN_IOS_ARM64) $(THIRD_PARTY_LICENSES)

release-packages: $(RELEASE_LINUX_ARCHIVE) $(RELEASE_IOS_ARMV7_ARCHIVE) $(RELEASE_IOS_ARM64_ARCHIVE)
	cd $(RELEASE_DIR) && sha256sum $(notdir $(RELEASE_LINUX_ARCHIVE)) $(notdir $(RELEASE_IOS_ARMV7_ARCHIVE)) $(notdir $(RELEASE_IOS_ARM64_ARCHIVE)) > SHA256SUMS

clean:
	rm -rf build $(BIN_LINUX) $(BIN_IOS) $(BIN_IOS_ARM64)

-include $(OBJ_LINUX:.o=.d) $(OBJ_IOS:.o=.d) $(OBJ_IOS_ARM64:.o=.d)

.PHONY: all linux ios ios-arm64 check-ios-toolchain check-ios-arm64-toolchain clean openssl-ios6 openssl-ios-arm64 zlib-ios6 zlib-ios-arm64 curl-ios6 curl-ios-arm64 curl-ios6-package release-packages
