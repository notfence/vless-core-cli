ROOT := $(abspath ..)
.DEFAULT_GOAL := test
HOST_CC ?= cc
HOST_BUILD_DIR ?= $(ROOT)/build/host-tests
TEST_OPENSSL_PREFIX ?= $(HOME)/.local/openssl-3.5
TEST_XRAY_BIN ?= $(abspath $(ROOT)/../tools/xray-v26.6.27-linux-64/xray)
HOST_FLAGS := -O1 -g -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -I$(ROOT)/include -I$(TEST_OPENSSL_PREFIX)/include $(SANITIZE)
HOST_LIBS := $(TEST_OPENSSL_PREFIX)/lib/libssl.a $(TEST_OPENSSL_PREFIX)/lib/libcrypto.a -lpthread -ldl $(SANITIZE)
HOST_LIB_FILES := $(TEST_OPENSSL_PREFIX)/lib/libssl.a $(TEST_OPENSSL_PREFIX)/lib/libcrypto.a
BASE_SRC := $(filter-out $(ROOT)/src/main.c,$(wildcard $(ROOT)/src/*.c))
BASE_OBJ := $(patsubst $(ROOT)/src/%.c,$(HOST_BUILD_DIR)/src/%.o,$(BASE_SRC))
NETWORK_GUARD := $(HOST_BUILD_DIR)/network_guard.o
NETWORK_FLAGS := -Wl,--wrap=getaddrinfo,--wrap=connect
TEST_SOURCES := $(wildcard $(ROOT)/tests/test_*.c $(ROOT)/tests/*_test.c)
TEST_NAMES := test_uri $(filter-out test_uri,$(sort $(basename $(notdir $(TEST_SOURCES)))))
TEST_BINS := $(addprefix $(HOST_BUILD_DIR)/,$(TEST_NAMES))
ifneq ($(findstring --coverage,$(HOST_FLAGS)),)
CLI_COVERAGE_OBJ := $(HOST_BUILD_DIR)/coverage_stop.o
CLI_COVERAGE_FLAGS := -Wl,--wrap=main
endif
$(TEST_BINS) $(HOST_BUILD_DIR)/vless-core-test: $(HOST_LIB_FILES)
$(BASE_OBJ) $(HOST_BUILD_DIR)/src/main.o $(NETWORK_GUARD) $(CLI_COVERAGE_OBJ) $(addsuffix .o,$(addprefix $(HOST_BUILD_DIR)/,$(TEST_NAMES))): $(HOST_BUILD_DIR)/settings

$(HOST_BUILD_DIR)/settings: FORCE | requirements
	python3 $(ROOT)/tests/requirements.py settings "$@" "$(HOST_CC)" "$(HOST_FLAGS)" "$(HOST_LIBS)"

test: requirements $(TEST_BINS) $(HOST_BUILD_DIR)/vless-core-test
	TEST_BUILD_DIR="$(HOST_BUILD_DIR)" TEST_OPENSSL_PREFIX="$(TEST_OPENSSL_PREFIX)" TEST_XRAY_BIN="$(TEST_XRAY_BIN)" TEST_HOST_FLAGS="$(HOST_FLAGS)" TEST_HOST_LIBS="$(HOST_LIBS)" TEST_HOST_CC="$(HOST_CC)" TEST_NATIVE_NAMES="$(TEST_NAMES)" python3 $(ROOT)/tests/run.py

native: requirements $(TEST_BINS) $(HOST_BUILD_DIR)/vless-core-test

requirements:
	TEST_OPENSSL_PREFIX="$(TEST_OPENSSL_PREFIX)" TEST_XRAY_BIN="$(TEST_XRAY_BIN)" python3 $(ROOT)/tests/requirements.py

$(HOST_LIB_FILES): | requirements
	@echo "Missing test OpenSSL library: $@" >&2
	@false

$(HOST_BUILD_DIR)/src/%.o: $(ROOT)/src/%.c | requirements
	mkdir -p $(dir $@)
	$(HOST_CC) $(HOST_FLAGS) -MMD -MP -c $< -o $@

$(HOST_BUILD_DIR)/%.o: $(ROOT)/tests/%.c $(ROOT)/tests/check.h | requirements
	mkdir -p $(dir $@)
	$(HOST_CC) $(HOST_FLAGS) -MMD -MP -c $< -o $@

$(HOST_BUILD_DIR)/test_main: $(HOST_BUILD_DIR)/test_main.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=calloc,--wrap=pthread_create,--wrap=accept

$(HOST_BUILD_DIR)/test_tls: $(HOST_BUILD_DIR)/test_tls.o $(filter-out $(HOST_BUILD_DIR)/src/tls13_reality.o,$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=write,--wrap=rename,--wrap=fsync

$(HOST_BUILD_DIR)/test_socket: $(HOST_BUILD_DIR)/test_socket.o
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) -Wl,--wrap=connect,--wrap=select,--wrap=getsockopt

$(HOST_BUILD_DIR)/test_encryption: $(HOST_BUILD_DIR)/test_encryption.o $(HOST_BUILD_DIR)/src/blake3.o
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS)

$(HOST_BUILD_DIR)/%: $(HOST_BUILD_DIR)/%.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/vless-core-test: $(HOST_BUILD_DIR)/src/main.o $(BASE_OBJ) $(NETWORK_GUARD) $(CLI_COVERAGE_OBJ)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) $(CLI_COVERAGE_FLAGS)

asan:
	ASAN_OPTIONS=detect_leaks=1 $(MAKE) test HOST_BUILD_DIR=$(HOST_BUILD_DIR)-asan SANITIZE='-fsanitize=address -fno-omit-frame-pointer'

sanitizers:
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 $(MAKE) test HOST_BUILD_DIR=$(HOST_BUILD_DIR)-sanitized SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer'

coverage:
	python3 $(ROOT)/tests/test_build.py reset-coverage $(HOST_BUILD_DIR)-coverage
	GCOV_EXIT_AT_ERROR=1 $(MAKE) test HOST_BUILD_DIR=$(HOST_BUILD_DIR)-coverage SANITIZE='--coverage -O0 -fprofile-abs-path -fprofile-update=atomic'; result=$$?; python3 $(ROOT)/tests/test_build.py coverage $(HOST_BUILD_DIR)-coverage; coverage_result=$$?; if [ $$coverage_result -ne 0 ]; then exit $$coverage_result; fi; exit $$result

-include $(wildcard $(HOST_BUILD_DIR)/*.d $(HOST_BUILD_DIR)/src/*.d)
.SECONDARY: $(BASE_OBJ) $(addsuffix .o,$(addprefix $(HOST_BUILD_DIR)/,$(TEST_NAMES)))
.PHONY: test native requirements FORCE asan sanitizers coverage
