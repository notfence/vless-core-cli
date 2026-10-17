ROOT := $(abspath ..)
.DEFAULT_GOAL := test
HOST_CC ?= cc
HOST_BUILD_DIR ?= $(ROOT)/build/host-tests
TEST_OPENSSL_PREFIX ?= $(HOME)/.local/openssl-3.5
TEST_XRAY_BIN ?= $(abspath $(ROOT)/../tools/xray-v26.6.27-linux-64/xray)
FUZZ_CC ?= clang
FUZZ_RUNS ?= 10000
FUZZ_FLAGS := -O1 -g -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -I$(ROOT)/include -I$(TEST_OPENSSL_PREFIX)/include -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
TLS_INTERNAL_SRC := $(addprefix $(ROOT)/src/,tls_client_hello.c tls_certificate.c tls_records.c tls_handshake.c tls_transport.c tls_websocket.c tls_xhttp.c tls_http2.c)
TLS_INTERNAL_OBJ = $(patsubst $(ROOT)/src/%.c,$(HOST_BUILD_DIR)/src/%.o,$(TLS_INTERNAL_SRC))
FUZZ_SRC = $(filter-out $(ROOT)/src/tls13_reality.c $(TLS_INTERNAL_SRC),$(BASE_SRC))
FUZZ_OBJ = $(patsubst $(ROOT)/src/%.c,$(HOST_BUILD_DIR)/fuzz-src/%.o,$(FUZZ_SRC))
FUZZ_BIN := $(HOST_BUILD_DIR)/fuzz-parsers
ENCRYPTION_FUZZ_BIN := $(HOST_BUILD_DIR)/fuzz-encryption
POOL_FUZZ_BIN := $(HOST_BUILD_DIR)/fuzz-http2-pool
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
$(FUZZ_OBJ) $(HOST_BUILD_DIR)/fuzz_parsers.o $(HOST_BUILD_DIR)/fuzz_network_guard.o: $(HOST_BUILD_DIR)/settings
$(HOST_BUILD_DIR)/fuzz_encryption.o: $(HOST_BUILD_DIR)/settings
$(HOST_BUILD_DIR)/fuzz_http2_pool.o: $(HOST_BUILD_DIR)/settings

$(HOST_BUILD_DIR)/settings: FORCE | requirements
	python3 $(ROOT)/tests/requirements.py settings "$@" "$(HOST_CC)" "$(HOST_FLAGS)" "$(HOST_LIBS)" "$(FUZZ_CC)" "$(FUZZ_FLAGS)"

test: requirements $(TEST_BINS) $(HOST_BUILD_DIR)/vless-core-test $(FUZZ_BIN) $(ENCRYPTION_FUZZ_BIN) $(POOL_FUZZ_BIN)
	TEST_BUILD_DIR="$(HOST_BUILD_DIR)" TEST_OPENSSL_PREFIX="$(TEST_OPENSSL_PREFIX)" TEST_XRAY_BIN="$(TEST_XRAY_BIN)" TEST_HOST_FLAGS="$(HOST_FLAGS)" TEST_HOST_LIBS="$(HOST_LIBS)" TEST_HOST_CC="$(HOST_CC)" TEST_NATIVE_NAMES="$(TEST_NAMES)" TEST_FUZZ_RUNS="$(FUZZ_RUNS)" python3 $(ROOT)/tests/run.py

native: requirements $(TEST_BINS) $(HOST_BUILD_DIR)/vless-core-test

requirements:
	TEST_OPENSSL_PREFIX="$(TEST_OPENSSL_PREFIX)" TEST_XRAY_BIN="$(TEST_XRAY_BIN)" TEST_FUZZ_CC="$(FUZZ_CC)" python3 $(ROOT)/tests/requirements.py

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
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=calloc,--wrap=malloc,--wrap=pthread_create,--wrap=accept

$(HOST_BUILD_DIR)/test_relay_memory: $(HOST_BUILD_DIR)/test_relay_memory.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=realloc,--wrap=socketpair

$(HOST_BUILD_DIR)/test_tls: $(HOST_BUILD_DIR)/test_tls.o $(filter-out $(HOST_BUILD_DIR)/src/tls13_reality.o $(TLS_INTERNAL_OBJ),$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=write,--wrap=rename,--wrap=fsync,--wrap=core_http2_pending,--wrap=core_now_ms,--wrap=clock_gettime,--wrap=poll,--wrap=RAND_bytes

$(HOST_BUILD_DIR)/test_transport_wire: $(HOST_BUILD_DIR)/test_transport_wire.o $(filter-out $(HOST_BUILD_DIR)/src/tls13_reality.o $(TLS_INTERNAL_OBJ),$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=RAND_bytes

$(HOST_BUILD_DIR)/test_tls_handshake: $(HOST_BUILD_DIR)/test_tls_handshake.o $(filter-out $(HOST_BUILD_DIR)/src/tls13_reality.o $(TLS_INTERNAL_OBJ),$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/test_tls12_handshake: $(HOST_BUILD_DIR)/test_tls12_handshake.o $(filter-out $(HOST_BUILD_DIR)/src/tls13_reality.o $(TLS_INTERNAL_OBJ),$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/test_tls_state: $(HOST_BUILD_DIR)/test_tls_state.o $(filter-out $(HOST_BUILD_DIR)/src/tls13_reality.o $(TLS_INTERNAL_OBJ),$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=malloc

$(HOST_BUILD_DIR)/test_socket: $(HOST_BUILD_DIR)/test_socket.o $(HOST_BUILD_DIR)/src/connection_trace.o $(HOST_BUILD_DIR)/src/core_log.o $(HOST_BUILD_DIR)/src/deadline.o $(HOST_BUILD_DIR)/src/resolver.o
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) -Wl,--wrap=connect,--wrap=poll,--wrap=getsockopt

$(HOST_BUILD_DIR)/routing_direct_lease_test: $(HOST_BUILD_DIR)/routing_direct_lease_test.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=core_connect_with_timeout,--wrap=core_getaddrinfo

$(HOST_BUILD_DIR)/test_resolver: $(HOST_BUILD_DIR)/test_resolver.o $(filter-out $(HOST_BUILD_DIR)/src/resolver.o,$(BASE_OBJ))
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) -Wl,--wrap=getaddrinfo

$(HOST_BUILD_DIR)/test_dialer: $(HOST_BUILD_DIR)/test_dialer.o $(filter-out $(HOST_BUILD_DIR)/src/dialer.o,$(BASE_OBJ))
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) -Wl,--wrap=getaddrinfo,--wrap=connect,--wrap=poll

$(HOST_BUILD_DIR)/test_xmux: $(HOST_BUILD_DIR)/test_xmux.o $(filter-out $(HOST_BUILD_DIR)/src/http2_pool.o,$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=core_now_ms,--wrap=RAND_bytes,--wrap=core_poll

$(HOST_BUILD_DIR)/test_grpc: $(HOST_BUILD_DIR)/test_grpc.o $(filter-out $(HOST_BUILD_DIR)/src/grpc.o,$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=malloc

$(HOST_BUILD_DIR)/test_socks5: $(HOST_BUILD_DIR)/test_socks5.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=recv,--wrap=send,--wrap=core_now_ms

$(HOST_BUILD_DIR)/test_xhttp_payload: $(HOST_BUILD_DIR)/test_xhttp_payload.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) -Wl,--wrap=RAND_bytes

$(HOST_BUILD_DIR)/test_encryption: $(HOST_BUILD_DIR)/test_encryption.o $(filter-out $(HOST_BUILD_DIR)/src/vless_encryption.o $(HOST_BUILD_DIR)/src/tls13_reality.o $(TLS_INTERNAL_OBJ),$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/test_tls12: $(HOST_BUILD_DIR)/test_tls12.o $(filter-out $(HOST_BUILD_DIR)/src/tls12.o,$(BASE_OBJ)) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/%: $(HOST_BUILD_DIR)/%.o $(BASE_OBJ) $(NETWORK_GUARD)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/vless-core-test: $(HOST_BUILD_DIR)/src/main.o $(BASE_OBJ) $(NETWORK_GUARD) $(CLI_COVERAGE_OBJ)
	$(HOST_CC) $(filter %.o,$^) -o $@ $(HOST_LIBS) $(NETWORK_FLAGS) $(CLI_COVERAGE_FLAGS)

$(HOST_BUILD_DIR)/fuzz-src/%.o: $(ROOT)/src/%.c | requirements
	mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_FLAGS) -MMD -MP -c $< -o $@

$(HOST_BUILD_DIR)/fuzz_parsers.o: $(ROOT)/tests/fuzz_parsers.c | requirements
	mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_FLAGS) -MMD -MP -c $< -o $@

$(HOST_BUILD_DIR)/fuzz_network_guard.o: $(ROOT)/tests/network_guard.c | requirements
	mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_FLAGS) -MMD -MP -c $< -o $@

$(HOST_BUILD_DIR)/fuzz_encryption.o: $(ROOT)/tests/fuzz_encryption.c | requirements
	mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_FLAGS) -MMD -MP -c $< -o $@

$(FUZZ_BIN): $(HOST_BUILD_DIR)/fuzz_parsers.o $(HOST_BUILD_DIR)/fuzz_network_guard.o $(FUZZ_OBJ) $(HOST_LIB_FILES)
	$(FUZZ_CC) $(filter %.o,$^) -o $@ $(HOST_LIB_FILES) -lpthread -ldl -fsanitize=fuzzer,address,undefined $(NETWORK_FLAGS)

$(ENCRYPTION_FUZZ_BIN): $(HOST_BUILD_DIR)/fuzz_encryption.o $(HOST_BUILD_DIR)/fuzz_network_guard.o $(filter-out $(HOST_BUILD_DIR)/fuzz-src/vless_encryption.o,$(FUZZ_OBJ)) $(HOST_LIB_FILES)
	$(FUZZ_CC) $(filter %.o,$^) -o $@ $(HOST_LIB_FILES) -lpthread -ldl -fsanitize=fuzzer,address,undefined $(NETWORK_FLAGS)

$(HOST_BUILD_DIR)/fuzz_http2_pool.o: $(ROOT)/tests/fuzz_http2_pool.c | requirements
	mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_FLAGS) -MMD -MP -c $< -o $@

$(POOL_FUZZ_BIN): $(HOST_BUILD_DIR)/fuzz_http2_pool.o $(HOST_BUILD_DIR)/fuzz_network_guard.o $(filter-out $(HOST_BUILD_DIR)/fuzz-src/http2_pool.o $(HOST_BUILD_DIR)/fuzz-src/vless.o $(HOST_BUILD_DIR)/fuzz-src/vless_encryption.o,$(FUZZ_OBJ)) $(HOST_LIB_FILES)
	$(FUZZ_CC) $(filter %.o,$^) -o $@ $(HOST_LIB_FILES) -lpthread -ldl -fsanitize=fuzzer,address,undefined $(NETWORK_FLAGS)

fuzz: requirements $(FUZZ_BIN) $(ENCRYPTION_FUZZ_BIN) $(POOL_FUZZ_BIN)
	TEST_BUILD_DIR="$(HOST_BUILD_DIR)" TEST_FUZZ_RUNS="$(FUZZ_RUNS)" python3 $(ROOT)/tests/test_fuzz.py

asan:
	ASAN_OPTIONS=detect_leaks=1 $(MAKE) test HOST_BUILD_DIR=$(HOST_BUILD_DIR)-asan SANITIZE='-fsanitize=address -fno-omit-frame-pointer'

sanitizers:
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 $(MAKE) test HOST_BUILD_DIR=$(HOST_BUILD_DIR)-sanitized SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer'

coverage:
	python3 $(ROOT)/tests/test_build.py reset-coverage $(HOST_BUILD_DIR)-coverage
	GCOV_EXIT_AT_ERROR=1 $(MAKE) test HOST_BUILD_DIR=$(HOST_BUILD_DIR)-coverage SANITIZE='--coverage -O0 -fprofile-abs-path -fprofile-update=atomic'; result=$$?; python3 $(ROOT)/tests/test_build.py coverage $(HOST_BUILD_DIR)-coverage; coverage_result=$$?; if [ $$coverage_result -ne 0 ]; then exit $$coverage_result; fi; exit $$result

-include $(wildcard $(HOST_BUILD_DIR)/*.d $(HOST_BUILD_DIR)/src/*.d $(HOST_BUILD_DIR)/fuzz-src/*.d)
.SECONDARY: $(BASE_OBJ) $(addsuffix .o,$(addprefix $(HOST_BUILD_DIR)/,$(TEST_NAMES)))
.PHONY: test native requirements FORCE asan sanitizers coverage fuzz
