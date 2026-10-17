#define _POSIX_C_SOURCE 200809L
#include "check.h"
#define main vc_program_main
#include "../src/main.c"
#undef main
#include "../src/tls_internal.h"
#include <fcntl.h>
#include <signal.h>
static int allocation_failure, thread_failure, accept_fixture = -1, accept_transient_error;
static int reject_large_relay;
static unsigned large_relay_allocations;
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (reject_large_relay && size == 256U*1024U) { large_relay_allocations++; errno=ENOMEM; return NULL; }
    return __real_malloc(size);
}
void *__real_calloc(size_t count, size_t size);
int __real_accept(int fd, struct sockaddr *address, socklen_t *length);
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
void *__wrap_calloc(size_t count, size_t size) {
    if (allocation_failure && count == 1 && size == sizeof(client_ctx_t)) { allocation_failure = 0; return NULL; }
    return __real_calloc(count, size);
}
int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length) {
    if (accept_transient_error) { errno = accept_transient_error; accept_transient_error = 0; return -1; }
    if (accept_fixture >= 0) { int result = accept_fixture; accept_fixture = -2; return result; }
    if (accept_fixture == -2) { accept_fixture = -1; errno = EIO; return -1; }
    return __real_accept(fd, address, length);
}
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*fn)(void *), void *arg) {
    if (thread_failure && fn == client_worker) { thread_failure = 0; return EAGAIN; }
    return __real_pthread_create(thread, attr, fn, arg);
}
static void test_start_failure(int allocation, int transient) {
    int pair[2]; REQUIRE("clients/failure-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    accept_fixture = pair[0]; allocation_failure = allocation; thread_failure = !allocation; accept_transient_error = transient;
    int fd = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in address = {.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    REQUIRE("clients/port-reserve", bind(fd, (void *)&address, sizeof(address)) == 0); socklen_t size = sizeof(address); getsockname(fd, (void *)&address, &size); close(fd);
    char port[16], uri[] = "socks5://127.0.0.1:1080#vless-core"; snprintf(port, sizeof(port), "%u", ntohs(address.sin_port));
    char *args[] = {"vless-core-test", "--uri", uri, "--listen-port", port, NULL};
    CHECK(allocation ? "clients/allocation-failure-release" : "clients/thread-failure-release", vc_program_main(5, args) != 0 && g_active_client_count == 0);
    CHECK("clients/failure-closes-socket", fcntl(pair[0], F_GETFD) == -1 && errno == EBADF); close(pair[0]); close(pair[1]);
}

static void *relay_fixture_peer(void *opaque) {
    int listener=*(int *)opaque,fd=accept(listener,NULL,NULL);
    if (fd >= 0) {
        core_set_socket_io_timeout(fd,1000);
        uint8_t request[26],data[10],response[]={0,0};
        if (!read_exact(fd,request,sizeof(request)) && !write_all(fd,response,sizeof(response)) &&
            !read_exact(fd,data,sizeof(data))) (void)write_all(fd,data,sizeof(data));
        close(fd);
    }
    return NULL;
}

static void relay_minimum_allocation(void) {
    int listener=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    REQUIRE("relay/minimum-listener",listener >= 0 && bind(listener,(void *)&address,sizeof(address)) == 0 && listen(listener,1) == 0);
    socklen_t size=sizeof(address); REQUIRE("relay/minimum-port",getsockname(listener,(void *)&address,&size) == 0);
    int pair[2]; REQUIRE("relay/minimum-client-pair",socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    core_set_socket_io_timeout(pair[1],1500);
    client_ctx_t *ctx=calloc(1,sizeof(*ctx)); REQUIRE("relay/minimum-client-context",ctx != NULL);
    ctx->client_fd=pair[0]; char uri[256],error[256];
    snprintf(uri,sizeof(uri),"vless://00000000-0000-0000-0000-000000000001@127.0.0.1:%u?type=tcp&security=none",ntohs(address.sin_port));
    REQUIRE("relay/minimum-config",parse_core_uri(uri,&ctx->cfg,error,sizeof(error)) == 0 && routing_config_parse("1;proxy;0",&g_routing,error,sizeof(error)) == 0);
    pthread_t server,worker; reject_large_relay=1; large_relay_allocations=0;
    REQUIRE("relay/minimum-peer",pthread_create(&server,NULL,relay_fixture_peer,&listener) == 0);
    REQUIRE("relay/minimum-worker-slot",acquire_client_slot());
    REQUIRE("relay/minimum-worker",pthread_create(&worker,NULL,client_worker,ctx) == 0);
    uint8_t greeting[]={5,1,0},method[2],connect[]={5,1,0,1,127,0,0,1,1,187},reply[10],data[10];
    REQUIRE("relay/minimum-socks-method",write_all(pair[1],greeting,sizeof(greeting)) == 0 && !read_exact(pair[1],method,sizeof(method)) && !memcmp(method,"\x05\x00",2));
    REQUIRE("relay/minimum-socks-connect",write_all(pair[1],connect,sizeof(connect)) == 0 && !read_exact(pair[1],reply,sizeof(reply)) && reply[1] == 0);
    int exchanged=write_all(pair[1],(const uint8_t *)"vless-core",10) == 0 && !read_exact(pair[1],data,sizeof(data)) && !memcmp(data,"vless-core",10);
    shutdown(pair[1],SHUT_RDWR); close(pair[1]); pthread_join(worker,NULL); pthread_join(server,NULL); close(listener);
    reject_large_relay=0;
    CHECK("relay/minimum-buffer-keeps-connection-working",exchanged);
    CHECK("relay/no-eager-256k-allocation",large_relay_allocations == 0);
    CHECK("relay/minimum-worker-released",g_active_client_count == 0);
    routing_config_init(&g_routing);
}

static void relay_memory_pressure(void) {
    core_relay_memory_t memory={0}; core_buffer_budget_t pressure={0}; size_t capacity=0;
    REQUIRE("relay/pressure-memory",core_relay_memory_init(&memory,128U*1024U) == 1);
    REQUIRE("relay/pressure-reserve",core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,core_buffer_available(CORE_BUFFER_RELAY)) == 0);
    CHECK("relay/plain-input-uses-existing-floor",relay_input_room(&memory,128U*1024U,0,&capacity) == 1 && capacity == 8192);
    CHECK("relay/vision-input-pauses-without-reading",relay_input_room(&memory,128U*1024U,1,&capacity) == 0);
    REQUIRE("relay/pressure-watch-input",core_relay_memory_watch(&memory,CORE_RELAY_INPUT_WAIT) == 0);
    CHECK("relay/opposite-direction-can-progress",relay_output_room(&memory,NULL,8192,&capacity) == 1 && capacity == 8192);
    memory.output.length=8192;
    CHECK("relay/full-output-pauses-without-reading",relay_output_room(&memory,NULL,8192,&capacity) == 0 && memory.output.capacity == 8192);
    REQUIRE("relay/pressure-watch-output",core_relay_memory_watch(&memory,CORE_RELAY_OUTPUT_WAIT) == 0);
    core_relay_buffer_consume(&memory.output,8192);
    core_relay_memory_unwatch(&memory,CORE_RELAY_OUTPUT_WAIT);
    CHECK("relay/consumption-unblocks-without-free",memory.waiting == CORE_RELAY_INPUT_WAIT && relay_output_room(&memory,NULL,8192,&capacity) == 1);
    REQUIRE("relay/pressure-release",core_buffer_budget_clear(&pressure) == 0);
    CHECK("relay/input-recovers-large-batch",relay_input_room(&memory,128U*1024U,1,&capacity) == 1 && capacity == 128U*1024U);
    core_relay_memory_clear(&memory);
    size_t bytes,reserved; core_buffer_snapshot(CORE_BUFFER_RELAY,&bytes,&reserved);
    CHECK("relay/pressure-cancel-releases-everything",!bytes && !reserved);
    REQUIRE("relay/retained-fragment-memory",core_relay_memory_init(&memory,8192) == 1);
    void *retained=core_buffer_alloc(&memory.temporary,512);
    REQUIRE("relay/retained-fragment-allocation",retained != NULL);
    REQUIRE("relay/retained-fragment-pressure",core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,core_buffer_available(CORE_BUFFER_RELAY)-vision_wrap_buffer_bound(8192)) == 0);
    REQUIRE("relay/retained-fragment-read-reservation",relay_input_room(&memory,8192,1,&capacity) == 1);
    REQUIRE("relay/competing-client-takes-unreserved-capacity",core_buffer_budget_init(&pressure,CORE_BUFFER_RELAY,pressure.minimum+core_buffer_available(CORE_BUFFER_RELAY)) == 0);
    vision_wrap_t wrap; uint8_t uuid[16]={0},data[8192]={0}; vision_wrap_init(&wrap,uuid);
    CHECK("relay/transform-credit-includes-retained-fragment",vision_wrap_payload_buffer(&wrap,data,sizeof(data),&memory.wrapped) == 0);
    core_buffer_free(&memory.temporary,retained,512);
    core_relay_memory_clear(&memory); REQUIRE("relay/retained-fragment-pressure-release",core_buffer_budget_clear(&pressure) == 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    char private_uri[]="socks5://user:vless-core-private-value@127.0.0.1:1080#vless-core";
    char *invalid_args[]={"vless-core-test","--uri",private_uri,"--unknown-option"};
    CHECK("startup/invalid-arguments-clear-uri",vc_program_main(4,invalid_args) != 0 && !memcmp(private_uri,(char[sizeof(private_uri)]){0},sizeof(private_uri)));
    for (int i = 0; i < 256; i++) REQUIRE("clients/acquire", acquire_client_slot());
    CHECK("clients/limit-256", !acquire_client_slot() && g_active_client_count == 256);
    for (int i = 0; i < 256; i++) release_client_slot();
    release_client_slot(); CHECK("clients/release-no-underflow", g_active_client_count == 0);
    int pair[2]; REQUIRE("clients/worker-pair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    close(pair[1]); client_ctx_t *ctx = calloc(1, sizeof(*ctx)); ctx->client_fd = pair[0]; acquire_client_slot();
    client_worker(ctx); CHECK("clients/handshake-error-release", g_active_client_count == 0 && fcntl(pair[0], F_GETFD) == -1);
    relay_minimum_allocation();
    relay_memory_pressure();
    test_start_failure(1, 0); test_start_failure(0, 0);
    test_start_failure(1, EMFILE); test_start_failure(1, ENFILE);
    test_start_failure(1, ENOBUFS); test_start_failure(1, ENOMEM);
    test_start_failure(1, ECONNABORTED); test_start_failure(1, EAGAIN);
#ifdef __linux__
    const int network_errors[]={ENETDOWN,EPROTO,ENOPROTOOPT,EHOSTDOWN,ENONET,EHOSTUNREACH,EOPNOTSUPP,ENETUNREACH};
    for (size_t i=0;i<sizeof(network_errors)/sizeof(*network_errors);i++) test_start_failure(1,network_errors[i]);
#endif
    char domain[256]; const uint8_t request[] = "GET / HTTP/1.1\r\nHost: VLESS-core.test.:443\r\n\r\n";
    CHECK("sniff/http-host", parse_http_host(request, sizeof(request)-1, domain, sizeof(domain)) == 0 && strcmp(domain, "VLESS-core.test") == 0);
    const char *bad[] = {"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n", "GET / HTTP/1.1\r\nHost: a..b\r\n\r\n", "GET / HTTP/1.1\r\nHost: a:x\r\n\r\n", "GET / HTTP/1.1\r\nHost:\r\n\r\n"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(*bad); i++) CHECK("sniff/http-invalid", parse_http_host((const uint8_t *)bad[i], strlen(bad[i]), domain, sizeof(domain)) != 0);
    uint8_t hello[256] = {22,3,3}; size_t p = 5; hello[p++] = 1; size_t hs_len_pos = p; p += 3; hello[p++] = 3; hello[p++] = 3; p += 32;
    hello[p++] = 0; hello[p++] = 0; hello[p++] = 2; hello[p++] = 0x13; hello[p++] = 3; hello[p++] = 1; hello[p++] = 0;
    size_t ext_pos = p; p += 2; hello[p++] = 0; hello[p++] = 0; hello[p++] = 0; hello[p++] = 20; hello[p++] = 0; hello[p++] = 18; hello[p++] = 0; hello[p++] = 0; hello[p++] = 15;
    memcpy(hello+p, "vless-core.test", 15); p += 15; hello[ext_pos+1] = 24; hello[hs_len_pos+2] = p-9; hello[4] = p-5;
    CHECK("sniff/tls-sni", parse_tls_sni(hello, p, domain, sizeof(domain)) == 0 && strcmp(domain, "vless-core.test") == 0);
    for (size_t i = 0; i < p; i++) CHECK("sniff/truncated-hello", parse_tls_sni(hello, i, domain, sizeof(domain)) != 0);
    CHECK("sniff/tls-record-size", tls_records_needed(hello, p, &p) == 1);
    char uri[CORE_URI_MAX_LENGTH+1], ips[SERVER_IP_LIST_MAX_LENGTH+1]; int pipe_fds[2];
    REQUIRE("fd/pipe", pipe(pipe_fds) == 0); const char *input = "socks5://127.0.0.1:1080#vless-core\n127.0.0.1,127.0.0.2";
    REQUIRE("fd/connection-write", write(pipe_fds[1], input, strlen(input)) == (ssize_t)strlen(input)); close(pipe_fds[1]);
    CHECK("fd/connection", read_connection_from_fd(pipe_fds[0], uri, ips) == 0 && strcmp(ips, "127.0.0.1,127.0.0.2") == 0); close(pipe_fds[0]);
    const char *bad_inputs[] = {"", "socks5://127.0.0.1", "\n127.0.0.1", "socks5://127.0.0.1\n", "a\nb\nc", "a\r\nb"};
    for (size_t i = 0; i < sizeof(bad_inputs)/sizeof(*bad_inputs); i++) { REQUIRE("fd/invalid-pipe", pipe(pipe_fds) == 0); REQUIRE("fd/invalid-write", write(pipe_fds[1], bad_inputs[i], strlen(bad_inputs[i])) == (ssize_t)strlen(bad_inputs[i])); close(pipe_fds[1]); CHECK("fd/connection-invalid", read_connection_from_fd(pipe_fds[0], uri, ips) != 0); close(pipe_fds[0]); }
    REQUIRE("fd/nul-pipe", pipe(pipe_fds) == 0); REQUIRE("fd/nul-write", write(pipe_fds[1], "a\0b", 3) == 3); close(pipe_fds[1]); CHECK("fd/uri-nul", read_uri_from_fd(pipe_fds[0], uri) != 0); close(pipe_fds[0]);
    CHECK("fd/closed", read_uri_from_fd(-1, uri) != 0);
    unsetenv("VLESS_TLS_MODE"); unsetenv("VLESS_XHTTP_TLS_MODE"); CHECK("startup/tls-default", strcmp(tls_mode_startup_label(0), "strict") == 0);
    setenv("VLESS_TLS_MODE", "auto", 1); CHECK("startup/auto-strict", strcmp(tls_mode_startup_label(0), "strict") == 0);
    CHECK("startup/explicit-insecure", strcmp(tls_mode_startup_label(1), "insecure") == 0);
    return test_result();
}
