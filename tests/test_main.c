#define _POSIX_C_SOURCE 200809L
#include "check.h"
#define main vc_program_main
#include "../src/main.c"
#undef main
#include <fcntl.h>
#include <signal.h>
static int allocation_failure, thread_failure, accept_fixture = -1, accept_transient_error;
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
