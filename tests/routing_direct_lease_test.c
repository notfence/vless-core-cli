#define _POSIX_C_SOURCE 200809L

#include "routing.h"
#include "deadline.h"
#include "socket_util.h"
#include <errno.h>

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "check.h"

typedef struct {
    int listener;
    int hold;
    atomic_int commands;
    int reject, reject_remove, allow_missing;
} control_server_t;

static uint16_t expire_target_port;
static uint64_t test_time;
static uint64_t test_clock(void) { return test_time; }
int __real_core_connect_with_timeout(int, const struct sockaddr *, socklen_t, int);
int __wrap_core_connect_with_timeout(int fd, const struct sockaddr *address, socklen_t length, int timeout) {
    if (expire_target_port && address->sa_family == AF_INET && ntohs(((const struct sockaddr_in *)address)->sin_port) == expire_target_port) {
        test_time+=1000; errno=ETIMEDOUT; return -1;
    }
    return __real_core_connect_with_timeout(fd,address,length,timeout);
}

static void *serve_control(void *arg) {
    control_server_t *server = arg;
    const char *expected[] = {
        "ROUTE_DIRECT_ADD\t127.0.0.1\n",
        "ROUTE_DIRECT_REMOVE\t127.0.0.1\n",
    };
    for (size_t i = 0; i < (server->reject ? 1U : 2U); i++) {
        if (server->allow_missing && core_wait_socket(server->listener,POLLIN,1000) <= 0) return NULL;
        int fd = accept(server->listener, NULL, NULL);
        assert(fd >= 0);
        char command[128] = {0};
        size_t length = 0;
        do {
            assert(length + 1 < sizeof(command));
            ssize_t received=read(fd, &command[length], 1);
            if (server->allow_missing && received != 1) { close(fd); return NULL; }
            assert(received == 1);
        } while (command[length++] != '\n');
        assert(strcmp(command, expected[i]) == 0);
        atomic_fetch_add(&server->commands, 1);
        const char *reply = server->reject || (server->reject_remove && i == 1) ? "ERR denied\n" : (i == 0 && server->hold ? "OK hold\n" : "OK\n");
        for (size_t byte = 0; byte < strlen(reply); byte++) assert(write(fd, reply+byte, 1) == 1);
        close(fd);
    }
    return NULL;
}

static void run_case(int hold, int tcp, int refuse_target, int reject, int reject_remove, int expire) {
    char directory[] = "/tmp/vless-route-lease-XXXXXX";
    assert(mkdtemp(directory) != NULL);
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    assert(snprintf(path, sizeof(path), "%s/control.sock", directory) < (int)sizeof(path));

    int control_fd = socket(tcp ? AF_INET : AF_UNIX, SOCK_STREAM, 0);
    assert(control_fd >= 0);
    struct sockaddr_un control_address = {0};
    control_address.sun_family = AF_UNIX;
    strcpy(control_address.sun_path, path);
    struct sockaddr_in tcp_address = {.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(bind(control_fd, tcp ? (struct sockaddr *)&tcp_address : (struct sockaddr *)&control_address, tcp ? sizeof(tcp_address) : sizeof(control_address)) == 0);
    socklen_t tcp_length = sizeof(tcp_address);
    if (tcp) assert(getsockname(control_fd, (void *)&tcp_address, &tcp_length) == 0);
    assert(listen(control_fd, 2) == 0);

    control_server_t control = {.listener = control_fd, .hold = hold, .reject = reject, .reject_remove = reject_remove, .allow_missing=expire};
    atomic_init(&control.commands, 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_control, &control) == 0);

    int target_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(target_fd >= 0);
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = 0};
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(target_fd, (struct sockaddr *)&target, sizeof(target)) == 0);
    if (!refuse_target) assert(listen(target_fd, 1) == 0);
    socklen_t target_length = sizeof(target);
    assert(getsockname(target_fd, (struct sockaddr *)&target, &target_length) == 0);

    core_deadline_t deadline;
    if (expire) {
        REQUIRE("routes/expired-lease-deadline", core_deadline_attach(&deadline) == 0);
        deadline.now_ms=test_clock; test_time=1000; core_deadline_begin(1000);
        expire_target_port=ntohs(target.sin_port);
    }

    routing_direct_lease_t lease;
    char error[128];
    int direct_fd = routing_open_direct("127.0.0.1", ntohs(target.sin_port),
                                        tcp ? ntohs(tcp_address.sin_port) : 0, tcp ? NULL : path, &lease, error, sizeof(error));
    int accepted_fd = -1;
    if (refuse_target || reject || expire) {
        CHECK("routes/lease-connect-failure", direct_fd < 0 && lease.bypass_ip[0] == 0);
    } else {
        REQUIRE("routes/lease-connect", direct_fd >= 0);
        accepted_fd = accept(target_fd, NULL, NULL);
        assert(accepted_fd >= 0);
        assert(strcmp(lease.bypass_ip, hold ? "127.0.0.1" : "") == 0);
        assert(atomic_load(&control.commands) == (hold ? 1 : 2));
        CHECK("routes/lease-close", routing_close_direct(direct_fd, tcp ? ntohs(tcp_address.sin_port) : 0, tcp ? NULL : path, &lease) == (reject_remove && hold ? -1 : 0));
    }
    assert(lease.bypass_ip[0] == '\0');
    if (expire) {
        CHECK("routes/rollback-keeps-original-deadline-expired", core_deadline_active() && !core_deadline_remaining());
        expire_target_port=0; core_deadline_detach();
    }
    assert(pthread_join(thread, NULL) == 0);
    CHECK("routes/lease-cleanup-count", atomic_load(&control.commands) == (reject ? 1 : 2));

    if (accepted_fd >= 0) close(accepted_fd);
    close(target_fd);
    close(control_fd);
    if (!tcp) assert(unlink(path) == 0);
    assert(rmdir(directory) == 0);
}

int main(void) {
    for (int tcp = 0; tcp < 2; tcp++) for (int hold = 0; hold < 2; hold++) run_case(hold, tcp, 0, 0, 0, 0);
    for (int tcp = 0; tcp < 2; tcp++) { run_case(1, tcp, 1, 0, 0, 0); run_case(1, tcp, 0, 1, 0, 0); run_case(1, tcp, 0, 0, 1, 0); run_case(1, tcp, 0, 0, 0, 1); }
    puts("routing direct lease: OK");
    return test_result();
}
