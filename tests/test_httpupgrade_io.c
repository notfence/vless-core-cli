#include "check.h"
#include "tls_fixture.h"

static int fail_allocation;
void *__real_realloc(void *,size_t);
void *__wrap_realloc(void *data,size_t size) {
    if (fail_allocation) { fail_allocation=0; errno=ENOMEM; return NULL; }
    return __real_realloc(data,size);
}

static const char response[]="HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

static void fragmented(void) {
    int pair[2]; REQUIRE("httpupgrade/io-socketpair",!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    REQUIRE("httpupgrade/io-nonblocking",!fcntl(pair[0],F_SETFL,O_NONBLOCK));
    tls13_conn_t connection={.fd=pair[0],.mode=CONN_MODE_PLAIN,.httpupgrade=1,.httpupgrade_pending=1,.relay_async=1};
    uint8_t output[16]; size_t length=0;
    CHECK("httpupgrade/io-empty-read-is-not-eof",tls13_read_app(&connection,output,sizeof(output),&length)==1 && !length);
    REQUIRE("httpupgrade/io-partial-header-write",write(pair[1],response,20)==20);
    CHECK("httpupgrade/io-partial-is-not-eof",tls13_read_app(&connection,output,sizeof(output),&length)==1 && !length && connection.httpupgrade_pending);
    CHECK("httpupgrade/io-partial-does-not-spin",!tls13_has_pending_input(&connection));
    REQUIRE("httpupgrade/io-header-remainder",write(pair[1],response+20,sizeof(response)-21)==sizeof(response)-21);
    REQUIRE("httpupgrade/io-application-with-zeros",write(pair[1],"\0\0last",6)==6);
    REQUIRE("httpupgrade/io-queued-request",!db_append(&connection.xmux_wire_output,"request",7));
    tls13_set_request_fence(&connection);
    REQUIRE("httpupgrade/io-decode",!tls13_read_app(&connection,output,2,&length));
    CHECK("httpupgrade/io-last-data-retained",length==2 && !output[0] && !output[1] && tls13_has_pending_input(&connection));
    CHECK("httpupgrade/io-physical-fence-remains",tls13_request_pending(&connection));
    CHECK("httpupgrade/io-send-finish",!tls13_finish_write(&connection,0));
    CHECK("httpupgrade/io-repeat-finish-idempotent",!tls13_finish_write(&connection,0));
    CHECK("httpupgrade/io-flush",!tls13_flush(&connection) && !tls13_request_pending(&connection));
    CHECK("httpupgrade/io-physical-request",read(pair[1],output,sizeof(output))==7 && !memcmp(output,"request",7));
    CHECK("httpupgrade/io-request-fin",read(pair[1],output,sizeof(output))==0);
    REQUIRE("httpupgrade/io-peer-fin",!shutdown(pair[1],SHUT_WR));
    CHECK("httpupgrade/io-final-buffer-before-eof",!tls13_read_app(&connection,output,sizeof(output),&length) && length==4 && !memcmp(output,"last",4));
    CHECK("httpupgrade/io-header-buffer-released",!connection.ws_net_cache.data && !connection.ws_net_cache.cap);
    CHECK("httpupgrade/io-final-eof",!tls13_read_app(&connection,output,sizeof(output),&length) && !length);
    db_free(&connection.ws_net_cache); db_free(&connection.xmux_wire_output); close(pair[0]); close(pair[1]);
}

static void failures(void) {
    int pair[2]; REQUIRE("httpupgrade/fail-socketpair",!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    tls13_conn_t connection={.fd=pair[0],.mode=CONN_MODE_PLAIN,.httpupgrade=1,.httpupgrade_pending=1,.relay_async=1};
    REQUIRE("httpupgrade/fail-nonblocking",!fcntl(pair[0],F_SETFL,O_NONBLOCK));
    uint8_t output[16]; size_t length;
    fail_allocation=1;
    CHECK("httpupgrade/fail-allocation",tls13_read_app(&connection,output,sizeof(output),&length)<0 && !length && !connection.ws_net_cache.len);
    REQUIRE("httpupgrade/fail-incomplete",write(pair[1],response,20)==20);
    REQUIRE("httpupgrade/fail-peer-fin",!shutdown(pair[1],SHUT_WR));
    CHECK("httpupgrade/fail-truncated-upgrade",tls13_read_app(&connection,output,sizeof(output),&length)<0 && errno==EPROTO && !length);
    db_free(&connection.ws_net_cache); close(pair[0]); close(pair[1]);
}

static void budget(void) {
    size_t before,after; core_buffer_snapshot(CORE_BUFFER_RELAY,&before,NULL);
    core_buffer_budget_t occupied={0},memory={0};
    REQUIRE("httpupgrade/budget-holder",!core_buffer_budget_init(&occupied,CORE_BUFFER_RELAY,0));
    REQUIRE("httpupgrade/budget-input",!core_buffer_budget_init(&memory,CORE_BUFFER_RELAY,0));
    REQUIRE("httpupgrade/budget-exhaust",!core_buffer_hold(&occupied,CORE_BUFFER_TOTAL_LIMIT-before));
    tls13_conn_t connection={.fd=-1,.mode=CONN_MODE_PLAIN,.httpupgrade=1,.httpupgrade_pending=1,.relay_async=1};
    connection.ws_net_cache.memory=&memory;
    uint8_t output[16]; size_t length;
    CHECK("httpupgrade/budget-refuses-unaccounted-input",tls13_read_app(&connection,output,sizeof(output),&length)<0 && errno==ENOBUFS && !connection.ws_net_cache.cap);
    core_buffer_drop(&occupied,CORE_BUFFER_TOTAL_LIMIT-before);
    db_free(&connection.ws_net_cache);
    CHECK("httpupgrade/budget-clear-input",!core_buffer_budget_clear(&memory));
    CHECK("httpupgrade/budget-clear-holder",!core_buffer_budget_clear(&occupied));
    core_buffer_snapshot(CORE_BUFFER_RELAY,&after,NULL);
    CHECK("httpupgrade/budget-restored",after==before);
}

int main(void) { fragmented(); failures(); budget(); return test_result(); }
