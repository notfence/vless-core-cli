#include "check.h"
#include "tls_fixture.h"
#include <dirent.h>

static uint64_t clock_ms;
static int lock_probe,lock_attempts,lock_interrupt,blocking_attempts,expire_commit;
uint64_t __real_core_now_ms(void);
int __real_poll(struct pollfd *,nfds_t,int);
int __real_flock(int,int);
int __real_fsync(int);
uint64_t __wrap_core_now_ms(void) { return clock_ms ? clock_ms : __real_core_now_ms(); }
int __wrap_poll(struct pollfd *fds,nfds_t count,int timeout) {
    if (!clock_ms || count) return __real_poll(fds,count,timeout);
    clock_ms+=(unsigned)(timeout > 0 ? timeout : 0); return 0;
}
int __wrap_flock(int fd,int operation) {
    if (lock_probe && (operation&LOCK_EX)) {
        lock_attempts++;
        if (!(operation&LOCK_NB)) { blocking_attempts++; errno=EWOULDBLOCK; return -1; }
        if (lock_interrupt) { lock_interrupt=0; clock_ms+=2; errno=EINTR; return -1; }
        if (lock_probe < 0 || lock_attempts < lock_probe) { errno=EWOULDBLOCK; return -1; }
    }
    return __real_flock(fd,operation);
}
int __wrap_fsync(int fd) {
    int result=__real_fsync(fd);
    if (expire_commit) { clock_ms+=100; expire_commit=0; }
    return result;
}
static void *unlock_later(void *opaque) {
    int fd=(int)(intptr_t)opaque;
    (void)__real_poll(NULL,0,100); (void)__real_flock(fd,LOCK_UN); return NULL;
}
int main(void) {
    const char *root=getenv("TEST_PRIVATE_ROOT"); REQUIRE("tofu-deadline/private-root",root != NULL);
    char path[PATH_MAX],lock_path[PATH_MAX],pin[65],error[256];
    snprintf(path,sizeof(path),"%s/deadline-pins",root); snprintf(lock_path,sizeof(lock_path),"%s/deadline-pins.lock",root);
    memset(pin,'a',64); pin[64]=0; setenv("VLESS_XHTTP_PIN_FILE",path,1);
    core_deadline_t deadline; REQUIRE("tofu-deadline/attach",core_deadline_attach(&deadline) == 0);
    clock_ms=1000; core_deadline_begin(35); lock_probe=-1; lock_attempts=blocking_attempts=0; int stored=-1;
    int result=secure_tofu_verify_or_store("vless-core.test:443",pin,&stored,error,sizeof(error));
    CHECK("tofu-deadline/contention-expires",result < 0 && errno == ETIMEDOUT && clock_ms == 1035);
    CHECK("tofu-deadline/no-blocking-lock",!blocking_attempts);
    CHECK("tofu-deadline/timeout-no-pin",access(path,F_OK) != 0 && stored == -1);
    CHECK("tofu-deadline/original-budget-preserved",deadline.active && deadline.until_ms == 1035);
    clock_ms=2000; core_deadline_begin(100); lock_probe=4; lock_attempts=0; lock_interrupt=1; error[0]=0;
    CHECK("tofu-deadline/release-and-eintr-recovers",secure_tofu_verify_or_store("vless-core.test:443",pin,&stored,error,sizeof(error)) == 0 && stored == 1 && lock_attempts == 4 && clock_ms < 2100);
    lock_probe=0; clock_ms=3000; core_deadline_begin(1); clock_ms=3001;
    CHECK("tofu-deadline/expired-before-lock",secure_tofu_verify_or_store("new.test:443",pin,&stored,error,sizeof(error)) < 0 && errno == ETIMEDOUT);
    clock_ms=4000; core_deadline_begin(50); expire_commit=1;
    CHECK("tofu-deadline/expired-before-rename",secure_tofu_verify_or_store("new.test:443",pin,&stored,error,sizeof(error)) < 0 && errno == ETIMEDOUT);
    int fd=open(path,O_RDONLY); char existing[65];
    REQUIRE("tofu-deadline/old-pin-readable",fd >= 0);
    CHECK("tofu-deadline/old-pin-preserved",find_pin_in_fd(fd,"vless-core.test:443",existing) == 0 && !strcmp(existing,pin));
    CHECK("tofu-deadline/new-pin-not-committed",find_pin_in_fd(fd,"new.test:443",existing) == 1); close(fd);
    DIR *directory=opendir(root); REQUIRE("tofu-deadline/temporary-directory",directory != NULL);
    struct dirent *entry; int temporary=0;
    while ((entry=readdir(directory))) if (!strncmp(entry->d_name,"deadline-pins.tmp.",18)) temporary++;
    closedir(directory); CHECK("tofu-deadline/temporary-files-cleaned",temporary == 0);
    core_deadline_end(); clock_ms=5000; lock_probe=-1; lock_attempts=0;
    CHECK("tofu-deadline/fallback-bounded-at-12s",secure_tofu_verify_or_store("new.test:443",pin,&stored,error,sizeof(error)) < 0 && errno == ETIMEDOUT && clock_ms == 17000 && !deadline.active);
    lock_probe=0; clock_ms=0;
    int holder=open(lock_path,O_RDWR); REQUIRE("tofu-deadline/real-lock",holder >= 0 && __real_flock(holder,LOCK_EX) == 0);
    pthread_t release; REQUIRE("tofu-deadline/real-release-worker",pthread_create(&release,NULL,unlock_later,(void *)(intptr_t)holder) == 0);
    core_deadline_begin(25);
    CHECK("tofu-deadline/real-contention-respects-budget",secure_tofu_verify_or_store("real.test:443",pin,&stored,error,sizeof(error)) < 0 && errno == ETIMEDOUT);
    REQUIRE("tofu-deadline/real-release-joined",pthread_join(release,NULL) == 0); close(holder); core_deadline_end();
    CHECK("tofu-deadline/after-contention-reconnect",secure_tofu_verify_or_store("real.test:443",pin,&stored,error,sizeof(error)) == 0 && stored == 1);
    core_deadline_detach(); return test_result();
}
