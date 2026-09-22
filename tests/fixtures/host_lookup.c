#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Delay only the supervisor's lookup, never the managed application's libc. */
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **result) {
    int (*native)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
    native = dlsym(RTLD_NEXT, "getaddrinfo");
    if (!native) return EAI_SYSTEM;
    const char *owner = getenv("SCPROXY_TEST_RESOLVER_PID");
    if (owner && getpid() == atoi(owner) && node && strcmp(node, "slow-direct.invalid") == 0) {
        const char *ready = getenv("SCPROXY_TEST_RESOLVER_READY");
        const char *release = getenv("SCPROXY_TEST_RESOLVER_RELEASE");
        if (!ready || !release) return EAI_SYSTEM;
        int fd = open(ready, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) return EAI_SYSTEM;
        close(fd);
        while (access(release, F_OK) != 0) usleep(1000);
        const char *mode = getenv("SCPROXY_TEST_MODE");
        if (mode && strcmp(mode, "failure") == 0) return EAI_NONAME;
        return native("127.0.0.1", service, hints, result);
    }
    return native(node, service, hints, result);
}
