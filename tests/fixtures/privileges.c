#define _GNU_SOURCE
#include <assert.h>
#include <linux/capability.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    assert(argc >= 4);
    assert(getuid() == 0);
    assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);

    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {0};
    assert(syscall(SYS_capget, &header, data) == 0);
    unsigned int mask = 1U << CAP_SYS_ADMIN;
    assert(data[0].effective & mask);
    if (strcmp(argv[1], "drop") == 0) {
        // Dropping the bounding bit prevents exec as UID 0 from regaining it.
        assert(prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0) == 0);
        data[0].effective &= ~mask;
        data[0].permitted &= ~mask;
        data[0].inheritable &= ~mask;
        assert(syscall(SYS_capset, &header, data) == 0);
    } else {
        assert(strcmp(argv[1], "keep") == 0);
    }
    if (strcmp(argv[2], "1") == 0) {
        assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    } else {
        assert(strcmp(argv[2], "0") == 0);
    }
    execvp(argv[3], argv + 3);
    perror("execvp");
    return 1;
}
