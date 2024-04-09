#include <stdint.h>

#include "ckb_syscalls.h"
#include "spawn_utils.h"

int main() {
    int err = 0;
    uint64_t fd[2] = {0};
    for (int i = 0; i < 32; i++) {
        err = ckb_pipe(fd);
        CHECK(err);
    }
    // Create up to 64 fds.
    err = ckb_pipe(fd);
    err = err - 9;

exit:
    return err;
}
