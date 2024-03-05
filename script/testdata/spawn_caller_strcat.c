#include <stdint.h>
#include <string.h>

#include "ckb_syscalls.h"
#include "utils.h"

int main() {
    int err = 0;
    const char *argv[] = {"hello", "world"};
    uint64_t pid = 0;
    uint64_t to_child[2] = {0};
    uint64_t to_parent[2] = {0};

    err = ckb_pipe(to_child);
    CHECK(err);
    err = ckb_pipe(to_parent);
    CHECK(err);

    uint64_t inherited_fds[2] = {to_child[0], to_parent[1]};
    spawn_args_t spgs = {
        .argc = 2,
        .argv = argv,
        .process_id = &pid,
        .inherited_fds = inherited_fds,
    };
    err = ckb_spawn(1, 3, 0, 0, &spgs);
    CHECK(err);
    uint8_t buffer[1024] = {0};
    size_t length = 1024;
    err = ckb_read(to_parent[0], buffer, &length);
    CHECK(err);
    err = memcmp("helloworld", buffer, length);
    CHECK(err);

exit:
    return err;
}
