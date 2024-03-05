#include <stdint.h>
#include <string.h>

#include "ckb_syscalls.h"
#include "utils.h"

int main(int argc, char *argv[]) {
    int err = 0;
    char content[80];
    for (int i = 0; i < argc; i++) {
        strcat(content, argv[i]);
    }
    uint64_t content_size = (uint64_t)strlen(content);
    uint64_t fds[2] = {0};
    uint64_t length = countof(fds);
    err = ckb_inherited_file_descriptors(fds, &length);
    CHECK(err);
    CHECK2(length == 2, 1);
    err = ckb_write(fds[CKB_STDOUT], content, content_size);
    CHECK(err);
exit:
    return err;
}

