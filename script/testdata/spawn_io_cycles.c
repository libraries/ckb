#include <stdint.h>
#include <string.h>

#include "ckb_syscalls.h"
#include "spawn_utils.h"

const uint64_t SYSCALL_CYCLES_BASE = 500;
const uint64_t SPAWN_EXTRA_CYCLES_BASE = 100000;
const uint64_t SPAWN_YIELD_CYCLES_BASE = 800;

int tic() {
    static uint64_t tic = 0;
    uint64_t cur_cycles = ckb_current_cycles();
    uint64_t toc = cur_cycles - tic;
    tic = cur_cycles;
    return toc;
}

uint64_t cal_cycles(uint64_t nbase, uint64_t yield, uint64_t extra) {
    uint64_t r = 0;
    r += SYSCALL_CYCLES_BASE * nbase;
    r += SPAWN_YIELD_CYCLES_BASE * yield;
    r += SPAWN_EXTRA_CYCLES_BASE * extra;
    return r;
}

uint64_t cal_cycles_floor(uint64_t nbase, uint64_t yield, uint64_t extra) {
    return cal_cycles(nbase, yield, extra);
}

uint64_t cal_cycles_upper(uint64_t nbase, uint64_t yield, uint64_t extra) {
    return cal_cycles(nbase, yield, extra) + 8192;
}

#define BUFFER_SIZE 1024 * 4

typedef struct {
    uint64_t io_size;
    bool check_buffer;
} ScriptArgs;

int parent(ScriptArgs* args, uint8_t* buffer) {
    int err = 0;
    const char* argv[] = {"", 0};
    uint64_t fds[2] = {0};
    uint64_t pid = 0;
    err = full_spawn(0, 1, argv, fds, &pid);
    CHECK(err);

    uint64_t buf_len = args->io_size;

    err = ckb_read(fds[CKB_STDIN], buffer, &buf_len);
    CHECK(err);
    CHECK2(buf_len == args->io_size, -1);
    if (args->check_buffer) {
        for (size_t i = 0; i < args->io_size; i++)
            CHECK2(buffer[i] == (uint8_t)i, -1);
    }

    int8_t exit_code = 0;
    err = ckb_wait(pid, &exit_code);
    CHECK(err);
    CHECK(exit_code);

exit:
    return err;
}

int child(ScriptArgs* args, uint8_t* buffer) {
    int err = 0;
    uint64_t inherited_fds[2];
    size_t inherited_fds_length = 2;
    err = ckb_inherited_file_descriptors(inherited_fds, &inherited_fds_length);
    CHECK(err);

    uint64_t buf_len = args->io_size;

    if (args->check_buffer) {
        for (size_t i = 0; i < args->io_size; i++) buffer[i] = i;
    }

    err = ckb_write(inherited_fds[CKB_STDOUT], buffer, &buf_len);

    CHECK(err);
    CHECK2(buf_len == args->io_size, -1);
exit:
    return err;
}

int main() {
    int err = 0;
    ScriptArgs script_args;
    size_t script_args_length = sizeof(script_args);
    err = load_script_args((uint8_t*)&script_args, &script_args_length);
    CHECK(err);
    CHECK2(script_args_length == sizeof(script_args), -1);

    uint64_t cid = ckb_process_id();
    uint8_t buffer[BUFFER_SIZE] = {0};

    if (cid == 0) {
        return parent(&script_args, buffer);
    } else {
        return child(&script_args, buffer);
    }

exit:
    return err;
}
