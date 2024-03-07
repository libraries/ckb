#include "utils.h"

int parent_simple_read_write() {
    int err = 0;
    const char* argv[] = {"", 0};
    uint64_t fds[2] = {0};
    uint64_t inherited_fds[3] = {0};
    err = create_std_pipes(fds, inherited_fds);
    CHECK(err);

    uint64_t pid = 0;
    spawn_args_t spgs = {.argc = 1, .argv = argv, .process_id = &pid, .inherited_fds = inherited_fds};
    err = ckb_spawn(0, CKB_SOURCE_CELL_DEP, 0, 0, &spgs);
    CHECK(err);

    // write
    uint8_t block[11] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    for (size_t i = 0; i < 7; i++) {
        size_t actual_length = 0;
        err = write_exact(fds[CKB_STDOUT], block, sizeof(block), &actual_length);
        CHECK(err);
        CHECK2(actual_length == sizeof(block), -2);
    }
    // read
    for (size_t i = 0; i < 7; i++) {
        uint8_t block[11] = {0};
        size_t actual_length = 0;
        err = read_exact(fds[CKB_STDIN], block, sizeof(block), &actual_length);
        CHECK(err);
        CHECK2(actual_length == sizeof(block), -2);
        for (size_t j = 0; j < sizeof(block); j++) {
            CHECK2(block[j] == 0xFF, -2);
        }
    }
    printf("simple_read_write case passed for parent");
exit:
    return err;
}

int child_simple_read_write() {
    int err = 0;
    uint64_t inherited_fds[2];
    size_t inherited_fds_length = 2;
    err = ckb_inherited_file_descriptors(inherited_fds, &inherited_fds_length);
    // read
    for (size_t i = 0; i < 11; i++) {
        uint8_t block[7] = {0};
        size_t actual_length = 0;
        err = read_exact(inherited_fds[CKB_STDIN], block, sizeof(block), &actual_length);
        CHECK(err);
        CHECK2(actual_length == sizeof(block), -2);
        for (size_t j = 0; j < sizeof(block); j++) {
            CHECK2(block[j] == 0xFF, -3);
        }
    }
    // write
    uint8_t block[11] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    for (size_t i = 0; i < 7; i++) {
        size_t actual_length = 0;
        err = write_exact(inherited_fds[CKB_STDOUT], block, sizeof(block), &actual_length);
        CHECK(err);
        CHECK2(actual_length == sizeof(block), -2);
    }
    printf("simple_read_write case passed for child");
exit:
    return err;
}

int parent_write_dead_lock() {
    int err = 0;
    const char* argv[] = {"", 0};
    uint64_t fds[2] = {0};
    uint64_t inherited_fds[3] = {0};
    err = create_std_pipes(fds, inherited_fds);
    CHECK(err);

    uint64_t pid = 0;
    spawn_args_t spgs = {.argc = 1, .argv = argv, .process_id = &pid, .inherited_fds = inherited_fds};
    err = ckb_spawn(0, CKB_SOURCE_CELL_DEP, 0, 0, &spgs);
    CHECK(err);
    uint8_t data[10];
    size_t data_length = sizeof(data);
    err = ckb_write(fds[CKB_STDOUT], data, &data_length);
    CHECK(err);

exit:
    return err;
}

int child_write_dead_lock() {
    int err = 0;
    uint64_t inherited_fds[3] = {0};
    size_t inherited_fds_length = 3;
    err = ckb_inherited_file_descriptors(inherited_fds, &inherited_fds_length);
    CHECK(err);
    uint8_t data[10];
    size_t data_length = sizeof(data);
    err = ckb_write(inherited_fds[CKB_STDOUT], data, &data_length);
    CHECK(err);
exit:
    return err;
}

int parent_invalid_fd() {
    uint64_t invalid_fd = 0xff;
    uint8_t data[4];
    size_t data_length = sizeof(data);
    int err = ckb_read(invalid_fd, data, &data_length);
    CHECK2(err != 0, -2);

    uint64_t fds[2] = {0};
    err = ckb_pipe(fds);
    // read on write fd
    err = ckb_read(fds[CKB_STDOUT], data, &data_length);
    CHECK2(err != 0, -3);
    // write on read fd
    err = ckb_write(fds[CKB_STDIN], data, &data_length);
    CHECK2(err != 0, -3);

    // pass fd to child to make it invalid
    const char* argv[] = {"", 0};
    uint64_t pid = 0;
    uint64_t inherited_fds[2] = {fds[0], 0};
    spawn_args_t spgs = {.argc = 1, .argv = argv, .process_id = &pid, .inherited_fds = inherited_fds};
    err = ckb_spawn(0, CKB_SOURCE_CELL_DEP, 0, 0, &spgs);
    CHECK(err);
    err = ckb_read(fds[0], data, &data_length);
    CHECK2(err != 0, -3);

    // write to fd but the other end is closed
    err = ckb_pipe(fds);
    CHECK(err);
    err = ckb_close(fds[CKB_STDIN]);
    CHECK(err);
    err = ckb_write(fds[CKB_STDOUT], data, &data_length);
    CHECK2(err == CKB_OTHER_END_CLOSED, -2);

    // read from fd but the ohter end is closed
    err = ckb_pipe(fds);
    CHECK(err);
    err = ckb_close(fds[CKB_STDOUT]);
    CHECK(err);
    err = ckb_read(fds[CKB_STDIN], data, &data_length);
    CHECK2(err == CKB_OTHER_END_CLOSED, -2);
    err = 0;
exit:
    return err;
}

int parent_entry(int case_id) {
    if (case_id == 1) {
        return parent_simple_read_write();
    } else if (case_id == 2) {
        return parent_write_dead_lock();
    } else if (case_id == 3) {
        return parent_invalid_fd();
    } else {
        return -1;
    }
}

int child_entry(int case_id) {
    if (case_id == 1) {
        return child_simple_read_write();
    } else if (case_id == 2) {
        return child_write_dead_lock();
    } else if (case_id == 3) {
        return 0;
    } else {
        return -1;
    }
}

int main(int argc, const char* argv[]) {
    uint8_t script_args[8];
    size_t script_args_length = 8;
    int err = load_script_args(script_args, &script_args_length);
    if (err) {
        return err;
    }
    int case_id = (int)script_args[0];
    if (argc > 0) {
        return child_entry(case_id);
    } else {
        return parent_entry(case_id);
    }
}
