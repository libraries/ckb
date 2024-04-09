#define CKB_C_STDLIB_PRINTF 1
#include <ckb_syscalls.h>
#include <stdio.h>

#include "spawn_dag.h"
#include "spawn_dag_escape_encoding.h"
#include "ckb_syscalls.h"

#define INPUT_DATA_LENGTH (600 * 1024)
#define MAX_FD_COUNT 3200
#define MAX_SPAWNED_VMS 1024

#define _BASE_ERROR_CODE 42
#define ERROR_NO_SPACE_FOR_FDS (_BASE_ERROR_CODE + 1)
#define ERROR_NOT_FOUND (_BASE_ERROR_CODE + 2)
#define ERROR_ENCODING (_BASE_ERROR_CODE + 3)
#define ERROR_ARGV (_BASE_ERROR_CODE + 4)
#define ERROR_TOO_MANY_SPAWNS (_BASE_ERROR_CODE + 5)
#define ERROR_FD_CLOSED (_BASE_ERROR_CODE + 6)
#define ERROR_CORRUPTED_DATA (_BASE_ERROR_CODE + 7)

typedef struct {
    uint64_t indices[MAX_FD_COUNT];
    uint64_t ids[MAX_FD_COUNT + 1];
    size_t used;
} fds_t;

void fds_init(fds_t *fds) {
    fds->used = 0;
    fds->ids[fds->used] = 0;
}

int fds_add(fds_t *fds, uint64_t index, uint64_t id) {
    if (fds->used >= MAX_FD_COUNT) {
        return ERROR_NO_SPACE_FOR_FDS;
    }
    fds->indices[fds->used] = index;
    fds->ids[fds->used] = id;
    fds->used++;
    fds->ids[fds->used] = 0;
    return CKB_SUCCESS;
}

int fds_find(const fds_t *fds, uint64_t index, uint64_t *id) {
    for (size_t i = 0; i < fds->used; i++) {
        if (fds->indices[i] == index) {
            *id = fds->ids[i];
            return CKB_SUCCESS;
        }
    }
    return ERROR_NOT_FOUND;
}

int main(int argc, char *argv[]) {
    uint8_t data_buffer[INPUT_DATA_LENGTH];
    fds_t current_fds;
    fds_init(&current_fds);

    uint64_t data_length = INPUT_DATA_LENGTH;
    int ret = ckb_load_witness(data_buffer, &data_length, 0, 0, CKB_SOURCE_INPUT);
    if (ret != CKB_SUCCESS) {
        return ret;
    }
    mol_seg_t data_seg;
    data_seg.ptr = data_buffer;
    data_seg.size = data_length;

    if (MolReader_Data_verify(&data_seg, false) != MOL_OK) {
        return ERROR_ENCODING;
    }

    mol_seg_t spawns_seg = MolReader_Data_get_spawns(&data_seg);
    uint64_t vm_index = 0;
    if (argc != 0) {
        // For spawned VMs, read current VM index and passed fds from argv
        if (argc != 2) {
            return ERROR_ARGV;
        }

        uint64_t decoded_length = 0;
        ret = ee_decode_char_string_in_place(argv[0], &decoded_length);
        if (ret != 0) {
            return ret;
        }
        if (decoded_length != 8) {
            return ERROR_ARGV;
        }
        vm_index = *((uint64_t *)argv[0]);

        int spawn_found = 0;
        mol_seg_t spawn_seg;
        for (mol_num_t i = 0; i < MolReader_Spawns_length(&spawns_seg); i++) {
            mol_seg_res_t spawn_res = MolReader_Spawns_get(&spawns_seg, i);
            if (spawn_res.errno != MOL_OK) {
                return ERROR_ENCODING;
            }
            mol_seg_t child_seg = MolReader_Spawn_get_child(&spawn_res.seg);
            uint64_t child_index = *((uint64_t *)child_seg.ptr);
            if (child_index == vm_index) {
                spawn_seg = spawn_res.seg;
                spawn_found = 1;
                break;
            }
        }
        if (spawn_found == 0) {
            return ERROR_ARGV;
        }
        mol_seg_t passed_fds_seg = MolReader_Spawn_get_fds(&spawn_seg);

        decoded_length = 0;
        ret = ee_decode_char_string_in_place(argv[1], &decoded_length);
        if (ret != 0) {
            return ret;
        }
        if (decoded_length != MolReader_FdIndices_length(&passed_fds_seg) * 8) {
            return ERROR_ARGV;
        }
        for (mol_num_t i = 0; i < MolReader_FdIndices_length(&passed_fds_seg); i++) {
            mol_seg_res_t fd_res = MolReader_FdIndices_get(&passed_fds_seg, i);
            if (fd_res.errno != MOL_OK) {
                return ERROR_ENCODING;
            }
            uint64_t fd_index = *((uint64_t *)fd_res.seg.ptr);
            uint64_t fd_id = *((uint64_t *)&argv[1][i * 8]);

            ret = fds_add(&current_fds, fd_index, fd_id);
            if (ret != 0) {
                return ret;
            }
        }
    }

    // Create new fds that should be created from current VM
    mol_seg_t fds_seg = MolReader_Data_get_fds(&data_seg);
    for (mol_num_t i = 0; i < MolReader_Fds_length(&fds_seg); i++) {
        mol_seg_res_t fd_pair_res = MolReader_Fds_get(&fds_seg, i);
        if (fd_pair_res.errno != MOL_OK) {
            return ERROR_ENCODING;
        }
        mol_seg_t fd_pair_seg = fd_pair_res.seg;

        uint64_t pair_vm_index = *((uint64_t *)MolReader_Fd_get_vm(&fd_pair_seg).ptr);
        if (pair_vm_index == vm_index) {
            uint64_t read_index = *((uint64_t *)MolReader_Fd_get_read_fd(&fd_pair_seg).ptr);
            uint64_t write_index = *((uint64_t *)MolReader_Fd_get_write_fd(&fd_pair_seg).ptr);

            uint64_t fildes[2];
            ret = ckb_pipe(fildes);
            if (ret != 0) {
                return ret;
            }
            ret = fds_add(&current_fds, read_index, fildes[0]);
            if (ret != 0) {
                return ret;
            }
            ret = fds_add(&current_fds, write_index, fildes[1]);
            if (ret != 0) {
                return ret;
            }
        }
    }

    uint64_t spawned_vms[MAX_SPAWNED_VMS];
    size_t spawned_count = 0;

    // Issue spawn syscalls for child VMs
    for (mol_num_t i = 0; i < MolReader_Spawns_length(&spawns_seg); i++) {
        mol_seg_res_t spawn_res = MolReader_Spawns_get(&spawns_seg, i);
        if (spawn_res.errno != MOL_OK) {
            return ERROR_ENCODING;
        }
        mol_seg_t spawn_seg = spawn_res.seg;

        uint64_t from_index = *((uint64_t *)MolReader_Spawn_get_from(&spawn_seg).ptr);
        if (from_index == vm_index) {
            if (spawned_count >= MAX_SPAWNED_VMS) {
                return ERROR_TOO_MANY_SPAWNS;
            }

            uint64_t child_index = *((uint64_t *)MolReader_Spawn_get_child(&spawn_seg).ptr);

            fds_t passed_fds;
            fds_init(&passed_fds);

            mol_seg_t fd_indices = MolReader_Spawn_get_fds(&spawn_seg);
            for (mol_num_t i = 0; i < MolReader_FdIndices_length(&fd_indices); i++) {
                mol_seg_res_t index_res = MolReader_FdIndices_get(&fd_indices, i);
                if (index_res.errno != MOL_OK) {
                    return ERROR_ENCODING;
                }
                mol_seg_t index_seg = index_res.seg;
                uint64_t index = *((uint64_t *)index_seg.ptr);

                uint64_t id = 0;
                ret = fds_find(&current_fds, index, &id);
                if (ret != 0) {
                    return ret;
                }

                ret = fds_add(&passed_fds, index, id);
                if (ret != 0) {
                    return ret;
                }
            }

            size_t src_len = 8;
            size_t dst_len = ee_maximum_encoding_length(src_len);
            uint8_t encoded_child_index[dst_len + 1];
            ret = ee_encode(encoded_child_index, &dst_len, (const uint8_t *)&child_index, &src_len);
            if (ret != 0) {
                return ret;
            }
            encoded_child_index[dst_len] = '\0';

            src_len = passed_fds.used * 8;
            dst_len = ee_maximum_encoding_length(src_len);
            uint8_t encoded_ids[dst_len + 1];
            ret = ee_encode(encoded_ids, &dst_len, (const uint8_t *)passed_fds.ids, &src_len);
            if (ret != 0) {
                return ret;
            }
            encoded_ids[dst_len] = '\0';

            const char *argv[2] = {(char *)encoded_child_index, (char *)encoded_ids};
            spawn_args_t sargs;
            sargs.argc = 2;
            sargs.argv = argv;
            sargs.process_id = &spawned_vms[spawned_count++];
            sargs.inherited_fds = (const uint64_t *)passed_fds.ids;

            ret = ckb_spawn(0, CKB_SOURCE_CELL_DEP, 0, 0, &sargs);
            if (ret != 0) {
                return ret;
            }
        }
    }

    // Process all reads & writes
    mol_seg_t writes_seg = MolReader_Data_get_writes(&data_seg);
    for (mol_num_t i = 0; i < MolReader_Writes_length(&writes_seg); i++) {
        mol_seg_res_t write_res = MolReader_Writes_get(&writes_seg, i);
        if (write_res.errno != MOL_OK) {
            return ERROR_ENCODING;
        }
        mol_seg_t write_seg = write_res.seg;

        uint64_t from = *((uint64_t *)MolReader_Write_get_from(&write_seg).ptr);
        uint64_t to = *((uint64_t *)MolReader_Write_get_to(&write_seg).ptr);

        if (from == vm_index) {
            // Write data
            uint64_t from_fd = *((uint64_t *)MolReader_Write_get_from_fd(&write_seg).ptr);
            mol_seg_t data_seg = MolReader_Write_get_data(&write_seg);

            uint64_t fd_id = 0;
            ret = fds_find(&current_fds, from_fd, &fd_id);
            if (ret != 0) {
                return ret;
            }

            uint32_t written = 0;
            while (written < data_seg.size) {
                size_t length = data_seg.size - written;
                ret = ckb_write(fd_id, &data_seg.ptr[written], &length);
                if (ret != 0) {
                    return ret;
                }
                if (length == 0) {
                    return ERROR_FD_CLOSED;
                }
                written += length;
            }
        } else if (to == vm_index) {
            // Read data
            uint64_t to_fd = *((uint64_t *)MolReader_Write_get_to_fd(&write_seg).ptr);
            mol_seg_t data_seg = MolReader_Write_get_data(&write_seg);

            uint64_t fd_id = 0;
            ret = fds_find(&current_fds, to_fd, &fd_id);
            if (ret != 0) {
                return ret;
            }

            uint32_t read = 0;
            while (read < data_seg.size) {
                size_t length = data_seg.size - read;
                uint8_t data[length];
                memset(data, 0, length);
                ret = ckb_read(fd_id, data, &length);
                if (ret != 0) {
                    return ret;
                }
                if (length == 0) {
                    return ERROR_FD_CLOSED;
                }
                if (memcmp(&data_seg.ptr[read], data, length) != 0) {
                    return ERROR_CORRUPTED_DATA;
                }
                read += length;
            }
        }
    }

    // Join all spawned VMs
    for (size_t i = 0; i < spawned_count; i++) {
        size_t j = spawned_count - i - 1;
        int8_t exit_code = 0xFF;
        ret = ckb_wait(spawned_vms[j], &exit_code);
        if (ret != 0) {
            return ret;
        }
        if (exit_code != 0) {
            return exit_code;
        }
    }

    return 0;
}
