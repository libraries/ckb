use ckb_types::{
    core::{Capacity, TransactionBuilder, capacity_bytes},
    packed::{CellInput, CellOutputBuilder, OutPoint, Script},
    prelude::*,
};
use std::collections::VecDeque;

use super::SCRIPT_VERSION;
use crate::verify::{tests::utils::*, *};

#[test]
fn check_cfi_secp256k1_ecdsa_resume() {
    let script_version = SCRIPT_VERSION;
    if script_version < ScriptVersion::V3 {
        return;
    }

    let (current_cycles_cell, current_cycles_data_hash) =
        load_cell_from_path("testdata/cfi_secp256k1_ecdsa");

    let current_cycles_script = Script::new_builder()
        .hash_type(script_version.data_hash_type())
        .code_hash(current_cycles_data_hash)
        .build();
    let output = CellOutputBuilder::default()
        .capacity(capacity_bytes!(100))
        .lock(current_cycles_script)
        .build();
    let input = CellInput::new(OutPoint::null(), 0);

    let transaction = TransactionBuilder::default().input(input).build();
    let dummy_cell = create_dummy_cell(output);

    let rtx = ResolvedTransaction {
        transaction,
        resolved_cell_deps: vec![current_cycles_cell],
        resolved_inputs: vec![dummy_cell],
        resolved_dep_groups: vec![],
    };

    let mut cycles = 0;
    let verifier = TransactionScriptsVerifierWithEnv::new();
    let step_cycles = 4096;

    verifier.verify_map(script_version, &rtx, |verifier| {
        let mut groups: VecDeque<_> = verifier.groups_with_type().collect();
        let mut tmp: Option<FullSuspendedState> = None;
        let mut current_group = None;
        let mut limit = step_cycles;

        loop {
            if let Some(cur_state) = tmp.take() {
                match verifier.verify_group_with_chunk(
                    current_group.unwrap(),
                    limit,
                    &Some(cur_state),
                ) {
                    Ok(ChunkState::Completed(used_cycles, _consumed_cycles)) => {
                        cycles += used_cycles;
                        groups.pop_front();
                        tmp = None;
                    }
                    Ok(ChunkState::Suspended(suspend_state)) => {
                        tmp = suspend_state;
                        limit += step_cycles;
                        continue;
                    }
                    Err(_error) => {
                        unreachable!();
                    }
                }
            }
            if groups.is_empty() {
                break;
            }

            while let Some((_, _, group)) = groups.front().cloned() {
                match verifier
                    .verify_group_with_chunk(group, limit, &tmp)
                    .unwrap()
                {
                    ChunkState::Completed(used_cycles, _consumed_cycles) => {
                        cycles += used_cycles;
                        groups.pop_front();
                        tmp = None;
                        if groups.front().is_some() {
                            limit = step_cycles;
                        }
                    }
                    ChunkState::Suspended(suspend_state) => {
                        if suspend_state.is_some() {
                            tmp = suspend_state;
                            current_group = Some(group);
                        } else {
                            limit += step_cycles;
                        }
                        break;
                    }
                }
            }
        }
    });
}

#[test]
fn check_vm_version() {
    let script_version = SCRIPT_VERSION;

    let (vm_version_cell, vm_version_data_hash) = load_cell_from_path("testdata/vm_version_3");

    let vm_version_script = Script::new_builder()
        .hash_type(script_version.data_hash_type())
        .code_hash(vm_version_data_hash)
        .build();
    let output = CellOutputBuilder::default()
        .capacity(capacity_bytes!(100))
        .lock(vm_version_script)
        .build();
    let input = CellInput::new(OutPoint::null(), 0);

    let transaction = TransactionBuilder::default().input(input).build();
    let dummy_cell = create_dummy_cell(output);

    let rtx = ResolvedTransaction {
        transaction,
        resolved_cell_deps: vec![vm_version_cell],
        resolved_inputs: vec![dummy_cell],
        resolved_dep_groups: vec![],
    };

    let verifier = TransactionScriptsVerifierWithEnv::new();
    let result = verifier.verify_without_limit(script_version, &rtx);
    assert_eq!(result.is_ok(), script_version == ScriptVersion::V3);
}
