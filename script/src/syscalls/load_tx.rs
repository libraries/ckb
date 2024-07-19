use crate::{
    cost_model::transferred_byte_cycles,
    syscalls::{
        utils::store_data, LOAD_TRANSACTION_SYSCALL_NUMBER, LOAD_TX_HASH_SYSCALL_NUMBER, SUCCESS,
    },
};
use ckb_types::{core::cell::ResolvedTransaction, prelude::*};
use ckb_vm::{
    registers::{A0, A7},
    Error as VMError, Register, SupportMachine, Syscalls,
};
use std::sync::Arc;

#[derive(Debug)]
pub struct LoadTx {
    rtx: Arc<ResolvedTransaction>,
}

impl LoadTx {
    pub fn new(rtx: Arc<ResolvedTransaction>) -> LoadTx {
        LoadTx { rtx }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for LoadTx {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let wrote_size = match machine.registers()[A7].to_u64() {
            LOAD_TX_HASH_SYSCALL_NUMBER => {
                // println!("{:x}", machine.pc().to_u64());
                // println!("{:?}", mem_checksum(machine.memory_mut()));
                // println!("{:x}", self.rtx.transaction.hash());
                let r = store_data(machine, self.rtx.transaction.hash().as_slice())?;
                // println!("{:?}", mem_checksum(machine.memory_mut()));
                r
            }
            LOAD_TRANSACTION_SYSCALL_NUMBER => {
                store_data(machine, self.rtx.transaction.data().as_slice())?
            }
            _ => return Ok(false),
        };

        machine.add_cycles_no_checking(transferred_byte_cycles(wrote_size))?;
        machine.set_register(A0, Mac::REG::from_u8(SUCCESS));
        Ok(true)
    }
}

use ckb_vm::Memory;
fn mem_checksum<T: Memory>(m: &mut T) -> u8 {
    let mut s = 0u8;
    for i in m.load_bytes(0, 4 * 1024 * 1024).unwrap().to_vec() {
        s = s.wrapping_add(i);
    }
    return s;
}
