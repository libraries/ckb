use crate::syscalls::FD;
use crate::types::{FdArgs, Message, VmId};
use ckb_vm::{
    registers::{A0, A7},
    Error as VMError, Register, SupportMachine, Syscalls,
};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Fd {
    id: VmId,
    message_box: Arc<Mutex<Vec<Message>>>,
}

impl Fd {
    pub fn new(id: VmId, message_box: Arc<Mutex<Vec<Message>>>) -> Self {
        Self { id, message_box }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for Fd {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        if machine.registers()[A7].to_u64() != FD {
            return Ok(false);
        }
        let fd1_addr = machine.registers()[A0].to_u64();
        let fd2_addr = fd1_addr.wrapping_add(8);
        self.message_box
            .lock()
            .map_err(|e| VMError::Unexpected(e.to_string()))?
            .push(Message::Fd(self.id, FdArgs { fd1_addr, fd2_addr }));
        Err(VMError::External("YIELD".to_string()))
    }
}
