use crate::cost_model::transferred_byte_cycles;
use crate::syscalls::utils::load_c_string;
use crate::syscalls::{INDEX_OUT_OF_BOUND, SLICE_OUT_OF_BOUND, SPAWN, SPAWN_EXTRA_CYCLES_BASE};
use crate::v2_types::{DataPieceId, Message, PipeId, SpawnArgs, TxData, VmId};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_vm::{
    machine::SupportMachine,
    memory::Memory,
    registers::{A0, A1, A2, A3, A4, A7},
    snapshot2::{DataSource, Snapshot2Context},
    syscalls::Syscalls,
    Error as VMError, Register,
};
use std::sync::{Arc, Mutex};

pub struct Spawn<DL>
where
    DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
{
    id: VmId,
    message_box: Arc<Mutex<Vec<Message>>>,
    snapshot2_context: Arc<Mutex<Snapshot2Context<DataPieceId, TxData<DL>>>>,
}

impl<DL> Spawn<DL>
where
    DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
{
    pub fn new(
        id: VmId,
        message_box: Arc<Mutex<Vec<Message>>>,
        snapshot2_context: Arc<Mutex<Snapshot2Context<DataPieceId, TxData<DL>>>>,
    ) -> Self {
        Self {
            id,
            message_box,
            snapshot2_context,
        }
    }
}

impl<Mac, DL> Syscalls<Mac> for Spawn<DL>
where
    Mac: SupportMachine,
    DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
{
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        if machine.registers()[A7].to_u64() != SPAWN {
            return Ok(false);
        }
        let index = machine.registers()[A0].to_u64();
        let source = machine.registers()[A1].to_u64();
        let place = machine.registers()[A2].to_u64();
        let data_piece_id = match DataPieceId::try_from((source, index, place)) {
            Ok(id) => id,
            Err(_) => {
                machine.set_register(A0, Mac::REG::from_u8(INDEX_OUT_OF_BOUND));
                return Ok(true);
            }
        };
        let bounds = machine.registers()[A3].to_u64();
        let offset = bounds >> 32;
        let length = bounds as u32 as u64;
        let spgs_addr = machine.registers()[A4].to_u64();
        let argc_addr = spgs_addr;
        let argc = machine
            .memory_mut()
            .load64(&Mac::REG::from_u64(argc_addr))?
            .to_u64();
        let argv_addr_addr = spgs_addr.wrapping_add(8);
        let argv_addr = machine
            .memory_mut()
            .load64(&Mac::REG::from_u64(argv_addr_addr))?
            .to_u64();
        let mut addr = argv_addr;
        let mut argv = Vec::new();
        for _ in 0..argc {
            let target_addr = machine
                .memory_mut()
                .load64(&Mac::REG::from_u64(addr))?
                .to_u64();
            let cstr = load_c_string(machine, target_addr)?;
            argv.push(cstr);
            addr = addr.wrapping_add(8);
        }

        let process_id_addr_addr = spgs_addr.wrapping_add(16);
        let process_id_addr = machine
            .memory_mut()
            .load64(&Mac::REG::from_u64(process_id_addr_addr))?
            .to_u64();
        let pipes_addr_addr = spgs_addr.wrapping_add(24);
        let mut pipes_addr = machine
            .memory_mut()
            .load64(&Mac::REG::from_u64(pipes_addr_addr))?
            .to_u64();

        let mut pipes = vec![];
        if pipes_addr != 0 {
            loop {
                let pipe = machine
                    .memory_mut()
                    .load64(&Mac::REG::from_u64(pipes_addr))?
                    .to_u64();
                if pipe == 0 {
                    break;
                }
                pipes.push(PipeId(pipe));
                pipes_addr += 8;
            }
        }

        // We are fetching the actual cell here for some in-place validation
        let sc = self
            .snapshot2_context
            .lock()
            .map_err(|e| VMError::Unexpected(e.to_string()))?;
        let (_, full_length) = match sc.data_source().load_data(&data_piece_id, 0, 0) {
            Ok(val) => val,
            Err(VMError::External(m)) if m == "INDEX_OUT_OF_BOUND" => {
                // This comes from TxData results in an out of bound error, to
                // mimic current behavior, we would return INDEX_OUT_OF_BOUND error.
                machine.set_register(A0, Mac::REG::from_u8(INDEX_OUT_OF_BOUND));
                return Ok(true);
            }
            Err(e) => return Err(e),
        };
        if offset >= full_length {
            machine.set_register(A0, Mac::REG::from_u8(SLICE_OUT_OF_BOUND));
            return Ok(true);
        }
        if length > 0 {
            let end = offset.checked_add(length).ok_or(VMError::MemOutOfBound)?;
            if end > full_length {
                machine.set_register(A0, Mac::REG::from_u8(SLICE_OUT_OF_BOUND));
                return Ok(true);
            }
        }
        machine.add_cycles_no_checking(SPAWN_EXTRA_CYCLES_BASE)?;
        machine.add_cycles_no_checking(transferred_byte_cycles(full_length))?;
        self.message_box
            .lock()
            .map_err(|e| VMError::Unexpected(e.to_string()))?
            .push(Message::Spawn(
                self.id,
                SpawnArgs {
                    data_piece_id,
                    offset,
                    length,
                    argv,
                    pipes,
                    process_id_addr,
                },
            ));
        Err(VMError::External("YIELD".to_string()))
    }
}
