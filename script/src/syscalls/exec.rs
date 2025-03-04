use crate::cost_model::transferred_byte_cycles;
use crate::syscalls::{
    Place, Source, SourceEntry, EXEC, INDEX_OUT_OF_BOUND, MAX_ARGV_LENGTH, SLICE_OUT_OF_BOUND,
    WRONG_FORMAT,
};
use crate::types::SgData;
use ckb_traits::CellDataProvider;
use ckb_types::core::cell::CellMeta;
use ckb_types::core::error::ARGV_TOO_LONG_TEXT;
use ckb_types::packed::{Bytes as PackedBytes, BytesVec};
use ckb_vm::memory::load_c_string_byte_by_byte;
use ckb_vm::Memory;
use ckb_vm::{
    registers::{A0, A1, A2, A3, A4, A5, A7},
    Error as VMError, Register, SupportMachine, Syscalls,
};
use ckb_vm::{DEFAULT_STACK_SIZE, RISCV_MAX_MEMORY};

#[derive(Debug)]
pub struct Exec<DL> {
    sg_data: SgData<DL>,
}

impl<DL: CellDataProvider + Clone> Exec<DL> {
    pub fn new(sg_data: &SgData<DL>) -> Exec<DL> {
        Exec {
            sg_data: sg_data.clone(),
        }
    }

    #[inline]
    fn resolved_inputs(&self) -> &Vec<CellMeta> {
        &self.sg_data.rtx.resolved_inputs
    }

    #[inline]
    fn resolved_cell_deps(&self) -> &Vec<CellMeta> {
        &self.sg_data.rtx.resolved_cell_deps
    }

    #[inline]
    fn witnesses(&self) -> BytesVec {
        self.sg_data.rtx.transaction.witnesses()
    }

    fn fetch_cell(&self, source: Source, index: usize) -> Result<&CellMeta, u8> {
        let cell_opt = match source {
            Source::Transaction(SourceEntry::Input) => self.resolved_inputs().get(index),
            Source::Transaction(SourceEntry::Output) => self.sg_data.outputs().get(index),
            Source::Transaction(SourceEntry::CellDep) => self.resolved_cell_deps().get(index),
            Source::Group(SourceEntry::Input) => self
                .sg_data
                .group_inputs()
                .get(index)
                .and_then(|actual_index| self.resolved_inputs().get(*actual_index)),
            Source::Group(SourceEntry::Output) => self
                .sg_data
                .group_outputs()
                .get(index)
                .and_then(|actual_index| self.sg_data.outputs().get(*actual_index)),
            Source::Transaction(SourceEntry::HeaderDep)
            | Source::Group(SourceEntry::CellDep)
            | Source::Group(SourceEntry::HeaderDep) => {
                return Err(INDEX_OUT_OF_BOUND);
            }
        };

        cell_opt.ok_or(INDEX_OUT_OF_BOUND)
    }

    fn fetch_witness(&self, source: Source, index: usize) -> Result<PackedBytes, u8> {
        let witness_opt = match source {
            Source::Group(SourceEntry::Input) => self
                .sg_data
                .group_inputs()
                .get(index)
                .and_then(|actual_index| self.witnesses().get(*actual_index)),
            Source::Group(SourceEntry::Output) => self
                .sg_data
                .group_outputs()
                .get(index)
                .and_then(|actual_index| self.witnesses().get(*actual_index)),
            Source::Transaction(SourceEntry::Input) => self.witnesses().get(index),
            Source::Transaction(SourceEntry::Output) => self.witnesses().get(index),
            _ => {
                return Err(INDEX_OUT_OF_BOUND);
            }
        };

        witness_opt.ok_or(INDEX_OUT_OF_BOUND)
    }
}

impl<Mac: SupportMachine, DL: CellDataProvider + Send + Sync + Clone> Syscalls<Mac> for Exec<DL> {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        if machine.registers()[A7].to_u64() != EXEC {
            return Ok(false);
        }
        let index = machine.registers()[A0].to_u64();
        let source = Source::parse_from_u64(machine.registers()[A1].to_u64())?;
        let place = Place::parse_from_u64(machine.registers()[A2].to_u64())?;
        let bounds = machine.registers()[A3].to_u64();
        let offset = (bounds >> 32) as usize;
        let length = bounds as u32 as usize;

        let data = match place {
            Place::CellData => {
                let cell = self.fetch_cell(source, index as usize);
                if let Err(err) = cell {
                    machine.set_register(A0, Mac::REG::from_u8(err));
                    return Ok(true);
                }
                let cell = cell.unwrap();
                self.sg_data
                    .data_loader()
                    .load_cell_data(cell)
                    .ok_or_else(|| {
                        VMError::Unexpected(format!(
                            "Unexpected load_cell_data failed {}",
                            cell.out_point,
                        ))
                    })?
            }
            Place::Witness => {
                let witness = self.fetch_witness(source, index as usize);
                if let Err(err) = witness {
                    machine.set_register(A0, Mac::REG::from_u8(err));
                    return Ok(true);
                }
                let witness = witness.unwrap();
                witness.raw_data()
            }
        };
        let data_size = data.len();
        if offset >= data_size {
            machine.set_register(A0, Mac::REG::from_u8(SLICE_OUT_OF_BOUND));
            return Ok(true);
        };
        let data = if length == 0 {
            data.slice(offset..data_size)
        } else {
            // Both offset and length are <= u32::MAX, so offset.checked_add(length) will be always a Some.
            let end = offset.checked_add(length).ok_or(VMError::MemOutOfBound)?;
            if end > data_size {
                machine.set_register(A0, Mac::REG::from_u8(SLICE_OUT_OF_BOUND));
                return Ok(true);
            }
            data.slice(offset..end)
        };
        let argc = machine.registers()[A4].to_u64();
        let mut addr = machine.registers()[A5].to_u64();
        let mut argv = Vec::new();
        let mut argv_length: u64 = 0;
        for _ in 0..argc {
            let target_addr = machine.memory_mut().load64(&Mac::REG::from_u64(addr))?;
            let cstr = load_c_string_byte_by_byte(machine.memory_mut(), &target_addr)?;
            let cstr_len = cstr.len();
            argv.push(cstr);

            // Number of argv entries should also be considered
            argv_length = argv_length
                .saturating_add(8)
                .saturating_add(cstr_len as u64);
            if argv_length > MAX_ARGV_LENGTH {
                return Err(VMError::Unexpected(ARGV_TOO_LONG_TEXT.to_string()));
            }

            addr += 8;
        }

        let cycles = machine.cycles();
        let max_cycles = machine.max_cycles();
        machine.reset(max_cycles);
        machine.set_cycles(cycles);

        match machine.load_elf(&data, true) {
            Ok(size) => {
                machine.add_cycles_no_checking(transferred_byte_cycles(size))?;
            }
            Err(_) => {
                machine.set_register(A0, Mac::REG::from_u8(WRONG_FORMAT));
                return Ok(true);
            }
        }

        match machine.initialize_stack(
            argv.into_iter().map(Ok),
            (RISCV_MAX_MEMORY - DEFAULT_STACK_SIZE) as u64,
            DEFAULT_STACK_SIZE as u64,
        ) {
            Ok(size) => {
                machine.add_cycles_no_checking(transferred_byte_cycles(size))?;
            }
            Err(_) => {
                machine.set_register(A0, Mac::REG::from_u8(WRONG_FORMAT));
                return Ok(true);
            }
        }
        Ok(true)
    }
}
