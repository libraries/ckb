use crate::types::{DebugPrinter, Machine, SyscallGenerator};
use crate::{
    Scheduler, ScriptError, ScriptGroupType, ScriptVersion, TransactionScriptsVerifier,
    TxVerifyEnv, generate_ckb_syscalls,
};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::core::cell::{
    CellProvider, HeaderChecker, ResolvedTransaction, resolve_transaction,
};
use ckb_types::core::{
    Cycle, HeaderView, TransactionView,
    hardfork::{CKB2021, CKB2023, HardForks},
};
use ckb_types::packed::Byte32;
use ckb_types::prelude::Pack;
use ckb_vm::decoder::{Decoder, build_decoder};
use ckb_vm::elf::ProgramMetadata;
use ckb_vm::{
    Bytes, CoreMachine, DefaultMachine, DefaultMachineRunner, Error as VmError, SupportMachine,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Enum representing cell types (input or output) in a transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CellType {
    Input,
    Output,
}

impl std::fmt::Display for CellType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CellType::Input => write!(f, "input"),
            CellType::Output => write!(f, "output"),
        }
    }
}

impl std::str::FromStr for CellType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "input" => Ok(CellType::Input),
            "output" => Ok(CellType::Output),
            _ => Err("unknown cell type"),
        }
    }
}

impl TryFrom<&str> for CellType {
    type Error = <Self as std::str::FromStr>::Err;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// Configuration struct for the script runner.
pub struct Config<DL, V, M>
where
    DL: CellDataProvider
        + CellProvider
        + HeaderChecker
        + HeaderProvider
        + ExtensionProvider
        + Send
        + Sync
        + Clone
        + 'static,
    V: Clone,
    M: DefaultMachineRunner,
{
    /// Maximum number of cycles allowed for execution.
    pub max_cycles: u64,
    /// Generator for system calls used by the virtual machine.
    pub syscall_generator: SyscallGenerator<DL, V, <M as DefaultMachineRunner>::Inner>,
    /// Context for system calls.
    pub syscall_context: V,
    /// Version of the script being executed.
    pub version: ScriptVersion,
}

impl<DL> Default for Config<DL, DebugPrinter, Machine>
where
    DL: CellDataProvider
        + CellProvider
        + HeaderChecker
        + HeaderProvider
        + ExtensionProvider
        + Send
        + Sync
        + Clone
        + 'static,
{
    fn default() -> Self {
        Self {
            max_cycles: 100_000_000,
            syscall_generator: generate_ckb_syscalls,
            syscall_context: Arc::new(|_: &Byte32, message: &str| {
                let message = message.trim_end_matches('\n');
                if message != "" {
                    println!("{}", &format!("Script log: {}", message));
                }
            }),
            version: ScriptVersion::V2,
        }
    }
}

/// Trait defining hooks for customizing virtual machine behavior.
pub trait Hook<M>
where
    M: DefaultMachineRunner,
{
    /// Initializes the hook with the given machine.
    fn init(machine: &M) -> Self;
    /// Initializes the hook when exec syscall done.
    fn init_by_exec(&mut self, machine: &M);
    /// Loads a program into the machine with provided arguments.
    fn load_program(
        &mut self,
        machine: &M,
        program: &Bytes,
        args: impl ExactSizeIterator<Item = Result<Bytes, VmError>>,
    );
    /// Executes a single step in the machine's execution cycle.
    fn step(&mut self, machine: &mut M, decoder: &mut Decoder) -> Result<(), VmError>;
}

/// Wrapper struct combining a machine runner with a hook for extended functionality.
pub struct HookWraper<M, H>
where
    M: DefaultMachineRunner,
    H: Hook<M>,
{
    /// The underlying machine runner.
    pub machine: M,
    /// Thread-safe hook instance shared via Arc and Mutex.
    pub hook: Arc<Mutex<H>>,
}

impl<M, H> DefaultMachineRunner for HookWraper<M, H>
where
    M: DefaultMachineRunner,
    H: Hook<M>,
{
    type Inner = M::Inner;

    fn new(machine: DefaultMachine<Self::Inner>) -> Self {
        let machine = M::new(machine);
        let hook = Arc::new(Mutex::new(H::init(&machine)));
        Self { machine, hook }
    }

    fn machine(&self) -> &DefaultMachine<Self::Inner> {
        self.machine.machine()
    }

    fn machine_mut(&mut self) -> &mut DefaultMachine<Self::Inner> {
        self.machine.machine_mut()
    }

    fn run(&mut self) -> Result<i8, ckb_vm::Error> {
        let mut decoder = build_decoder::<u64>(self.machine().isa(), self.machine().version());
        self.machine_mut().set_running(true);
        while self.machine().running() {
            if self.machine_mut().reset_signal() {
                decoder.reset_instructions_cache();
                self.hook.lock().unwrap().init_by_exec(&mut self.machine);
            }
            self.hook
                .lock()
                .unwrap()
                .step(&mut self.machine, &mut decoder)?;
            self.machine_mut().step(&mut decoder)?;
        }
        Ok(self.machine().exit_code())
    }

    fn load_program(
        &mut self,
        program: &Bytes,
        args: impl ExactSizeIterator<Item = Result<Bytes, VmError>>,
    ) -> Result<u64, VmError> {
        let args: Vec<Result<Bytes, VmError>> = args.collect();
        self.hook.lock().unwrap().load_program(
            &mut self.machine,
            program,
            args.clone().into_iter(),
        );
        self.machine_mut().load_program(program, args.into_iter())
    }

    fn load_program_with_metadata(
        &mut self,
        program: &Bytes,
        metadata: &ProgramMetadata,
        args: impl ExactSizeIterator<Item = Result<Bytes, VmError>>,
    ) -> Result<u64, VmError> {
        let args: Vec<Result<Bytes, VmError>> = args.collect();
        self.hook.lock().unwrap().load_program(
            &mut self.machine,
            program,
            args.clone().into_iter(),
        );
        self.machine_mut()
            .load_program_with_metadata(program, metadata, args.into_iter())
    }
}

/// Main runner struct for executing and verifying scripts.
pub struct Runner<DL, V, M>
where
    DL: CellDataProvider
        + CellProvider
        + HeaderChecker
        + HeaderProvider
        + ExtensionProvider
        + Send
        + Sync
        + Clone
        + 'static,
    V: Clone,
    M: DefaultMachineRunner,
{
    /// Configuration for the runner.
    pub config: Config<DL, V, M>,
    /// Resolved transaction data.
    pub rtx: ResolvedTransaction,
    /// Verifier for transaction scripts.
    pub verifier: TransactionScriptsVerifier<DL, V, M>,
}

impl<DL, V, M> Runner<DL, V, M>
where
    DL: CellDataProvider
        + CellProvider
        + HeaderChecker
        + HeaderProvider
        + ExtensionProvider
        + Send
        + Sync
        + Clone
        + 'static,
    V: Clone,
    M: DefaultMachineRunner,
{
    /// Creates a new Runner instance with the given transaction, data loader, and config.
    pub fn new(
        tx: TransactionView,
        data_loader: DL,
        config: Config<DL, V, M>,
    ) -> Result<Self, ckb_error::Error> {
        let rtx = resolve_transaction(tx, &mut HashSet::new(), &data_loader, &data_loader)?;
        let hardforks = HardForks {
            ckb2021: CKB2021::new_mirana()
                .as_builder()
                .rfc_0032(20)
                .build()
                .unwrap(),
            ckb2023: CKB2023::new_mirana()
                .as_builder()
                .rfc_0049(30)
                .build()
                .unwrap(),
        };
        let consensus = Arc::new(
            ConsensusBuilder::default()
                .hardfork_switch(hardforks)
                .build(),
        );
        let epoch = match config.version {
            ScriptVersion::V0 => ckb_types::core::EpochNumberWithFraction::new(15, 0, 1),
            ScriptVersion::V1 => ckb_types::core::EpochNumberWithFraction::new(25, 0, 1),
            ScriptVersion::V2 => ckb_types::core::EpochNumberWithFraction::new(35, 0, 1),
        };
        let header_view = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        let tx_env = Arc::new(TxVerifyEnv::new_commit(&header_view));
        let verifier = TransactionScriptsVerifier::new_with_generator(
            Arc::new(rtx.clone()),
            data_loader.clone(),
            consensus.clone(),
            tx_env.clone(),
            config.syscall_generator,
            config.syscall_context.clone(),
        );
        Ok(Self {
            config,
            rtx,
            verifier,
        })
    }

    /// Retrieves the script hash for a given cell type, index, and script group type.
    pub fn get_script_hash_by_location(
        &self,
        cell_type: CellType,
        cell_index: usize,
        script_group_type: ScriptGroupType,
    ) -> Result<Byte32, ScriptError> {
        let script_hash = match (&script_group_type, cell_type) {
            (ScriptGroupType::Lock, CellType::Input) => self
                .rtx
                .resolved_inputs
                .get(cell_index)
                .ok_or_else(|| ScriptError::Other("index out of bound".into()))?
                .cell_output
                .calc_lock_hash(),
            (ScriptGroupType::Type, CellType::Input) => self
                .rtx
                .resolved_inputs
                .get(cell_index)
                .ok_or_else(|| ScriptError::Other("index out of bound".into()))?
                .cell_output
                .type_()
                .to_opt()
                .ok_or_else(|| ScriptError::Other("cell should have type script".into()))?
                .calc_script_hash(),
            (ScriptGroupType::Type, CellType::Output) => self
                .rtx
                .transaction
                .output(cell_index)
                .ok_or_else(|| ScriptError::Other("index out of bound".into()))?
                .type_()
                .to_opt()
                .ok_or_else(|| ScriptError::Other("cell should have type script".into()))?
                .calc_script_hash(),
            _ => panic!(
                "Invalid specified script: {:?} {} {}",
                script_group_type, cell_type, cell_index
            ),
        };
        Ok(script_hash)
    }

    /// Creates a scheduler based on the verification method (hash or location).
    pub fn get_scheduler(&self, by: VerifyBy) -> Result<Scheduler<DL, V, M>, ScriptError> {
        match by {
            VerifyBy::Hash {
                script_group_type,
                script_hash,
            } => self.get_scheduler_by_hash(script_group_type, &script_hash),
            VerifyBy::Location {
                cell_type,
                cell_index,
                script_group_type,
            } => self.get_scheduler_by_location(cell_type, cell_index, script_group_type),
        }
    }

    /// Creates a scheduler for a script identified by its hash and group type..
    pub fn get_scheduler_by_hash(
        &self,
        script_group_type: ScriptGroupType,
        script_hash: &Byte32,
    ) -> Result<Scheduler<DL, V, M>, ScriptError> {
        let script_group = self
            .verifier
            .find_script_group(script_group_type, &script_hash)
            .unwrap();
        self.verifier.create_scheduler(script_group)
    }

    /// Creates a scheduler for a script identified by its cell location and group type.
    pub fn get_scheduler_by_location(
        &self,
        cell_type: CellType,
        cell_index: usize,
        script_group_type: ScriptGroupType,
    ) -> Result<Scheduler<DL, V, M>, ScriptError> {
        let script_hash =
            self.get_script_hash_by_location(cell_type, cell_index, script_group_type)?;
        let script_group = self
            .verifier
            .find_script_group(script_group_type, &script_hash)
            .unwrap();
        self.verifier.create_scheduler(script_group)
    }

    /// Verifies a script based on the verification method (hash or location).
    pub fn verify(&self, by: VerifyBy) -> Result<Cycle, ScriptError> {
        match by {
            VerifyBy::Hash {
                script_group_type,
                script_hash,
            } => self.verify_by_hash(script_group_type, &script_hash),
            VerifyBy::Location {
                cell_type,
                cell_index,
                script_group_type,
            } => self.verify_by_location(cell_type, cell_index, script_group_type),
        }
    }

    /// Verifies a script identified by its hash and group type.
    pub fn verify_by_hash(
        &self,
        script_group_type: ScriptGroupType,
        script_hash: &Byte32,
    ) -> Result<Cycle, ScriptError> {
        self.verifier
            .verify_single(script_group_type, script_hash, self.config.max_cycles)
    }

    /// Verifies a script identified by its cell location and group type.
    pub fn verify_by_location(
        &self,
        cell_type: CellType,
        cell_index: usize,
        script_group_type: ScriptGroupType,
    ) -> Result<Cycle, ScriptError> {
        let script_hash =
            self.get_script_hash_by_location(cell_type, cell_index, script_group_type)?;
        self.verify_by_hash(script_group_type, &script_hash)
    }
}

/// Enum representing different methods to identify a script for verification.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum VerifyBy {
    /// Identifies a script by its hash and group type.
    Hash {
        script_group_type: ScriptGroupType,
        script_hash: Byte32,
    },
    /// Identifies a script by its cell location and group type.
    Location {
        cell_type: CellType,
        cell_index: usize,
        script_group_type: ScriptGroupType,
    },
}
