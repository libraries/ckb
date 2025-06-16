use crate::types::{DebugPrinter, Machine, SyscallGenerator};
use crate::{
    ScriptError, ScriptGroupType, ScriptVersion, TransactionScriptsVerifier, TxVerifyEnv,
    generate_ckb_syscalls,
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
use ckb_vm::DefaultMachineRunner;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

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
    pub max_cycles: u64,
    pub syscall_generator: SyscallGenerator<DL, V, <M as DefaultMachineRunner>::Inner>,
    pub syscall_context: V,
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
    option: Config<DL, V, M>,
    rtx: ResolvedTransaction,
    verifier: TransactionScriptsVerifier<DL, V, M>,
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
    pub fn new(
        tx: TransactionView,
        data_loader: DL,
        option: Config<DL, V, M>,
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
        let epoch = match option.version {
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
            option.syscall_generator,
            option.syscall_context.clone(),
        );
        Ok(Self {
            option,
            rtx,
            verifier,
        })
    }

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

    pub fn verify_by_hash(
        &self,
        script_group_type: ScriptGroupType,
        script_hash: &Byte32,
    ) -> Result<Cycle, ScriptError> {
        self.verifier
            .verify_single(script_group_type, script_hash, self.option.max_cycles)
    }

    pub fn verify_by_location(
        &self,
        cell_type: CellType,
        cell_index: usize,
        script_group_type: ScriptGroupType,
    ) -> Result<Cycle, ScriptError> {
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
        self.verify_by_hash(script_group_type, &script_hash)
    }
}

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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum VerifyBy {
    Hash {
        script_group_type: ScriptGroupType,
        script_hash: Byte32,
    },
    Location {
        cell_type: CellType,
        cell_index: usize,
        script_group_type: ScriptGroupType,
    },
}
