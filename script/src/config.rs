use crate::types::{DebugPrinter, Machine, SyscallGenerator};
use crate::{TransactionScriptsVerifier, TxVerifyEnv, generate_ckb_syscalls};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::core::cell::{CellProvider, HeaderChecker, resolve_transaction};
use ckb_types::core::{
    EpochNumber, HeaderView, TransactionView,
    hardfork::{CKB2021, CKB2023, HardForks},
};
use ckb_types::packed::Byte32;
use ckb_types::prelude::Pack;
use ckb_vm::DefaultMachineRunner;
use std::collections::HashSet;
use std::sync::Arc;

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
    /// Epoch number.
    pub epoch: EpochNumber,
    /// Hardforks configuration.
    pub hardforks: HardForks,
    /// Context for system calls.
    pub syscall_context: V,
    /// Generator for system calls used by the virtual machine.
    pub syscall_generator: SyscallGenerator<DL, V, <M as DefaultMachineRunner>::Inner>,
}

impl<DL, V, M> Config<DL, V, M>
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
    /// Converts the Config into a ConfigBuilder for further customization.
    pub fn as_builder(self) -> ConfigBuilder<DL, V, M> {
        ConfigBuilder { inner: self }
    }

    /// Creates a TransactionScriptsVerifier for validating transaction scripts.
    /// Resolves the transaction and sets up the environment for script execution.
    pub fn transaction_scripts_verifier(
        self,
        tx: TransactionView,
        data_loader: DL,
    ) -> Result<TransactionScriptsVerifier<DL, V, M>, ckb_error::Error> {
        let rtx = resolve_transaction(tx, &mut HashSet::new(), &data_loader, &data_loader)?;
        let consensus = Arc::new(
            ConsensusBuilder::default()
                .hardfork_switch(self.hardforks)
                .build(),
        );
        let header_view = HeaderView::new_advanced_builder()
            .epoch(self.epoch.pack())
            .build();
        let tx_env = Arc::new(TxVerifyEnv::new_commit(&header_view));
        Ok(TransactionScriptsVerifier::new_with_generator(
            Arc::new(rtx),
            data_loader,
            consensus,
            tx_env,
            self.syscall_generator,
            self.syscall_context,
        ))
    }
}

impl<DL> Config<DL, DebugPrinter, Machine>
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
    /// Creates a Config instance for the devnet environment with default settings.
    pub fn devnet() -> Self {
        Self {
            epoch: 1,
            hardforks: HardForks {
                ckb2021: CKB2021::new_dev_default(),
                ckb2023: CKB2023::new_dev_default(),
            },
            syscall_context: Arc::new(debug_printer),
            syscall_generator: generate_ckb_syscalls,
        }
    }

    /// Creates a Config instance for the mainnet environment with Mirana hardfork settings.
    pub fn mainnet() -> Self {
        Self {
            epoch: ckb_constant::hardfork::mainnet::CKB2023_START_EPOCH + 1,
            hardforks: HardForks {
                ckb2021: CKB2021::new_mirana(),
                ckb2023: CKB2023::new_mirana(),
            },
            syscall_context: Arc::new(debug_printer),
            syscall_generator: generate_ckb_syscalls,
        }
    }

    /// Returns a new builder.
    pub fn new_builder() -> ConfigBuilder<DL, DebugPrinter, Machine> {
        Self::devnet().as_builder()
    }

    /// Creates a Config instance for the testnet environment with Mirana and RFC settings.
    pub fn testnet() -> Self {
        Self {
            epoch: ckb_constant::hardfork::testnet::CKB2023_START_EPOCH + 1,
            hardforks: HardForks {
                ckb2021: CKB2021::new_mirana().as_builder()
                    .rfc_0028(ckb_constant::hardfork::testnet::RFC0028_RFC0032_RFC0033_RFC0034_START_EPOCH)
                    .rfc_0029(ckb_constant::hardfork::testnet::CKB2021_START_EPOCH)
                    .rfc_0030(ckb_constant::hardfork::testnet::CKB2021_START_EPOCH)
                    .rfc_0031(ckb_constant::hardfork::testnet::CKB2021_START_EPOCH)
                    .rfc_0032(ckb_constant::hardfork::testnet::RFC0028_RFC0032_RFC0033_RFC0034_START_EPOCH)
                    .rfc_0036(ckb_constant::hardfork::testnet::CKB2021_START_EPOCH)
                    .rfc_0038(ckb_constant::hardfork::testnet::CKB2021_START_EPOCH)
                    .build().unwrap(),
                ckb2023: CKB2023::new_mirana().as_builder()
                    .rfc_0048(ckb_constant::hardfork::testnet::CKB2023_START_EPOCH)
                    .rfc_0049(ckb_constant::hardfork::testnet::CKB2023_START_EPOCH)
                    .build()
                    .unwrap()
            },
            syscall_context: Arc::new(debug_printer),
            syscall_generator: generate_ckb_syscalls,
        }
    }
}

/// Builder struct for constructing a Config instance with customizable parameters.
pub struct ConfigBuilder<DL, V, M>
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
    inner: Config<DL, V, M>,
}

impl<DL> ConfigBuilder<DL, DebugPrinter, Machine>
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
    /// Finalizes and returns the built Config instance.
    pub fn build(self) -> Config<DL, DebugPrinter, Machine> {
        self.inner
    }

    /// Sets the epoch number for the Config.
    pub fn epoch(mut self, epoch: EpochNumber) -> Self {
        self.inner.epoch = epoch;
        self
    }

    /// Sets the hardfork configuration for the Config.
    pub fn hardforks(mut self, hardforks: HardForks) -> Self {
        self.inner.hardforks = hardforks;
        self
    }

    /// Sets the syscall context for the Config.
    pub fn syscall_context(mut self, syscall_context: DebugPrinter) -> Self {
        self.inner.syscall_context = syscall_context;
        self
    }

    /// Sets the syscall generator function for the Config.
    pub fn syscall_generator(
        mut self,
        syscall_generator: SyscallGenerator<
            DL,
            DebugPrinter,
            <Machine as DefaultMachineRunner>::Inner,
        >,
    ) -> Self {
        self.inner.syscall_generator = syscall_generator;
        self
    }
}

fn debug_printer(_: &Byte32, message: &str) {
    let message = message.trim_end_matches('\n');
    if message != "" {
        println!("{}", &format!("Script log: {}", message));
    }
}
