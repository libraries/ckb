use crate::core::EpochNumber;
use ckb_constant::hardfork;
use paste::paste;

/// A switch to select hard fork features base on the epoch number.
///
/// For safety, all fields are private and not allowed to update.
/// This structure can only be constructed by [`CKB2025Builder`].
///
/// [`CKB2025Builder`]:  struct.CKB2025Builder.html
#[derive(Debug, Clone)]
pub struct CKB2025 {
    rfc_0099: EpochNumber,
}

/// Builder for [`CKB2025`].
///
/// [`CKB2025`]:  struct.CKB2025.html
#[derive(Debug, Clone, Default)]
pub struct CKB2025Builder {
    rfc_0099: Option<EpochNumber>,
}

impl CKB2025 {
    /// Creates a new builder to build an instance.
    pub fn new_builder() -> CKB2025Builder {
        Default::default()
    }

    /// Creates a new builder based on the current instance.
    pub fn as_builder(&self) -> CKB2025Builder {
        Self::new_builder().rfc_0099(self.rfc_0099())
    }

    /// Creates a new mirana instance.
    pub fn new_mirana() -> Self {
        Self::new_builder()
            .rfc_0099(hardfork::mainnet::CKB2025_START_EPOCH)
            .build()
            .unwrap()
    }

    /// Creates a new dev instance.
    pub fn new_dev_default() -> Self {
        // Use a builder to ensure all features are set manually.
        Self::new_builder().rfc_0099(0).build().unwrap()
    }

    /// Creates a new instance with specified.
    pub fn new_with_specified(epoch: EpochNumber) -> Self {
        // Use a builder to ensure all features are set manually.
        Self::new_builder().rfc_0099(epoch).build().unwrap()
    }
}

define_methods!(
    CKB2025,
    rfc_0099,
    vm_version_3_and_syscalls_4,
    is_vm_version_3_and_syscalls_4_enabled,
    disable_rfc_0099,
    "RFC PR 0099"
);

impl CKB2025Builder {
    /// Build a new [`CKB2025`].
    ///
    /// Returns an error if failed at any check, for example, there maybe are some features depend
    /// on others.
    ///
    /// [`CKB2025`]: struct.CKB2025.html
    pub fn build(self) -> Result<CKB2025, String> {
        let rfc_0099 = try_find!(self, rfc_0099);

        Ok(CKB2025 { rfc_0099 })
    }
}
