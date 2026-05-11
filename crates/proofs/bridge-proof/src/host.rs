//! Host construction for [`crate::BridgeProofProgram`].
//!
//! All `cfg(feature = "sp1")` gating lives in this file; downstream crates
//! select the constructor variant based on the active feature.

#[cfg(not(feature = "sp1"))]
mod backend {
    use zkaleido_native_adapter::NativeHost;

    use crate::statements::process_bridge_proof;

    /// The host used to generate bridge proofs.
    ///
    /// Resolves to `NativeHost` in the default build, `SP1Host` under the
    /// `sp1` feature.
    pub type BridgeProofHost = NativeHost;

    /// Constructs the [`BridgeProofHost`] for the active backend.
    pub fn build_bridge_proof_host() -> BridgeProofHost {
        NativeHost::new(process_bridge_proof)
    }
}

#[cfg(feature = "sp1")]
mod backend {
    use zkaleido_sp1_host::SP1Host;

    /// The host used to generate bridge proofs.
    ///
    /// Resolves to `NativeHost` in the default build, `SP1Host` under the
    /// `sp1` feature.
    pub type BridgeProofHost = SP1Host;

    /// Constructs the [`BridgeProofHost`] from a pre-loaded SP1 guest ELF.
    ///
    /// The guest ELF lives in `strata-bridge-sp1-guest-builder`
    pub fn build_bridge_proof_host(elf: &[u8]) -> BridgeProofHost {
        SP1Host::init(elf)
    }
}

pub use backend::{BridgeProofHost, build_bridge_proof_host};
