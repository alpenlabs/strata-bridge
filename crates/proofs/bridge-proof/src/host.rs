//! Host construction for [`crate::BridgeProofProgram`].
//!
//! All `cfg(feature = "sp1")` gating lives in this file; the binary forwards
//! the Cargo feature instead of branching on `cfg` directly.

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

    /// Constructs the [`BridgeProofHost`] for the active backend.
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-1977>
    // Wire the SP1 host once the bridge-proof guest builder lands.
    pub fn build_bridge_proof_host() -> BridgeProofHost {
        todo!("SP1 bridge-proof host not yet wired")
    }
}

pub use backend::{BridgeProofHost, build_bridge_proof_host};
