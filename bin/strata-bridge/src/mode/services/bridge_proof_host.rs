//! Selects the bridge-proof host (native or SP1) for the active build.
//!
//! Lives in the binary crate so that the SP1 branch can pull in
//! `strata-bridge-sp1-guest-builder` (which build-depends on
//! `strata-bridge-proof`) without creating a dependency cycle through the
//! proof crate itself.

use strata_bridge_proof::BridgeProofHost;

/// Constructs the [`BridgeProofHost`] for the active backend.
#[cfg(not(feature = "sp1"))]
pub(in crate::mode) fn build_bridge_proof_host() -> BridgeProofHost {
    strata_bridge_proof::build_bridge_proof_host()
}

/// Constructs the [`BridgeProofHost`] for the active backend.
///
/// Reads the SP1 guest ELF cached by `strata-bridge-sp1-guest-builder`'s
/// build script. The ELF is produced only in `--release` builds; debug
/// builds will panic on the missing file.
#[cfg(feature = "sp1")]
pub(in crate::mode) fn build_bridge_proof_host() -> BridgeProofHost {
    use std::fs;

    use strata_bridge_sp1_guest_builder::bridge_proof_elf_path;

    let path = bridge_proof_elf_path();
    let elf = fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read bridge-proof guest ELF at {} \
             (build with --release to populate the cache): {err}",
            path.display()
        )
    });
    strata_bridge_proof::build_bridge_proof_host(&elf)
}
