//! Stable cache path to the compiled SP1 `guest-bridge-proof` ELF.

use std::path::PathBuf;

/// Path to the cached SP1 `guest-bridge-proof` ELF.
///
/// Populated by `build.rs` in `--release` builds; `dev`-profile builds skip the SP1
/// pipeline entirely, so the path may be stale or absent. Callers that actually read
/// the file should handle the missing-file case (e.g., a clear panic on
/// `fs::read` failure).
pub fn bridge_proof_elf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("guest-bridge-proof/build/guest-sp1-bridge-proof.elf")
}
