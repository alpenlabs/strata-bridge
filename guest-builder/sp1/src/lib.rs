//! Public ELF path exports produced by this crate's build script.
//!
//! The ELFs are emitted into `<crate>/elfs/` by `build.rs` (release-profile
//! builds only); the constants below point at those stable paths rather than
//! into cargo's `target/`. Dev-profile builds skip the SP1 pipeline entirely,
//! so the files may be stale or absent. Callers that actually read a file
//! should handle the missing-file case (e.g., a clear panic on `fs::read`
//! failure).

pub const BRIDGE_PROOF_ELF_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/bridge-proof.elf");

/// Path to the `Sp1Groth16:<hex>` predicate string emitted next to the ELF by
/// `build.rs`. Operators load this into their consensus params.
pub const BRIDGE_PROOF_PREDICATE_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/bridge-proof.predicate");

pub const BRIDGE_COUNTERPROOF_ELF_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/counterproof.elf");
