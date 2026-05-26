//! Public ELF path exports produced by this crate's build script.
//!
//! The ELF is emitted into `<crate>/elfs/` by `build.rs` (release-profile
//! builds only); the constant below points at that stable path rather than
//! into cargo's `target/`. Dev-profile builds skip the SP1 pipeline entirely,
//! so the file may be stale or absent. Callers that actually read the file
//! should handle the missing-file case (e.g., a clear panic on `fs::read`
//! failure).

pub const BRIDGE_PROOF_ELF_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/bridge-proof.elf");

/// Path to the `Sp1Groth16:<hex>` predicate string emitted next to the ELF by
/// `build.rs`. Operators load this into their consensus params.
pub const BRIDGE_PROOF_PREDICATE_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/bridge-proof.predicate");
