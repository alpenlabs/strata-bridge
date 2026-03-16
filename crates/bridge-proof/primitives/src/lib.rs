//! This crate provides essential primitives for proving transaction inclusion in the Strata bridge.

// This was a temporary separation from `strata-bridge-primitives` due to its dependency on `bitvm`,
// which in turn depends on `tokio`, making it incompatible with compilation inside the ZKVM.
//
// **FIXME:** Move this functionality back into `strata-bridge-primitives`.

mod tx;
mod utils;

mod tx_inclusion_proof;
pub use tx_inclusion_proof::*;
pub use utils::*;
