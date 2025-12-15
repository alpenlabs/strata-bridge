//! Strata P2P protocol v1 messages.

#[allow(missing_docs)] // Auto-generated module, docs are not in our control.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/strata.bitvm2.p2p.v1.rs"));
}

pub(crate) mod typed;
pub use typed::*;
