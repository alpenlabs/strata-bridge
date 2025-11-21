//! Types for the Strata P2P messaging protocol.
#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

mod deposit_data;
mod operator;
mod scope;
mod session_id;
mod stake_chain_id;
mod wots;

pub use deposit_data::{Groth16PublicKeys, WotsPublicKeys};
pub use operator::P2POperatorPubKey;
pub use scope::Scope;
pub use session_id::SessionId;
pub use stake_chain_id::StakeChainId;
pub use wots::{Wots128PublicKey, Wots160PublicKey, Wots256PublicKey, WOTS_SINGLE};
