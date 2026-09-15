//! Public membership and covenant history, independent of local staking participation.
//!
//! Inputs are authorized registrations, ordered admin updates, and validated on-chain exits.
//! Membership transitions retain historical identities and reject intermediate empty sets.

mod schedule;
mod state;

pub use schedule::MembershipUpdate;
pub use state::{MembershipCause, MembershipSnapshot, OperatorSetError, OperatorSetSM};

#[cfg(test)]
mod tests;
