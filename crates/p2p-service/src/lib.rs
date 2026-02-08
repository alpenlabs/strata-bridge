//! Strata Bridge P2P.
#![allow(
    incomplete_features,
    reason = "`strata-p2p` needs `generic_const_exprs` which itself is an `incomplete_feature`"
)]
#![feature(generic_const_exprs)] //strata-p2p

pub mod bootstrap;
pub mod config;
pub mod constants;
pub mod message_handler;
pub mod message_handler2;

pub use bootstrap::bootstrap;
pub use config::{Configuration, GossipsubScoringPreset};
pub use message_handler::MessageHandler;
pub use message_handler2::{MessageHandler as MessageHandler2, OuroborosMessage};

#[cfg(test)]
mod tests;
