//! This crate implements a system that monitors external Bitcoin chain events as well as the
//! operator P2P network and responds to those events in accordance with the Strata Bridge protocol
//! rules.
#![allow(
    incomplete_features,
    reason = "`strata-p2p` needs `generic_const_exprs` which itself is an `incomplete_feature`"
)]
#![feature(generic_const_exprs)] // strata-p2p

pub mod contract_actor;
pub mod contract_manager;
pub mod contract_persister;
pub mod contract_state_machine;
pub mod errors;
pub mod executors;
pub mod predicates;
pub mod shutdown;
pub mod stake_chain_persister;
pub mod stake_chain_state_machine;
