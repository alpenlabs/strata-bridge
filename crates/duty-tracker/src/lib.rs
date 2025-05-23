//! This crate implements a system that monitors external Bitcoin chain events as well as the
//! operator P2P network and responds to those events in accordance with the Strata Bridge protocol
//! rules.
#![feature(result_flattening)]

pub mod contract_manager;
pub mod contract_persister;
pub mod contract_state_machine;
pub mod errors;
pub mod executors;
pub mod predicates;
pub mod s2_session_manager;
pub mod stake_chain_persister;
pub mod stake_chain_state_machine;
pub mod tx_driver;
