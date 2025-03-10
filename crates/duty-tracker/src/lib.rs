//! This crate implements a system that monitors external Bitcoin chain events as well as the
//! operator P2P network and responds to those events in accordance with the Strata Bridge protocol
//! rules.
#![feature(result_flattening)]
pub mod contract_manager;
pub mod contract_persister;
pub mod contract_state_machine;
pub mod predicates;
pub mod tx_driver;
