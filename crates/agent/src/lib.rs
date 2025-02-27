#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

pub mod base;
pub mod bitcoin_watcher;
pub mod duty_watcher;
pub mod operator;
pub mod proof_interop;
pub mod signal;
pub mod verifier;
