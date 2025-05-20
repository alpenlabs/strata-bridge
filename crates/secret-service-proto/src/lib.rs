#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
//! Protocol definitions for the Secret Service.

#[allow(missing_docs)] // because lints wouldn't shut up about rkyv's Archive proc macro
pub mod v1;
pub mod wire;
