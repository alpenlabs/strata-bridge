#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(trivial_bounds)]
//! Protocol definitions for the Secret Service.

#[allow(missing_docs)] // because lints wouldn't shut up about rkyv's Archive proc macro
pub mod v2;
pub mod wire;
