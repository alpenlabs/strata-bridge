//! Protobuf definitions for the Strata P2P protocol.
#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds

pub mod p2p;
