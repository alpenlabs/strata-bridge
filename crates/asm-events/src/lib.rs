//! # `asm-tracker`
//!
//! `asm-tracker` streams assignment snapshots from the Anchor State Machine (ASM) keyed by
//! Bitcoin block hashes.

pub mod client;
pub mod config;
pub mod event;
pub mod subscription;
