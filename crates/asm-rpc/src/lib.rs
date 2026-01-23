//! Provides RPC types and traits for querying AnchorStateMachine (ASM) outputs.
//!
//! The ASM is a minimal, provable state machine that advances on each Bitcoin block. It is the
//! source of truth for sidesystem state. This crate defines the RPC interface for retrieving
//! ASM-derived outputs keyed by Bitcoin block hashes.

pub mod traits;
