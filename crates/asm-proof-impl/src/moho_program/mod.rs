//! [`MohoProgram`](moho_runtime_interface::MohoProgram) implementation for the ASM STF.
//!
//! This module adapts the ASM state transition function to work with the Moho runtime by
//! implementing the [`MohoProgram`](moho_runtime_interface::MohoProgram) trait. It defines how L1
//! Bitcoin blocks are used as step inputs, how state commitments are computed, and how the ASM STF
//! is executed as a verified transition step in the recursive proof chain.

pub mod input;
pub mod program;
