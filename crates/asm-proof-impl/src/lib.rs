//! Moho step proof implementation of the ASM STF.
//!
//! This crate implements the step proof, which is the ASM STF itself. It does so by implementing
//! the [`MohoProgram`](moho_runtime_interface::MohoProgram) trait, which allows the generic Moho
//! runtime to drive ASM state transitions as verified steps.
pub mod moho_program;
pub mod program;
pub mod statements;
