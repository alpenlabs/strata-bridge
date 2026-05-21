//! Prints the `Sp1Groth16:<hex>` predicate that pins a given SP1 guest ELF's verifying
//! key. Used by the functional tests to derive `asm-vk.json` / `moho-vk.json` from the
//! asm/moho guest ELFs so the bridge proof verifies their Groth16 proofs.
//!
//! Usage: `sp1-predicate <path-to-elf>`

// This thin helper only needs `strata_bridge_proof`; the crate's other deps are used by
// the library, not this bin target.
#![allow(unused_crate_dependencies)]

use std::process::ExitCode;

use strata_bridge_proof::sp1_groth16_predicate_string;

fn main() -> ExitCode {
    let Some(elf_path) = std::env::args().nth(1) else {
        eprintln!("usage: sp1-predicate <path-to-elf>");
        return ExitCode::FAILURE;
    };

    let elf = match std::fs::read(&elf_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("failed to read ELF at {elf_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    match sp1_groth16_predicate_string(&elf) {
        Ok(predicate) => {
            println!("{predicate}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to derive Sp1Groth16 predicate: {e}");
            ExitCode::FAILURE
        }
    }
}
