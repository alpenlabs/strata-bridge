//! Derives the [`PredicateTypeId::Sp1Groth16`] predicate that pins an SP1 guest's
//! verifying key, used by operators to verify Groth16-wrapped SP1 proofs.

use anyhow::{Context, Result};
use sp1_sdk::{
    HashableKey, ProvingKey,
    blocking::{Prover, ProverClient},
};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

/// Extracts the SP1 program's 32-byte verifying-key digest from a guest `elf`.
pub fn sp1_program_vkey_hash(elf: &[u8]) -> Result<[u8; 32]> {
    let prover = ProverClient::builder().cpu().build();
    let pk = prover
        .setup(elf.to_vec().into())
        .map_err(|e| anyhow::anyhow!("sp1 key setup: {e}"))?;
    Ok(pk.verifying_key().bytes32_raw())
}

/// Builds the [`PredicateKey`] that verifies SP1 Groth16 proofs of a program with the
/// given 32-byte verifying-key digest. Pair with [`sp1_program_vkey_hash`] when starting
/// from an ELF.
pub fn sp1_groth16_predicate_key(vkey_hash: [u8; 32]) -> Result<PredicateKey> {
    let verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, vkey_hash, *VK_ROOT_BYTES, true)
        .context("load SP1 Groth16 verifier")?;
    let condition = verifier.to_uncompressed_bytes();

    Ok(PredicateKey::new(PredicateTypeId::Sp1Groth16, condition))
}

/// [`sp1_groth16_predicate_key`] for a given `elf`, rendered as `Sp1Groth16:<hex>` — the
/// form the params TOML parser expects.
pub fn sp1_groth16_predicate_string(elf: &[u8]) -> Result<String> {
    let vkey_hash = sp1_program_vkey_hash(elf)?;
    sp1_groth16_predicate_string_from_key(&sp1_groth16_predicate_key(vkey_hash)?)
}

/// Renders a [`PredicateKey`] via its human-readable `Serialize` impl, yielding the
/// `Sp1Groth16:<hex>` form.
pub fn sp1_groth16_predicate_string_from_key(key: &PredicateKey) -> Result<String> {
    let value = serde_json::to_value(key).context("serialize PredicateKey")?;
    value
        .as_str()
        .map(str::to_owned)
        .context("PredicateKey did not serialize as a JSON string")
}
