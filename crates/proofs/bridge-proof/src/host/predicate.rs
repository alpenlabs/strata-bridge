//! Derives the [`PredicateTypeId::Sp1Groth16`] predicate that pins the bridge-proof guest's
//! verifying key, used by operators to verify Groth16-wrapped SP1 proofs.

use anyhow::{Context, Result};
use sp1_sdk::{
    HashableKey, ProvingKey,
    blocking::{Prover, ProverClient},
};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

/// Derives the [`PredicateKey`] that verifies SP1 proofs from the bridge-proof guest `elf`.
///
/// The CPU prover is used only for key setup; the verifying key depends on the ELF alone,
/// not the proving backend.
pub fn sp1_groth16_predicate_key(elf: &[u8]) -> Result<PredicateKey> {
    let prover = ProverClient::builder().cpu().build();
    let pk = prover
        .setup(elf.to_vec().into())
        .map_err(|e| anyhow::anyhow!("sp1 key setup for predicate derivation: {e}"))?;
    let program_vk_hash = pk.verifying_key().bytes32_raw();

    let verifier =
        SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_vk_hash, *VK_ROOT_BYTES, true)
            .context("load SP1 Groth16 verifier")?;
    let condition = borsh::to_vec(&verifier).context("borsh-encode SP1 Groth16 verifier")?;

    Ok(PredicateKey::new(PredicateTypeId::Sp1Groth16, condition))
}

/// [`sp1_groth16_predicate_key`] rendered as `Sp1Groth16:<hex>`, the form the params TOML
/// parser expects.
pub fn sp1_groth16_predicate_string(elf: &[u8]) -> Result<String> {
    let key = sp1_groth16_predicate_key(elf)?;
    Ok(format!(
        "{}:{}",
        PredicateTypeId::Sp1Groth16,
        hex::encode(key.condition())
    ))
}
