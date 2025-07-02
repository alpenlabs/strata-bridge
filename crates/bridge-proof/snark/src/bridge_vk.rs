//! Bridge verification key.

use std::{path::Path, sync::LazyLock};

use ark_bn254::{Bn254, Fr};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use tracing::info;

/// Fetches the Groth16 verification key from the specified path if it exists and is valid.
pub fn fetch_groth16_vk(path: impl AsRef<Path>) -> Option<VerifyingKey<Bn254>> {
    if path.as_ref().exists() {
        info!(path=%path.as_ref().display(), "loading verification key from file");

        let contents = std::fs::read(path.as_ref()).ok()?;
        let vk_bytes = hex::decode(contents).ok()?;

        VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).ok()
    } else {
        info!(path=%path.as_ref().display(), "verification key file does not exist");
        None
    }
}

/// The Groth16 verification key that is generated at runtime.
///
/// # Note
///
/// If the environment variable `ZKVM_MOCK` is set to `1` or `true`, a mock
/// verification key is used.
///
/// Otherwise, it generates a new verification key by calling the SP1 prover client provided that
/// the following environment variables are also set.
///
/// - `SP1_PROVER`: the prover to use (set this to `network` to make the network call to SP1)
/// - `SP1_PROOF_STRATEGY`: the proof [fulfillment strategy](sp1_sdk::network::FulfillmentStrategy)
///   to use.
/// - `NETWORK_PRIVATE_KEY`: the private key of the account that will be used to pay for the proof
///   request.
/// - `NETWORK_RPC_URL`: The RPC URL of the network to use.
pub static GROTH16_VERIFICATION_KEY: LazyLock<VerifyingKey<Bn254>> = LazyLock::new(|| {
    let sp1_vk = if std::env::var("ZKVM_MOCK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        const MOCK_KEY: &str = "f11a13dc16284374ad770eb12246bbcd2931cf02e76e0bc4046156cb2cd7d8f4";
        info!(key=%MOCK_KEY, "Using mock verification key");

        hex::decode(MOCK_KEY).unwrap()
    } else {
        info!("generating new verification key");

        use sp1_sdk::{HashableKey, Prover, ProverClient};
        use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;

        let pc = ProverClient::builder().network().build();
        let (_, sp1_vk) = pc.setup(GUEST_BRIDGE_ELF);

        let sp1_vk = sp1_vk
            .bytes32()
            .strip_prefix("0x")
            .expect("vk hex must begin with 0x")
            .to_string();

        hex::decode(sp1_vk).expect("vk bytes must be valid hex")
    };

    let compile_time_public_inputs = [Fr::from_be_bytes_mod_order(&sp1_vk)];

    // embed first public input to the groth16 vk
    let mut vk = sp1_verifier::load_ark_groth16_verifying_key_from_bytes(
        sp1_verifier::GROTH16_VK_BYTES.as_ref(),
    )
    .unwrap();
    let mut vk_gamma_abc_g1_0 = vk.gamma_abc_g1[0] * Fr::ONE;
    for (i, public_input) in compile_time_public_inputs.iter().enumerate() {
        vk_gamma_abc_g1_0 += vk.gamma_abc_g1[i + 1] * public_input;
    }
    let mut vk_gamma_abc_g1 = vec![vk_gamma_abc_g1_0.into_affine()];
    vk_gamma_abc_g1.extend(&vk.gamma_abc_g1[1 + compile_time_public_inputs.len()..]);
    vk.gamma_abc_g1 = vk_gamma_abc_g1;

    vk
});
