use std::str::FromStr;

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use bitvm::groth16::g16;
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, Prover, ProverClient, SP1ProofWithPublicValues,
    SP1VerifyingKey,
};
use sp1_verifier::Groth16Verifier;
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;
use strata_bridge_proof_protocol::{BridgeProofInput, BridgeProofPublicParams, StrataBridgeState};
use strata_primitives::params::RollupParams;
use tracing::info;
use zkaleido::{ZkVmError, ZkVmInputBuilder};
use zkaleido_sp1_adapter::SP1ProofInputBuilder;

use crate::sp1;

pub fn prove(
    input: &[u8],
    strata_bridge_state: &StrataBridgeState,
    rollup_params: &RollupParams,
) -> anyhow::Result<(g16::Proof, [Fr; 1], BridgeProofPublicParams)> {
    let bridge_proof_input: BridgeProofInput =
        bincode::deserialize(input).context("should be able to deserialize input")?;

    let (mut sp1prf, sp1vk) = default_prove(bridge_proof_input, rollup_params, strata_bridge_state)
        .context("cannot generate proof")?;

    info!(action = "verifying proof");
    Groth16Verifier::verify(
        &sp1prf.bytes(),
        sp1prf.public_values.as_slice(),
        &sp1vk.bytes32(),
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .context("proof verification failed")?;

    let bridge_proof_public_params: BridgeProofPublicParams = sp1prf.public_values.read();
    let groth16 = sp1prf.proof.try_as_groth_16().unwrap();
    let proof = sp1::load_groth16_proof_from_bytes(&hex::decode(groth16.raw_proof).unwrap());
    let public_inputs =
        [Fr::from_bigint(BigInt::from_str(&groth16.public_inputs[1]).unwrap()).unwrap()];

    Ok((proof, public_inputs, bridge_proof_public_params))
}

pub fn default_prove(
    bridge_proof_input: BridgeProofInput,
    rollup_params: &RollupParams,
    strata_bridge_state: &StrataBridgeState,
) -> anyhow::Result<(SP1ProofWithPublicValues, SP1VerifyingKey)> {
    let input = {
        let mut input_builder = SP1ProofInputBuilder::new();
        input_builder.write_serde(&bridge_proof_input)?;
        input_builder.write_serde(&rollup_params)?;
        input_builder.write_borsh(strata_bridge_state)?;
        input_builder.build()?
    };

    if std::env::var("SP1_PROVER").is_err() {
        panic!("Only network prover is supported");
    }

    // Prover network
    let prover_client = ProverClient::builder().network().build();
    let (proving_key, verifying_key) = prover_client.setup(GUEST_BRIDGE_ELF);

    let network_prover_builder = prover_client
        .prove(&proving_key, &input)
        .strategy(FulfillmentStrategy::Reserved);

    let network_prover = network_prover_builder.groth16().skip_simulation(true);

    let proof = network_prover
        .run()
        .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

    anyhow::Ok((proof, verifying_key))
}

// #[cfg(test)]
// mod test {
//     use std::{fs, str::FromStr};
//
//     use ark_ff::BigInt;
//     use bitcoin::{block::Header, Block};
//     use sp1_verifier::Groth16Verifier;
//     use strata_bridge_proof_protocol::BridgeProofInput;
//     use strata_primitives::l1::OutputRef;
//     use strata_state::l1::HeaderVerificationState;
//
//     use super::*;
//     use crate::bridge_poc::GROTH16_VERIFICATION_KEY;
//
//     #[derive(serde::Serialize, serde::Deserialize, Debug)]
//     pub struct CheckpointInputOld {
//         pub block: Block,
//         pub out_ref: OutputRef,
//     }
//
//     #[derive(serde::Serialize, serde::Deserialize, Debug)]
//     pub struct BridgeProofInputOld {
//         pub checkpoint_input: CheckpointInputOld,
//         pub payment_txn_block: Block,
//         pub claim_txn_block: Block,
//         pub payment_txn_idx: u32,
//         pub claim_txn_idx: u32,
//         pub ts_block_header: Header,
//         pub headers: Vec<Header>,
//         pub start_header_state: HeaderVerificationState,
//     }
//
//     #[test]
//     fn test_bridge_poc_groth16_vk() {
//         dbg!(GROTH16_VERIFICATION_KEY.clone());
//     }
//
//     #[test]
//     fn test_bridge_poc_groth16_prove() {
//         sp1_sdk::utils::setup_logger();
//         let bridge_proof_input: BridgeProofInput = bincode::deserialize(include_bytes!(
//             "../../protocol/inputs/bridge_proof_input.bin"
//         ))
//         .unwrap();
//         let strata_bridge_state: StrataBridgeState = borsh::from_slice(include_bytes!(
//             "../../protocol/inputs/strata_bridge_state.bin"
//         ))
//         .unwrap();
//
//         let input = bincode::serialize(&bridge_proof_input).unwrap();
//         let (proof, public_inputs, params) = prove(&input, strata_bridge_state).unwrap();
//
//         dbg!(&proof, &public_inputs, &params);
//     }
//
//     #[test]
//     fn test_bridge_poc_groth16_verify() {
//         let (mut sp1prf, sp1vk): (SP1ProofWithPublicValues, SP1VerifyingKey) =
//             bincode::deserialize(include_bytes!("../proof_data/proof_data.bin")).unwrap();
//
//         Groth16Verifier::verify(
//             &sp1prf.bytes(),
//             sp1prf.public_values.as_slice(),
//             &sp1vk.bytes32(),
//             &sp1_verifier::GROTH16_VK_BYTES,
//         )
//         .context("proof verification failed")
//         .unwrap();
//
//         let bridge_proof_public_params: BridgeProofPublicParams = sp1prf.public_values.read();
//         let groth16 = sp1prf.proof.try_as_groth_16().unwrap();
//         let proof = sp1::load_groth16_proof_from_bytes(&hex::decode(groth16.raw_proof).unwrap());
//         let public_inputs =
//             vec![Fr::from_bigint(BigInt::from_str(&groth16.public_inputs[1]).unwrap()).unwrap()];
//
//         dbg!(&bridge_proof_public_params);
//         dbg!(&proof);
//         dbg!(&public_inputs);
//     }
//
//     #[test]
//     fn test_prove() {
//         sp1_sdk::utils::setup_logger();
//
//         let bridge_proof_input: BridgeProofInput = bincode::deserialize(include_bytes!(
//             "../../protocol/inputs/bridge_proof_input.bin"
//         ))
//         .unwrap();
//         let strata_bridge_state: StrataBridgeState = borsh::from_slice(include_bytes!(
//             "../../protocol/inputs/strata_bridge_state.bin"
//         ))
//         .unwrap();
//
//         let proof_data = default_prove(bridge_proof_input, strata_bridge_state).unwrap();
//
//         fs::write(
//             "proof_data/proof_data.bin",
//             bincode::serialize(&proof_data).unwrap(),
//         )
//         .unwrap();
//     }
//
//     #[test]
//     fn test_verify() {
//         let (sp1prf, sp1vk): (SP1ProofWithPublicValues, SP1VerifyingKey) =
//             bincode::deserialize(include_bytes!("../proof_data/proof_data.bin")).unwrap();
//         Groth16Verifier::verify(
//             &sp1prf.bytes(),
//             sp1prf.public_values.as_slice(),
//             &sp1vk.bytes32(),
//             &sp1_verifier::GROTH16_VK_BYTES,
//         )
//         .expect("Invalid groth16 proof");
//     }
// }
