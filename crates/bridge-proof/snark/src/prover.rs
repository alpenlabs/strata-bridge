use std::str::FromStr;

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use bitvm::groth16::g16;
use sp1_sdk::{HashableKey, SP1VerifyingKey};
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;
use strata_bridge_proof_protocol2::{
    get_native_host, BridgeProofInput, BridgeProofOutput, BridgeProver,
};
use tracing::info;
use zkaleido::{ZkVmHost, ZkVmProver};
use zkaleido_sp1_adapter::{verify_groth16, SP1Host};

use crate::sp1;

pub fn prove(input: &BridgeProofInput) -> anyhow::Result<(g16::Proof, [Fr; 1], BridgeProofOutput)> {
    info!(action = "simulating proof in native mode");
    let native_host = get_native_host();
    let _ = BridgeProver::prove(input, &native_host).expect("failed to assert proof statements");

    if std::env::var("SP1_PROVER").is_err() {
        panic!("Only network prover is supported");
    }

    info!(action = "generating proof");
    let host = SP1Host::init(GUEST_BRIDGE_ELF);
    let proof_receipt = BridgeProver::prove(input, &host)?;

    let vk: SP1VerifyingKey = bincode::deserialize(host.get_verification_key().as_bytes())?;

    info!(action = "verifying proof");
    verify_groth16(&proof_receipt, &vk.bytes32_raw()).context("proof verification failed")?;

    let output = BridgeProver::process_output::<SP1Host>(proof_receipt.public_values())?;

    let proof = sp1::load_groth16_proof_from_bytes(proof_receipt.proof().as_bytes());

    // TODO: fix this
    // let public_inputs =
    //     [Fr::from_bigint(BigInt::from_str(&groth16.public_inputs[1]).unwrap()).unwrap()];

    let public_inputs = [Fr::from_bigint(BigInt::from_str("0").unwrap()).unwrap()];

    Ok((proof, public_inputs, output))
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
