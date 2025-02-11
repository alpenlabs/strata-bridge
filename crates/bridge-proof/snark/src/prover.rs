use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use bitvm::groth16::g16;
use sp1_sdk::{HashableKey, SP1VerifyingKey};
use sp1_verifier::hash_public_inputs;
use strata_bridge_guest_builder::GUEST_BRIDGE_ELF;
use strata_bridge_proof_protocol2::{
    get_native_host, BridgeProofInput, BridgeProofOutput, BridgeProver,
};
use tracing::info;
use zkaleido::{ZkVmHost, ZkVmProver};
use zkaleido_sp1_adapter::{verify_groth16, SP1Host};

use crate::sp1;

pub fn sp1_prove(
    input: &BridgeProofInput,
) -> anyhow::Result<(g16::Proof, [Fr; 1], BridgeProofOutput)> {
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

    // SP1 prepends the raw Groth16 proof with the first 4 bytes of the groth16 vkey
    // The use of correct vkey is checked in verify_groth16 function above
    let proof = sp1::load_groth16_proof_from_bytes(&proof_receipt.proof().as_bytes()[4..]);
    let public_inputs = [Fr::from_be_bytes_mod_order(&hash_public_inputs(
        proof_receipt.public_values().as_bytes(),
    ))];
    info!(action = "loaded proof and public params");

    Ok((proof, public_inputs, output))
}

#[cfg(test)]
mod test {
    use borsh::BorshDeserialize;
    use prover_test_utils::{
        extract_test_headers, get_strata_checkpoint_tx, get_withdrawal_fulfillment_tx,
        header_verification_state, load_test_chainstate, load_test_rollup_params,
    };
    use strata_bridge_proof_protocol2::BridgeProofInput;
    use strata_primitives::buf::Buf64;

    use super::sp1_prove;

    fn get_input() -> BridgeProofInput {
        let sig_bytes: Vec<u8> = hex::decode("47d264910cb48a1ca933f4fc3f55188c0fda70cef1216cd38a887e169e7faed03fc49ffacd645dd11ba68bbb038a782d1b21875f0e6ebd7eb7816ee642e642f7").unwrap();
        let sig_buf64 = Buf64::try_from_slice(&sig_bytes).unwrap();

        BridgeProofInput {
            rollup_params: load_test_rollup_params(),
            headers: extract_test_headers(),
            chain_state: load_test_chainstate(),
            header_vs: header_verification_state(),
            deposit_idx: 0,
            strata_checkpoint_tx: get_strata_checkpoint_tx(),
            withdrawal_fulfillment_tx: get_withdrawal_fulfillment_tx(),
            op_signature: sig_buf64,
        }
    }

    #[test]
    fn test_sp1_prove() {
        let input = get_input();
        let res = sp1_prove(&input);
        assert!(res.is_ok());
    }
}
