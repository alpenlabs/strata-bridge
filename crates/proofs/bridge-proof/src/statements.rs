//! Bridge proof statements.

use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_bridge_proof_common::{verify_claim_unlock_inclusion, verify_moho_proof};
use strata_codec::decode_buf_exact;
use zkaleido::{ZkVmEnv, ZkVmEnvSsz};

#[cfg(not(target_os = "zkvm"))]
use crate::genesis::load_genesis_from_env;
use crate::types::{BridgeProofGenesis, BridgeProofInput, BridgeProofOutput};

/// Native entry point: loads genesis and runs the bridge proof.
#[cfg(not(target_os = "zkvm"))]
pub fn process_bridge_proof(zkvm: &impl ZkVmEnv) {
    let genesis = load_genesis_from_env();
    process_bridge_proof_inner(zkvm, &genesis);
}

/// zkVM entry point: runs the bridge proof.
#[cfg(target_os = "zkvm")]
pub fn process_bridge_proof(zkvm: &impl ZkVmEnv, genesis: BridgeProofGenesis) {
    process_bridge_proof_inner(zkvm, &genesis);
}

/// Reads the SSZ input, verifies it against `genesis`, and commits the output.
///
/// Steps:
/// 1. Decode `BridgeProofInput` from the zkVM environment.
/// 2. Verify the recursive Moho proof against genesis params.
/// 3. Verify the operator claim unlock is included in the bridge-v1 export-entries MMR.
/// 4. Commit `BridgeProofOutput` as public values.
fn process_bridge_proof_inner(zkvm: &impl ZkVmEnv, genesis: &BridgeProofGenesis) {
    // 1: Decode BridgeProofInput from the zkVM environment.
    let BridgeProofInput {
        moho_state,
        moho_proof,
        claim_unlock,
        claim_unlock_inclusion_proof,
    } = zkvm.read_ssz();
    let claim_unlock_typed: OperatorClaimUnlock = decode_buf_exact(&claim_unlock)
        .expect("invalid bridge proof: invalid encoding of claim unlock");

    // 2: Verify the recursive Moho proof.
    verify_moho_proof(
        &moho_state,
        &moho_proof,
        genesis.genesis_moho_state.reference(),
        genesis.moho_vk.clone(),
        "invalid bridge proof: invalid moho proof",
    );

    // Extract the bridge-v1 export container from the Moho state.
    let bridge_container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
        .expect("invalid bridge proof: moho state doesn't contain bridge-v1 export container");

    // 3: Verify the operator claim is included in the bridge-v1 MMR.
    verify_claim_unlock_inclusion(
        &claim_unlock_typed,
        bridge_container,
        &claim_unlock_inclusion_proof,
        "invalid bridge proof: invalid inclusion proof for claim unlock",
    );

    // 4: Commit public values.
    zkvm.commit_ssz(&BridgeProofOutput {
        total_pow: *bridge_container.extra_data(),
        claim_unlock,
        mmr_idx: claim_unlock_inclusion_proof.index(),
    });
}

#[cfg(test)]
mod tests {
    use moho_types::{ExportContainer, MohoState};
    use ssz::{Decode, Encode};
    use strata_bridge_proof_common::{MOHO_GENESIS_ATTESTATION, generate_moho_state};
    use strata_codec::encode_to_vec;
    use strata_predicate::PredicateKey;
    use zkaleido_native_adapter::NativeMachine;

    use super::*;

    // Builds a minimal genesis with always-accept predicates
    fn make_genesis() -> BridgeProofGenesis {
        BridgeProofGenesis {
            moho_vk: PredicateKey::always_accept(),
            genesis_moho_state: *MOHO_GENESIS_ATTESTATION,
        }
    }

    // Runs BridgeProofInput through the zkVM and returns the committed output.
    fn run_bridge_proof(
        genesis: &BridgeProofGenesis,
        input: BridgeProofInput,
    ) -> BridgeProofOutput {
        let mut machine = NativeMachine::new();
        machine.write_slice(input.as_ssz_bytes());
        process_bridge_proof_inner(&machine, genesis);
        BridgeProofOutput::from_ssz_bytes(&machine.state.borrow().output).unwrap()
    }

    fn bridge_container(moho_state: &MohoState) -> &ExportContainer {
        moho_state
            .export_state()
            .containers()
            .iter()
            .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
            .expect("moho_state must contain a bridge-v1 export container")
    }

    #[test]
    fn test_claim_unlock_inclusion_success() {
        let claim = OperatorClaimUnlock::new(0, 0);
        let (moho_state, _, [proof]) = generate_moho_state([claim.clone()], [0u8; 32]);
        verify_claim_unlock_inclusion(
            &claim,
            bridge_container(&moho_state),
            &proof,
            "claim_unlock must be included in the bridge-v1 MMR",
        );
    }

    #[test]
    #[should_panic(expected = "invalid bridge proof: invalid inclusion proof for claim unlock")]
    fn test_claim_unlock_inclusion_wrong_claim() {
        let claim = OperatorClaimUnlock::new(0, 0);
        let other = OperatorClaimUnlock::new(1, 1);
        let (moho_state, _, [proof]) = generate_moho_state([claim], [0u8; 32]);
        verify_claim_unlock_inclusion(
            &other,
            bridge_container(&moho_state),
            &proof,
            "invalid bridge proof: invalid inclusion proof for claim unlock",
        );
    }

    #[test]
    fn test_process_bridge_proof_inner_success() {
        let genesis = make_genesis();
        let claim = OperatorClaimUnlock::new(42, 7);
        let (moho_state, moho_proof, [inclusion_proof]) =
            generate_moho_state([claim.clone()], [0u8; 32]);
        let input = BridgeProofInput {
            moho_state,
            moho_proof,
            claim_unlock: encode_to_vec(&claim).unwrap(),
            claim_unlock_inclusion_proof: inclusion_proof,
        };

        let output = run_bridge_proof(&genesis, input);
        assert_eq!(output.claim_unlock, encode_to_vec(&claim).unwrap());
        assert_eq!(output.mmr_idx, 0);
        assert_eq!(output.total_pow, [0u8; 32]);
    }

    #[test]
    fn test_process_bridge_proof_inner_non_zero_mmr_idx() {
        let genesis = make_genesis();
        let claims = [
            OperatorClaimUnlock::new(10, 0),
            OperatorClaimUnlock::new(20, 1),
        ];
        let (moho_state, moho_proof, inclusion_proofs) =
            generate_moho_state(claims.clone(), [0u8; 32]);
        let input = BridgeProofInput {
            moho_state,
            moho_proof,
            claim_unlock: encode_to_vec(&claims[1]).unwrap(),
            claim_unlock_inclusion_proof: inclusion_proofs[1].clone(),
        };

        let output = run_bridge_proof(&genesis, input);
        assert_eq!(output.claim_unlock, encode_to_vec(&claims[1]).unwrap());
        assert_eq!(output.mmr_idx, 1);
        assert_eq!(output.total_pow, [0u8; 32]);
    }
}
