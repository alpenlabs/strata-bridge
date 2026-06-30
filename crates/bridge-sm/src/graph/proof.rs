//! Verification of bridge proofs against the graph the watchtower defends.

use ssz::Decode;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_proof::{BridgeProofOutput, OperatorClaimUnlock};
use strata_codec::decode_buf_exact;
use strata_predicate::PredicateKey;
use zkaleido::ProofReceipt;

/// Returns `true` if `proof` verifies under `predicate_key` and commits to the claim expected for
/// the graph identified by `graph_idx`.
pub(crate) fn verify_bridge_proof(
    graph_idx: GraphIdx,
    predicate_key: &PredicateKey,
    proof: &ProofReceipt,
) -> bool {
    // The SNARK must verify against the public values the prover committed.
    if predicate_key
        .verify_claim_witness(proof.public_values().as_bytes(), proof.proof().as_bytes())
        .is_err()
    {
        tracing::warn!(
            reason = "snark verification failed",
            "bridge proof rejected"
        );
        return false;
    }

    let Ok(output) = BridgeProofOutput::from_ssz_bytes(proof.public_values().as_bytes()) else {
        tracing::warn!(
            reason = "could not decode public values as BridgeProofOutput",
            "bridge proof rejected"
        );
        return false;
    };

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-3863>
    // Bind `output.total_pow` to a trusted chain-work threshold once "heavier chain mode" lands.
    // We have no threshold to compare against yet, so PoW stays unchecked.
    let _ = output.total_pow;

    // Bind the committed claim to the one this graph defends.
    let Ok(actual_claim) = decode_buf_exact::<OperatorClaimUnlock>(&output.claim_unlock) else {
        tracing::warn!(
            reason = "could not decode claim_unlock as OperatorClaimUnlock",
            "bridge proof rejected"
        );
        return false;
    };

    let expected_claim = OperatorClaimUnlock::new(graph_idx.deposit, graph_idx.operator);
    if actual_claim != expected_claim {
        tracing::warn!(
            ?expected_claim,
            ?actual_claim,
            reason = "claim does not match the defended graph",
            "bridge proof rejected"
        );
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use strata_codec::encode_to_vec;
    use strata_predicate::PredicateKey;
    use zkaleido::{Proof, ProofReceipt, PublicValues};

    use super::*;

    const DEPOSIT_IDX: u32 = 7;
    const OPERATOR_IDX: u32 = 3;

    fn receipt_for(deposit_idx: u32, operator_idx: u32) -> ProofReceipt {
        let claim_unlock =
            encode_to_vec(&OperatorClaimUnlock::new(deposit_idx, operator_idx)).unwrap();
        let output = BridgeProofOutput {
            total_pow: [0u8; 32],
            claim_unlock,
            mmr_idx: 0,
        };
        ProofReceipt::new(
            Proof::new(vec![]),
            PublicValues::new(ssz::Encode::as_ssz_bytes(&output)),
        )
    }

    fn graph_idx() -> GraphIdx {
        GraphIdx {
            deposit: DEPOSIT_IDX,
            operator: OPERATOR_IDX,
        }
    }

    #[test]
    fn rejects_invalid_snark() {
        let receipt = receipt_for(DEPOSIT_IDX, OPERATOR_IDX);
        assert!(!verify_bridge_proof(
            graph_idx(),
            &PredicateKey::never_accept(),
            &receipt
        ));
    }

    #[test]
    fn rejects_undecodable_public_values() {
        // Empty public values cannot decode into a `BridgeProofOutput`.
        let receipt = ProofReceipt::new(Proof::new(vec![]), PublicValues::new(vec![]));
        assert!(!verify_bridge_proof(
            graph_idx(),
            &PredicateKey::always_accept(),
            &receipt
        ));
    }

    #[test]
    fn accepts_valid_matching_claim() {
        let receipt = receipt_for(DEPOSIT_IDX, OPERATOR_IDX);
        assert!(verify_bridge_proof(
            graph_idx(),
            &PredicateKey::always_accept(),
            &receipt
        ));
    }

    #[test]
    fn rejects_valid_snark_with_wrong_operator() {
        let receipt = receipt_for(DEPOSIT_IDX, OPERATOR_IDX + 1);
        assert!(!verify_bridge_proof(
            graph_idx(),
            &PredicateKey::always_accept(),
            &receipt
        ));
    }

    #[test]
    fn rejects_valid_snark_with_wrong_deposit() {
        let receipt = receipt_for(DEPOSIT_IDX + 1, OPERATOR_IDX);
        assert!(!verify_bridge_proof(
            graph_idx(),
            &PredicateKey::always_accept(),
            &receipt
        ));
    }

    #[test]
    fn rejects_garbage_claim_bytes() {
        let output = BridgeProofOutput {
            total_pow: [0u8; 32],
            claim_unlock: vec![0xff; 3],
            mmr_idx: 0,
        };
        let receipt = ProofReceipt::new(
            Proof::new(vec![]),
            PublicValues::new(ssz::Encode::as_ssz_bytes(&output)),
        );
        assert!(!verify_bridge_proof(
            graph_idx(),
            &PredicateKey::always_accept(),
            &receipt
        ));
    }
}
