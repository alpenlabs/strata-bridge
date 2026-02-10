//! The duties that need to be performed in the Graph State Machine in response to the state
//! transitions.

use bitcoin::Txid;
use musig2::AggNonce;
use strata_bridge_primitives::types::OperatorIdx;
use zkaleido::ProofReceipt;

/// The duties that need to be performed to drive the Graph State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphDuty {
    /// Verify the adaptor signatures for the generated graph.
    VerifyAdaptors,

    /// Publish nonces for graph signing.
    PublishGraphNonces {
        /// The index of the deposit this graph is associated with.
        deposit_idx: u32,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,
    },

    /// Publish partial signatures for graph signing.
    PublishGraphPartials {
        /// The index of the deposit this graph is associated with.
        deposit_idx: u32,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,

        /// Aggregated nonce to be used for partial signature generation.
        agg_nonce: AggNonce,

        /// The txid of the claim transaction (must not exist on chain before signing).
        claim_txid: Txid,
    },

    /// Publish the claim transaction on-chain.
    PublishClaim {
        /// The txid of the claim transaction to publish.
        claim_txid: Txid,
    },

    /// Publish the contest transaction on-chain in response to a faulty claim.
    PublishContest {
        /// The txid of the claim transaction being contested.
        claim_txid: Txid,
    },

    /// Publish a bridge proof on-chain to defend against a contest.
    PublishBridgeProof {
        /// The index of the deposit this graph is associated with.
        deposit_idx: u32,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,
    },

    /// Publish a counterproof on-chain to challenge a bridge proof.
    PublishCounterProof {
        /// The index of the deposit this graph is associated with.
        deposit_idx: u32,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,

        /// The bridge proof to counter.
        proof: ProofReceipt,
    },

    /// Publish a counterproof NACK on-chain to reject an invalid counterproof.
    PublishCounterProofNack {
        /// The index of the deposit this graph is associated with.
        deposit_idx: u32,

        /// The index of the operator who submitted the counterproof.
        counter_prover_idx: OperatorIdx,
    },
}
