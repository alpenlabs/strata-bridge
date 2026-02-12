//! The duties that need to be performed in the Graph State Machine in response to the state
//! transitions.

use bitcoin::{Transaction, Txid};
use musig2::{AggNonce, secp256k1::Message};
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};
use zkaleido::ProofReceipt;

/// The duties that need to be performed to drive the Graph State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphDuty {
    /// Verify the adaptor signatures for the generated graph.
    VerifyAdaptors(Vec<Message>),

    /// Publish nonces for graph signing.
    PublishGraphNonces {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,
    },

    /// Publish partial signatures for graph signing.
    PublishGraphPartials {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,

        /// Aggregated nonce to be used for partial signature generation.
        agg_nonce: AggNonce,

        /// The txid of the claim transaction (must not exist on chain before signing).
        claim_txid: Txid,
    },

    /// Publish the claim transaction on-chain.
    PublishClaim {
        /// The claim transaction to publish.
        claim_txid: Transaction,
    },

    /// Publish the uncontested payout transaction.
    PublishUncontestedPayout {
        /// The uncontested payout transaction
        uncontested_payout_txid: Transaction,
    },

    /// Publish the contest transaction on-chain in response to a faulty claim.
    PublishContest {
        /// The claim transaction being contested.
        claim_txid: Transaction,
    },

    /// Publish a bridge proof on-chain to defend against a contest.
    PublishBridgeProof {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,
    },

    /// Publish a bridge proof timeout transaction.
    PublishBridgeProofTimeout {
        /// The bridge proof timeout transaction to be published.
        timeout_tx: Transaction,
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

    /// Publish a counterproof ACK transaction.
    PublishCounterProofAck {
        /// The counterproof ACK transaction to be published.
        counter_proof_ack_tx: Transaction,
    },

    /// Publish a counterproof NACK on-chain to reject an invalid counterproof.
    PublishCounterProofNack {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator who submitted the counterproof.
        counter_prover_idx: OperatorIdx,
    },

    /// Publish a slash transaction.
    PublishSlash {
        /// The slash transaction to be published.
        slash_tx: Transaction,
    },

    /// Publish a contested payout transaction.
    PublishContestedPayout {
        /// The contested payout transaction to be published.
        contested_payout_tx: Transaction,
    },
}
