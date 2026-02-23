//! The duties that need to be performed in the Graph State Machine in response to the state
//! transitions.

use bitcoin::{OutPoint, Transaction, Txid};
use musig2::{AggNonce, secp256k1::Message};
use strata_bridge_primitives::{
    mosaic::Labels,
    scripts::taproot::TaprootTweak,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use zkaleido::ProofReceipt;

/// The duties that need to be performed to drive the Graph State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphDuty {
    /// Generate the data required to generate the graph.
    ///
    /// Generation of these data require communicating with external service in an effectful way.
    GenerateGraphData {
        /// The index of the graph this duty is associated with.
        graph_idx: GraphIdx,
    },

    /// Verify the adaptor signatures for the generated graph.
    VerifyAdaptors {
        /// The index of the graph this duty is associated with.
        graph_idx: GraphIdx,

        /// Wathchtower index to verify adaptors for.
        watchtower_idx: OperatorIdx,

        /// Sighashes to verify adaptors against
        sighashes: Vec<Message>,
    },

    /// Publish nonces for graph signing.
    PublishGraphNonces {
        /// The index of the graph this duty is associated with.
        graph_idx: GraphIdx,

        /// The inpoints of the graph used to retrieve musig2 session per input being signed.
        graph_inpoints: Vec<OutPoint>,

        /// The tweak required for taproot spend per input being signed.
        graph_tweaks: Vec<TaprootTweak>,
    },

    /// Publish partial signatures for graph signing.
    PublishGraphPartials {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,

        /// Aggregated nonces to be used for partial signature generation.
        agg_nonces: Vec<AggNonce>,

        /// Sighashes to sign.
        sighashes: Vec<Message>,

        /// The inpoints of the graph used to retrieve musig2 session per input being signed.
        graph_inpoints: Vec<OutPoint>,

        /// The tweak required for taproot spend per input being signed.
        graph_tweaks: Vec<TaprootTweak>,

        /// The txid of the claim transaction (must not exist on chain before signing).
        claim_txid: Txid,
    },

    /// Publish the claim transaction on-chain.
    PublishClaim {
        /// The signed claim transaction to publish.
        signed_claim_tx: Transaction,
    },

    /// Publish the uncontested payout transaction.
    PublishUncontestedPayout {
        /// The signed uncontested payout transaction to publish.
        signed_uncontested_payout_tx: Transaction,
    },

    /// Publish the contest transaction on-chain in response to a faulty claim.
    PublishContest {
        /// The signed contest transaction to publish.
        signed_contest_tx: Transaction,
    },

    /// Publish a bridge proof on-chain to defend against a contest.
    PublishBridgeProof {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,

        /// The bridge proof transaction to be published (unsigned).
        bridge_proof_tx: Transaction,
    },

    /// Publish a bridge proof timeout transaction.
    PublishBridgeProofTimeout {
        /// The signed bridge proof timeout transaction to be published.
        signed_timeout_tx: Transaction,
    },

    /// Publish a counterproof on-chain to challenge a bridge proof.
    PublishCounterProof {
        /// The index of the deposit this graph is associated with.
        deposit_idx: u32,

        /// The index of the operator this graph belongs to.
        operator_idx: OperatorIdx,

        /// The counterproof transaction to be published (unsigned; signed via adaptors).
        counterproof_tx: Transaction,

        /// The bridge proof to counter.
        proof: ProofReceipt,
    },

    /// Publish a counterproof ACK transaction.
    PublishCounterProofAck {
        /// The signed counterproof ACK transaction to be published.
        signed_counter_proof_ack_tx: Transaction,
    },

    /// Publish a counterproof NACK on-chain to reject an invalid counterproof.
    PublishCounterProofNack {
        /// The index of the deposit this graph is associated with.
        deposit_idx: DepositIdx,

        /// The index of the operator who submitted the counterproof.
        counter_prover_idx: OperatorIdx,

        /// The counterproof NACK transaction to be published (unsigned; signed by mosaic after GC
        /// evaluation).
        counterproof_nack_tx: Transaction,

        /// The labels committed in the counterproof.
        labels: Vec<Labels>,
    },

    /// Publish a slash transaction.
    PublishSlash {
        /// The signed slash transaction to be published.
        signed_slash_tx: Transaction,
    },

    /// Publish a contested payout transaction.
    PublishContestedPayout {
        /// The signed contested payout transaction to be published.
        signed_contested_payout_tx: Transaction,
    },
}

impl std::fmt::Display for GraphDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GraphDuty::GenerateGraphData { .. } => "GenerateGraphData".to_string(),
            GraphDuty::VerifyAdaptors { .. } => "VerifyAdaptors".to_string(),
            GraphDuty::PublishGraphNonces { .. } => "PublishGraphNonces".to_string(),
            GraphDuty::PublishGraphPartials { .. } => "PublishGraphPartials".to_string(),
            GraphDuty::PublishClaim { .. } => "PublishClaim".to_string(),
            GraphDuty::PublishUncontestedPayout { .. } => "PublishUncontestedPayout".to_string(),
            GraphDuty::PublishContest { .. } => "PublishContest".to_string(),
            GraphDuty::PublishBridgeProof { .. } => "PublishBridgeProof".to_string(),
            GraphDuty::PublishBridgeProofTimeout { .. } => "PublishBridgeProofTimeout".to_string(),
            GraphDuty::PublishCounterProof { .. } => "PublishCounterProof".to_string(),
            GraphDuty::PublishCounterProofAck { .. } => "PublishCounterProofAck".to_string(),
            GraphDuty::PublishCounterProofNack { .. } => "PublishCounterProofNack".to_string(),
            GraphDuty::PublishSlash { .. } => "PublishSlash".to_string(),
            GraphDuty::PublishContestedPayout { .. } => "PublishContestedPayout".to_string(),
        };
        write!(f, "{s}")
    }
}
