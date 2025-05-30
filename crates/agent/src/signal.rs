//! Signals for the agent.

use bitcoin::Txid;
use musig2::{AggNonce, PartialSignature, PubNonce};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::peg_out_graph::PegOutGraphInput;

/// The deposit signal.
#[derive(Debug, Clone)]
pub enum DepositSignal {
    /// Sent by signers to each other for a nonce.
    Nonce {
        /// The transaction ID.
        txid: Txid,

        /// The public nonce.
        pubnonce: PubNonce,

        /// The sender ID.
        sender_id: OperatorIdx,
    },

    /// Sent by signers to each other.
    Signature {
        /// The transaction ID.
        txid: Txid,

        /// The partial signature.
        signature: PartialSignature,

        /// The sender ID.
        sender_id: OperatorIdx,
    },
}

/// The watcher signal.
#[derive(Debug, Clone)]
pub enum WatcherSignal {
    /// Sent by bitcoin watcher to disprover for a claim.
    AssertChainAvailable {
        /// The claim transaction ID.
        claim_txid: Txid,

        /// The pre-assert transaction ID.
        pre_assrt_txid: Txid,

        /// The assert data transaction ID.
        assert_data_txid: Txid,

        /// The post-assert transaction ID.
        post_assert_txid: Txid,
    },
}

/// The covenant nonce signal.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CovenantNonceSignal {
    /// Sent by operators to signers for a nonce.
    Request {
        /// The covenant nonce request.
        details: CovenantNonceRequest,

        /// The sender ID.
        sender_id: OperatorIdx,
    },

    /// Sent by signers to operators for a nonce.
    RequestFulfilled {
        /// The covenant nonce request fulfilled.
        details: CovenantNonceRequestFulfilled,

        /// The sender ID.
        sender_id: OperatorIdx,

        /// The destination ID.
        destination_id: OperatorIdx,
    },
}

/// The covenant nonce request.
#[derive(Debug, Clone)]
pub struct CovenantNonceRequest {
    /// The peg-out graph input.
    pub peg_out_graph_input: PegOutGraphInput, // single field struct created for consistency
}

/// The covenant nonce request fulfilled.
#[derive(Debug, Clone)]
pub struct CovenantNonceRequestFulfilled {
    /// The pre-assert nonce.
    pub pre_assert: PubNonce,

    /// The post-assert nonce.
    pub post_assert: PubNonce,

    /// The disprove nonce.
    pub disprove: PubNonce,

    /// The payout nonce index 0.
    pub payout_0: PubNonce, // requires key-spend key aggregation

    /// The payout nonce index 1.
    pub payout_1: PubNonce, // requires script-spend key aggregation

    /// The payout nonce index 2.
    pub payout_2: PubNonce, // requires key-spend key aggregation

    /// The payout nonce index 3.
    pub payout_3: PubNonce, // requires key-spend key aggregation with tweak
}

/// The covenant signature signal.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CovenantSignatureSignal {
    /// Sent by operators to signers.
    Request {
        /// The covenant signature request.
        details: CovenantSigRequest,

        /// The sender ID.
        sender_id: OperatorIdx,
    },

    /// Sent by signers to operators.
    RequestFulfilled {
        /// The covenant signature request fulfilled.
        details: CovenantSigRequestFulfilled,

        /// The sender ID.
        sender_id: OperatorIdx,

        /// The destination ID.
        destination_id: OperatorIdx,
    },
}

/// The covenant signature request.
#[derive(Debug, Clone)]
pub struct CovenantSigRequest {
    /// The peg-out graph input.
    pub peg_out_graph_input: PegOutGraphInput,

    /// The aggregated nonces.
    pub agg_nonces: AggNonces,
}

/// The covenant signature request fulfilled.
#[derive(Debug, Clone)]
pub struct CovenantSigRequestFulfilled {
    /// The pre-assert partial signatures.
    pub pre_assert: Vec<PartialSignature>,

    /// The post-assert partial signatures.
    pub post_assert: Vec<PartialSignature>,

    /// The disprove partial signatures.
    pub disprove: Vec<PartialSignature>,

    /// The payout partial signatures.
    pub payout: Vec<PartialSignature>,
}

/// The aggregated nonces.
#[derive(Debug, Clone)]
pub struct AggNonces {
    /// The pre-assert nonce.
    pub pre_assert: AggNonce,

    /// The post-assert nonce.
    pub post_assert: AggNonce,

    /// The disprove nonce.
    pub disprove: AggNonce,

    /// The payout nonce index 0.
    pub payout_0: AggNonce,

    /// The payout nonce index 1.
    pub payout_1: AggNonce,

    /// The payout nonce index 2.
    pub payout_2: AggNonce,

    /// The payout nonce index 3.
    pub payout_3: AggNonce,
}
