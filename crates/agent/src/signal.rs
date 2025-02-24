use bitcoin::Txid;
use musig2::{AggNonce, PartialSignature, PubNonce};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::peg_out_graph::PegOutGraphInput;

#[derive(Debug, Clone)]
pub enum DepositSignal {
    /// Sent by signers to each other.
    Nonce {
        txid: Txid,
        pubnonce: PubNonce,
        sender_id: OperatorIdx,
    },

    /// Sent by signers to each other.
    Signature {
        txid: Txid,
        signature: PartialSignature,
        sender_id: OperatorIdx,
    },
}

#[derive(Debug, Clone)]
pub enum WatcherSignal {
    /// Sent by bitcoin watcher to disprover
    AssertChainAvailable {
        claim_txid: Txid,
        pre_assrt_txid: Txid,
        assert_data_txid: Txid,
        post_assert_txid: Txid,
    },
    // Add other signals like: `ChallengeReceived`
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CovenantNonceSignal {
    /// Sent by operators to signers.
    Request {
        details: CovenantNonceRequest,

        // metadata
        sender_id: OperatorIdx,
    },

    /// Sent by signers to operators.
    RequestFulfilled {
        details: CovenantNonceRequestFulfilled,

        // metadata
        sender_id: OperatorIdx,
        destination_id: OperatorIdx,
    },
}

#[derive(Debug, Clone)]
pub struct CovenantNonceRequest {
    pub peg_out_graph_input: PegOutGraphInput, // single field struct created for consistency
}

#[derive(Debug, Clone)]
pub struct CovenantNonceRequestFulfilled {
    pub pre_assert: PubNonce,
    pub post_assert: PubNonce,
    pub disprove: PubNonce,
    pub payout_0: PubNonce, // requires key-spend key aggregation
    pub payout_1: PubNonce, // requires script-spend key aggregation
    pub payout_2: PubNonce, // requires key-spend key aggregation with tweak
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CovenantSignatureSignal {
    /// Sent by operators to signers.
    Request {
        details: CovenantSigRequest,

        // metadata
        sender_id: OperatorIdx,
    },

    /// Sent by signers to operators.
    RequestFulfilled {
        details: CovenantSigRequestFulfilled,

        // metadata
        sender_id: OperatorIdx,
        destination_id: OperatorIdx,
    },
}

#[derive(Debug, Clone)]
pub struct CovenantSigRequest {
    pub peg_out_graph_input: PegOutGraphInput,
    pub agg_nonces: AggNonces,
}

#[derive(Debug, Clone)]
pub struct CovenantSigRequestFulfilled {
    pub pre_assert: Vec<PartialSignature>,
    pub post_assert: Vec<PartialSignature>, // for each of the inputs
    pub disprove: Vec<PartialSignature>,
    pub payout: Vec<PartialSignature>,
}

#[derive(Debug, Clone)]
pub struct AggNonces {
    pub pre_assert: AggNonce,
    pub post_assert: AggNonce,
    pub disprove: AggNonce,
    pub payout_0: AggNonce,
    pub payout_1: AggNonce,
}
