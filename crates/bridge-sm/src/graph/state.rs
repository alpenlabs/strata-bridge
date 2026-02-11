//! The States for the Graph State Machine.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::{Txid, taproot::Signature};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PubNonce};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::game_graph::{GameGraph, GameGraphSummary};
use zkaleido::ProofReceipt;

/// The state of a pegout graph associated with a particular deposit.
/// Each graph is uniquely identified by the two-tuple (depositIdx, operatorIdx)
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphState {
    /// A new deposit request has been identified
    Created {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
    },
    /// The pegout graph for this deposit and operator has been generated
    GraphGenerated {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,
    },
    /// All adaptors for this pegout graph have been verified
    AdaptorsVerified {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// All required nonces for this pegout graph have been collected
    NoncesCollected {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Aggregated nonce used to validate partial signatures.
        agg_nonce: AggNonce,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,

        /// Partial signatures from operators for the deposit transaction.
        partial_signatures: BTreeMap<OperatorIdx, Signature>,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,
    },
    /// All required aggregate signatures for this pegout graph have been collected
    GraphSigned {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures per operator graph
        signature: Signature,
    },
    /// The deposit associated with this pegout graph has been assigned
    Assigned {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures per operator graph
        signature: Signature,

        /// The operator assigned to fulfill the withdrawal.
        assignee: OperatorIdx,

        /// The block height deadline for the assignment.
        deadline: BitcoinBlockHeight,

        /// The descriptor of the withdrawal recipient.
        recipient_desc: Descriptor,
    },
    /// The pegout graph has been activated to initiate reimbursement (this is redundant w.r.t.
    /// to the DSM's `Fulfilled` state, but is included here in order to preserve relative
    /// independence of GSM to recognize faulty claims)
    Fulfilled {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// The txid of the fulfillment transaction
        fulfillment_txid: Txid,

        /// The block height at which the fulfillment transaction was confirmed
        fulfillment_block_height: BitcoinBlockHeight,
    },
    /// The claim transaction has been posted on chain
    Claimed {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        fulfillment_txid: Option<Txid>,

        /// The block height at which the fulfillment transaction was confirmed (None in faulty
        /// claim cases).
        fulfillment_block_height: Option<BitcoinBlockHeight>,

        /// The block height at which the claim transaction was confirmed.
        claim_block_height: BitcoinBlockHeight,
    },
    /// The contest transaction has been posted on chain
    Contested {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        fulfillment_txid: Option<Txid>,

        /// The block height at which the fulfillment transaction was confirmed (None in faulty
        /// claim cases).
        fulfillment_block_height: Option<BitcoinBlockHeight>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,
    },
    /// The bridge proof transaction has been posted on chain
    BridgeProofPosted {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        fulfillment_txid: Option<Txid>,

        /// The block height at which the fulfillment transaction was confirmed (None in faulty
        /// claim cases).
        fulfillment_block_height: Option<BitcoinBlockHeight>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the bridge proof transaction submitted on chain.
        bridge_proof_txid: Txid,

        /// The block height at which the bridge proof transaction was confirmed.
        bridge_proof_block_height: BitcoinBlockHeight,

        /// The bridge proof.
        proof: ProofReceipt,
    },
    /// The bridge proof timeout transaction has been posted on chain
    BridgeProofTimedout {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        fulfillment_txid: Option<Txid>,

        /// The block height at which the fulfillment transaction was confirmed (None in faulty
        /// claim cases).
        fulfillment_block_height: Option<BitcoinBlockHeight>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected slash transaction.
        expected_slash_txid: Txid,

        /// The txid of the claim transaction.
        claim_txid: Txid,
    },
    /// A counterproof transaction has been posted on chain
    CounterProofPosted {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Collection of the transactions of a game.
        graph_data: GameGraph,

        /// Collection of the IDs of all transactions of a [`GameGraph`].
        graph_summary: GameGraphSummary,

        /// The block height at which the contest transaction was confirmed
        contest_block_height: BitcoinBlockHeight,

        /// The txids of the counterproof transactions submitted on chain along with their
        /// confirmation heights.
        counterproofs_and_confs: BTreeMap<OperatorIdx, (Txid, BitcoinBlockHeight)>,

        /// The txids of the counterproof NACK transactions submitted on chain.
        counterproof_nacks: BTreeMap<OperatorIdx, Txid>,
    },
    /// All possible counterproof transactions have been NACK'd on chain
    AllNackd {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// The block height at which the contest transaction was confirmed
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected contested payout transaction
        expected_payout_txid: Txid,

        /// The txid of the possible slash transaction
        possible_slash_txid: Txid,
    },
    /// A counterproof has been ACK'd on chain
    Acked {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// The block height at which the contest transaction was confirmed
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected slash transaction
        expected_slash_txid: Txid,

        /// The txid of the claim transaction
        claim_txid: Txid,
    },
    /// The deposit output has been spent by either uncontested or contested payout
    Withdrawn {
        /// The txid of the transaction (uncontested or contested payout) that spent the deposit
        /// output
        payout_txid: Txid,
    },
    /// The operator has been slashed on chain
    Slashed {
        /// The txid of the slash transaction.
        slash_txid: Txid,
    },
    /// The graph has been aborted due to the payout connector being spent
    Aborted {
        /// The reason for the abort.
        reason: AbortReason,
    },
}

impl GraphState {
    /// Constructs a new [`GraphState`] in the [`GraphState::Created`] variant.
    pub const fn new(block_height: BitcoinBlockHeight) -> Self {
        Self::Created {
            last_block_height: block_height,
        }
    }
}

impl Display for GraphState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            GraphState::Created { .. } => "Created",
            GraphState::GraphGenerated { .. } => "GraphGenerated",
            GraphState::AdaptorsVerified { .. } => "AdaptorsVerified",
            GraphState::NoncesCollected { .. } => "NoncesCollected",
            GraphState::GraphSigned { .. } => "GraphSigned",
            GraphState::Assigned { .. } => "Assigned",
            GraphState::Fulfilled { .. } => "Fulfilled",
            GraphState::Claimed { .. } => "Claimed",
            GraphState::Contested { .. } => "Contested",
            GraphState::BridgeProofPosted { .. } => "BridgeProofPosted",
            GraphState::BridgeProofTimedout { .. } => "BridgeProofTimedout",
            GraphState::CounterProofPosted { .. } => "CounterProofPosted",
            GraphState::AllNackd { .. } => "AllNackd",
            GraphState::Acked { .. } => "Acked",
            GraphState::Withdrawn { .. } => "Withdrawn",
            GraphState::Slashed { .. } => "Slashed",
            GraphState::Aborted { .. } => "Aborted",
        };
        write!(f, "{}", display_str)
    }
}
