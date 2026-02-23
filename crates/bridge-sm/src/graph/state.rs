//! The States for the Graph State Machine.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::Txid;
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::schnorr::Signature};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::game_graph::{DepositParams, GameGraphSummary};
use zkaleido::ProofReceipt;

/// The state of a pegout graph associated with a particular deposit.
/// Each graph is uniquely identified by the two-tuple (depositIdx, operatorIdx).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphState {
    /// A new deposit request has been identified.
    Created {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
    },
    /// The pegout graph for this deposit and operator has been generated.
    GraphGenerated {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,
    },
    /// All adaptors for this pegout graph have been verified.
    AdaptorsVerified {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, Vec<PubNonce>>,
    },
    /// All required nonces for this pegout graph have been collected.
    NoncesCollected {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, Vec<PubNonce>>,

        /// Aggregated nonces used to validate partial signatures.
        agg_nonces: Vec<AggNonce>,

        /// Partial signature from each operator.
        partial_signatures: BTreeMap<OperatorIdx, Vec<PartialSignature>>,
    },
    /// All required aggregate signatures for this pegout graph have been collected.
    GraphSigned {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,
    },
    /// The deposit associated with this pegout graph has been assigned.
    Assigned {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The operator assigned to fulfill the withdrawal.
        assignee: OperatorIdx,

        /// The block height deadline for the assignment.
        deadline: BitcoinBlockHeight,

        /// The descriptor of the withdrawal recipient.
        recipient_desc: Descriptor,
    },
    /// The pegout graph has been activated to initiate reimbursement (this is redundant w.r.t.
    /// to the DSM's `Fulfilled` state, but is included here in order to preserve relative
    /// independence of GSM to recognize faulty claims).
    Fulfilled {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction.
        fulfillment_txid: Txid,

        /// The block height at which the fulfillment transaction was confirmed.
        fulfillment_block_height: BitcoinBlockHeight,
    },
    /// The claim transaction has been posted on chain.
    Claimed {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        fulfillment_txid: Option<Txid>,

        /// The block height at which the fulfillment transaction was confirmed (None in faulty
        /// claim cases).
        fulfillment_block_height: Option<BitcoinBlockHeight>,

        /// The block height at which the claim transaction was confirmed.
        claim_block_height: BitcoinBlockHeight,
    },
    /// The contest transaction has been posted on chain.
    Contested {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        fulfillment_txid: Option<Txid>,

        /// The block height at which the fulfillment transaction was confirmed (None in faulty
        /// claim cases).
        fulfillment_block_height: Option<BitcoinBlockHeight>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,
    },
    /// The bridge proof transaction has been posted on chain.
    BridgeProofPosted {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the bridge proof transaction submitted on chain.
        bridge_proof_txid: Txid,

        /// The block height at which the bridge proof transaction was confirmed.
        bridge_proof_block_height: BitcoinBlockHeight,

        /// The bridge proof.
        proof: ProofReceipt,
    },
    /// The bridge proof timeout transaction has been posted on chain.
    BridgeProofTimedout {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected slash transaction.
        expected_slash_txid: Txid,

        /// The txid of the claim transaction.
        claim_txid: Txid,
    },
    /// A counterproof transaction has been posted on chain.
    CounterProofPosted {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph2::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txids of the counterproof transactions submitted on chain along with their
        /// confirmation heights.
        counterproofs_and_confs: BTreeMap<OperatorIdx, (Txid, BitcoinBlockHeight)>,

        /// The txids of the counterproof NACK transactions submitted on chain.
        counterproof_nacks: BTreeMap<OperatorIdx, Txid>,
    },
    /// All possible counterproof transactions have been NACK'd on chain.
    AllNackd {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected contested payout transaction.
        expected_payout_txid: Txid,

        /// The txid of the possible slash transaction.
        possible_slash_txid: Txid,
    },
    /// A counterproof has been ACK'd on chain.
    Acked {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected slash transaction.
        expected_slash_txid: Txid,

        /// The txid of the claim transaction.
        claim_txid: Txid,
    },
    /// The deposit output has been spent by either uncontested or contested payout.
    Withdrawn {
        /// The txid of the transaction (uncontested or contested payout) that spent the deposit
        /// output.
        payout_txid: Txid,
    },
    /// The operator has been slashed on chain.
    Slashed {
        /// The txid of the slash transaction.
        slash_txid: Txid,
    },
    /// The graph has been aborted due to the payout connector being spent.
    Aborted {
        /// Transaction ID of the payout connector spend that caused the abort.
        payout_connector_spend_txid: Txid,

        /// The reason for the abort.
        reason: String,
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

impl GraphState {
    /// Returns the height of the last processed Bitcoin block for this graph state.
    pub const fn last_processed_block_height(&self) -> Option<&BitcoinBlockHeight> {
        match self {
            GraphState::Created {
                last_block_height: block_height,
                ..
            }
            | GraphState::GraphGenerated {
                last_block_height: block_height,
                ..
            }
            | GraphState::AdaptorsVerified {
                last_block_height: block_height,
                ..
            }
            | GraphState::NoncesCollected {
                last_block_height: block_height,
                ..
            }
            | GraphState::GraphSigned {
                last_block_height: block_height,
                ..
            }
            | GraphState::Assigned {
                last_block_height: block_height,
                ..
            }
            | GraphState::Fulfilled {
                last_block_height: block_height,
                ..
            }
            | GraphState::Claimed {
                last_block_height: block_height,
                ..
            }
            | GraphState::Contested {
                last_block_height: block_height,
                ..
            }
            | GraphState::BridgeProofPosted {
                last_block_height: block_height,
                ..
            }
            | GraphState::BridgeProofTimedout {
                last_block_height: block_height,
                ..
            }
            | GraphState::CounterProofPosted {
                last_block_height: block_height,
                ..
            }
            | GraphState::AllNackd {
                last_block_height: block_height,
                ..
            }
            | GraphState::Acked {
                last_block_height: block_height,
                ..
            } => Some(block_height),
            GraphState::Withdrawn { .. }
            | GraphState::Slashed { .. }
            | GraphState::Aborted { .. } => {
                // Terminal states do not track block height
                None
            }
        }
    }
}
