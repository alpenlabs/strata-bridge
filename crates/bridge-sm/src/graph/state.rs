//! The States for the Graph State Machine.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::{Transaction, Txid};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::schnorr::Signature};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph::game_graph::{DepositParams, GameGraphSummary};
use strata_mosaic_client_api::types::CompletedSignatures;
use zkaleido::ProofReceipt;

/// Reason why a graph was [`Aborted`](GraphState::Aborted).
///
/// Each variant precisely describes the on-chain spends that were known at the
/// moment the GSM transitioned to `Aborted`. The `Both` variant is reached
/// when the GSM is driven into `Aborted` by the second spend arriving at a
/// state that was already holding the first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    /// The payout connector was consumed by a transaction other than the
    /// legitimate payout (e.g. unstaking-burn or admin-burn), while the
    /// stake outpoint remained unspent at the time of abort.
    PayoutConnectorSpent {
        /// Txid of the transaction that consumed the payout connector.
        spending_txid: Txid,
    },
    /// The stake outpoint was consumed by a transaction other than this
    /// graph's slash (a sibling graph's slash, the operator's unstaking,
    /// etc.), while the payout connector remained unspent at the time of
    /// abort.
    StakeSpent {
        /// Txid of the transaction that consumed the stake outpoint.
        spending_txid: Txid,
    },
    /// Both the payout connector and the stake outpoint have been consumed.
    Both {
        /// Txid of the transaction that consumed the payout connector.
        payout_connector_spending_txid: Txid,
        /// Txid of the transaction that consumed the stake outpoint.
        stake_spending_txid: Txid,
    },
}

impl AbortReason {
    /// Builds the variant that matches the `(stake, connector)` spend status.
    /// Returns `None` if neither spend has occurred (an invalid abort).
    pub const fn from_spends(
        stake_spending_txid: Option<Txid>,
        payout_connector_spending_txid: Option<Txid>,
    ) -> Option<Self> {
        match (stake_spending_txid, payout_connector_spending_txid) {
            (Some(stake_spending_txid), Some(payout_connector_spending_txid)) => Some(Self::Both {
                payout_connector_spending_txid,
                stake_spending_txid,
            }),
            (Some(spending_txid), None) => Some(Self::StakeSpent { spending_txid }),
            (None, Some(spending_txid)) => Some(Self::PayoutConnectorSpent { spending_txid }),
            (None, None) => None,
        }
    }
}

/// On-chain record of a confirmed counterproof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterproofData {
    /// Txid of the confirmed counterproof.
    pub txid: Txid,
    /// Bitcoin block height at which it confirmed.
    pub conf_height: BitcoinBlockHeight,
    /// Per-byte operator signatures decoded from the counterproof witness.
    #[serde(with = "BigArray")]
    pub completed_signatures: CompletedSignatures,
}

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
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,
    },
    /// All adaptors for this pegout graph have been verified.
    AdaptorsVerified {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
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
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, Vec<PubNonce>>,

        /// Aggregated nonces used to validate partial signatures.
        agg_nonces: Vec<AggNonce>,

        /// Partial signature from each operator.
        partial_signatures: BTreeMap<OperatorIdx, Vec<PartialSignature>>,

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,
    },
    /// All required aggregate signatures for this pegout graph have been collected.
    GraphSigned {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game's transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated nonces retained to respond to nag for graph partial signatures.
        ///
        /// This is `Some` when the state was reached via the normal signing flow
        /// (`NoncesCollected` -> `GraphSigned`) and `None` when reached via reversion
        /// from `Assigned` (when a different assignee is assigned). The presence of
        /// `agg_nonces` determines whether the GSM should respond to nag requests for
        /// graph partials.
        agg_nonces: Option<Vec<AggNonce>>,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,
    },
    /// The deposit associated with this pegout graph has been assigned.
    Assigned {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game's transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The operator assigned to fulfill the withdrawal.
        assignee: OperatorIdx,

        /// The block height deadline for the assignment.
        deadline: BitcoinBlockHeight,

        /// The descriptor of the withdrawal recipient.
        recipient_desc: Descriptor,

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,
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
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Whether the cooperative payout has failed and the unilateral claim path is activated.
        coop_payout_failed: bool,

        /// The operator who fulfilled the withdrawal.
        assignee: OperatorIdx,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction.
        fulfillment_txid: Txid,

        /// The block height at which the fulfillment transaction was confirmed.
        fulfillment_block_height: BitcoinBlockHeight,

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,
    },
    /// The claim transaction has been posted on chain.
    Claimed {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
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

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,

        /// Set when the payout connector is consumed by something other than
        /// the legitimate payout.
        payout_connector_spent: Option<Txid>,
    },
    /// The contest transaction has been posted on chain.
    Contested {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
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

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,

        /// Set when the payout connector is consumed by something other than
        /// the legitimate payout.
        payout_connector_spent: Option<Txid>,
    },
    /// The bridge proof transaction has been posted on chain.
    BridgeProofPosted {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        // NOTE: (@Rajil1213) this field is required purely for monitoring/introspection purposes.
        fulfillment_txid: Option<Txid>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The bridge proof transaction submitted on chain.
        bridge_proof_tx: Transaction,

        /// The block height at which the bridge proof transaction was confirmed.
        bridge_proof_block_height: BitcoinBlockHeight,

        /// The bridge proof.
        proof: ProofReceipt,

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,

        /// Set when the payout connector is consumed by something other than
        /// the legitimate payout.
        payout_connector_spent: Option<Txid>,
    },
    /// The bridge proof timeout transaction has been posted on chain.
    BridgeProofTimedout {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Collection of the IDs of all transactions of a
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        // NOTE: (@Rajil1213) this field is required purely for monitoring/introspection purposes.
        fulfillment_txid: Option<Txid>,

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
        /// [`strata_bridge_tx_graph::game_graph::GameGraph`].
        graph_summary: GameGraphSummary,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        // NOTE: (@Rajil1213) this field is required purely for monitoring/introspection purposes.
        fulfillment_txid: Option<Txid>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The bridge proof transaction and its receipt currently being refuted, if one has
        /// been posted.
        refuted_bridge_proof: Option<(Transaction, ProofReceipt)>,

        /// Per-counterprover record of confirmed counterproofs.
        counterproofs_and_confs: BTreeMap<OperatorIdx, CounterproofData>,

        /// The txids of the counterproof NACK transactions submitted on chain.
        counterproof_nacks: BTreeMap<OperatorIdx, Txid>,

        /// Set when the stake outpoint is consumed by something other than
        /// this graph's slash.
        stake_spent: Option<Txid>,

        /// Set when the payout connector is consumed by something other than
        /// the legitimate payout.
        payout_connector_spent: Option<Txid>,
    },
    /// All possible counterproof transactions have been NACK’d on chain.
    AllNackd {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The transaction ID of the claim transaction.
        // NOTE: (@Rajil1213) this field is required purely for monitoring/introspection purposes.
        claim_txid: Txid,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        // NOTE: (@Rajil1213) this field is required purely for monitoring/introspection purposes.
        fulfillment_txid: Option<Txid>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected contested payout transaction.
        expected_payout_txid: Txid,

        /// The txid of the possible slash transaction.
        possible_slash_txid: Txid,
    },
    /// A counterproof has been ACK’d on chain.
    Acked {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Deposit-time data required to generate the game’s transaction graph.
        graph_data: DepositParams,

        /// Aggregated final signatures for the graph.
        signatures: Vec<Signature>,

        /// The block height at which the contest transaction was confirmed.
        contest_block_height: BitcoinBlockHeight,

        /// The txid of the expected slash transaction.
        expected_slash_txid: Txid,

        /// The txid of the claim transaction.
        claim_txid: Txid,

        /// The txid of the fulfillment transaction (None in faulty claim cases).
        // NOTE: (@Rajil1213) this field is required purely for monitoring/introspection purposes.
        fulfillment_txid: Option<Txid>,
    },
    /// The deposit output has been spent by either uncontested or contested payout.
    Withdrawn {
        /// The txid of the claim transaction associated with this reimbursement path.
        claim_txid: Txid,

        /// The txid of the transaction (uncontested or contested payout) that spent the deposit
        /// output.
        payout_txid: Txid,
    },
    /// The operator has been slashed on chain.
    Slashed {
        /// The txid of the claim transaction associated with this reimbursement path.
        claim_txid: Txid,

        /// The txid of the slash transaction.
        slash_txid: Txid,
    },
    /// The graph has been aborted because at least one of its on-chain
    /// dependencies has been consumed by something other than the
    /// expected transaction.
    Aborted {
        /// The txid of the claim transaction associated with this reimbursement path, if one
        /// exists.
        claim_txid: Option<Txid>,

        /// Why the graph was aborted, including the txid(s) of the
        /// triggering on-chain spend(s).
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

    /// Returns the recorded `stake_spent` txid for this state, if any.
    pub const fn stake_spent_txid(&self) -> Option<Txid> {
        match self {
            GraphState::NoncesCollected { stake_spent, .. }
            | GraphState::GraphSigned { stake_spent, .. }
            | GraphState::Assigned { stake_spent, .. }
            | GraphState::Fulfilled { stake_spent, .. }
            | GraphState::Claimed { stake_spent, .. }
            | GraphState::Contested { stake_spent, .. }
            | GraphState::BridgeProofPosted { stake_spent, .. }
            | GraphState::CounterProofPosted { stake_spent, .. } => *stake_spent,
            _ => None,
        }
    }

    /// Returns the recorded `payout_connector_spent` txid for this state, if any.
    pub const fn payout_connector_spent_txid(&self) -> Option<Txid> {
        match self {
            GraphState::Claimed {
                payout_connector_spent,
                ..
            }
            | GraphState::Contested {
                payout_connector_spent,
                ..
            }
            | GraphState::BridgeProofPosted {
                payout_connector_spent,
                ..
            }
            | GraphState::CounterProofPosted {
                payout_connector_spent,
                ..
            } => *payout_connector_spent,
            _ => None,
        }
    }

    /// Returns the txid of the claim transaction that initiated this reimbursement path, if known.
    pub const fn claim_txid(&self) -> Option<Txid> {
        match self {
            GraphState::GraphGenerated { graph_summary, .. }
            | GraphState::AdaptorsVerified { graph_summary, .. }
            | GraphState::NoncesCollected { graph_summary, .. }
            | GraphState::GraphSigned { graph_summary, .. }
            | GraphState::Fulfilled { graph_summary, .. }
            | GraphState::Assigned { graph_summary, .. }
            | GraphState::Claimed { graph_summary, .. }
            | GraphState::Contested { graph_summary, .. }
            | GraphState::BridgeProofPosted { graph_summary, .. }
            | GraphState::CounterProofPosted { graph_summary, .. } => Some(graph_summary.claim),

            GraphState::BridgeProofTimedout { claim_txid, .. }
            | GraphState::AllNackd { claim_txid, .. }
            | GraphState::Acked { claim_txid, .. }
            | GraphState::Slashed { claim_txid, .. }
            | GraphState::Withdrawn { claim_txid, .. } => Some(*claim_txid),

            GraphState::Aborted { claim_txid, .. } => *claim_txid,

            GraphState::Created { .. } => None,
        }
    }

    /// Returns the txid of the slash transaction that, if confirmed, would
    /// drive this graph to [`GraphState::Slashed`]. `None` for states from
    /// which slashing is not yet realizable.
    pub const fn expected_slash_txid(&self) -> Option<Txid> {
        match self {
            GraphState::Claimed { graph_summary, .. }
            | GraphState::Contested { graph_summary, .. }
            | GraphState::BridgeProofPosted { graph_summary, .. }
            | GraphState::CounterProofPosted { graph_summary, .. } => Some(graph_summary.slash),
            GraphState::BridgeProofTimedout {
                expected_slash_txid,
                ..
            }
            | GraphState::Acked {
                expected_slash_txid,
                ..
            } => Some(*expected_slash_txid),
            GraphState::AllNackd {
                possible_slash_txid,
                ..
            } => Some(*possible_slash_txid),
            _ => None,
        }
    }

    /// Records `stake_spent`. Returns `false` if the current state does not
    /// carry the field.
    pub const fn set_stake_spent(&mut self, txid: Txid) -> bool {
        match self {
            GraphState::NoncesCollected { stake_spent, .. }
            | GraphState::GraphSigned { stake_spent, .. }
            | GraphState::Assigned { stake_spent, .. }
            | GraphState::Fulfilled { stake_spent, .. }
            | GraphState::Claimed { stake_spent, .. }
            | GraphState::Contested { stake_spent, .. }
            | GraphState::BridgeProofPosted { stake_spent, .. }
            | GraphState::CounterProofPosted { stake_spent, .. } => {
                *stake_spent = Some(txid);
                true
            }
            _ => false,
        }
    }

    /// Records `payout_connector_spent`. Returns `false` if the current state
    /// does not carry the field.
    pub const fn set_payout_connector_spent(&mut self, txid: Txid) -> bool {
        match self {
            GraphState::Claimed {
                payout_connector_spent,
                ..
            }
            | GraphState::Contested {
                payout_connector_spent,
                ..
            }
            | GraphState::BridgeProofPosted {
                payout_connector_spent,
                ..
            }
            | GraphState::CounterProofPosted {
                payout_connector_spent,
                ..
            } => {
                *payout_connector_spent = Some(txid);
                true
            }
            _ => false,
        }
    }
}
