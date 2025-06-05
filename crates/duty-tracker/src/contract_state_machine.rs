//! This module defines the core state machine for the Bridge Deposit Contract. All of the states,
//! events and transition rules are encoded in this structure. When the ContractSM accepts an event
//! it may or may not give back an OperatorDuty to execute as a result of this state transition.
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    sync::Arc,
    thread,
};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{
    hashes::{
        serde::{Deserialize, Serialize},
        sha256,
    },
    sighash::{Prevouts, SighashCache},
    taproot, Network, OutPoint, ScriptBuf, TapSighashType, Transaction, Txid, XOnlyPublicKey,
};
use bitcoin_bosd::Descriptor;
use musig2::{
    secp256k1::{self, Message},
    verify_partial, AggNonce, KeyAggContext, PartialSignature, PubNonce,
};
use strata_bridge_primitives::{
    build_context::TxBuildContext,
    constants::NUM_ASSERT_DATA_TX,
    operator_table::OperatorTable,
    scripts::taproot::{create_message_hash, TaprootWitness},
    types::{BitcoinBlockHeight, OperatorIdx},
    wots::{self, Groth16Sigs, Wots256Sig},
};
use strata_bridge_stake_chain::{
    prelude::{STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::{StakeTxData, StakeTxKind},
};
use strata_bridge_tx_graph::{
    peg_out_graph::{PegOutGraph, PegOutGraphInput, PegOutGraphSummary},
    pog_musig_functor::PogMusigF,
    transactions::{
        claim::ClaimTx,
        deposit::DepositTx,
        payout::NUM_PAYOUT_INPUTS,
        prelude::{
            AssertDataTxBatch, CovenantTx, WithdrawalMetadata, NUM_PAYOUT_OPTIMISTIC_INPUTS,
        },
    },
};
use strata_p2p_types::{P2POperatorPubKey, WotsPublicKeys};
use strata_primitives::params::RollupParams;
use strata_state::bridge_state::{DepositEntry, DepositState};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::predicates::{is_challenge, is_disprove, is_fulfillment_tx};

/// Helper structure for passing around the relevant information we receive in the DepositSetup P2P
/// message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositSetup {
    /// The index of the stake transaction associated with this deposit.
    pub index: u32,

    /// The stake hash we received in the DepositSetup P2P message.
    pub hash: sha256::Hash,

    /// The peg-out-graph dust output funding source outpoint received in the DepositSetup P2P
    /// message.
    pub funding_outpoint: OutPoint,

    /// The P2TR key where the operator will ultimately receive a reimbursement for a valid
    /// withdrawal fulfillment.
    pub operator_pk: XOnlyPublicKey,

    /// The public wots keys we received from the DepositSetup P2P message.
    pub wots_pks: WotsPublicKeys,
}

impl DepositSetup {
    /// Conversion function into StakeTxData.
    pub fn stake_tx_data(&self) -> StakeTxData {
        StakeTxData {
            operator_funds: self.funding_outpoint,
            hash: self.hash,
            withdrawal_fulfillment_pk: strata_bridge_primitives::wots::Wots256PublicKey(Arc::new(
                self.wots_pks.withdrawal_fulfillment.0,
            )),
        }
    }
}

/// This is the unified event type for this state machine.
///
/// Events of this type will be repeatedly fed to the state machine until it terminates.
#[derive(Debug)]
pub enum ContractEvent {
    /// Signifies that we have a new set of WOTS keys from one of our peers.
    DepositSetup {
        /// The operator's P2P public key.
        operator_p2p_key: P2POperatorPubKey,

        /// The operator's X-only public key used for CPFP outputs, payouts and funding inputs.
        operator_btc_key: XOnlyPublicKey,

        /// The hash used in the hashlock in the previous stake transaction.
        stake_hash: sha256::Hash,

        /// The stake transaction id that holds the stake corresponding to the current contract.
        stake_txid: Txid,

        /// The wots keys needed to construct the pog.
        wots_keys: Box<wots::PublicKeys>,
    },

    /// Signifies that we have a new set of nonces for the peg out graph from one of our peers for
    /// a graph with the given claim txid.
    GraphNonces {
        /// The peer identified by the public key that broadcasted the nonces.
        signer: P2POperatorPubKey,

        /// The Transaction ID of the claim transaction in the graph being signed.
        claim_txid: Txid,

        /// The set of pubnonces associated with each transaction input in the graph that needs to
        /// be MuSig2 signed.
        pubnonces: Vec<PubNonce>,
    },

    /// Signifies that we have a new set of signatures for the peg out graph from one of our peers
    /// for a graph with the given claim txid.
    GraphSigs {
        /// The peer identified by the public key that broadcasted the signatures.
        signer: P2POperatorPubKey,

        /// The Transaction ID of the claim transaction in the graph being signed.
        claim_txid: Txid,

        /// The set of partial signatures associated with each transaction input in the graph that
        /// needs to be MuSig2 signed.
        signatures: Vec<PartialSignature>,
    },

    /// Signifies that the partial signatures for the peg out graph have been aggregated.
    AggregatedSigs {
        /// The aggregated signatures for the peg out graph indexed by the transaction ID of the
        /// claim transaction in the peg out graph.
        agg_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,
    },

    /// Signifies that we have received a new deposit nonce from one of our peers.
    RootNonce(P2POperatorPubKey, PubNonce),

    /// Signifies that we have a new deposit signature from one of our peers.
    RootSig(P2POperatorPubKey, PartialSignature),

    /// Signifies that this withdrawal has been assigned.
    Assignment {
        /// The deposit entry that contains a valid assignment.
        deposit_entry: DepositEntry,

        /// The stake transaction that needs to be settled before the withdrawal fulfillment and
        /// claim transactions can be settled.
        stake_tx: StakeTxKind,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// Signifies that the deposit transaction has been confirmed, the second value is the global
    /// deposit index.
    DepositConfirmation(Transaction),

    /// Signifies that a new transaction has been confirmed.
    PegOutGraphConfirmation(Transaction, BitcoinBlockHeight),

    /// Signifies that a new block has been connected to the chain tip.
    Block(BitcoinBlockHeight),

    /// Signifies that the claim transaction for this contract has failed verification.
    ClaimFailure,

    /// Signifies that the assertion chain for this contract is invalid.
    AssertionFailure,
}

/// Ways in which a contract can be resolved.
///
/// It may be resolved optimistically -- meaning that no challenges occur.
/// Or it may be resolved after the operator posts a valid proof on chain if their claim is
/// challenged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionPath {
    /// The optimistic resolution path is the one where the operator's claim is unchallenged and
    /// they are able to submit the Payout Optimistic transaction.
    Optimistic,

    /// The contested resolution path is the one where the operator's claim is challenged but they
    /// are able to post a valid proof on chain and subsequently submit the Payout transaction.
    Contested,
}

impl Display for ResolutionPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionPath::Optimistic => write!(f, "optimistic"),
            ResolutionPath::Contested => write!(f, "contested"),
        }
    }
}

/// This type contains all of the relevant state for the [`ContractSM`] on a per phase basis.
///
/// State Transitions:
/// - Requested -> Deposited
/// - Deposited -> Assigned
/// - Assigned -> Fulfilled
/// - Fulfilled -> Claimed
/// - Claimed -> Resolved
/// - Claimed -> ChainDisputed
/// - Claimed -> Challenged
/// - Claimed -> Asserted
/// - Asserted -> Disproved
/// - Asserted -> Resolved
///
/// The transaction ID used to index transactions and other data is the transaction ID of the claim
/// transaction in the operators' graphs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractState {
    /// This state describes everything from the moment the deposit request confirms, to the moment
    /// the deposit confirms.
    Requested {
        /// The txid of the deposit request transaction that kicked off this contract.
        deposit_request_txid: Txid,

        /// This is the height where the requester can reclaim the request output if it has not yet
        /// been converted to a deposit.
        abort_deadline: BitcoinBlockHeight,

        /// This is a collection of the information needed to generate the peg-out-graphs on
        /// a per-operator basis.
        peg_out_graph_inputs: BTreeMap<P2POperatorPubKey, PegOutGraphInput>,

        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle.
        peg_out_graph_summaries: BTreeMap<Txid, PegOutGraphSummary>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of nonces for all graphs and for all operators.
        graph_nonces: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PubNonce>>>,

        /// This is a collection of all the packed aggregated nonces for each graph.
        ///
        /// This is used to validate partial signatures as they are received from the p2p.
        agg_nonces: BTreeMap<Txid, Vec<AggNonce>>,

        /// This is a collection of all partial signatures for all graphs (indexed by the claim
        /// txid) and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// This is a collection of nonces for the deposit tx for all operators.
        root_nonces: BTreeMap<P2POperatorPubKey, PubNonce>,

        /// This is a collection of all partial signatures for the deposit tx for all operators.
        root_partials: BTreeMap<P2POperatorPubKey, PartialSignature>,
    },

    /// This state describes everything from the moment the deposit confirms, to the moment the
    /// strata state commitment that assigns this deposit confirms.
    Deposited {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,
    },

    /// This state describes everything from the moment the strata state commitment corresponding
    /// to a valid withdrawal assignment is posted to bitcoin all the way to the corresponding
    /// stake transaction being confirmed.
    Assigned {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The descriptor of the recipient.
        recipient: Descriptor,

        /// The deadline by which the operator must fulfill the withdrawal before it is reassigned.
        deadline: BitcoinBlockHeight,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The transaction ID of the withdrawal request transaction in the execution environment.
        withdrawal_request_txid: Txid,

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// This state describes everything from the moment stake transaction corresponding to this
    /// deposit confirms to the moment the fulfillment transaction confirms for the assigned
    /// operator.
    StakeTxReady {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The descriptor of the recipient.
        recipient: Descriptor,

        /// The deadline by which the operator must fulfill the withdrawal before it is reassigned.
        deadline: BitcoinBlockHeight,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The transaction ID of the withdrawal request transaction in the execution environment.
        withdrawal_request_txid: Txid,

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// This state describes everything from the moment the fulfillment transaction confirms, to
    /// the moment the claim transaction confirms.
    Fulfilled {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The withdrawal fulfillment transaction ID.
        withdrawal_fulfillment_txid: Txid,

        /// The bitcoin block height at which the withdrawal fulfillment transaction was confirmed.
        withdrawal_fulfillment_height: BitcoinBlockHeight,

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// This state describes everything from the moment the claim transaction confirms, to the
    /// moment either the challenge transaction confirms, or the optimistic payout transaction
    /// confirms.
    Claimed {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The height at which the claim transaction was confirmed.
        claim_height: BitcoinBlockHeight,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The commitment to the withdrawal fulfillment txid that was included in the claim
        /// transaction.
        withdrawal_fulfillment_commitment: Wots256Sig,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// This state describes everything till the challenge transaction is confirmed.
    Challenged {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The height at which the claim transaction was confirmed.
        claim_height: BitcoinBlockHeight,

        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The commitment to the withdrawal fulfillment txid that was included in the claim
        /// transaction.
        withdrawal_fulfillment_commitment: Wots256Sig,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// This state describes everything till the pre-assert transaction is confirmed.
    PreAssertConfirmed {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The height at which the claim transaction was confirmed.
        claim_height: BitcoinBlockHeight,

        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The commitment to the withdrawal fulfillment txid that was included in the claim
        /// transaction.
        withdrawal_fulfillment_commitment: Wots256Sig,

        /// The height of the last block in bitcoin covered by the sidesystem checkpoint containing
        /// the assignment.
        l1_start_height: BitcoinBlockHeight,
    },

    /// This state describes everything till the assert-data transactions are confirmed.
    AssertDataConfirmed {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The commitment to the withdrawal fulfillment txid that was included in the claim
        /// transaction.
        withdrawal_fulfillment_commitment: Wots256Sig,

        /// The witnesses in each of the assert-data transactions that commit to the proof.
        signed_assert_data_txs: HashMap<Txid, Transaction>,
    },

    /// This state describes everything till the post-assert transaction is confirmed.
    Asserted {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of the aggregated signatures per graph that can be used to settle
        /// transactions in the peg out graph at withdrawal time.
        graph_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The height at which the post-assert transaction was confirmed.
        post_assert_height: BitcoinBlockHeight,

        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The commitment to the withdrawal fulfillment txid that was included in the claim
        /// transaction.
        withdrawal_fulfillment_commitment: Wots256Sig,

        /// The commitment to the proof that was included in the assert-data transactions.
        proof_commitment: Groth16Sigs,
    },

    /// This state describes the state after the disprove transaction confirms.
    Disproved {},

    /// This state describes the state after either the optimistic or defended payout transactions
    /// confirm.
    Resolved {
        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The transaction ID of either the optimistic payout transaction or the contested payout
        /// transaction.
        payout_txid: Txid,

        /// The nature of the resolution.
        path: ResolutionPath,
    },

    /// This state is a stub used for bypassing borrow-checker limitations during state
    /// transitions.
    Stub,
}

impl Display for ContractState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            ContractState::Requested {
                deposit_request_txid,
                ..
            } => format!("Requested ({})", deposit_request_txid),
            ContractState::Deposited { .. } => "Deposited".to_string(),
            ContractState::Assigned {
                fulfiller,
                recipient,
                deadline,
                ..
            } => format!(
                "Assigned to {} with recipient: {} and deadline {}",
                fulfiller, recipient, deadline
            ),
            ContractState::StakeTxReady {
                active_graph,
                fulfiller,
                ..
            } => format!(
                "StakeTxReady ({}) for operator {}",
                active_graph.1.stake_txid, fulfiller
            ),
            ContractState::Fulfilled { fulfiller, .. } => {
                format!("Fulfilled by operator {}", fulfiller)
            }
            ContractState::Claimed {
                claim_height,
                fulfiller,
                active_graph,
                ..
            } => format!(
                "Claimed by operator {} at height {} ({})",
                fulfiller, claim_height, active_graph.1.claim_txid
            ),
            ContractState::Challenged {
                fulfiller,
                active_graph,
                ..
            } => format!(
                "Challenged operator {}'s claim ({})",
                fulfiller, active_graph.1.claim_txid
            ),
            ContractState::PreAssertConfirmed {
                fulfiller,
                active_graph,
                ..
            } => {
                format!(
                    "PreAssertConfirmed by operator {} for claim ({})",
                    fulfiller, active_graph.1.claim_txid
                )
            }
            ContractState::AssertDataConfirmed {
                fulfiller,
                active_graph,
                signed_assert_data_txs,
                ..
            } => {
                format!(
                    "AssertDataConfirmed by operator {} for claim ({}) - {}/{NUM_ASSERT_DATA_TX}",
                    fulfiller,
                    active_graph.1.claim_txid,
                    signed_assert_data_txs.len(),
                )
            }
            ContractState::Asserted {
                fulfiller,
                active_graph,
                ..
            } => format!(
                "Asserted by operator {} ({})",
                fulfiller, active_graph.1.post_assert_txid
            ),
            ContractState::Disproved { .. } => "Disproved".to_string(),
            ContractState::Resolved {
                withdrawal_fulfillment_txid,
                payout_txid,
                path,
            } => {
                format!("Resolved via {path} path with withdrawal fulfillment ({withdrawal_fulfillment_txid}) and payout ({payout_txid})")
            }
            ContractState::Stub => "Stub".to_string(),
        };

        write!(f, "ContractState: {}", display_str)
    }
}

impl ContractState {
    /// Initializes a contract state at the beginning of its lifecycle with the given arguments.
    pub const fn new(
        deposit_request_txid: Txid,
        abort_deadline: BitcoinBlockHeight,
    ) -> ContractState {
        ContractState::Requested {
            deposit_request_txid,
            abort_deadline,
            peg_out_graph_inputs: BTreeMap::new(),
            peg_out_graph_summaries: BTreeMap::new(),
            claim_txids: BTreeMap::new(),
            graph_nonces: BTreeMap::new(),
            agg_nonces: BTreeMap::new(),
            graph_partials: BTreeMap::new(),
            graph_sigs: BTreeMap::new(),
            root_nonces: BTreeMap::new(),
            root_partials: BTreeMap::new(),
        }
    }

    /// Computes all of the [`PegOutGraphSummary`]s that this contract state is currently aware of.
    pub fn summaries(&self) -> Vec<PegOutGraphSummary> {
        fn get_summaries<T>(
            g: &BTreeMap<T, (PegOutGraphInput, PegOutGraphSummary)>,
        ) -> Vec<PegOutGraphSummary> {
            g.values().map(|(_, summary)| summary).cloned().collect()
        }

        match self {
            ContractState::Requested {
                peg_out_graph_summaries: peg_out_graphs,
                ..
            } => peg_out_graphs.values().cloned().collect(),
            ContractState::Deposited { peg_out_graphs, .. }
            | ContractState::Assigned { peg_out_graphs, .. }
            | ContractState::StakeTxReady { peg_out_graphs, .. }
            | ContractState::Fulfilled { peg_out_graphs, .. }
            | ContractState::Claimed { peg_out_graphs, .. }
            | ContractState::Challenged { peg_out_graphs, .. }
            | ContractState::PreAssertConfirmed { peg_out_graphs, .. }
            | ContractState::AssertDataConfirmed { peg_out_graphs, .. }
            | ContractState::Asserted { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Disproved { .. }
            | ContractState::Resolved { .. }
            | ContractState::Stub => vec![],
        }
    }

    /// Gets the transaction IDs of the claim transactions for this contract.
    pub fn claim_txids(&self) -> HashSet<Txid> {
        let claim_txids = match &self {
            ContractState::Requested { claim_txids, .. }
            | ContractState::Deposited { claim_txids, .. }
            | ContractState::Assigned { claim_txids, .. }
            | ContractState::StakeTxReady { claim_txids, .. }
            | ContractState::Fulfilled { claim_txids, .. }
            | ContractState::Claimed { claim_txids, .. }
            | ContractState::Challenged { claim_txids, .. }
            | ContractState::PreAssertConfirmed { claim_txids, .. }
            | ContractState::AssertDataConfirmed { claim_txids, .. }
            | ContractState::Asserted { claim_txids, .. } => claim_txids,
            ContractState::Disproved { .. }
            | ContractState::Resolved { .. }
            | ContractState::Stub => &BTreeMap::new(),
        };

        claim_txids.values().copied().collect()
    }

    /// Gets the musig2-aggregated graph signatures for this contract.
    pub fn graph_sigs(&self) -> BTreeMap<Txid, PogMusigF<taproot::Signature>> {
        let graph_sigs = match &self {
            ContractState::Requested { graph_sigs, .. }
            | ContractState::Deposited { graph_sigs, .. }
            | ContractState::Assigned { graph_sigs, .. }
            | ContractState::StakeTxReady { graph_sigs, .. }
            | ContractState::Fulfilled { graph_sigs, .. }
            | ContractState::Claimed { graph_sigs, .. }
            | ContractState::Challenged { graph_sigs, .. }
            | ContractState::PreAssertConfirmed { graph_sigs, .. }
            | ContractState::AssertDataConfirmed { graph_sigs, .. }
            | ContractState::Asserted { graph_sigs, .. } => graph_sigs,
            ContractState::Disproved { .. }
            | ContractState::Resolved { .. }
            | ContractState::Stub => &BTreeMap::new(),
        };

        graph_sigs.clone()
    }

    /// Maps the claim_txid to the operator's p2p key.
    pub fn claim_to_operator(&self, claim_txid: &Txid) -> Option<P2POperatorPubKey> {
        let claim_txids = match self {
            ContractState::Requested { claim_txids, .. }
            | ContractState::Deposited { claim_txids, .. }
            | ContractState::Assigned { claim_txids, .. }
            | ContractState::StakeTxReady { claim_txids, .. }
            | ContractState::Fulfilled { claim_txids, .. }
            | ContractState::Claimed { claim_txids, .. }
            | ContractState::Challenged { claim_txids, .. }
            | ContractState::PreAssertConfirmed { claim_txids, .. }
            | ContractState::AssertDataConfirmed { claim_txids, .. } => claim_txids,
            ContractState::Asserted { claim_txids, .. } => claim_txids,
            ContractState::Disproved {} | ContractState::Resolved { .. } | ContractState::Stub => {
                &BTreeMap::new()
            }
        };

        claim_txids.iter().find_map(|(op_key, claim)| {
            if claim == claim_txid {
                Some(op_key.clone())
            } else {
                None
            }
        })
    }

    /// Gets the graph input for a particular claim transaction ID.
    pub fn graph_input(&self, claim_txid: Txid) -> Option<&PegOutGraphInput> {
        match self {
            ContractState::Requested {
                peg_out_graph_inputs,
                ..
            } => self
                .claim_to_operator(&claim_txid)
                .and_then(|op_key| peg_out_graph_inputs.get(&op_key)),
            ContractState::Deposited { peg_out_graphs, .. }
            | ContractState::Assigned { peg_out_graphs, .. }
            | ContractState::StakeTxReady { peg_out_graphs, .. }
            | ContractState::Fulfilled { peg_out_graphs, .. }
            | ContractState::Claimed { peg_out_graphs, .. }
            | ContractState::Challenged { peg_out_graphs, .. }
            | ContractState::PreAssertConfirmed { peg_out_graphs, .. }
            | ContractState::AssertDataConfirmed { peg_out_graphs, .. }
            | ContractState::Asserted { peg_out_graphs, .. } => {
                peg_out_graphs.get(&claim_txid).map(|(input, _)| input)
            }
            ContractState::Disproved {} | ContractState::Resolved { .. } | ContractState::Stub => {
                None
            }
        }
    }
}

/// This is the set of events that are not directly derived from the chain state or the p2p network
/// but rather serve a specific auxiliary function in the contract state machine architecture.
#[derive(Debug, Clone)]
pub enum SyntheticEvent {
    /// Siginifies that we have aggregated the partial signatures for all relevant inpoints of all
    /// the graphs for a particular contract (identified by the deposit txid) and that these need
    /// to be committed.
    ///
    /// The committed signatures are used during withdrawal execution to settle relevant
    /// transactions in the pre-signed peg-out graph.
    AggregatedSigs {
        /// The transaction ID of the deposit transaction that this contract is associated with.
        deposit_txid: Txid,

        /// The aggregated signatures for the peg out graph indexed by the transaction ID of the
        /// claim transaction in the peg out graph.
        agg_sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,
    },
}

/// This is the superset of all possible operator duties.
#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum OperatorDuty {
    /// Instructs us to terminate this contract.
    Abort,

    /// Instructs us to publish our pre-stake data.
    PublishStakeChainExchange,

    /// Instructs us to publish the setup data for this contract.
    PublishDepositSetup {
        /// Transaction ID of the DT
        deposit_txid: Txid,

        /// The index of the deposit
        deposit_idx: u32,

        /// The data about the stake transaction.
        stake_chain_inputs: StakeChainInputs,
    },

    /// Instructs us to publish our graph nonces for this contract.
    PublishGraphNonces {
        /// Claim Transaction ID of the Graph being signed.
        claim_txid: Txid,

        /// The set of outpoints that need to be signed.
        pog_prevouts: PogMusigF<OutPoint>,

        /// The set of taproot witnesses required to reconstruct the taproot control blocks for the
        /// outpoints.
        pog_witnesses: PogMusigF<TaprootWitness>,

        /// Pre-generated nonces to publish.
        ///
        /// The duty executor will generate new nonces if [`None`] is passed.
        nonces: Option<PogMusigF<PubNonce>>,
    },

    /// Instructs us to send out signatures for the peg out graph.
    PublishGraphSignatures {
        /// Transaction ID of the DT.
        claim_txid: Txid,

        /// Nonces collected from each operator's musig2 sessions.
        /// Order of Vecs is determined by implementation.
        pubnonces: BTreeMap<secp256k1::PublicKey, PogMusigF<PubNonce>>,

        /// The set of outpoints that need to be signed.
        pog_prevouts: PogMusigF<OutPoint>,

        /// The set of sighashes that need to be signed.
        pog_sighashes: PogMusigF<Message>,

        /// Pre-generated partial signatures to publish.
        ///
        /// The duty executor will generate new partial signatures if [`None`] is passed.
        partial_signatures: Option<PogMusigF<PartialSignature>>,
    },

    /// Instructs us to commit the aggregated signatures to state.
    CommitSig {
        /// The transaction ID of the deposit transaction for this contract.
        deposit_txid: Txid,

        /// The partial signatures for all graphs.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

        /// The inpoints that need to be MuSig2-signed.
        pog_inpoints: BTreeMap<Txid, PogMusigF<OutPoint>>,

        /// The witness types for the inputs that need to be MuSig2-signed.
        pog_sighash_types: BTreeMap<Txid, PogMusigF<TapSighashType>>,
    },

    /// Instructs us to send out our nonce for the deposit transaction signature.
    PublishRootNonce {
        /// Transaction ID of the DRT
        deposit_request_txid: Txid,

        /// The taproot witness required to reconstruct the taproot control block for the outpoint.
        witness: TaprootWitness,

        /// Pre-generated nonce to publish.
        ///
        /// The duty executor will generate new nonce if [`None`] is passed.
        nonce: Option<PubNonce>,
    },

    /// Instructs us to send out signatures for the deposit transaction.
    PublishRootSignature {
        /// Transaction ID of the DRT
        deposit_request_txid: Txid,

        /// The nonces received from peers.
        nonces: BTreeMap<secp256k1::PublicKey, PubNonce>,

        /// The sighash that needs to be signed.
        sighash: Message,

        /// Pre-generated partial signature to publish.
        ///
        /// The duty executor will generate new partial signature if [`None`] is passed.
        partial_signature: Option<PartialSignature>,
    },

    /// Instructs us to submit the deposit transaction to the network.
    PublishDeposit {
        /// Deposit transaction to be signed and published.
        deposit_tx: DepositTx,

        /// Partial signatures from peers.
        partial_sigs: BTreeMap<P2POperatorPubKey, PartialSignature>,
    },

    /// Injection function for a FulfillerDuty.
    FulfillerDuty(FulfillerDuty),

    /// Injection function for a VerifierDuty.
    VerifierDuty(VerifierDuty),
}

impl Display for OperatorDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorDuty::Abort => write!(f, "Abort"),
            OperatorDuty::PublishStakeChainExchange => write!(f, "PublishStakeChainExchange"),
            OperatorDuty::PublishDepositSetup {
                deposit_txid,
                deposit_idx,
                ..
            } => write!(f, "PublishDepositSetup ({deposit_txid}, {deposit_idx})"),
            OperatorDuty::PublishGraphNonces { claim_txid, .. } => {
                write!(f, "PublishGraphNonces ({claim_txid})")
            }
            OperatorDuty::PublishGraphSignatures { claim_txid, .. } => {
                write!(f, "PublishGraphSignatures ({claim_txid})")
            }
            OperatorDuty::CommitSig { deposit_txid, .. } => {
                write!(f, "CommitSig (deposit: {deposit_txid})")
            }
            OperatorDuty::PublishRootNonce {
                deposit_request_txid,
                ..
            } => write!(f, "PublishRootNonce ({deposit_request_txid})"),
            OperatorDuty::PublishRootSignature {
                deposit_request_txid,
                ..
            } => write!(f, "PublishRootSignature ({deposit_request_txid})"),
            OperatorDuty::PublishDeposit { deposit_tx, .. } => {
                write!(f, "PublishDeposit ({})", deposit_tx.compute_txid())
            }
            OperatorDuty::FulfillerDuty(fulfiller_duty) => {
                write!(f, "FulfillerDuty: {fulfiller_duty}")
            }
            OperatorDuty::VerifierDuty(verifier_duty) => write!(f, "VerifierDuty: {verifier_duty}"),
        }
    }
}

/// This is a duty that has to be carried out if we are the assigned operator.
#[derive(Debug, Clone)]
pub enum FulfillerDuty {
    /// Instructs us to send our initial StakeChainExchange message.
    InitStakeChain,

    /// Originates when strata state on L1 is published and there has been an assignment.
    AdvanceStakeChain {
        /// Index of the stake transaction to advance to.
        stake_index: u32,

        /// The stake transaction to advance corresponding to the stake index.
        stake_tx: StakeTxKind,
    },

    /// Originates when strata state on L1 is published and assignment is self.
    PublishFulfillment {
        /// Withdrawal metadata.
        withdrawal_metadata: WithdrawalMetadata,

        /// The BOSD Descriptor of the user.
        user_descriptor: Descriptor,
    },

    /// Originates when Fulfillment confirms (is buried?)
    PublishClaim {
        /// The transaction ID of the withdrawal fulfillment transaction that is committed in the
        /// claim transaction.
        withdrawal_fulfillment_txid: Txid,

        /// The transaction ID of the stake transaction whose output is spent by the claim
        /// transaction.
        stake_txid: Txid,

        /// The transaction ID of the deposit transaction that is being claimed.
        deposit_txid: Txid,
    },

    /// Originates after reaching timelock expiry for Claim transaction
    PublishPayoutOptimistic {
        /// The transaction ID of the deposit transaction that is being claimed.
        deposit_txid: Txid,

        /// The transaction ID of the claim transaction whose output(s) the payout optimistic
        /// transaction
        /// spends.
        claim_txid: Txid,

        /// The transaction ID of the stake transaction whose output is spent by the claim
        /// transaction.
        stake_txid: Txid,

        /// The index of the associated stake transaction.
        stake_index: u32,

        /// The partial signatures required to settle the `PayoutOptimistic` transaction.
        agg_sigs: Box<[taproot::Signature; NUM_PAYOUT_OPTIMISTIC_INPUTS]>,
    },

    /// Originates once challenge is issued.
    PublishPreAssert {
        /// The index of the deposit being claimed.
        deposit_idx: u32,

        /// The transaction ID of the deposit being claimed.
        deposit_txid: Txid,

        /// The transaction ID of the claim transaction in the peg-out graph.
        claim_txid: Txid,

        /// The aggregate signature required to settle the pre-assert transaction.
        agg_sig: taproot::Signature,
    },

    /// Originates once the pre-assert transaction is confirmed.
    PublishAssertData {
        /// The transaction ID of the withdrawal fulfillment transaction.
        withdrawal_fulfillment_txid: Txid,

        /// Start height of the bitcoin chain fragment that is part of the proof being asserted.
        start_height: BitcoinBlockHeight,

        /// The index of the deposit being claimed.
        deposit_idx: u32,

        /// The transaction ID of the deposit being claimed.
        deposit_txid: Txid,

        /// The transaction ID of the pre-assert transaction.
        pre_assert_txid: Txid,

        /// The locking scripts in the output of the pre-assert transaction.
        pre_assert_locking_scripts: Box<[ScriptBuf; NUM_ASSERT_DATA_TX]>,
    },

    /// Originates once all the assert-data transactions have been confirmed.
    PublishPostAssertData {
        /// The transaction ID of the deposit transaction whose output is being claimed.
        deposit_txid: Txid,

        /// The transaction IDs of all the assert-data transactions whose outputs are spent by the
        /// post-assert transaction, in order.
        assert_data_txids: Box<[Txid; NUM_ASSERT_DATA_TX]>,

        /// The MuSig2 aggregated signatures required to settle the post-assert transaction.
        agg_sigs: Box<[taproot::Signature; NUM_ASSERT_DATA_TX]>,
    },

    /// Originates after post-assert timelock expires
    PublishPayout {
        /// The index of the deposit transaction whose output is being used to reimburse the
        /// operator.
        deposit_idx: u32,

        /// The transaction ID of the deposit transaction whose output is being used to reimburse
        /// the operator.
        deposit_txid: Txid,

        /// The transaction ID of the post-assert transaction whose output is being spent by the
        /// payout transaction.
        post_assert_txid: Txid,

        /// The transaction ID of the claim transaction whose output is being spent by the payout
        /// transaction.
        claim_txid: Txid,

        /// The transaction ID of the stake transaction whose output is spent by the payout
        /// transaction.
        stake_txid: Txid,

        /// The MuSig2 aggregated signatures required to settle the payout transaction.
        agg_sigs: Box<[taproot::Signature; NUM_PAYOUT_INPUTS]>,
    },
}

impl Display for FulfillerDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FulfillerDuty::InitStakeChain => write!(f, "InitStakeChain"),
            FulfillerDuty::AdvanceStakeChain {
                stake_index,
                stake_tx,
            } => write!(
                f,
                "AdvanceStakeChain for stake_index: {stake_index}, stake_tx: {:?}",
                &stake_tx.psbt().unsigned_tx
            ),
            FulfillerDuty::PublishFulfillment {
                withdrawal_metadata,
                ..
            } => write!(f, "PublishFulfillment: {withdrawal_metadata:?}"),
            FulfillerDuty::PublishClaim { deposit_txid, .. } => {
                write!(f, "PublishClaim for {deposit_txid}")
            }
            FulfillerDuty::PublishPayoutOptimistic { deposit_txid, .. } => {
                write!(f, "PublishPayoutOptimistic for {deposit_txid}")
            }
            FulfillerDuty::PublishPreAssert {
                deposit_idx,
                deposit_txid,
                claim_txid,
                ..
            } => write!(
                f,
                "PublishPreAssert for deposit {deposit_idx} ({deposit_txid} and claim ({claim_txid}))"
            ),
            FulfillerDuty::PublishAssertData {
                withdrawal_fulfillment_txid,
                deposit_idx,
                ..
            } => write!(f, "PublishAssertData for {withdrawal_fulfillment_txid} and deposit {deposit_idx}"),
            FulfillerDuty::PublishPostAssertData { .. } => {
                write!(f, "PublishPostAssertData")
            }
            FulfillerDuty::PublishPayout { deposit_idx, deposit_txid, .. } => write!(f, "PublishPayout for deposit {deposit_idx} ({deposit_txid})"),
        }
    }
}

/// This is a duty that must be carried out as a Verifier.
#[derive(Debug, Clone)]
pub enum VerifierDuty {
    /// Originates when *other* operator Claim transaction is issued
    VerifyClaim,

    /// Originates when *other* operator PostAssert transaction is issued
    VerifyAssertion,

    /// Originates when any of other operator's Claim, PreAssert, Assert, or Post-Assert are
    /// issued.
    VerifyStake,

    /// Originates when fraudulent Claim transaction is issued
    PublishChallenge,

    /// Originates after Post-Assert is issued if Disprove script is satisfiable
    PublishDisprove,
}

impl Display for VerifierDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifierDuty::VerifyClaim => write!(f, "VerifyClaim"),
            VerifierDuty::VerifyAssertion => write!(f, "VerifyAssertion"),
            VerifierDuty::VerifyStake => write!(f, "VerifyStake"),
            VerifierDuty::PublishChallenge => write!(f, "PublishChallenge"),
            VerifierDuty::PublishDisprove => write!(f, "PublishDisprove"),
        }
    }
}

/// Error representing an invalid state transition.
#[derive(Debug, Clone, Error)]
pub struct TransitionErr(pub String);
impl Display for TransitionErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransitionErr: {}", self.0)
    }
}

/// Holds the state machine values that remain static for the lifetime of the contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCfg {
    /// The bitcoin chain to which this state machine is bound.
    pub network: Network,

    /// The pointed operator set.
    pub operator_table: OperatorTable,

    /// Consensus critical parameters for computing the locking conditions of the connector
    /// outputs.
    pub connector_params: ConnectorParams,

    /// Consensus critical parameters associated with the transactions in the peg out graph.
    pub peg_out_graph_params: PegOutGraphParams,

    /// Consensus critical parameters associated with the sidesystem this contract is tied to.
    pub sidesystem_params: RollupParams,

    /// Consensus critical parameters associated with the stake chain.
    pub stake_chain_params: StakeChainParams,

    /// The global index of this contract. This is decided by the bridge upon the recognition of
    /// a deposit request.
    pub deposit_idx: u32,

    /// The predetermined deposit transaction that the rest of the graph is built from.
    pub deposit_tx: DepositTx,
}

impl ContractCfg {
    /// Builds a [`PegOutGraph`] from a [`PegOutGraphInput`].
    pub fn build_graph(&self, graph_input: &PegOutGraphInput) -> PegOutGraph {
        PegOutGraph::generate(
            graph_input,
            &self.operator_table.tx_build_context(self.network),
            self.deposit_tx.compute_txid(),
            self.peg_out_graph_params,
            self.connector_params,
            self.stake_chain_params,
            Vec::new(),
        )
        .0
    }

    /// Builds a TxBuildContext from the ContractCfg.
    pub fn tx_build_context(&self) -> TxBuildContext {
        self.operator_table.tx_build_context(self.network)
    }

    /// Returns the transaction ID of the deposit request for this contract.
    pub fn deposit_request_txid(&self) -> Txid {
        self.deposit_tx.psbt().unsigned_tx.input[0]
            .previous_output
            .txid
    }
}

/// Holds the state machine values that change over the lifetime of the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineState {
    /// The most recent block height the state machine is aware of.
    pub block_height: BitcoinBlockHeight,

    /// The state of the contract itself.
    pub state: ContractState,
}

/// This is the core state machine for a given deposit contract.
#[derive(Debug)]
pub struct ContractSM {
    /// The configuration of the contract.
    cfg: ContractCfg,

    /// The state of the contract itself.
    state: MachineState,

    /// The peg out graphs associated with each operator for the given deposit.
    ///
    /// This is used for caching the peg out graphs for the contract.
    /// The graphs are indexed by the transaction ID of the corresponding stake transaction.
    pog: BTreeMap<Txid, PegOutGraph>,
}

impl ContractSM {
    /// Builds a new ContractSM around a given deposit transaction.
    ///
    /// This will be constructible once we have a deposit request.
    pub fn new(
        cfg: ContractCfg,
        block_height: BitcoinBlockHeight,
        abort_deadline: BitcoinBlockHeight,
    ) -> Self {
        let deposit_request_txid = cfg.deposit_tx.psbt().unsigned_tx.input[0]
            .previous_output
            .txid;

        let state = ContractState::new(deposit_request_txid, abort_deadline);
        let state = MachineState {
            block_height,
            state,
        };

        ContractSM {
            cfg,
            state,
            pog: BTreeMap::new(),
        }
    }

    /// Restores a [`ContractSM`] from its [`ContractCfg`] and [`MachineState`]
    pub const fn restore(cfg: ContractCfg, state: MachineState) -> Self {
        ContractSM {
            cfg,
            state,
            pog: BTreeMap::new(),
        }
    }

    /// Filter that specifies which transactions should be delivered to this state machine.
    pub fn transaction_filter(&self, tx: &Transaction) -> bool {
        let deposit_txid = self.deposit_txid();
        let summaries = &self.state.state.summaries();
        let cfg = self.cfg();
        let txid = tx.compute_txid();

        let operator_ids = cfg.operator_table.operator_idxs();
        if let ContractState::StakeTxReady { recipient, .. } = &self.state.state {
            if operator_ids.iter().any(|operator_idx| {
                is_fulfillment_tx(
                    cfg.network,
                    &cfg.peg_out_graph_params,
                    *operator_idx,
                    cfg.deposit_idx,
                    deposit_txid,
                    recipient.clone(),
                )(tx)
            }) {
                return true;
            }
        }

        summaries.iter().any(|g| {
            deposit_txid == txid
                || g.stake_txid == txid
                || g.claim_txid == txid
                || g.payout_optimistic_txid == txid
                || g.pre_assert_txid == txid
                || g.assert_data_txids.contains(&txid)
                || g.post_assert_txid == txid
                || g.payout_txid == txid
                || is_challenge(g.claim_txid)(tx)
                || is_disprove(g.post_assert_txid)(tx)
        })
    }

    /// Retrieves the [`PegOutGraph`] associated with this contract state machine.
    ///
    /// If the peg out graph is already cached, it will be returned. Otherwise, it will be built and
    /// cached.
    pub fn retrieve_graph(&mut self, input: &PegOutGraphInput) -> PegOutGraph {
        let stake_txid = input.stake_outpoint.txid;
        if let Some(pog) = self.pog.get(&stake_txid) {
            debug!(reimbursement_key = %input.operator_pubkey, %stake_txid,"retrieving peg out graph from cache");
            pog.clone()
        } else {
            debug!(reimbursement_key = %input.operator_pubkey, %stake_txid,"generating and caching peg out graph");
            let pog = self.cfg.build_graph(input);
            self.pog.insert(stake_txid, pog.clone());
            pog
        }
    }

    /// Processes the unified event type for the ContractSM.
    ///
    /// This is the primary state folding function.
    pub fn process_contract_event(
        &mut self,
        ev: ContractEvent,
    ) -> Result<Vec<OperatorDuty>, TransitionErr> {
        match ev {
            ContractEvent::DepositSetup {
                operator_p2p_key,
                operator_btc_key,
                stake_hash,
                stake_txid,
                wots_keys,
            } => self.process_deposit_setup(
                operator_p2p_key,
                operator_btc_key,
                stake_hash,
                stake_txid,
                *wots_keys,
            ),

            ContractEvent::GraphNonces {
                signer,
                claim_txid,
                pubnonces,
            } => self
                .process_graph_nonces(signer, claim_txid, pubnonces)
                .map(|x| x.into_iter().collect()),

            ContractEvent::GraphSigs {
                signer,
                claim_txid,
                signatures,
            } => self
                .process_graph_signatures(signer, claim_txid, signatures)
                .map(|x| x.into_iter().collect()),

            ContractEvent::AggregatedSigs { agg_sigs } => self
                .process_aggregate_sigs(agg_sigs)
                .map(|x| x.into_iter().collect()),

            ContractEvent::RootNonce(op, nonce) => self
                .process_root_nonce(op, nonce)
                .map(|x| x.into_iter().collect()),

            ContractEvent::RootSig(op, sig) => self
                .process_root_signature(op, sig)
                .map(|x| x.into_iter().collect()),

            ContractEvent::DepositConfirmation(tx) => self
                .process_deposit_confirmation(tx)
                .map(|x| x.into_iter().collect()),

            ContractEvent::Assignment {
                deposit_entry,
                stake_tx,
                l1_start_height,
            } => self
                .process_assignment(&deposit_entry, stake_tx, l1_start_height)
                .map(|x| x.into_iter().collect()),

            ContractEvent::PegOutGraphConfirmation(tx, height) => self
                .process_peg_out_graph_tx_confirmation(height, &tx)
                .map(|x| x.into_iter().collect()),

            ContractEvent::Block(height) => self
                .notify_new_block(height)
                .map(|x| x.into_iter().collect()),

            ContractEvent::ClaimFailure => self
                .process_claim_verification_failure()
                .map(|x| x.into_iter().collect()),

            ContractEvent::AssertionFailure => self
                .process_assertion_verification_failure()
                .map(|x| x.into_iter().collect()),
        }
    }

    // NOTE: (@proofofkeags)
    //
    // All the following functions that handle contract events have these semantics:
    //
    // If an event cannot be consumed by the CSM it should give back an error. If it does get
    // consumed by the CSM it should not have the same state prior. Not all errors need to be fatal
    // but semantically there's no difference between rejecting an event because it has the wrong
    // internal state or rejecting an event because the event doesn't apply to the machine. Either
    // way the error semantics should be about whether or not the event was accepted or rejected.
    // We can annotate it with different reasons still if we use errors.

    fn process_deposit_confirmation(
        &mut self,
        tx: Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let deposit_txid = tx.compute_txid();
        info!(%deposit_txid, "processing deposit confirmation");

        let expected_txid = self.deposit_txid();
        if tx.compute_txid() != expected_txid {
            error!(txid=%deposit_txid, %expected_txid, "deposit confirmation delivered to the wrong CSM");

            return Err(TransitionErr(format!(
                "deposit confirmation for ({}) delivered to wrong CSM ({})",
                deposit_txid, expected_txid,
            )));
        }

        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        match current {
            ContractState::Requested {
                peg_out_graph_inputs,
                peg_out_graph_summaries,
                claim_txids,
                graph_sigs,
                graph_partials,
                ..
            } => {
                debug!(%deposit_txid, "clearing peg out graph cache");
                self.clear_pog_cache();
                let mut peg_out_graph_inputs = peg_out_graph_inputs;
                let mut peg_out_graph_summaries = peg_out_graph_summaries;

                info!(%deposit_txid, "updating contract state to deposited");
                let peg_out_graphs = claim_txids
                    .iter()
                    .map(|(key, claim_txid)| {
                        let input = peg_out_graph_inputs
                            .remove(key)
                            .expect("peg out graph input must exist");
                        let summary = peg_out_graph_summaries
                            .remove(claim_txid)
                            .expect("peg out graph summary must exist")
                            .to_owned();

                        (*claim_txid, (input.clone(), summary))
                    })
                    .collect();

                self.state.state = ContractState::Deposited {
                    peg_out_graphs,
                    claim_txids,
                    graph_sigs,
                    graph_partials,
                }
            }
            invalid_state => {
                self.state.state = invalid_state;
                error!(txid=%deposit_txid, state=%self.state.state, "deposit confirmation delivered to CSM not in Requested state");

                return Err(TransitionErr(format!(
                    "deposit confirmation ({}) delivered to CSM not in Requested state ({})",
                    deposit_txid, self.state.state
                )));
            }
        }

        Ok(None)
    }

    /// Processes a transaction that is assumed to be in the peg-out-graph.
    fn process_peg_out_graph_tx_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &self.state.state {
            ContractState::Requested { .. } => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Requested state ({})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Deposited { .. } => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Deposited state ({})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Assigned { .. } => self.process_stake_chain_advancement(tx),
            ContractState::StakeTxReady { .. } => self.process_fulfillment_confirmation(tx, height),
            ContractState::Fulfilled { .. } => self.process_claim_confirmation(height, tx),
            ContractState::Claimed { .. } => self.process_challenge_confirmation(tx).or_else(|e| {
                warn!(%e, "could not process challenge tx");

                // maybe it's an optimistic payout tx
                self.process_optimistic_payout_confirmation(tx)
                    .or_else(|e| {
                        warn!(%e, "could not process optimistic payout confirmation");

                        // or maybe it's assert chain confirmation and some operator did not take
                        // the payout optimistic path
                        self.process_pre_assert_confirmation(tx)
                    })
            }),

            ContractState::Challenged { .. } => self.process_pre_assert_confirmation(tx),
            ContractState::PreAssertConfirmed { .. }
            | ContractState::AssertDataConfirmed { .. } => self
                .process_assert_data_confirmation(tx)
                .or_else(|_e| self.process_post_assert_confirmation(tx, height)),
            ContractState::Asserted { .. } => self.process_disprove_confirmation(tx).or_else(|e| {
                warn!(%e, "could not process disprove tx");

                // maybe it's a defended payout tx
                self.process_defended_payout_confirmation(tx)
            }),
            ContractState::Disproved {} => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Disproved state ({})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Resolved { .. } => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Resolved state ({})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Stub => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Stub state ({})",
                tx.compute_txid(),
                self.state.state
            ))),
        }
    }

    /// Updates the current state of the machine with the new data i.e., the new stake transaction,
    /// the new wots keys and all the resulting transaction IDs in the transaction graph that
    /// need to be monitored on chain.
    ///
    /// This only happens if the contract is in the [`Requested`](ContractState::Requested) state.
    /// This may produce the duty to publish the graph nonces.
    ///
    /// # Parameters
    ///
    /// - `signer`: the p2p key of the operator that owns the graph.
    /// - `operator_pubkey`: the operator's public key used for CPFP outputs and receiving
    ///   reimbursements.
    /// - `new_stake_hash`: the hash of the stake transaction associated with the graph that is to
    ///   be generated.
    /// - `new_stake_tx`: the stake transaction associated with the graph that is to be generated.
    /// - `new_wots_keys`: the WOTS keys associated with the graph that is to be generated.
    fn process_deposit_setup(
        &mut self,
        signer: P2POperatorPubKey,
        operator_pubkey: XOnlyPublicKey,
        new_stake_hash: sha256::Hash,
        new_stake_txid: Txid,
        new_wots_keys: wots::PublicKeys,
    ) -> Result<Vec<OperatorDuty>, TransitionErr> {
        // TODO(proofofkeags): thoroughly review this code it is ALMOST CERTAINLY WRONG IN SOME
        // SUBTLE WAY.

        let deposit_txid = self.deposit_txid();
        match &mut self.state.state {
            ContractState::Requested {
                peg_out_graph_inputs,
                peg_out_graph_summaries: peg_out_graphs,
                claim_txids,
                graph_nonces,
                graph_partials,
                ..
            } => {
                let pog_input = PegOutGraphInput {
                    stake_outpoint: OutPoint::new(new_stake_txid, STAKE_VOUT),
                    withdrawal_fulfillment_outpoint: OutPoint::new(
                        new_stake_txid,
                        WITHDRAWAL_FULFILLMENT_VOUT,
                    ),
                    stake_hash: new_stake_hash,
                    wots_public_keys: new_wots_keys,
                    operator_pubkey,
                };

                if let Some(existing) = peg_out_graph_inputs.get(&signer) {
                    warn!(
                        "already received deposit setup from {signer} for contract {deposit_txid}"
                    );
                    debug_assert_eq!(
                        &pog_input, existing,
                        "conflicting deposit setup from {signer} for contract {deposit_txid}"
                    );

                    // FIXME: (@Rajil1213) this should return an error
                    return Ok(vec![]);
                }

                peg_out_graph_inputs.insert(signer, pog_input);

                if peg_out_graph_inputs.len() != self.cfg.operator_table.cardinality() {
                    // FIXME: (@Rajil1213) this should return an error
                    return Ok(vec![]);
                }

                let graphs = if std::env::var("MULTI_THREAD_GRAPH_GEN").is_ok_and(|v| v == "1") {
                    let shared_cfg = Arc::new(self.cfg.clone());

                    let jobs = peg_out_graph_inputs
                        .iter()
                        .map(|(signer, input)| {
                            let thread_cfg = shared_cfg.clone();
                            let input = input.clone();

                            (
                                signer,
                                // TODO(proofofkeags): use async thread pool in future commit.
                                //
                                // This is currently implemented as an OS thread for a couple of
                                // reasons. First, we'd like to be able to test this without having
                                // to invoke an async runtime. As
                                // of right now this is inside of a pure
                                // function which means its testing requirements are a little bit
                                // more relaxed. Secondly, the
                                // value of async is much less pronounced for
                                // operations that are waiting on compute instead of IO.
                                thread::Builder::new()
                                    .stack_size(8 * 1024 * 1024)
                                    .spawn(move || {
                                        debug!(
                                            stake_txid = %input.stake_outpoint.txid,
                                            "building graph..."
                                        );
                                        thread_cfg.build_graph(&input.clone())
                                    })
                                    .expect("spawn succeeds"),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();

                    jobs.into_iter()
                        .map(|(signer, job)| {
                            (
                                signer,
                                job.join().expect("peg out graph generation panic'ed"),
                            )
                        })
                        .collect::<BTreeMap<_, _>>()
                } else {
                    peg_out_graph_inputs
                        .iter()
                        .map(|(signer, pog_input)| {
                            let pog = {
                                let stake_txid = pog_input.stake_outpoint.txid;

                                // NOTE: (@Rajil1213) we cannot invoke `retrieve_graph` here because it needs
                                // `&mut self` and the borrow checker does not allow us to reborrow it mutably
                                // inside the mutable context of the state transition functions even though the fields being mutated
                                // are different.

                                if let Some(pog) = self.pog.get(&stake_txid){
                                    debug!(reimbursement_key = %pog_input.operator_pubkey, %stake_txid,"retrieving peg out graph from cache");
                                    pog.clone()
                                } else {
                                    debug!(reimbursement_key = %pog_input.operator_pubkey, %stake_txid,"generating and caching peg out graph");
                                    let pog = self.cfg.build_graph(pog_input);
                                    self.pog.insert(stake_txid, pog.clone());
                                    pog
                                }
                            };

                            (signer, pog)
                        })
                        .collect::<BTreeMap<_, _>>()
                };

                let duties = graphs
                    .values()
                    .map(|graph| OperatorDuty::PublishGraphNonces {
                        claim_txid: graph.claim_tx.compute_txid(),
                        pog_prevouts: graph.musig_inpoints(),
                        pog_witnesses: graph.musig_witnesses(),
                        nonces: None,
                    })
                    .collect::<Vec<_>>();

                for (signer, graph) in graphs {
                    let pog_summary = graph.summarize();
                    let claim_txid = pog_summary.claim_txid;

                    peg_out_graphs.insert(claim_txid, pog_summary);
                    claim_txids.insert(signer.clone(), claim_txid);
                    graph_nonces.insert(claim_txid, BTreeMap::new());
                    graph_partials.insert(claim_txid, BTreeMap::new());
                }

                Ok(duties)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_deposit_setup ({})",
                self.state.state
            ))),
        }
    }

    fn process_graph_nonces(
        &mut self,
        signer: P2POperatorPubKey,
        claim_txid: Txid,
        nonces: Vec<PubNonce>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        debug!(%claim_txid, %signer, "processing graph nonces");
        let cfg = self.cfg().clone();
        let graph_owner = self
            .state
            .state
            .claim_to_operator(&claim_txid)
            .ok_or(TransitionErr(format!(
                "claim txid ({}) not found in claim txids map",
                claim_txid
            )))?;

        match &mut self.state.state {
            ContractState::Requested {
                peg_out_graph_inputs,
                graph_nonces,
                agg_nonces,
                ..
            } => {
                let unpacked = PogMusigF::unpack(nonces).ok_or(TransitionErr(
                    "could not unpack nonce vector into PogMusigF".to_string(),
                ))?;

                // session nonces must be present for this claim_txid at this point
                let Some(session_nonces) = graph_nonces.get_mut(&claim_txid) else {
                    return Err(TransitionErr(format!(
                        "could not process graph nonces. claim_txid ({claim_txid}) not found in nonce map"
                    )));
                };

                if let Some(existing) = session_nonces.get(&signer) {
                    warn!(%claim_txid, %signer, "already received nonces for graph");
                    debug_assert_eq!(
                        &unpacked, existing,
                        "conflicting graph nonces received from {signer} for claim {claim_txid}"
                    );

                    // FIXME: (@Rajil1213) this should return an error
                    return Ok(None);
                }

                session_nonces.insert(signer.clone(), unpacked);

                let num_operators = self.cfg.operator_table.cardinality();
                let have_all_graphs = graph_nonces.values().count() == num_operators;
                let have_all_nonces_in_each_graph = graph_nonces
                    .values()
                    .all(|session_nonces| session_nonces.len() == num_operators);
                let have_all_nonces = have_all_graphs && have_all_nonces_in_each_graph;

                if !have_all_nonces {
                    let received_nonces = graph_nonces
                        .iter()
                        .map(|(claim, nonces)| (claim, nonces.len()))
                        .collect::<Vec<_>>();
                    info!(?received_nonces, required=%num_operators, "waiting for more nonces for some graphs");

                    return Ok(None);
                }

                info!(%claim_txid, %signer, "received all nonces for all graphs, aggregating them");

                *agg_nonces = aggregate_nonces(&cfg.operator_table, graph_nonces);

                let Some(pog_input) = peg_out_graph_inputs.get(&graph_owner) else {
                    return Err(TransitionErr(format!(
                        "could not process graph nonces. claim_txid ({claim_txid}) not found in peg out graph map"
                    )));
                };
                let graph_nonces = graph_nonces.get(&claim_txid).unwrap().clone();

                // NOTE: (@Rajil1213) we cannot use `self.retrieve_graph` here because it needs
                // `&mut self` and the borrow checker does not allow us to reborrow it mutably
                // inside the current mutable context even though the fields being mutated are
                // different.
                let stake_txid = pog_input.stake_outpoint.txid;
                let pog = if let Some(pog) = self.pog.get(&stake_txid) {
                    debug!(reimbursement_key=%pog_input.operator_pubkey, %stake_txid, "retrieving peg out graph from cache");
                    pog.clone()
                } else {
                    debug!(reimbursement_key=%pog_input.operator_pubkey, %stake_txid, "generating and caching peg out graph");
                    let pog = self.cfg.build_graph(pog_input);
                    self.pog.insert(stake_txid, pog.clone());

                    pog
                };

                let pubnonces = self
                    .cfg
                    .operator_table
                    .convert_map_op_to_btc(graph_nonces)
                    .map_err(|e| {
                        TransitionErr(format!(
                            "could not convert nonce map keys: {e} not in operator table",
                        ))
                    })?;

                Ok(Some(OperatorDuty::PublishGraphSignatures {
                    claim_txid,
                    pubnonces,
                    pog_prevouts: pog.musig_inpoints(),
                    pog_sighashes: pog.musig_sighashes(),
                    partial_signatures: None,
                }))
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_graph_nonces ({})",
                self.state.state
            ))),
        }
    }

    /// Processes a graph signature payload from our peer.
    fn process_graph_signatures(
        &mut self,
        signer: P2POperatorPubKey,
        claim_txid: Txid,
        partial_sigs: Vec<PartialSignature>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        debug!(%claim_txid, %signer, "processing graph signatures");

        let unpacked = PogMusigF::unpack(partial_sigs.clone()).ok_or(TransitionErr(
            "could not unpack sig vector into PogMusigF".to_string(),
        ))?;

        let cfg = self.cfg().clone();
        let pog_cache = self.pog.clone();
        let deposit_txid = self.deposit_txid();
        match &mut self.state.state {
            ContractState::Requested {
                peg_out_graph_inputs,
                graph_nonces,
                agg_nonces,
                claim_txids,
                graph_partials,
                ..
            } => {
                // session partials must be present for this claim_txid at this point
                let Some(session_partials) = graph_partials.get_mut(&claim_txid) else {
                    return Err(TransitionErr(format!(
                        "could not process graph partials. claim_txid ({}) not found in partials map",
                        claim_txid
                    )));
                };

                if let Some(existing) = session_partials.get(&signer) {
                    warn!(%claim_txid, %signer, "already received signatures for graph");
                    debug_assert_eq!(
                        &unpacked, existing,
                        "conflicting graph signatures received from {} for claim {}",
                        &signer, &claim_txid
                    );

                    // FIXME: (@Rajil1213) this should return an error
                    return Ok(None);
                }

                let graph_owner_for_claim = claim_txids
                    .iter()
                    .find_map(|(signer_in_map, claim_txid_in_map)| {
                        if *claim_txid_in_map == claim_txid {
                            Some(signer_in_map)
                        } else {
                            None
                        }
                    })
                    .ok_or(TransitionErr(format!(
                        "claim txid ({claim_txid}) not found in claim txids map"
                    )))?;

                let graph_input =
                    peg_out_graph_inputs
                        .get(graph_owner_for_claim)
                        .ok_or(TransitionErr(format!(
                            "peg out graph input missing for signer ({signer})"
                        )))?;

                let pog = pog_cache
                    .get(&graph_input.stake_outpoint.txid)
                    .cloned()
                    .unwrap_or_else(|| cfg.build_graph(graph_input));

                verify_partials_from_peer(
                    &cfg,
                    &signer,
                    &claim_txid,
                    pog,
                    graph_nonces,
                    agg_nonces,
                    &partial_sigs,
                )?;

                info!("partials verified successfully, adding to collection");
                session_partials.insert(signer, unpacked);

                let num_operators = self.cfg.operator_table.cardinality();
                let have_all_graphs = graph_partials.values().count() == num_operators;
                let have_all_partials_for_all_graphs = graph_partials
                    .values()
                    .all(|session_partials| session_partials.len() == num_operators);
                let have_all_partials = have_all_graphs && have_all_partials_for_all_graphs;

                if !have_all_partials {
                    let received_partials = graph_partials
                        .iter()
                        .map(|(claim, partials)| (claim, partials.len()))
                        .collect::<Vec<_>>();

                    info!(?received_partials, %num_operators, "waiting for more partials for graph");

                    return Ok(None);
                }

                info!(%claim_txid, "received all partials for all graphs");

                let (pog_inpoints, pog_sighash_types): (
                    BTreeMap<Txid, PogMusigF<OutPoint>>,
                    BTreeMap<Txid, PogMusigF<TapSighashType>>,
                ) = claim_txids
                    .iter()
                    .filter_map(|(signer, claim_txid)| {
                        peg_out_graph_inputs
                            .get(signer)
                            .map(|pog_input| (claim_txid, pog_input))
                    })
                    .map(|(claim_txid, pog_input)| {
                        let pog = pog_cache
                            .get(&pog_input.stake_outpoint.txid)
                            .cloned()
                            .unwrap_or_else(|| cfg.build_graph(pog_input));

                        (
                            (*claim_txid, pog.musig_inpoints()),
                            (*claim_txid, pog.musig_sighash_types()),
                        )
                    })
                    .unzip();

                Ok(Some(OperatorDuty::CommitSig {
                    deposit_txid,
                    graph_partials: graph_partials.clone(),
                    pog_inpoints,
                    pog_sighash_types,
                }))
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_graph_signatures ({})",
                self.state.state
            ))),
        }
    }

    fn process_aggregate_sigs(
        &mut self,
        sigs: BTreeMap<Txid, PogMusigF<taproot::Signature>>,
    ) -> Result<Vec<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { graph_sigs, .. } => {
                *graph_sigs = sigs;

                Ok(vec![])
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_aggregate_sigs ({:?})",
                self.state.state
            ))),
        }
    }

    fn process_root_nonce(
        &mut self,
        signer: P2POperatorPubKey,
        nonce: PubNonce,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let deposit_txid = self.deposit_txid();
        match &mut self.state.state {
            ContractState::Requested { root_nonces, .. } => {
                if let Some(existing) = root_nonces.get(&signer) {
                    warn!(%signer, "already received nonce for root");
                    debug_assert_eq!(
                        &nonce, existing,
                        "conflicting root nonce received from {} for contract {}",
                        signer, deposit_txid,
                    );

                    // FIXME: (@Rajil1213) this should return an error
                    return Ok(None);
                }

                root_nonces.insert(signer, nonce);

                Ok(
                    if root_nonces.len() == self.cfg.operator_table.cardinality() {
                        // we have all the sigs now
                        // issue deposit signature
                        let deposit_tx = &self.cfg.deposit_tx;

                        let txouts = deposit_tx
                            .psbt()
                            .inputs
                            .iter()
                            .map(|i| i.witness_utxo.clone().expect("witness_utxo must be set"))
                            .collect::<Vec<_>>();

                        let witness = &deposit_tx.witnesses()[0];

                        let sighash = create_message_hash(
                            &mut SighashCache::new(&deposit_tx.psbt().unsigned_tx),
                            Prevouts::All(&txouts),
                            witness,
                            TapSighashType::All,
                            0,
                        )
                        .map_err(|e| TransitionErr(e.to_string()))?;

                        Some(OperatorDuty::PublishRootSignature {
                            nonces: self
                                .cfg
                                .operator_table
                                .convert_map_op_to_btc(root_nonces.clone())
                                .expect("received nonces from nonexistent operator"),
                            deposit_request_txid: self.deposit_request_txid(),
                            sighash,
                            partial_signature: None,
                        })
                    } else {
                        None
                    },
                )
            }
            ContractState::Deposited { .. } => {
                // somebody else may have deposited already.
                warn!("contract already in deposited state, skipping root nonce generation");
                // FIXME: (@Rajil1213) this should return an error
                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_root_nonce ({})",
                self.state.state
            ))),
        }
    }

    /// Processes a signature for the deposit transaction from our peer.
    fn process_root_signature(
        &mut self,
        signer: P2POperatorPubKey,
        sig: PartialSignature,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let deposit_txid = self.deposit_txid();
        match &mut self.state.state {
            ContractState::Requested { root_partials, .. } => {
                if let Some(existing) = root_partials.get(&signer) {
                    warn!(%signer, "already received signature for root");
                    debug_assert_eq!(
                        &sig, existing,
                        "conflicting root signature received from {} for contract {}",
                        signer, deposit_txid
                    );

                    // FIXME: (@Rajil1213) this should return an error
                    return Ok(None);
                }

                root_partials.insert(signer, sig);

                Ok(
                    if root_partials.len() == self.cfg.operator_table.cardinality() {
                        // we have all the deposit sigs now
                        // we can publish the deposit

                        Some(OperatorDuty::PublishDeposit {
                            partial_sigs: root_partials.clone(),
                            deposit_tx: self.cfg.deposit_tx.clone(),
                        })
                    } else {
                        None
                    },
                )
            }
            ContractState::Deposited { .. } => {
                // somebody else may have deposited already.
                warn!("contract already in deposited state, skipping root signature generation");
                // FIXME: (@Rajil1213) this should return an error
                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_root_signature ({})",
                self.state.state
            ))),
        }
    }

    /// Increment the internally tracked block height.
    fn notify_new_block(
        &mut self,
        height: BitcoinBlockHeight,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        if self.state.block_height + 1 == height {
            self.state.block_height = height;
        } else {
            return Err(TransitionErr(format!(
                "received unexpected new block notification, wanted {}, got {}",
                self.state.block_height + 1,
                height
            )));
        }
        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);

        let duty = match &current {
            // the next states for the following states do not depend on a timelock
            // and so are agnostic to new block events.
            ContractState::Deposited { .. }
            | ContractState::Assigned { .. }
            | ContractState::StakeTxReady { .. }
            | ContractState::Fulfilled { .. }
            | ContractState::PreAssertConfirmed { .. }
            | ContractState::AssertDataConfirmed { .. }
            | ContractState::Disproved {}
            | ContractState::Resolved { .. }
            | ContractState::Stub => None,

            // the next states for the following states depend on a timelock
            // and therefore care about a new block event.
            ContractState::Requested { abort_deadline, .. } => {
                if self.state.block_height >= *abort_deadline {
                    Some(OperatorDuty::Abort)
                } else {
                    None
                }
            }
            ContractState::Claimed {
                fulfiller,
                claim_height,
                graph_sigs,
                active_graph,
                ..
            } => {
                let pov_idx = self.cfg.operator_table.pov_idx();

                if self.state.block_height
                    >= claim_height + self.cfg.connector_params.payout_optimistic_timelock as u64
                    && *fulfiller == pov_idx
                {
                    let deposit_txid = self.cfg().deposit_tx.compute_txid();
                    let stake_index = self.cfg().deposit_idx;
                    let claim_txid = active_graph.1.claim_txid;
                    let stake_txid = active_graph.1.stake_txid;
                    let agg_sigs = graph_sigs
                        .get(&claim_txid)
                        .ok_or(TransitionErr(format!(
                            "could not find graph sigs for claim txid {claim_txid} in claimed state after payout optimistic timelock",
                        )))?
                        .payout_optimistic;

                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishPayoutOptimistic {
                            deposit_txid,
                            claim_txid,
                            stake_txid,
                            stake_index,
                            agg_sigs: agg_sigs.into(),
                        },
                    ))
                } else {
                    None
                }
            }
            ContractState::Challenged {
                claim_height,
                fulfiller,
                active_graph,
                graph_sigs,
                ..
            } => {
                let pov_idx = self.cfg.operator_table.pov_idx();

                if self.state.block_height
                    >= claim_height + self.cfg.connector_params.pre_assert_timelock as u64
                    && *fulfiller == pov_idx
                {
                    let deposit_idx = self.cfg.deposit_idx;
                    let deposit_txid = self.deposit_txid();
                    let claim_txid = active_graph.1.claim_txid;

                    let agg_sig = graph_sigs
                        .get(&claim_txid)
                        .ok_or(TransitionErr(format!(
                            "could not find graph sigs for claim txid {claim_txid} in challenged state",
                        )))?
                        .pre_assert;

                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishPreAssert {
                            deposit_idx,
                            deposit_txid,
                            claim_txid,
                            agg_sig,
                        },
                    ))
                } else {
                    None
                }
            }
            ContractState::Asserted {
                post_assert_height,
                fulfiller,
                active_graph,
                graph_sigs,
                ..
            } => {
                if self.state.block_height
                    >= post_assert_height + self.cfg.connector_params.payout_timelock as u64
                    && *fulfiller == self.cfg.operator_table.pov_idx()
                {
                    Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishPayout {
                        deposit_idx: self.cfg.deposit_idx,
                        deposit_txid: self.deposit_txid(),
                        post_assert_txid: active_graph.1.post_assert_txid,
                        claim_txid: active_graph.1.claim_txid,
                        stake_txid: active_graph.0.stake_outpoint.txid,
                        agg_sigs: graph_sigs
                            .get(&active_graph.1.claim_txid)
                            .ok_or(TransitionErr(format!(
                                "could not find graph sigs for claim txid {} in asserted state after payout timelock",
                                active_graph.1.claim_txid
                            )))?
                            .payout
                            .into(),
                    }))
                } else {
                    None
                }
            }
        };

        // restore state
        self.state.state = current;

        Ok(duty)
    }

    /// Processes an assignment from the strata state commitment.
    pub fn process_assignment(
        &mut self,
        assignment: &DepositEntry,
        stake_tx: StakeTxKind,
        height: BitcoinBlockHeight,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        info!(?assignment, current_state=%self.state().state, "processing assignment");

        if assignment.idx() != self.cfg.deposit_idx {
            return Err(TransitionErr(format!(
                "unexpected assignment ({}) delivered to CSM ({})",
                assignment.idx(),
                self.cfg.deposit_idx
            )));
        }

        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        let copy_of_current = current.clone();

        match current {
            ContractState::Deposited {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                graph_partials,
            } => {
                match assignment.deposit_state() {
                    DepositState::Dispatched(dispatched_state) => {
                        let fulfiller = dispatched_state.assignee();
                        let fulfiller_key = match self.cfg.operator_table.idx_to_op_key(&fulfiller)
                        {
                            Some(op_key) => op_key.clone(),
                            None => {
                                return Err(TransitionErr(format!(
                                    "could not convert operator index {} to operator key",
                                    fulfiller
                                )));
                            }
                        };

                        let fulfiller_claim_txid =
                            claim_txids
                                .get(&fulfiller_key)
                                .ok_or(TransitionErr(format!(
                                "could not find claim_txid for operator {fulfiller_key} in csm {}",
                                self.deposit_txid()
                            )))?;

                        let deadline = dispatched_state.exec_deadline();
                        let active_graph = peg_out_graphs
                            .get(fulfiller_claim_txid)
                            .ok_or(TransitionErr(format!(
                                "could not find peg out graph {fulfiller_claim_txid} in csm {}",
                                self.deposit_txid()
                            )))?
                            .to_owned();

                        let recipient = dispatched_state
                            .cmd()
                            .withdraw_outputs()
                            .first()
                            .map(|out| out.destination());

                        if let (Some(recipient), Some(withdrawal_request_txid)) =
                            (recipient, assignment.withdrawal_request_txid())
                        {
                            self.state.state = ContractState::Assigned {
                                peg_out_graphs: peg_out_graphs.clone(),
                                claim_txids: claim_txids.clone(),
                                graph_sigs,
                                fulfiller,
                                deadline,
                                active_graph,
                                recipient: recipient.clone(),
                                withdrawal_request_txid: withdrawal_request_txid.into(),
                                graph_partials: graph_partials.clone(),
                                l1_start_height: height,
                            };

                            let stake_index = assignment.idx();

                            Ok(Some(OperatorDuty::FulfillerDuty(
                                FulfillerDuty::AdvanceStakeChain {
                                    stake_tx,
                                    stake_index,
                                },
                            )))
                        } else {
                            warn!(?assignment, "assignment does not contain a recipient or withdrawal request txid");
                            self.state.state = copy_of_current.clone();

                            Err(TransitionErr(format!("invalid assignment state, missing recipient or withdrawal request txid, {assignment:?}")))
                        }
                    }

                    _ => Err(TransitionErr(format!(
                        "received a non-dispatched deposit entry as an assignment {:?}",
                        assignment
                    ))),
                }
            }
            ContractState::Assigned { .. } => {
                // TODO: (@Rajil1213) check if this is a new assignment i.e., the assignee is
                // different

                warn!("received assignment even though contract is already assigned");
                self.state.state = current;

                Ok(None)
            }
            _ => {
                warn!(?assignment, %current, "received stale assignment, ignoring...");
                self.state.state = current;

                Ok(None)
            }
        }
    }

    fn process_stake_chain_advancement(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        info!("processing stake chain advancement");

        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        let copy_of_current = current.clone();

        match current {
            ContractState::Assigned {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                fulfiller,
                recipient,
                deadline,
                active_graph,
                withdrawal_request_txid,
                graph_partials,
                l1_start_height,
            } => {
                if tx.compute_txid() != active_graph.1.stake_txid {
                    // might be somebody else's stake txid
                    self.state.state = copy_of_current;

                    // FIXME: (@Rajil1213) This should be an error variant that the upstream code
                    // can handle. Most likely, the upstream code will just
                    // ignore this error.
                    return Ok(None);
                }

                self.state.state = ContractState::StakeTxReady {
                    peg_out_graphs,
                    graph_sigs,
                    claim_txids,
                    fulfiller,
                    recipient: recipient.clone(),
                    deadline,
                    active_graph,
                    withdrawal_request_txid,
                    graph_partials,
                    l1_start_height,
                };
                let is_assigned_to_me = fulfiller == self.cfg.operator_table.pov_idx();

                if !is_assigned_to_me {
                    // FIXME: (@Rajil1213) this should be an error case (all cases that don't update
                    // the state are error cases).
                    return Ok(None);
                }

                // if this withdrawal is assigned to this operator, then it needs to fulfill
                // it.
                let withdrawal_metadata = WithdrawalMetadata {
                    tag: self.cfg.peg_out_graph_params.tag,
                    operator_idx: fulfiller,
                    deposit_idx: self.cfg.deposit_idx,
                    deposit_txid: self.deposit_txid(),
                };

                Ok(Some(OperatorDuty::FulfillerDuty(
                    FulfillerDuty::PublishFulfillment {
                        withdrawal_metadata,
                        user_descriptor: recipient,
                    },
                )))
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_stake_chain_advancement ({})",
                current
            ))),
        }
    }

    fn process_fulfillment_confirmation(
        // Analyze fulfillment transaction to determine
        &mut self,
        tx: &Transaction,
        height: BitcoinBlockHeight,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        let copy_of_current = current.clone();

        match current {
            ContractState::StakeTxReady {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                fulfiller,
                active_graph,
                recipient,
                graph_partials,
                l1_start_height,
                ..
            } => {
                // TODO(proofofkeags): we need to verify that this is bound properly to the correct
                // operator.
                let cfg = self.cfg();
                let deposit_txid = cfg.deposit_tx.compute_txid();
                let stake_txid = active_graph.1.stake_txid;

                if !is_fulfillment_tx(
                    cfg.network,
                    &cfg.peg_out_graph_params,
                    fulfiller,
                    cfg.deposit_idx,
                    cfg.deposit_tx.compute_txid(),
                    recipient.clone(),
                )(tx)
                {
                    // might get somebody else's stake transaction here.
                    // this can happen if this node's stake transaction is settled before other
                    // nodes'.
                    self.state.state = copy_of_current;

                    // FIXME: (@Rajil1213) this should be an error case.

                    return Ok(None);
                }

                let withdrawal_fulfillment_txid = tx.compute_txid();
                debug!(%withdrawal_fulfillment_txid, "discovered withdrawal fulfillment");
                self.state.state = ContractState::Fulfilled {
                    peg_out_graphs,
                    claim_txids,
                    graph_sigs,
                    fulfiller,
                    active_graph,
                    graph_partials,
                    withdrawal_fulfillment_txid,
                    withdrawal_fulfillment_height: height,
                    l1_start_height,
                };

                let duty = if fulfiller == self.cfg.operator_table.pov_idx() {
                    Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishClaim {
                        withdrawal_fulfillment_txid: tx.compute_txid(),
                        stake_txid,
                        deposit_txid,
                    }))
                } else {
                    None
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_fulfillment_confirmation ({})",
                current
            ))),
        }
    }

    fn process_claim_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        debug!(txid=%tx.compute_txid(), %height, "processing confirmation of claim tx");

        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        let copy_of_current = current.clone();
        match current {
            ContractState::Fulfilled {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                fulfiller,
                active_graph,
                graph_partials,
                withdrawal_fulfillment_txid,
                l1_start_height,
                ..
            } => {
                if tx.compute_txid() != active_graph.1.claim_txid {
                    self.state.state = copy_of_current;

                    return Err(TransitionErr(format!(
                        "invalid claim confirmation ({})",
                        tx.compute_txid()
                    )));
                }

                let duty = if fulfiller != self.cfg.operator_table.pov_idx() {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyClaim))
                } else {
                    None
                };

                let commitment = ClaimTx::parse_witness(tx).map_err(|e| {
                    error!(%e, "could not parse witness from claim tx");

                    TransitionErr(format!("could not parse claim tx witness: {e}"))
                })?;

                self.state.state = ContractState::Claimed {
                    peg_out_graphs,
                    claim_txids,
                    graph_sigs,
                    claim_height: height,
                    fulfiller,
                    active_graph,
                    graph_partials,
                    l1_start_height,
                    withdrawal_fulfillment_txid,
                    withdrawal_fulfillment_commitment: Wots256Sig(commitment),
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_claim_confirmation ({})",
                current
            ))),
        }
    }

    /// Tells the state machine that the claim was assessed to be fraudulent.
    fn process_claim_verification_failure(
        &mut self,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &self.state.state {
            ContractState::Claimed { .. } => Ok(Some(OperatorDuty::VerifierDuty(
                VerifierDuty::PublishChallenge,
            ))),
            _ => Err(TransitionErr(format!(
                "unexpected state in process_claim_verification_failure ({})",
                self.state.state
            ))),
        }
    }

    fn process_challenge_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        let copy_of_current = current.clone();
        match current {
            ContractState::Claimed {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                fulfiller,
                active_graph,
                claim_height,
                l1_start_height,
                withdrawal_fulfillment_txid,
                withdrawal_fulfillment_commitment,
                ..
            } => {
                let claim_txid = active_graph.1.claim_txid;
                if !is_challenge(claim_txid)(tx) {
                    self.state.state = copy_of_current;

                    return Err(TransitionErr(format!(
                        "received non-challenge tx in process_challenge_confirmation: {}",
                        tx.compute_txid()
                    )));
                }

                let challenge_txid = tx.compute_txid();
                info!(%claim_txid, %challenge_txid, "received challenge confirmation");
                self.state.state = ContractState::Challenged {
                    peg_out_graphs,
                    claim_txids,
                    graph_sigs,
                    fulfiller,
                    active_graph,
                    claim_height,
                    l1_start_height,
                    withdrawal_fulfillment_txid,
                    withdrawal_fulfillment_commitment,
                };

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_challenge_confirmation ({})",
                current
            ))),
        }
    }

    fn process_pre_assert_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        let copy_of_current = current.clone();

        let txid = tx.compute_txid();
        match current {
            ContractState::Challenged {
                peg_out_graphs,
                claim_txids,
                active_graph,
                graph_sigs,
                fulfiller,
                claim_height,
                l1_start_height,
                withdrawal_fulfillment_txid,
                withdrawal_fulfillment_commitment,
                ..
            }
            | ContractState::Claimed {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                claim_height,
                fulfiller,
                active_graph,
                withdrawal_fulfillment_txid,
                withdrawal_fulfillment_commitment,
                l1_start_height,
                ..
            } => {
                if txid != active_graph.1.pre_assert_txid {
                    self.state.state = copy_of_current;

                    return Err(TransitionErr(format!(
                        "invalid pre assert transaction ({}) in process_pre_assert_confirmation",
                        tx.compute_txid()
                    )));
                }

                self.state.state = ContractState::PreAssertConfirmed {
                    peg_out_graphs,
                    claim_txids,
                    graph_sigs,
                    fulfiller,
                    active_graph,
                    claim_height,
                    l1_start_height,
                    withdrawal_fulfillment_txid,
                    withdrawal_fulfillment_commitment,
                };

                let pre_assert_locking_scripts = tx
                    .output
                    .iter()
                    .map(|out| out.script_pubkey.clone())
                    .take(NUM_ASSERT_DATA_TX)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("pre-assert tx must have the right number of outputs");

                let pov_idx = self.cfg.operator_table.pov_idx();
                if fulfiller != pov_idx {
                    return Ok(None);
                }

                Ok(Some(OperatorDuty::FulfillerDuty(
                    FulfillerDuty::PublishAssertData {
                        withdrawal_fulfillment_txid,
                        start_height: l1_start_height,
                        deposit_idx: self.cfg.deposit_idx,
                        deposit_txid: self.deposit_txid(),
                        pre_assert_txid: txid,
                        pre_assert_locking_scripts,
                    },
                )))
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_pre_assert_confirmation ({})",
                current
            ))),
        }
    }

    fn process_assert_data_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let txid = tx.compute_txid();
        let deposit_txid = self.deposit_txid();

        match &mut self.state.state {
            ContractState::PreAssertConfirmed {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                fulfiller,
                active_graph,
                withdrawal_fulfillment_txid,
                withdrawal_fulfillment_commitment,
                ..
            } => {
                if !active_graph.1.assert_data_txids.contains(&txid) {
                    return Err(TransitionErr(format!(
                        "non assert data tx ({txid}) received in process_assert_data_confirmation when pre-assert confirmed"
                    )));
                }

                // a lot of clone here but this is only going to be done once
                // v/s the next match arm that is going to be called `NUM_ASSERT_DATA_TX` - 1 times
                // where we want to mutate some part of the state (not to mention a copy of the
                // entire state that will have to be maintained always in order to restore the state
                // after a mem::replace in the event of an error)
                self.state.state = ContractState::AssertDataConfirmed {
                    peg_out_graphs: peg_out_graphs.clone(),
                    claim_txids: claim_txids.clone(),
                    graph_sigs: graph_sigs.clone(),
                    fulfiller: *fulfiller,
                    active_graph: active_graph.clone(),
                    withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                    withdrawal_fulfillment_commitment: *withdrawal_fulfillment_commitment,
                    signed_assert_data_txs: HashMap::from([(txid, tx.clone())]),
                };

                Ok(None)
            }
            ContractState::AssertDataConfirmed {
                active_graph,
                signed_assert_data_txs,
                graph_sigs,
                fulfiller,
                ..
            } => {
                if !active_graph.1.assert_data_txids.contains(&txid) {
                    return Err(TransitionErr(format!(
                        "non assert data tx ({txid}) received in process_assert_data_confirmation after {} assert-data confirmed",
                        signed_assert_data_txs.keys().count()
                    )));
                }

                signed_assert_data_txs.insert(txid, tx.clone());

                if signed_assert_data_txs.keys().count() == NUM_ASSERT_DATA_TX {
                    info!("all assert data transactions confirmed");

                    let agg_sigs = graph_sigs
                        .get(&active_graph.1.claim_txid)
                        .ok_or(TransitionErr(format!(
                            "could not find graph sigs for claim txid {} in assert data confirmed state",
                            active_graph.1.claim_txid
                        )))?
                        .post_assert;

                    let pov_idx = self.cfg.operator_table.pov_idx();
                    if *fulfiller != pov_idx {
                        // not our turn to publish post-assert
                        return Ok(None);
                    }

                    Ok(Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishPostAssertData {
                            deposit_txid,
                            assert_data_txids: Box::new(active_graph.1.assert_data_txids),
                            agg_sigs: Box::new(agg_sigs),
                        },
                    )))
                } else {
                    Ok(None)
                }
            }
            invalid_state => Err(TransitionErr(format!(
                "unexpected state in process_assert_data_confirmation ({})",
                invalid_state
            ))),
        }
    }

    fn process_post_assert_confirmation(
        &mut self,
        tx: &Transaction,
        post_assert_height: BitcoinBlockHeight,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        match current {
            ContractState::AssertDataConfirmed {
                peg_out_graphs,
                claim_txids,
                graph_sigs,
                fulfiller,
                active_graph,
                withdrawal_fulfillment_txid,
                withdrawal_fulfillment_commitment,
                signed_assert_data_txs,
            } if signed_assert_data_txs.keys().count() == NUM_ASSERT_DATA_TX => {
                if tx.compute_txid() != active_graph.1.post_assert_txid {
                    return Err(TransitionErr(format!(
                        "invalid post assert transaction ({}) in process_assert_chain_confirmation",
                        tx.compute_txid()
                    )));
                }

                let assert_data_txs = active_graph
                    .1
                    .assert_data_txids
                    .iter()
                    .map(|txid| {
                        signed_assert_data_txs
                            .get(txid)
                            .ok_or(TransitionErr(format!(
                                "could not find assert data tx {txid} in csm {}",
                                self.deposit_txid()
                            )))
                            .cloned()
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .expect("must have right number of assert data transactions");

                let proof_commitment = AssertDataTxBatch::parse_witnesses(&assert_data_txs)
                    .map_err(|e| {
                        error!(%e, "could not parse witness from assert data txs");

                        TransitionErr(format!("could not parse assert data tx witness: {e}"))
                    })?;

                self.state.state = ContractState::Asserted {
                    peg_out_graphs,
                    claim_txids,
                    graph_sigs,
                    post_assert_height,
                    fulfiller,
                    active_graph,
                    withdrawal_fulfillment_txid,
                    withdrawal_fulfillment_commitment,
                    proof_commitment: Groth16Sigs(proof_commitment),
                };

                let duty = if fulfiller != self.cfg.operator_table.pov_idx() {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyAssertion))
                } else {
                    None
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_post_assert_confirmation ({})",
                current
            ))),
        }
    }

    /// Tells the state machine that the assertion chain is invalid.
    fn process_assertion_verification_failure(
        &mut self,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Stub);
        match current {
            ContractState::Asserted { .. } => Ok(Some(OperatorDuty::VerifierDuty(
                VerifierDuty::PublishDisprove,
            ))),
            _ => Err(TransitionErr(format!(
                "unexpected state in process_assert_verification_failure ({})",
                current
            ))),
        }
    }

    fn process_disprove_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.state.clone() {
            ContractState::Asserted { active_graph, .. } => {
                if !is_disprove(active_graph.1.post_assert_txid)(tx) {
                    return Err(TransitionErr(format!(
                        "invalid disprove transaction ({}) in process_disprove_confirmation",
                        tx.compute_txid()
                    )));
                }

                self.state.state = ContractState::Disproved {};

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_disprove_confirmation ({})",
                self.state.state
            ))),
        }
    }

    fn process_optimistic_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Claimed {
                active_graph,
                withdrawal_fulfillment_txid,
                ..
            } => {
                let payout_optimistic_txid = tx.compute_txid();
                if payout_optimistic_txid != active_graph.1.payout_optimistic_txid {
                    return Err(TransitionErr(format!("invalid optimistic payout transaction ({}) in process_optimistic_payout_confirmation", tx.compute_txid())));
                }

                info!(txid=%payout_optimistic_txid, "processing optimistic payout confirmation");
                self.state.state = ContractState::Resolved {
                    withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                    payout_txid: payout_optimistic_txid,
                    path: ResolutionPath::Optimistic,
                };

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_optimistic_payout_confirmation ({})",
                self.state.state
            ))),
        }
    }

    fn process_defended_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Asserted {
                active_graph,
                withdrawal_fulfillment_txid,
                ..
            } => {
                let defended_payout_txid = tx.compute_txid();
                if defended_payout_txid != active_graph.1.payout_txid {
                    return Err(TransitionErr(format!(
                        "invalid defended payout transaction ({}) in process_defended_payout_confirmation", tx.compute_txid()
                    )));
                }

                self.state.state = ContractState::Resolved {
                    withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                    payout_txid: defended_payout_txid,
                    path: ResolutionPath::Contested,
                };

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_defended_payout_confirmation ({})",
                self.state.state
            ))),
        }
    }

    /// Dumps the config parameters of the state machine.
    pub const fn cfg(&self) -> &ContractCfg {
        &self.cfg
    }

    /// Dumps the current state of the state machine.
    pub const fn state(&self) -> &MachineState {
        &self.state
    }

    /// Returns an immutable copy of the peg out graph.
    pub const fn pog(&self) -> &BTreeMap<Txid, PegOutGraph> {
        &self.pog
    }

    /// The txid of the deposit on which this contract is centered.
    pub fn deposit_txid(&self) -> Txid {
        self.cfg.deposit_tx.compute_txid()
    }

    /// The txid of the original deposit request that kicked off this contract.
    pub fn deposit_request_txid(&self) -> Txid {
        self.cfg().deposit_request_txid()
    }

    /// Clears the [`PegOutGraph`] cache.
    pub fn clear_pog_cache(&mut self) {
        self.pog.clear();
    }

    /// Gives us a list of claim txids that can be used to reference this contract.
    pub fn claim_txids(&self) -> Vec<Txid> {
        let dummy = BTreeMap::new();
        match &self.state().state {
            ContractState::Requested { claim_txids, .. }
            | ContractState::Deposited { claim_txids, .. }
            | ContractState::Assigned { claim_txids, .. }
            | ContractState::StakeTxReady { claim_txids, .. }
            | ContractState::Fulfilled { claim_txids, .. }
            | ContractState::Claimed { claim_txids, .. }
            | ContractState::Challenged { claim_txids, .. }
            | ContractState::PreAssertConfirmed { claim_txids, .. }
            | ContractState::AssertDataConfirmed { claim_txids, .. }
            | ContractState::Asserted { claim_txids, .. } => claim_txids,
            ContractState::Disproved {} | ContractState::Resolved { .. } | ContractState::Stub => {
                &dummy
            }
        }
        .values()
        .copied()
        .collect()
    }

    /// The txid of the assignment transaction for this contract.
    ///
    /// Note that this is only available if the contract is in the [`ContractState::Assigned`] or
    /// [`ContractState::StakeTxReady`] state.
    pub const fn withdrawal_request_txid(&self) -> Option<Txid> {
        match &self.state().state {
            ContractState::Assigned {
                withdrawal_request_txid,
                ..
            }
            | ContractState::StakeTxReady {
                withdrawal_request_txid,
                ..
            } => Some(*withdrawal_request_txid),

            ContractState::Requested { .. }
            | ContractState::Deposited { .. }
            | ContractState::Fulfilled { .. }
            | ContractState::Claimed { .. }
            | ContractState::Challenged { .. }
            | ContractState::PreAssertConfirmed { .. }
            | ContractState::AssertDataConfirmed { .. }
            | ContractState::Asserted { .. }
            | ContractState::Disproved {}
            | ContractState::Resolved { .. }
            | ContractState::Stub => None,
        }
    }
    /// The txid of the withdrawal fulfillment for this contract.
    ///
    /// Note that this is only available if the contract is in the [`ContractState::Fulfilled`]
    /// state.
    pub const fn withdrawal_fulfillment_txid(&self) -> Option<Txid> {
        match &self.state().state {
            ContractState::Requested { .. }
            | ContractState::Deposited { .. }
            | ContractState::Assigned { .. }
            | ContractState::StakeTxReady { .. }
            | ContractState::Disproved {}
            | ContractState::Resolved { .. }
            | ContractState::Stub => None,

            ContractState::Fulfilled {
                withdrawal_fulfillment_txid,
                ..
            }
            | ContractState::Claimed {
                withdrawal_fulfillment_txid,
                ..
            }
            | ContractState::Challenged {
                withdrawal_fulfillment_txid,
                ..
            }
            | ContractState::PreAssertConfirmed {
                withdrawal_fulfillment_txid,
                ..
            }
            | ContractState::AssertDataConfirmed {
                withdrawal_fulfillment_txid,
                ..
            }
            | ContractState::Asserted {
                withdrawal_fulfillment_txid,
                ..
            } => Some(*withdrawal_fulfillment_txid),
        }
    }
}

fn aggregate_nonces(
    operator_table: &OperatorTable,
    graph_nonces: &BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PubNonce>>>,
) -> BTreeMap<Txid, Vec<AggNonce>> {
    let signer_keys = operator_table
        .btc_keys()
        .into_iter()
        .filter_map(|btc_key| operator_table.btc_key_to_op_key(&btc_key))
        .collect::<Vec<_>>();

    graph_nonces
        .iter()
        .map(|(claim_txid, session_nonces)| {
            let nonces_per_graph: Vec<Vec<PubNonce>> = signer_keys
                .iter()
                .filter_map(|signer| {
                    session_nonces
                        .get(signer)
                        .map(|nonces| nonces.clone().pack())
                })
                .collect::<Vec<_>>();

            // all operators are guaranteed to produce the same number of nonces
            // so we can get the total number of inputs from the nonces generated by the
            // first operator.
            let num_inputs = nonces_per_graph.first().map(|v| v.len()).unwrap_or(0);

            // fold all the nonces into a single aggregated nonce per input
            let agg_nonces_per_graph: Vec<AggNonce> = (0..num_inputs)
                .map(|input_index| {
                    nonces_per_graph
                        .iter()
                        .filter_map(|nonces| nonces.get(input_index))
                        .sum::<AggNonce>()
                })
                .collect::<Vec<_>>();

            (*claim_txid, agg_nonces_per_graph)
        })
        .collect()
}

/// Verifies that a signature provided by the `signer` is valid for the given graph and the set of
/// the pubnonces shared previously.
fn verify_partials_from_peer(
    cfg: &ContractCfg,
    signer: &P2POperatorPubKey,
    claim_txid: &Txid,
    pog: PegOutGraph,
    graph_nonces: &BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PubNonce>>>,
    agg_nonces: &BTreeMap<Txid, Vec<AggNonce>>,
    partial_sigs: &[PartialSignature],
) -> Result<(), TransitionErr> {
    let individual_pubkey = cfg
        .operator_table
        .op_key_to_btc_key(signer)
        .expect("signer must be part of musig session");

    let individual_pubnonces = graph_nonces
        .get(claim_txid)
        .map(|v| {
            v.get(signer)
                .expect("individual pubnonce must be present in unpacked")
        })
        .expect("claim txid must be present in graph nonces")
        .clone()
        .pack();

    let agg_nonces = agg_nonces.get(claim_txid).ok_or(TransitionErr(format!(
        "agg nonces missing for claim ({claim_txid})"
    )))?;

    let messages = pog.musig_sighashes().clone().pack();
    let witnesses = pog.musig_witnesses().clone().pack();

    let key_agg_ctx_script = KeyAggContext::new(cfg.operator_table.btc_keys())
        .expect("must be able to create key agg ctx");
    let key_agg_ctx_key = key_agg_ctx_script
        .clone()
        .with_unspendable_taproot_tweak()
        .expect("must be able to add unspendable tweak");

    if individual_pubnonces
        .iter()
        .zip(messages)
        .zip(witnesses)
        .zip(partial_sigs)
        .zip(agg_nonces)
        .any(
            |(
                    (((individual_pubnonce, message), witness), partial_signature),
                    aggregated_nonce,
            )| {
                let key_agg_ctx = match witness {
                    TaprootWitness::Key => &key_agg_ctx_key,
                    TaprootWitness::Script { .. } => &key_agg_ctx_script,
                    TaprootWitness::Tweaked { tweak } => &key_agg_ctx_script
                        .clone()
                        .with_taproot_tweak(tweak.as_ref())
                        .expect("must be able to add tweak"),
                };

                verify_partial(
                    key_agg_ctx,
                    *partial_signature,
                    aggregated_nonce,
                    individual_pubkey,
                    individual_pubnonce,
                    message.as_ref(),
                )
                .inspect_err(
                    |e| error!(%e, ?signer, %message, ?partial_signature, "partial sig verification failed"),
                )
                .is_err()
            },
        )
    {
        return Err(TransitionErr(format!("partial signature verification failed for claim txid ({}) from signer ({})", claim_txid, signer)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use secp256k1::Parity;
    use strata_bridge_test_utils::prelude::generate_txid;
    use strata_bridge_tx_graph::transactions::{
        payout::NUM_PAYOUT_INPUTS, prelude::NUM_POST_ASSERT_INPUTS,
        slash_stake::NUM_SLASH_STAKE_INPUTS,
    };

    use super::*;

    #[test]
    fn test_aggregate_nonces() {
        let nonces = get_sample_pubnonces();
        let expected_agg_nonce = nonces.iter().sum::<AggNonce>();

        let txid = generate_txid();
        let operator_table = get_sample_operator_table(0);

        let mut graph_nonces = BTreeMap::new();
        let mut session_nonces = BTreeMap::new();
        operator_table.operator_idxs().iter().for_each(|op_idx| {
            let signer = operator_table.idx_to_op_key(op_idx).unwrap();

            // populate the nonce for every input with the same pubnonce.
            // this means that each input will have the same pubnonce for the same operator.
            // this is a hack so that we can just check the nonce aggregation without being
            // completely faithful to how it will be in practice.
            let nonce = nonces[*op_idx as usize].clone();

            let pog_nonces = PogMusigF::<PubNonce> {
                challenge: nonce.clone(),
                pre_assert: nonce.clone(),
                post_assert: vec![nonce.clone(); NUM_POST_ASSERT_INPUTS]
                    .try_into()
                    .unwrap(),
                payout_optimistic: vec![nonce.clone(); NUM_PAYOUT_OPTIMISTIC_INPUTS]
                    .try_into()
                    .unwrap(),
                payout: vec![nonce.clone(); NUM_PAYOUT_INPUTS].try_into().unwrap(),
                disprove: nonce.clone(),
                slash_stake: vec![vec![nonce.clone(); NUM_SLASH_STAKE_INPUTS]
                    .try_into()
                    .unwrap()],
            };

            session_nonces.insert(signer.clone(), pog_nonces);
        });

        graph_nonces.insert(txid, session_nonces);

        let agg_nonces_map = aggregate_nonces(&operator_table, &graph_nonces);

        agg_nonces_map.values().for_each(|agg_nonces| {
            agg_nonces.iter().enumerate().for_each(|(i, agg_nonce)| {
                assert_eq!(agg_nonce, &expected_agg_nonce, "agg_nonce mismatch at {i}");
            });
        });
    }

    fn get_sample_pubnonces() -> [PubNonce; 3] {
        // sample nonces from `musig2` crate's example: https://docs.rs/musig2/latest/musig2/#functional-api
        [
            "02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
                0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45",
            "020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
                03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d",
            "02d1e90616ea78a612dddfe97de7b5e7e1ceef6e64b7bc23b922eae30fa2475cca\
                02e676a3af322965d53cc128597897ef4f84a8d8080b456e27836db70e5343a2bb",
        ]
        .map(|nonce_str| nonce_str.parse::<PubNonce>().unwrap())
    }

    fn get_sample_operator_table(pov_idx: u32) -> OperatorTable {
        let key_entries = [
            (
                "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d",
                "020b1251c1a11d65a3cf324c66b67e9333799d21490d2e2c95866aab76e3a0f301",
            ),
            (
                "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4",
                "0232a73fb8a00f677703e95ebc398d806147587746d02d1945f9eff8703ccab4d0",
            ),
            (
                "a4d869ccd09c470f8f86d3f1b0997fa2695933aaea001875b9db145ae9c1f4ba",
                "02e9343c08723ba25cfaa6296ffe8bf57be391cac683f13a3de33a31734655b777",
            ),
        ]
        .map(|(btc_str, signer_str)| {
            (
                XOnlyPublicKey::from_str(btc_str)
                    .unwrap()
                    .public_key(Parity::Even),
                P2POperatorPubKey::from(hex::decode(signer_str).unwrap()),
            )
        })
        .iter()
        .enumerate()
        .map(|(i, (btc_key, p2p_key))| (i as u32, p2p_key.clone(), *btc_key))
        .collect::<Vec<_>>();

        let pov_idx = pov_idx % key_entries.len() as u32;
        OperatorTable::new(key_entries, pov_idx).unwrap()
    }
}

/// This module defines genenerator functions of various types defined in the super module.
#[cfg(test)]
mod prop_tests {
    use std::{str::FromStr, time::Instant};

    use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
    use bdk_wallet::miniscript::ToPublicKey;
    use bitcoin::{
        hashes::{sha256, sha256d, Hash},
        Network, Txid,
    };
    use proptest::{prelude::*, prop_compose};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_primitives::{
        build_context::BuildContext,
        operator_table::prop_test_generators::{arb_btc_key, arb_operator_table},
        wots,
    };
    use strata_bridge_tx_graph::transactions::deposit::{
        prop_tests::arb_deposit_request_data, DepositTx,
    };
    use strata_p2p_types::P2POperatorPubKey;
    use strata_primitives::{
        block_credential::CredRule,
        buf::Buf32,
        operator::OperatorPubkeys,
        params::{OperatorConfig, ProofPublishMode, RollupParams},
        proof::RollupVerifyingKey,
    };
    use tracing::{error, info};

    use super::{ContractCfg, ContractEvent, ContractSM, MachineState};

    prop_compose! {
        /// Generates a random 32 byte hash as a [`Txid`].
        fn arb_txid()(bs in any::<[u8; 32]>()) -> Txid {
            Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&bs))
        }
    }

    prop_compose! {
        /// Generates a random 32 byte hash as a [`sha256::Hash`].
        fn arb_hash()(bytes in any::<[u8; 32]>()) -> sha256::Hash {
            sha256::Hash::from_byte_array(bytes)
        }
    }

    prop_compose! {
        /// Generates a random [`ContractCfg`].
        pub fn arb_contract_cfg()(
            operator_table in arb_operator_table(),
            deposit_idx in 1..100,
            peg_out_graph_params in Just(PegOutGraphParams::default())
        )(
            deposit_idx in Just(deposit_idx),
            drt_data in arb_deposit_request_data(
                peg_out_graph_params.deposit_amount,
                peg_out_graph_params.refund_delay,
                operator_table.tx_build_context(Network::Regtest).aggregated_pubkey(),
            ),
            operator_table in Just(operator_table),
        ) -> ContractCfg {
            let peg_out_graph_params = PegOutGraphParams::default();

            let rollup_params = RollupParams {
                rollup_name: "strata".into(),
                block_time: 5000,
                da_tag: "strata-da".into(),
                checkpoint_tag: "strata-ckpt".into(),
                cred_rule: CredRule::SchnorrKey(
                    Buf32::from_str(
                        "8f2f6c25be6a4de02b8ae1f785749ba77431075ee801e00cfb0af1ed188f8eda"
                    ).unwrap(),
                ),
                horizon_l1_height: 50,
                genesis_l1_height: 100,
                operator_config: OperatorConfig::Static(vec![
                    OperatorPubkeys::new(
                        Buf32::from_str(
                            "8d86834e6fdb45ba6b7ffd067a27b9e1d67778047581d7ef757ed9e0fa474000"
                        ).unwrap(),
                        Buf32::from_str(
                            "b49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d"
                        ).unwrap()
                    ),
                    OperatorPubkeys::new(
                        Buf32::from_str(
                            "0abb00b8b17e2798ddebd0ccbb858b6f624a1ff7d93ec15baa8a7be3f136474d"
                        ).unwrap(),
                        Buf32::from_str(
                            "1e62d54af30569fd7269c14b6766f74d85ea00c911c4e1a423d4ba2ae4c34dc4"
                        ).unwrap()
                    ),
                    OperatorPubkeys::new(
                        Buf32::from_str(
                            "2a4b743dc2393a6ee038350a6ef3a55741e6c78ac6491478d832f4e2a23aa6be"
                        ).unwrap(),
                        Buf32::from_str(
                            "a4d869ccd09c470f8f86d3f1b0997fa2695933aaea001875b9db145ae9c1f4ba"
                        ).unwrap()
                    ),
                ]),
                evm_genesis_block_hash:
                    Buf32::from_str(
                        "37ad61cff1367467a98cf7c54c4ac99e989f1fbb1bc1e646235e90c065c565ba"
                    ).unwrap(),
                evm_genesis_block_state_root:
                    Buf32::from_str(
                        "351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f"
                    ).unwrap(),
                l1_reorg_safe_depth: 6,
                target_l2_batch_size: 3,
                address_length: 20,
                deposit_amount: peg_out_graph_params.deposit_amount.to_sat(),
                rollup_vk: RollupVerifyingKey::NativeVerifyingKey(
                    Buf32::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000000"
                    ).unwrap(),
                ),
                dispatch_assignment_dur: 1000000,
                proof_publish_mode: ProofPublishMode::Timeout(30),
                max_deposits_in_block: 16,
                network: Network::Regtest,
            };

            let deposit_tx = DepositTx::new(
                &drt_data,
                &operator_table.tx_build_context(Network::Regtest),
                &peg_out_graph_params,
                &rollup_params,
            ).expect("consistent parameterization");

            ContractCfg {
                network: bitcoin::Network::Regtest,
                operator_table,
                connector_params: ConnectorParams::default(),
                peg_out_graph_params,
                sidesystem_params: rollup_params,
                stake_chain_params: StakeChainParams::default(),
                deposit_idx: deposit_idx as u32,
                deposit_tx,
            }
        }
    }

    prop_compose! {
        /// Generates a random [`ContractEvent::DepositSetup`].
        pub fn arb_deposit_setup_from_operator(origin: P2POperatorPubKey)(
            cpfp_pubkey in arb_btc_key().prop_map(|x|x.to_x_only_pubkey()),
            stake_hash in arb_hash(),
            stake_txid in arb_txid(),
            wots_keys: wots::PublicKeys,
        ) -> ContractEvent {
            ContractEvent::DepositSetup {
                operator_p2p_key: origin.clone(),
                operator_btc_key: cpfp_pubkey,
                stake_hash,
                stake_txid,
                wots_keys: Box::new(wots_keys),
            }
        }
    }

    prop_compose! {
        /// Generates a [`MachineState`] with all three [`DepositSetup`](super::DepositSetup)
        /// messages.
        pub fn arb_machine_state()(
            cfg in arb_contract_cfg(),
            block_height in 500_000..800_000u64,
        )(
            events in cfg.operator_table.clone()
                .p2p_keys()
                .iter()
                .map(|pk| arb_deposit_setup_from_operator(pk.clone()).boxed()).collect::<Vec<_>>(),
            cfg in Just(cfg),
            block_height in Just(block_height),
        ) -> MachineState {
            let abort_deadline = block_height + cfg.peg_out_graph_params.refund_delay as u64;
            let mut csm = ContractSM::new(cfg, block_height, abort_deadline);

            // We have to set this environment variable to prevent the verifier script generation
            // from making network calls. We do this in the generator because it has to be done
            // before the graph generation jobs kick off which happens when we feed the contract
            // events to the CSM. We can't do this in the normal test case because generator
            // sampling happens before the test case run (call-by-value semantics).
            unsafe { std::env::set_var("ZKVM_MOCK", "true"); }
            for event in events {
                csm.process_contract_event(event).expect("valid deposit setup");
            }

            csm.state().clone()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(0))] // This still does 1 test case. It's weird.
        #[test]
        fn machine_state_serialization_invertible(state in arb_machine_state().no_shrink()) {
            logging::init(LoggerConfig::new("machine_state_serialization_invertible".to_string()));
            let mut time = Instant::now();
            info!("serializing machine state");
            match serde_json::to_string(&state) {
                Ok(serialized) => {
                    info!("serialization complete. time taken: {:?}", Instant::now().duration_since(time));
                    time = Instant::now();
                    info!("deserializing machine state");
                    match serde_json::from_str(&serialized) {
                        Ok(deserialized) => {
                            info!("deserialization complete. time taken: {:?}", Instant::now().duration_since(time));
                            prop_assert_eq!(
                                &state,
                                &deserialized,
                                "MachineState round trip serialization failed. before: {:?}, after: {:?}",
                                state,
                                deserialized
                            );
                        }
                        Err(e) => {
                            let msg = format!("MachineState could not be serialized: {e}");
                            error!("{}", &msg);
                            prop_assert!(false, "{}", &msg);
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("MachineState could not be serialized: {e}");
                    error!("{}", &msg);
                    prop_assert!(false, "{}", &msg);

                }
            };
        }
    }
}
