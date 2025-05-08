//! This module defines the core state machine for the Bridge Deposit Contract. All of the states,
//! events and transition rules are encoded in this structure. When the ContractSM accepts an event
//! it may or may not give back an OperatorDuty to execute as a result of this state transition.
use std::{collections::BTreeMap, fmt::Display, sync::Arc, thread};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{
    hashes::{
        serde::{Deserialize, Serialize},
        sha256,
    },
    sighash::{Prevouts, SighashCache},
    Network, OutPoint, TapSighashType, Transaction, Txid, XOnlyPublicKey,
};
use bitcoin_bosd::Descriptor;
use musig2::{
    secp256k1::{self, Message},
    PartialSignature, PubNonce,
};
use strata_bridge_primitives::{
    build_context::TxBuildContext,
    operator_table::OperatorTable,
    scripts::taproot::{create_message_hash, TaprootWitness},
    types::{BitcoinBlockHeight, OperatorIdx},
};
use strata_bridge_stake_chain::{
    prelude::{StakeTx, STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::StakeTxData,
};
use strata_bridge_tx_graph::{
    peg_out_graph::{PegOutGraph, PegOutGraphInput, PegOutGraphSummary},
    pog_musig_functor::PogMusigF,
    transactions::{
        deposit::DepositTx,
        prelude::{CovenantTx, WithdrawalMetadata, NUM_PAYOUT_OPTIMISTIC_INPUTS},
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
            withdrawal_fulfillment_pk: strata_bridge_primitives::wots::Wots256PublicKey(
                self.wots_pks.withdrawal_fulfillment.0,
            ),
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

        /// The stake transaction that holds the stake corresponding to the current contract.
        stake_tx: StakeTx,

        /// The wots keys needed to construct the pog.
        wots_keys: Box<WotsPublicKeys>,
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

    /// Signifies that we have received a new deposit nonce from one of our peers.
    RootNonce(P2POperatorPubKey, PubNonce),

    /// Signifies that we have a new deposit signature from one of our peers.
    RootSig(P2POperatorPubKey, PartialSignature),

    /// Signifies that this withdrawal has been assigned.
    Assignment(DepositEntry, StakeTx),

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// This is a collection of nonces for all graphs and for all operators.
        graph_nonces: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PubNonce>>>,

        /// This is a collection of all partial signatures for all graphs (indexed by the claim
        /// txid) and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,

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

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// The withdrawal fulfillment transaction ID.
        withdrawal_fulfillment_txid: Txid,

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,
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

        /// The height at which the claim transaction was confirmed.
        claim_height: BitcoinBlockHeight,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,
    },

    /// This state describes everything from the moment the challenge transaction confirms, to the
    /// moment the post-assert transaction confirms.
    Challenged {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,
    },

    /// This state describes everything from the moment the post-assert transaction confirms, to
    /// the moment either the disprove transaction confirms or the payout transaction confirms.
    Asserted {
        /// These are the actual peg-out-graph input parameters and summaries for each operator.
        /// This will be stored so we can monitor the transactions relevant to advancing the
        /// contract through its lifecycle, as well as reconstructing the graph when necessary.
        peg_out_graphs: BTreeMap<Txid, (PegOutGraphInput, PegOutGraphSummary)>,

        /// This is an index so we can look up the claim txid that is owned by the specified key.
        /// This is primarily used to process assignments.
        claim_txids: BTreeMap<P2POperatorPubKey, Txid>,

        /// The height at which the post-assert transaction was confirmed.
        post_assert_height: BitcoinBlockHeight,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: (PegOutGraphInput, PegOutGraphSummary),

        /// This is a collection of all partial signatures for all graphs and for all operators.
        graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,
    },

    /// This state describes the state after the disprove transaction confirms.
    Disproved {},

    /// This state describes the state after either the optimistic or defended payout transactions
    /// confirm.
    Resolved {},
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
            ContractState::Asserted {
                post_assert_height,
                fulfiller,
                active_graph,
                ..
            } => format!(
                "Asserted by operator {} at height {} ({})",
                fulfiller, post_assert_height, active_graph.1.post_assert_txid
            ),
            ContractState::Disproved { .. } => "Disproved".to_string(),
            ContractState::Resolved { .. } => "Resolved".to_string(),
        };

        write!(f, "ContractState: {}", display_str)
    }
}

impl ContractState {
    /// Computes all of the [`PegOutGraphSummary`]s that this contract state is currently aware of.
    pub fn summaries(&self) -> Vec<PegOutGraphSummary> {
        fn get_summaries<T>(
            g: &BTreeMap<T, (PegOutGraphInput, PegOutGraphSummary)>,
        ) -> Vec<PegOutGraphSummary> {
            g.values().map(|(_, summary)| summary).cloned().collect()
        }

        match self {
            ContractState::Requested { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Deposited { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Assigned { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::StakeTxReady { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Fulfilled { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Claimed { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Challenged { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Asserted { peg_out_graphs, .. } => get_summaries(peg_out_graphs),
            ContractState::Disproved { .. } => vec![],
            ContractState::Resolved { .. } => vec![],
        }
    }
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
    },

    /// Instructs us to send out our nonce for the deposit transaction signature.
    PublishRootNonce {
        /// Transaction ID of the DRT
        deposit_request_txid: Txid,

        /// The taproot witness required to reconstruct the taproot control block for the outpoint.
        witness: TaprootWitness,
    },

    /// Instructs us to send out signatures for the deposit transaction.
    PublishRootSignature {
        /// Transaction ID of the DRT
        deposit_request_txid: Txid,

        /// The nonces received from peers.
        nonces: BTreeMap<secp256k1::PublicKey, PubNonce>,

        /// The sighash that needs to be signed.
        sighash: Message,
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
        stake_tx: StakeTx,
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
        partials: [Vec<PartialSignature>; NUM_PAYOUT_OPTIMISTIC_INPUTS],
    },

    /// Originates once challenge transaction is issued
    PublishAssertChain,

    /// Originates after post-assert timelock expires
    PublishPayout,
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
                "AdvanceStakeChain for stake_index: {stake_index}, stake_tx: {stake_tx:?}"
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
            FulfillerDuty::PublishAssertChain => write!(f, "PublishAssertChain"),
            FulfillerDuty::PublishPayout => write!(f, "PublishPayout"),
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
    pub fn build_graph(&self, graph_input: PegOutGraphInput) -> PegOutGraph {
        PegOutGraph::generate(
            graph_input,
            &self.operator_table.tx_build_context(self.network),
            self.deposit_tx.compute_txid(),
            self.peg_out_graph_params.clone(),
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        operator_table: OperatorTable,
        connector_params: ConnectorParams,
        peg_out_graph_params: PegOutGraphParams,
        sidesystem_params: RollupParams,
        stake_chain_params: StakeChainParams,
        block_height: BitcoinBlockHeight,
        abort_deadline: BitcoinBlockHeight,
        deposit_idx: u32,
        deposit_request_txid: Txid,
        deposit_tx: DepositTx,
        stake_chain_inputs: StakeChainInputs,
    ) -> (Self, OperatorDuty) {
        let deposit_txid = deposit_tx.compute_txid();
        let cfg = ContractCfg {
            network,
            operator_table,
            connector_params,
            peg_out_graph_params,
            sidesystem_params,
            stake_chain_params,
            deposit_idx,
            deposit_tx,
        };

        let state = ContractState::Requested {
            deposit_request_txid,
            abort_deadline,
            peg_out_graph_inputs: BTreeMap::new(),
            peg_out_graphs: BTreeMap::new(),
            claim_txids: BTreeMap::new(),
            graph_nonces: BTreeMap::new(),
            graph_partials: BTreeMap::new(),
            root_nonces: BTreeMap::new(),
            root_partials: BTreeMap::new(),
        };
        let state = MachineState {
            block_height,
            state,
        };

        let contract_sm = ContractSM {
            cfg,
            state,
            pog: BTreeMap::new(),
        };

        let duty = OperatorDuty::PublishDepositSetup {
            deposit_txid,
            deposit_idx,
            stake_chain_inputs,
        };

        (contract_sm, duty)
    }

    /// Restores a [`ContractSM`] from its [`ContractCfg`] and [`MachineState`]
    pub fn restore(cfg: ContractCfg, state: MachineState) -> Self {
        ContractSM {
            cfg,
            state,
            pog: BTreeMap::new(),
        }
    }

    /// Filter that specifies which transactions should be delivered to this state machine.
    pub fn transaction_filter(&self, tx: &Transaction) -> bool {
        let deposit_txid = self.cfg.deposit_tx.compute_txid();
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
    pub fn retrieve_graph(&mut self, input: PegOutGraphInput) -> PegOutGraph {
        let stake_txid = input.stake_outpoint.txid;
        if let Some(pog) = self.pog.get(&stake_txid) {
            debug!(reimbursement_key=%input.operator_pubkey, %stake_txid, "retrieving peg out graph from cache");
            return pog.clone();
        }

        debug!(reimbursement_key=%input.operator_pubkey, %stake_txid, "generating and caching peg out graph");
        let pog = self.cfg.build_graph(input.clone());
        self.pog.insert(stake_txid, pog.clone());
        pog
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
                stake_tx,
                wots_keys,
            } => self.process_deposit_setup(
                operator_p2p_key,
                operator_btc_key,
                stake_hash,
                stake_tx,
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

            ContractEvent::RootNonce(op, nonce) => self
                .process_root_nonce(op, nonce)
                .map(|x| x.into_iter().collect()),

            ContractEvent::RootSig(op, sig) => self
                .process_root_signature(op, sig)
                .map(|x| x.into_iter().collect()),

            ContractEvent::DepositConfirmation(tx) => self
                .process_deposit_confirmation(tx)
                .map(|x| x.into_iter().collect()),

            ContractEvent::Assignment(deposit_entry, stake_tx) => self
                .process_assignment(&deposit_entry, stake_tx)
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

    fn process_deposit_confirmation(
        &mut self,
        tx: Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let deposit_txid = tx.compute_txid();
        info!(%deposit_txid, "processing deposit confirmation");

        let expected_txid = self.cfg.deposit_tx.compute_txid();
        if tx.compute_txid() != expected_txid {
            error!(txid=%deposit_txid, %expected_txid, "deposit confirmation delivered to the wrong CSM");

            return Err(TransitionErr(format!(
                "deposit confirmation for ({}) delivered to wrong CSM ({})",
                deposit_txid, expected_txid,
            )));
        }

        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        match current {
            ContractState::Requested {
                peg_out_graphs,
                claim_txids,
                graph_partials,
                ..
            } => {
                info!(%deposit_txid, "updating contract state to deposited");
                self.state.state = ContractState::Deposited {
                    peg_out_graphs,
                    claim_txids,
                    graph_partials,
                }
            }
            ContractState::Deposited { .. } => {
                // somebody else may have deposited already.
                info!("contract already in deposited state");
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
            ContractState::StakeTxReady { .. } => self.process_fulfillment_confirmation(tx),
            ContractState::Fulfilled { .. } => self.process_claim_confirmation(height, tx),
            ContractState::Claimed { .. } => {
                // could be challenged
                if let Some(duty) = self.process_challenge_confirmation(tx)? {
                    return Ok(Some(duty));
                }

                // or it could be an optimistic payout
                self.process_optimistic_payout_confirmation(tx)
            }
            ContractState::Challenged { .. } => self.process_assert_chain_confirmation(height, tx),
            ContractState::Asserted { .. } => {
                // could be disproved
                if let Some(duty) = self.process_disprove_confirmation(tx)? {
                    return Ok(Some(duty));
                }

                // or it could be a defended payout
                self.process_defended_payout_confirmation(tx)
            }
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
        new_stake_tx: StakeTx,
        new_wots_keys: WotsPublicKeys,
    ) -> Result<Vec<OperatorDuty>, TransitionErr> {
        // TODO(proofofkeags): thoroughly review this code it is ALMOST CERTAINLY WRONG IN SOME
        // SUBTLE WAY.

        match &mut self.state.state {
            ContractState::Requested {
                peg_out_graph_inputs,
                peg_out_graphs,
                claim_txids,
                graph_nonces,
                graph_partials,
                ..
            } => {
                if peg_out_graph_inputs.contains_key(&signer) {
                    let deposit_txid = self.cfg.deposit_tx.compute_txid();
                    warn!("already received operator's ({signer}) deposit setup for contract {deposit_txid}");
                    return Ok(vec![]);
                }

                let pog_input = PegOutGraphInput {
                    stake_outpoint: OutPoint::new(new_stake_tx.compute_txid(), STAKE_VOUT),
                    withdrawal_fulfillment_outpoint: OutPoint::new(
                        new_stake_tx.compute_txid(),
                        WITHDRAWAL_FULFILLMENT_VOUT,
                    ),
                    stake_hash: new_stake_hash,
                    wots_public_keys: new_wots_keys.clone(),
                    operator_pubkey,
                };
                peg_out_graph_inputs.insert(signer, pog_input.clone());

                if peg_out_graph_inputs.len() != self.cfg.operator_table.cardinality() {
                    return Ok(vec![]);
                }

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
                            // reasons. First, we'd like to be able to test this without having to
                            // invoke an async runtime. As of right now this is inside of a pure
                            // function which means its testing requirements are a little bit more
                            // relaxed. Secondly, the value of async is much less pronounced for
                            // operations that are waiting on compute instead of IO.
                            thread::Builder::new()
                                .stack_size(8 * 1024 * 1024)
                                .spawn(move || {
                                    info!("building graph...");
                                    thread_cfg.build_graph(input)
                                })
                                .expect("spawn succeeds"),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();

                let graphs = jobs
                    .into_iter()
                    .map(|(signer, job)| {
                        (
                            signer,
                            job.join().expect("peg out graph generation panic'ed"),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();

                let duties = graphs
                    .values()
                    .map(|graph| OperatorDuty::PublishGraphNonces {
                        claim_txid: graph.claim_tx.compute_txid(),
                        pog_prevouts: graph.musig_inpoints(),
                        pog_witnesses: graph.musig_witnesses(),
                    })
                    .collect::<Vec<_>>();

                for (signer, graph) in graphs {
                    let pog_summary = graph.summarize();
                    let claim_txid = pog_summary.claim_txid;

                    peg_out_graphs.insert(
                        claim_txid,
                        (
                            peg_out_graph_inputs.get(signer).unwrap().clone(),
                            pog_summary,
                        ),
                    );
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

        match &mut self.state.state {
            ContractState::Requested {
                peg_out_graphs,
                graph_nonces,
                ..
            } => {
                let unpacked = PogMusigF::unpack(nonces).ok_or(TransitionErr(
                    "could not unpack nonce vector into PogMusigF".to_string(),
                ))?;

                // session nonces must be present for this claim_txid at this point
                let Some(session_nonces) = graph_nonces.get_mut(&claim_txid) else {
                    return Err(TransitionErr(format!(
                        "could not process graph nonces. claim_txid ({}) not found in nonce map",
                        claim_txid
                    )));
                };

                if session_nonces.contains_key(&signer) {
                    warn!(%claim_txid, %signer, "already received nonces for graph");
                    return Ok(None);
                }

                session_nonces.insert(signer.clone(), unpacked);

                let num_operators = self.cfg.operator_table.cardinality();
                let have_all_graphs = graph_nonces.values().count() == num_operators;
                let have_all_nonces_in_each_graph = graph_nonces
                    .values()
                    .all(|session_nonces| session_nonces.len() == num_operators);
                let have_all_nonces = have_all_graphs && have_all_nonces_in_each_graph;

                Ok(if have_all_nonces {
                    info!(%claim_txid, %signer, "received all nonces for all graphs");

                    let Some((pog_input, _)) = peg_out_graphs.get(&claim_txid) else {
                        return Err(TransitionErr(format!(
                                "could not process graph nonces. claim_txid ({}) not found in peg out graph map" ,
                                claim_txid
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
                        let pog = self.cfg.build_graph(pog_input.clone());
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

                    Some(OperatorDuty::PublishGraphSignatures {
                        claim_txid,
                        pubnonces,
                        pog_prevouts: pog.musig_inpoints(),
                        pog_sighashes: pog.sighashes(),
                    })
                } else {
                    let received_nonces = graph_nonces
                        .iter()
                        .map(|(claim, nonces)| (claim, nonces.len()))
                        .collect::<Vec<_>>();
                    info!(?received_nonces, required=%num_operators, "waiting for more nonces for some graphs");

                    None
                })
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
        sig: Vec<PartialSignature>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        debug!(%claim_txid, %signer, "processing graph signatures");

        let unpacked = PogMusigF::unpack(sig).ok_or(TransitionErr(
            "could not unpack sig vector into PogMusigF".to_string(),
        ))?;
        let deposit_request_txid = self.deposit_request_txid();
        match &mut self.state.state {
            ContractState::Requested { graph_partials, .. } => {
                // session partials must be present for this claim_txid at this point
                let Some(session_partials) = graph_partials.get_mut(&claim_txid) else {
                    return Err(TransitionErr(format!(
                        "could not process graph partials. claim_txid ({}) not found in partials map",
                        claim_txid
                    )));
                };

                if session_partials.contains_key(&signer) {
                    warn!(%claim_txid, %signer, "already received signatures for graph");
                    return Ok(None);
                }

                session_partials.insert(signer, unpacked);

                let num_operators = self.cfg.operator_table.cardinality();
                let have_all_graphs = graph_partials.values().count() == num_operators;
                let have_all_partials_for_all_graphs = graph_partials
                    .values()
                    .all(|session_partials| session_partials.len() == num_operators);
                let have_all_partials = have_all_graphs && have_all_partials_for_all_graphs;

                Ok(if have_all_partials {
                    info!(%claim_txid, "received all partials for all graphs");

                    let witness = self.cfg().deposit_tx.witnesses()[0].clone();

                    Some(OperatorDuty::PublishRootNonce {
                        deposit_request_txid,
                        witness,
                    })
                } else {
                    let received_partials = graph_partials
                        .iter()
                        .map(|(claim, partials)| (claim, partials.len()))
                        .collect::<Vec<_>>();

                    info!(?received_partials, %num_operators, "waiting for more partials for graph");

                    None
                })
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_graph_signatures ({})",
                self.state.state
            ))),
        }
    }

    fn process_root_nonce(
        &mut self,
        signer: P2POperatorPubKey,
        nonce: PubNonce,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { root_nonces, .. } => {
                if root_nonces.contains_key(&signer) {
                    warn!(%signer, "already received nonce for root");
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
                        })
                    } else {
                        None
                    },
                )
            }
            ContractState::Deposited { .. } => {
                // somebody else may have deposited already.
                info!("contract already in deposited state, skipping root nonce generation");
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
        match &mut self.state.state {
            ContractState::Requested { root_partials, .. } => {
                if root_partials.contains_key(&signer) {
                    warn!(%signer, "already received signature for root");
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
                info!("contract already in deposited state, skipping root signature generation");
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
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});

        let duty = match &current {
            ContractState::Requested { abort_deadline, .. } => {
                if self.state.block_height >= *abort_deadline {
                    Some(OperatorDuty::Abort)
                } else {
                    None
                }
            }
            ContractState::Deposited { .. } => None,
            // handled in `process_peg_out_graph_tx_confirmation`
            ContractState::Assigned { .. } => None,
            // handled in `process_peg_out_graph_tx_confirmation`
            ContractState::StakeTxReady { .. } => None,
            ContractState::Fulfilled { .. } => None,
            ContractState::Claimed {
                fulfiller,
                claim_height,
                active_graph,
                graph_partials,
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
                    let partials = self.transpose_partials(graph_partials, claim_txid)?;

                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishPayoutOptimistic {
                            deposit_txid,
                            claim_txid,
                            stake_txid,
                            stake_index,
                            partials,
                        },
                    ))
                } else {
                    None
                }
            }
            ContractState::Challenged { .. } => None,
            ContractState::Asserted {
                post_assert_height,
                fulfiller,
                ..
            } => {
                if self.state.block_height
                    >= post_assert_height + self.cfg.connector_params.payout_timelock as u64
                    && *fulfiller == self.cfg.operator_table.pov_idx()
                {
                    Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishPayout))
                } else {
                    None
                }
            }
            ContractState::Disproved {} => None,
            ContractState::Resolved {} => None,
        };

        // restore state
        self.state.state = current;

        Ok(duty)
    }

    /// Transposes an array of partials for each input per operator into an array of partials for
    /// each operator per input.
    ///
    /// It accepts a map of graph partials such that each map holds the partials for an operator for
    /// all inputs and then changes them so that the end result is an array of partials from all
    /// operators for each input such that they can be aggregated on a per input basis.
    fn transpose_partials<const NUM_INPUTS: usize>(
        &mut self,
        graph_partials: &BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,
        claim_txid: Txid,
    ) -> Result<[Vec<PartialSignature>; NUM_INPUTS], TransitionErr> {
        let payout_optimistic_partials =
            graph_partials
                .get(&claim_txid)
                .ok_or(TransitionErr(format!(
                    "could not find graph partials for claim txid {}",
                    claim_txid
                )))?;
        let num_operators = self.cfg.operator_table.btc_keys().into_iter().count();

        let mut partials_per_input: [Vec<_>; NUM_INPUTS] = (0..NUM_INPUTS)
            .map(|_| Vec::with_capacity(num_operators))
            .collect::<Vec<_>>()
            .try_into()
            .expect("must have matching size");

        self.cfg
            .operator_table
            .btc_keys()
            .into_iter()
            .for_each(|btc_key| {
                let p2p_key = self
                    .cfg
                    .operator_table
                    .btc_key_to_op_key(&btc_key)
                    .expect("each btc key must have a p2p key");

                let partials_for_op = payout_optimistic_partials
                    .get(p2p_key)
                    .expect("each p2p key must have a partial")
                    .payout_optimistic;

                (0..NUM_INPUTS).for_each(|input| {
                    partials_per_input[input].push(partials_for_op[input]);
                });
            });

        Ok(partials_per_input)
    }

    /// Processes an assignment from the strata state commitment.
    pub fn process_assignment(
        &mut self,
        assignment: &DepositEntry,
        stake_tx: StakeTx,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        info!(?assignment, current_state=%self.state().state, "processing assignment");

        if assignment.idx() != self.cfg.deposit_idx {
            return Err(TransitionErr(format!(
                "unexpected assignment ({}) delivered to CSM ({})",
                assignment.idx(),
                self.cfg.deposit_idx
            )));
        }

        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        let copy_of_current = current.clone();

        match current {
            ContractState::Deposited {
                peg_out_graphs,
                claim_txids,
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
                                    "could not find claim_txid for operator {} in csm {}",
                                    fulfiller_key,
                                    self.cfg.deposit_tx.compute_txid()
                                )))?;

                        let deadline = dispatched_state.exec_deadline();
                        let active_graph = peg_out_graphs
                            .get(fulfiller_claim_txid)
                            .ok_or(TransitionErr(format!(
                                "could not find peg out graph {} in csm {}",
                                fulfiller_claim_txid,
                                self.cfg.deposit_tx.compute_txid()
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
                                fulfiller,
                                deadline,
                                active_graph,
                                recipient: recipient.clone(),
                                withdrawal_request_txid: withdrawal_request_txid.into(),
                                graph_partials: graph_partials.clone(),
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

                            Ok(None)
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

        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        let copy_of_current = current.clone();

        match current {
            ContractState::Assigned {
                peg_out_graphs,
                claim_txids,
                fulfiller,
                recipient,
                deadline,
                active_graph,
                withdrawal_request_txid,
                graph_partials,
            } => {
                if tx.compute_txid() != active_graph.1.stake_txid {
                    // might be somebody else's stake txid
                    self.state.state = copy_of_current;

                    return Ok(None);
                }

                self.state.state = ContractState::StakeTxReady {
                    peg_out_graphs,
                    claim_txids,
                    fulfiller,
                    recipient: recipient.clone(),
                    deadline,
                    active_graph,
                    withdrawal_request_txid,
                    graph_partials,
                };
                let is_assigned_to_me = fulfiller == self.cfg.operator_table.pov_idx();

                if !is_assigned_to_me {
                    return Ok(None);
                }

                // if this withdrawal is assigned to this operator, then it needs to fulfill
                // it.
                let withdrawal_metadata = WithdrawalMetadata {
                    tag: self.cfg.peg_out_graph_params.tag.as_bytes().to_vec(),
                    operator_idx: fulfiller,
                    deposit_idx: self.cfg.deposit_idx,
                    deposit_txid: self.cfg.deposit_tx.compute_txid(),
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
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        let copy_of_current = current.clone();

        match current {
            ContractState::StakeTxReady {
                peg_out_graphs,
                claim_txids,
                fulfiller,
                active_graph,
                recipient,
                graph_partials,
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

                    return Ok(None);
                }

                let withdrawal_fulfillment_txid = tx.compute_txid();
                debug!(%withdrawal_fulfillment_txid, "discovered withdrawal fulfillment");
                self.state.state = ContractState::Fulfilled {
                    peg_out_graphs,
                    claim_txids,
                    fulfiller,
                    active_graph,
                    graph_partials,
                    withdrawal_fulfillment_txid,
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
            ContractState::Fulfilled { .. } => {
                warn!(
                    "received fulfillment confirmation even though contract is already fulfilled"
                );
                self.state.state = copy_of_current;

                Ok(None)
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

        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        let copy_of_current = current.clone();
        match current {
            ContractState::Fulfilled {
                peg_out_graphs,
                claim_txids,
                fulfiller,
                active_graph,
                graph_partials,
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

                self.state.state = ContractState::Claimed {
                    peg_out_graphs,
                    claim_txids,
                    claim_height: height,
                    fulfiller,
                    active_graph,
                    graph_partials,
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
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        let copy_of_current = current.clone();
        match current {
            ContractState::Claimed {
                peg_out_graphs,
                claim_txids,
                fulfiller,
                active_graph,
                graph_partials,
                ..
            } => {
                if !is_challenge(active_graph.1.claim_txid)(tx) {
                    // could be an optimistic payout
                    self.state.state = copy_of_current;

                    return Ok(None);
                }

                let duty = if fulfiller == self.cfg.operator_table.pov_idx() {
                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishAssertChain,
                    ))
                } else {
                    None
                };

                self.state.state = ContractState::Challenged {
                    peg_out_graphs,
                    claim_txids,
                    fulfiller,
                    active_graph,
                    graph_partials,
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_challenge_confirmation ({})",
                current
            ))),
        }
    }

    fn process_assert_chain_confirmation(
        &mut self,
        post_assert_height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        match current {
            ContractState::Challenged {
                peg_out_graphs,
                claim_txids,
                fulfiller,
                active_graph,
                graph_partials,
                ..
            } => {
                if tx.compute_txid() != active_graph.1.post_assert_txid {
                    return Err(TransitionErr(format!(
                        "invalid post assert transaction ({}) in process_assert_chain_confirmation",
                        tx.compute_txid()
                    )));
                }

                let duty = if fulfiller != self.cfg.operator_table.pov_idx() {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyAssertion))
                } else {
                    None
                };

                self.state.state = ContractState::Asserted {
                    peg_out_graphs,
                    claim_txids,
                    post_assert_height,
                    fulfiller,
                    active_graph,
                    graph_partials,
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_assert_chain_confirmation ({})",
                current
            ))),
        }
    }

    /// Tells the state machine that the assertion chain is invalid.
    fn process_assertion_verification_failure(
        &mut self,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
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
        match self.state.state.clone() {
            ContractState::Claimed { active_graph, .. } => {
                if tx.compute_txid() != active_graph.1.payout_optimistic_txid {
                    return Err(TransitionErr(format!("invalid optimistic payout transaction ({}) in process_optimistic_payout_confirmation", tx.compute_txid())));
                }

                self.state.state = ContractState::Resolved {};

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
        match self.state.state.clone() {
            ContractState::Asserted { active_graph, .. } => {
                if tx.compute_txid() != active_graph.1.payout_txid {
                    return Err(TransitionErr(format!(
                        "invalid defended payout transaction ({}) in process_defended_payout_confirmation", tx.compute_txid()
                    )));
                }

                self.state.state = ContractState::Resolved {};

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_defended_payout_confirmation ({})",
                self.state.state
            ))),
        }
    }

    /// Dumps the config parameters of the state machine.
    pub fn cfg(&self) -> &ContractCfg {
        &self.cfg
    }

    /// Dumps the current state of the state machine.
    pub fn state(&self) -> &MachineState {
        &self.state
    }

    /// The txid of the deposit on which this contract is centered.
    pub fn deposit_txid(&self) -> Txid {
        self.cfg.deposit_tx.compute_txid()
    }

    /// The txid of the original deposit request that kicked off this contract.
    pub fn deposit_request_txid(&self) -> Txid {
        self.cfg().deposit_request_txid()
    }

    /// Gives us a list of claim txids that can be used to reference this contract.
    pub fn claim_txids(&self) -> Vec<Txid> {
        let dummy = BTreeMap::new();
        match &self.state().state {
            ContractState::Requested { claim_txids, .. } => claim_txids,
            ContractState::Deposited { claim_txids, .. } => claim_txids,
            ContractState::Assigned { claim_txids, .. } => claim_txids,
            ContractState::StakeTxReady { claim_txids, .. } => claim_txids,
            ContractState::Fulfilled { claim_txids, .. } => claim_txids,
            ContractState::Claimed { claim_txids, .. } => claim_txids,
            ContractState::Challenged { claim_txids, .. } => claim_txids,
            ContractState::Asserted { claim_txids, .. } => claim_txids,
            ContractState::Disproved {} => &dummy,
            ContractState::Resolved {} => &dummy,
        }
        .values()
        .copied()
        .collect()
    }

    /// The txid of the assignment transaction for this contract.
    ///
    /// Note that this is only available if the contract is in the [`ContractState::Assigned`] or
    /// [`ContractState::StakeTxReady`] state.
    pub fn withdrawal_request_txid(&self) -> Option<Txid> {
        match &self.state().state {
            ContractState::Requested { .. } => None,
            ContractState::Deposited { .. } => None,
            ContractState::Assigned {
                withdrawal_request_txid: assignment_txid,
                ..
            } => Some(*assignment_txid),
            ContractState::StakeTxReady {
                withdrawal_request_txid,
                ..
            } => Some(*withdrawal_request_txid),
            ContractState::Fulfilled { .. } => None,
            ContractState::Claimed { .. } => None,
            ContractState::Challenged { .. } => None,
            ContractState::Asserted { .. } => None,
            ContractState::Disproved {} => None,
            ContractState::Resolved {} => None,
        }
    }
    /// The txid of the withdrawal fulfillment for this contract.
    ///
    /// Note that this is only available if the contract is in the [`ContractState::Fulfilled`]
    /// state.
    pub fn withdrawal_fulfillment_txid(&self) -> Option<Txid> {
        match &self.state().state {
            ContractState::Requested { .. } => None,
            ContractState::Deposited { .. } => None,
            ContractState::Assigned { .. } => None,
            ContractState::StakeTxReady { .. } => None,
            ContractState::Fulfilled {
                withdrawal_fulfillment_txid,
                ..
            } => Some(*withdrawal_fulfillment_txid),
            ContractState::Claimed { .. } => None,
            ContractState::Challenged { .. } => None,
            ContractState::Asserted { .. } => None,
            ContractState::Disproved {} => None,
            ContractState::Resolved {} => None,
        }
    }
}
