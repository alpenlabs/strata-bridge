//! This module defines the core state machine for the Bridge Deposit Contract. All of the states,
//! events and transition rules are encoded in this structure. When the ContractSM accepts an event
//! it may or may not give back an OperatorDuty to execute as a result of this state transition.
use std::{collections::BTreeMap, fmt::Display};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{
    hashes::{
        serde::{Deserialize, Serialize},
        sha256,
    },
    Network, OutPoint, Transaction, Txid, XOnlyPublicKey,
};
use bitcoin_bosd::Descriptor;
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use musig2::{PartialSignature, PubNonce};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, OperatorIdx},
    wots::{Groth16PublicKeys, PublicKeys, Wots256PublicKey},
};
use strata_bridge_stake_chain::{
    prelude::{StakeTx, STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::StakeTxData,
};
use strata_bridge_tx_graph::{
    peg_out_graph::{PegOutGraph, PegOutGraphInput, PegOutGraphSummary},
    transactions::prelude::WithdrawalMetadata,
};
use strata_p2p_types::{P2POperatorPubKey, WotsPublicKeys};
use strata_state::bridge_state::{DepositEntry, DepositState};
use thiserror::Error;

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

    /// Signifies that we have a new set of nonces for the peg out graph from one of our peers.
    GraphNonces(P2POperatorPubKey, Vec<PubNonce>),

    /// Signifies that we have a new set of signatures for the peg out graph from one of our peers.
    GraphSigs(P2POperatorPubKey, Vec<PartialSignature>),

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

        /// This is a collection of the stake transaction data on a per-operator basis. This is
        /// used to eventually construct the peg-out-graphs.
        stake_txs: BTreeMap<P2POperatorPubKey, StakeTx>,

        /// This is a collection of the WOTS public keys needed to generate the peg-out-graphs on
        /// a per-operator basis.
        wots_keys: BTreeMap<P2POperatorPubKey, WotsPublicKeys>,

        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// This is a collection of nonces for the peg-out graph on a per-operator basis.
        graph_nonces: BTreeMap<P2POperatorPubKey, Vec<PubNonce>>,

        /// This is the collection of signatures for the peg-out graph on a per-operator basis.
        graph_sigs: BTreeMap<P2POperatorPubKey, Vec<PartialSignature>>,

        /// This is a collection of the nonces for the final musig2 signature needed to sweep the
        /// deposit request transaction to the deposit transaction.
        root_nonces: BTreeMap<P2POperatorPubKey, PubNonce>,

        /// This is the collection of signatures for the deposit transaction itself on a
        /// per-operator basis.
        root_sigs: BTreeMap<P2POperatorPubKey, PartialSignature>,
    },

    /// This state describes everything from the moment the deposit confirms, to the moment the
    /// strata state commitment that assigns this deposit confirms.
    Deposited {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,
    },

    /// This state describes everything from the moment the strata state commitment corresponding
    /// to a valid withdrawal assignment is posted to bitcoin all the way to the corresponding
    /// stake transaction being confirmed.
    Assigned {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The descriptor of the recipient.
        recipient: Descriptor,

        /// The deadline by which the operator must fulfill the withdrawal before it is reassigned.
        deadline: BitcoinBlockHeight,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment stake transaction corresponding to this
    /// deposit confirms to the moment the fulfillment transaction confirms for the assigned
    /// operator.
    StakeTxReady {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The descriptor of the recipient.
        recipient: Descriptor,

        /// The deadline by which the operator must fulfill the withdrawal before it is reassigned.
        deadline: BitcoinBlockHeight,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the fulfillment transaction confirms, to
    /// the moment the claim transaction confirms.
    Fulfilled {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the claim transaction confirms, to the
    /// moment either the challenge transaction confirms, or the optimistic payout transaction
    /// confirms.
    Claimed {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// The height at which the claim transaction was confirmed.
        claim_height: BitcoinBlockHeight,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the challenge transaction confirms, to the
    /// moment the post-assert transaction confirms.
    Challenged {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the post-assert transaction confirms, to
    /// the moment either the disprove transaction confirms or the payout transaction confirms.
    Asserted {
        /// These are the actual peg-out-graph summaries for each operator. This will be stored so
        /// we can monitor the transactions relevant to advancing the contract through its
        /// lifecycle.
        peg_out_graphs: BTreeMap<P2POperatorPubKey, PegOutGraphSummary>,

        /// The height at which the post-assert transaction was confirmed.
        post_assert_height: BitcoinBlockHeight,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes the state after the disprove transaction confirms.
    Disproved {},

    /// This state describes the state after either the optimistic or defended payout transactions
    /// confirm.
    Resolved {},
}

/// This is the superset of all possible operator duties.
#[derive(Debug)]
#[expect(clippy::large_enum_variant)]
pub enum OperatorDuty {
    /// Instructs us to terminate this contract.
    Abort,

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
    PublishGraphNonces,

    /// Instructs us to send out signatures for the peg out graph.
    PublishGraphSignatures,

    /// Instructs us to send out our nonce for the deposit transaction signature.
    PublishRootNonce,

    /// Instructs us to send out signatures for the deposit transaction.
    PublishRootSignature,

    /// Instructs us to submit the deposit transaction to the network.
    PublishDeposit,

    /// Injection function for a FulfillerDuty.
    FulfillerDuty(FulfillerDuty),

    /// Injection function for a VerifierDuty.
    VerifierDuty(VerifierDuty),
}

/// This is a duty that has to be carried out if we are the assigned operator.
#[derive(Debug)]
pub enum FulfillerDuty {
    /// Originates when strata state on L1 is published.
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
    PublishClaim,

    /// Originates after reaching timelock expiry for Claim transaction
    PublishPayoutOptimistic,

    /// Originates once challenge transaction is issued
    PublishAssertChain,

    /// Originates after post-assert timelock expires
    PublishPayout,
}

/// This is a duty that must be carried out as a Verifier.
#[derive(Debug)]
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

    /// Consensus critical parameters associated with the stake chain.
    pub stake_chain_params: StakeChainParams,

    /// The global index of this contract. This is decided by the bridge upon the recognition of
    /// a deposit request.
    pub deposit_idx: u32,

    /// The predetermined deposit transaction that the rest of the graph is built from.
    pub deposit_tx: Transaction,
}

/// Holds the state machine values that change over the lifetime of the contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineState {
    /// The most recent block height the state machine is aware of.
    pub block_height: BitcoinBlockHeight,

    /// The state of the contract itself.
    pub state: ContractState,
}

#[derive(Debug)]
/// This is the core state machine for a given deposit contract.
pub struct ContractSM {
    cfg: ContractCfg,
    state: MachineState,
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
        stake_chain_params: StakeChainParams,
        block_height: BitcoinBlockHeight,
        abort_deadline: BitcoinBlockHeight,
        deposit_idx: u32,
        deposit_request_txid: Txid,
        deposit_tx: Transaction,
        stake_chain_inputs: StakeChainInputs,
    ) -> (Self, OperatorDuty) {
        let deposit_txid = deposit_tx.compute_txid();
        let cfg = ContractCfg {
            network,
            operator_table,
            connector_params,
            peg_out_graph_params,
            stake_chain_params,
            deposit_idx,
            deposit_tx,
        };
        let state = ContractState::Requested {
            deposit_request_txid,
            abort_deadline,
            stake_txs: BTreeMap::new(),
            wots_keys: BTreeMap::new(),
            peg_out_graphs: BTreeMap::new(),
            graph_nonces: BTreeMap::new(),
            graph_sigs: BTreeMap::new(),
            root_nonces: BTreeMap::new(),
            root_sigs: BTreeMap::new(),
        };
        let state = MachineState {
            block_height,
            state,
        };
        (
            ContractSM { cfg, state },
            OperatorDuty::PublishDepositSetup {
                deposit_txid,
                deposit_idx,
                stake_chain_inputs,
            },
        )
    }

    /// Restores a [`ContractSM`] from its [`ContractCfg`] and [`MachineState`]
    pub fn restore(cfg: ContractCfg, state: MachineState) -> Self {
        ContractSM { cfg, state }
    }

    /// Filter that specifies which transactions should be delivered to this state machine.
    pub fn transaction_filter(&self, tx: &Transaction) -> bool {
        let deposit_txid = self.cfg.deposit_tx.compute_txid();
        let graphs = match &self.state.state {
            ContractState::Requested { .. } => Vec::new(),
            ContractState::Deposited { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::StakeTxReady { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::Assigned { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::Fulfilled { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::Claimed { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::Challenged { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::Asserted { peg_out_graphs, .. } => {
                peg_out_graphs.iter().map(|(_, g)| g.clone()).collect()
            }
            ContractState::Disproved {} => Vec::new(),
            ContractState::Resolved {} => Vec::new(),
        };

        let cfg = self.cfg();
        let txid = tx.compute_txid();

        let operator_ids = cfg.operator_table.operator_idxs();
        if let ContractState::Assigned { recipient, .. } = &self.state.state {
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

        graphs.iter().any(|g| {
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

    /// Processes the unified event type for the ContractSM.
    ///
    /// This is the primary state folding function.
    pub fn process_contract_event(
        &mut self,
        ev: ContractEvent,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
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
            ContractEvent::GraphNonces(op, nonces) => self.process_graph_nonces(op, nonces),
            ContractEvent::GraphSigs(op, sigs) => self.process_graph_signatures(op, sigs),
            ContractEvent::RootNonce(op, nonce) => self.process_root_nonce(op, nonce),
            ContractEvent::RootSig(op, sig) => self.process_root_signature(op, sig),
            ContractEvent::DepositConfirmation(tx) => self.process_deposit_confirmation(tx),
            ContractEvent::PegOutGraphConfirmation(tx, height) => {
                self.process_peg_out_graph_tx_confirmation(height, &tx)
            }
            ContractEvent::Block(height) => self.notify_new_block(height),
            ContractEvent::ClaimFailure => self.process_claim_verification_failure(),
            ContractEvent::AssertionFailure => self.process_assertion_verification_failure(),
            ContractEvent::Assignment(deposit_entry, stake_tx) => {
                self.process_assignment(&deposit_entry, stake_tx)
            }
        }
    }

    fn process_deposit_confirmation(
        &mut self,
        tx: Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        if tx.compute_txid() != self.cfg.deposit_tx.compute_txid() {
            return Err(TransitionErr(format!(
                "deposit confirmation for ({}) delivered to wrong CSM ({})",
                tx.compute_txid(),
                self.cfg.deposit_tx.compute_txid()
            )));
        }

        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        if let ContractState::Requested { peg_out_graphs, .. } = current {
            self.state.state = ContractState::Deposited { peg_out_graphs }
        } else {
            self.state.state = current;
            return Err(TransitionErr(format!(
                "deposit confirmation ({}) delivered to CSM not in Requested state ({:?})",
                tx.compute_txid(),
                self.state.state
            )));
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
                "peg out graph confirmation ({}) delivered to CSM in Requested state ({:?})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Deposited { .. } => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Deposited state ({:?})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Assigned { .. } => self.process_stake_chain_advancement(tx),
            ContractState::StakeTxReady { .. } => self.process_fulfillment_confirmation(tx),
            ContractState::Fulfilled { .. } => self.process_claim_confirmation(height, tx),
            ContractState::Claimed { .. } => self
                .process_challenge_confirmation(tx)
                .or_else(|_| self.process_optimistic_payout_confirmation(tx)),
            ContractState::Challenged { .. } => self.process_assert_chain_confirmation(height, tx),
            ContractState::Asserted { .. } => self
                .process_disprove_confirmation(tx)
                .or_else(|_| self.process_defended_payout_confirmation(tx)),
            ContractState::Disproved {} => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Disproved state ({:?})",
                tx.compute_txid(),
                self.state.state
            ))),
            ContractState::Resolved { .. } => Err(TransitionErr(format!(
                "peg out graph confirmation ({}) delivered to CSM in Resolved state ({:?})",
                tx.compute_txid(),
                self.state.state
            ))),
        }
    }

    fn convert_g16_keys(
        g16_keys: strata_p2p_types::Groth16PublicKeys,
    ) -> Result<strata_bridge_primitives::wots::Groth16PublicKeys, TransitionErr> {
        // TODO(proofofkeags): figure out why the hell try_into is so fucked so we can get
        // rid of the rats nest of code below.
        if g16_keys.public_inputs.len() != NUM_PUBS {
            return Err(TransitionErr(format!(
                "Could not convert groth 16 keys: invalid length of public inputs ({})",
                g16_keys.public_inputs.len()
            )));
        }
        let public_inputs = std::array::from_fn(|i| *g16_keys.public_inputs[i]);

        if g16_keys.fqs.len() != NUM_U256 {
            return Err(TransitionErr(format!(
                "Could not convert groth 16 keys: invalid length of fqs ({})",
                g16_keys.fqs.len()
            )));
        }
        let fqs = std::array::from_fn(|i| *g16_keys.fqs[i]);

        if g16_keys.hashes.len() != NUM_HASH {
            return Err(TransitionErr(format!(
                "Could not convert groth 16 keys: invalid length of hashes ({})",
                g16_keys.hashes.len()
            )));
        }
        let hashes = std::array::from_fn(|i| *g16_keys.hashes[i]);

        Ok(Groth16PublicKeys((public_inputs, fqs, hashes)))
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
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        // TODO(proofofkeags): thoroughly review this code it is ALMOST CERTAINLY WRONG IN SOME
        // SUBTLE WAY.
        match &mut self.state.state {
            ContractState::Requested {
                stake_txs,
                wots_keys,
                peg_out_graphs,
                ..
            } => {
                let wots_key_record = PublicKeys {
                    withdrawal_fulfillment: Wots256PublicKey(
                        new_wots_keys.withdrawal_fulfillment.0,
                    ),
                    groth16: Self::convert_g16_keys(new_wots_keys.groth16.clone())?,
                };
                let pog_input = PegOutGraphInput {
                    stake_outpoint: OutPoint::new(new_stake_tx.compute_txid(), STAKE_VOUT),
                    withdrawal_fulfillment_outpoint: OutPoint::new(
                        new_stake_tx.compute_txid(),
                        WITHDRAWAL_FULFILLMENT_VOUT,
                    ),
                    stake_hash: new_stake_hash,
                    wots_public_keys: wots_key_record,
                    operator_pubkey,
                };
                let pog_summary = PegOutGraph::generate(
                    pog_input,
                    &self.cfg.operator_table.tx_build_context(self.cfg.network),
                    self.cfg.deposit_tx.compute_txid(),
                    self.cfg.peg_out_graph_params.clone(),
                    self.cfg.connector_params,
                    self.cfg.stake_chain_params,
                    Vec::new(),
                )
                .map_err(|_| {
                    TransitionErr(
                        "peg out graph generation failure during deposit setup".to_string(),
                    )
                })?
                .0
                .summarize();

                stake_txs.insert(signer.clone(), new_stake_tx);
                wots_keys.insert(signer.clone(), new_wots_keys);
                peg_out_graphs.insert(signer, pog_summary);

                Ok(
                    // FIXME: (@Rajil1213) update this condition when multi stake chain is
                    // implemented.
                    if stake_txs.len() == self.cfg.operator_table.cardinality() {
                        Some(OperatorDuty::PublishGraphNonces)
                    } else {
                        None
                    },
                )
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_deposit_setup ({:?})",
                self.state.state
            ))),
        }
    }

    fn process_graph_nonces(
        &mut self,
        signer: P2POperatorPubKey,
        nonces: Vec<PubNonce>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { graph_nonces, .. } => {
                graph_nonces.insert(signer, nonces);
                Ok(
                    if graph_nonces.len() == self.cfg.operator_table.cardinality() {
                        Some(OperatorDuty::PublishGraphSignatures)
                    } else {
                        None
                    },
                )
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_graph_nonces ({:?})",
                self.state.state
            ))),
        }
    }

    /// Processes a graph signature payload from our peer.
    fn process_graph_signatures(
        &mut self,
        signer: P2POperatorPubKey,
        sig: Vec<PartialSignature>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { graph_sigs, .. } => {
                graph_sigs.insert(signer, sig);
                Ok(
                    if graph_sigs.len() == self.cfg.operator_table.cardinality() {
                        // we have all the sigs now
                        // issue deposit signature
                        Some(OperatorDuty::PublishRootNonce)
                    } else {
                        None
                    },
                )
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_graph_signatures ({:?})",
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
                root_nonces.insert(signer, nonce);
                Ok(
                    if root_nonces.len() == self.cfg.operator_table.cardinality() {
                        // we have all the sigs now
                        // issue deposit signature
                        Some(OperatorDuty::PublishRootSignature)
                    } else {
                        None
                    },
                )
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_root_nonce ({:?})",
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
            ContractState::Requested { root_sigs, .. } => {
                root_sigs.insert(signer, sig);
                Ok(
                    if root_sigs.len() == self.cfg.operator_table.cardinality() {
                        // we have all the deposit sigs now
                        // we can publish the deposit
                        Some(OperatorDuty::PublishDeposit)
                    } else {
                        None
                    },
                )
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_root_signature ({:?})",
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

        let duty = match current {
            ContractState::Requested { abort_deadline, .. } => {
                if self.state.block_height >= abort_deadline {
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
                ..
            } => {
                if self.state.block_height
                    >= claim_height + self.cfg.connector_params.payout_optimistic_timelock as u64
                    && fulfiller == self.cfg.operator_table.pov_idx()
                {
                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishPayoutOptimistic,
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
                    && fulfiller == self.cfg.operator_table.pov_idx()
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

    /// Processes an assignment from the strata state commitment.
    pub fn process_assignment(
        &mut self,
        assignment: &DepositEntry,
        stake_tx: StakeTx,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        if assignment.idx() != self.cfg.deposit_idx {
            return Err(TransitionErr(format!(
                "unexpected assignment ({}) delivered to CSM ({})",
                assignment.idx(),
                self.cfg.deposit_idx
            )));
        }

        match std::mem::replace(&mut self.state.state, ContractState::Resolved {}) {
            ContractState::Deposited { peg_out_graphs } => match assignment.deposit_state() {
                DepositState::Dispatched(dispatched_state) => {
                    let fulfiller = dispatched_state.assignee();
                    let fulfiller_key = match self.cfg.operator_table.idx_to_op_key(&fulfiller) {
                        Some(op_key) => op_key.clone(),
                        None => {
                            return Err(TransitionErr(format!(
                                "could not convert operator index {} to operator key",
                                fulfiller
                            )));
                        }
                    };
                    let deadline = dispatched_state.exec_deadline();
                    let active_graph = peg_out_graphs
                        .get(&fulfiller_key)
                        .ok_or(TransitionErr(format!(
                            "missing peg out graph for operator {}",
                            fulfiller_key
                        )))?
                        .to_owned();

                    let recipient = dispatched_state
                        .cmd()
                        .withdraw_outputs()
                        .first()
                        .map(|out| out.destination());

                    if let Some(recipient) = recipient {
                        self.state.state = ContractState::Assigned {
                            peg_out_graphs,
                            fulfiller,
                            deadline,
                            active_graph,
                            recipient: recipient.clone(),
                        };

                        let stake_index = assignment.idx();

                        Ok(Some(OperatorDuty::FulfillerDuty(
                            FulfillerDuty::AdvanceStakeChain {
                                stake_tx,
                                stake_index,
                            },
                        )))
                    } else {
                        Ok(None)
                    }
                }
                _ => Err(TransitionErr(format!(
                    "received a non-dispatched deposit entry as an assignment {:?}",
                    assignment
                ))),
            },
            _ => Err(TransitionErr(format!(
                "unexpected state in process_assignment ({:?})",
                self.state.state
            ))),
        }
    }

    fn process_stake_chain_advancement(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        match current {
            ContractState::Assigned {
                peg_out_graphs,
                fulfiller,
                recipient,
                deadline,
                active_graph,
            } => {
                if tx.compute_txid() != active_graph.stake_txid {
                    return Err(TransitionErr(format!(
                        "stake chain advancement txid ({}) doesn't match the stake txid of the active graph ({})", tx.compute_txid(), active_graph.stake_txid,
                    )));
                }

                self.state.state = ContractState::StakeTxReady {
                    peg_out_graphs,
                    fulfiller,
                    recipient: recipient.clone(),
                    deadline,
                    active_graph,
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
                "unexpected state in process_stake_chain_advancement ({:?})",
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
        match current {
            ContractState::StakeTxReady {
                peg_out_graphs,
                fulfiller,
                active_graph,
                recipient,
                ..
            } => {
                // TODO(proofofkeags): we need to verify that this is bound properly to the correct
                // operator.
                let cfg = self.cfg();
                if !is_fulfillment_tx(
                    cfg.network,
                    &cfg.peg_out_graph_params,
                    cfg.operator_table.pov_idx(),
                    cfg.deposit_idx,
                    cfg.deposit_tx.compute_txid(),
                    recipient,
                )(tx)
                {
                    return Err(TransitionErr(format!(
                        "invalid fulfillment transaction ({}) delivered to CSM ({})",
                        tx.compute_txid(),
                        self.cfg.deposit_tx.compute_txid()
                    )));
                }

                let duty = if fulfiller == self.cfg.operator_table.pov_idx() {
                    Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishClaim))
                } else {
                    None
                };

                self.state.state = ContractState::Fulfilled {
                    peg_out_graphs,
                    fulfiller,
                    active_graph,
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_fulfillment_confirmation ({:?})",
                current
            ))),
        }
    }

    fn process_claim_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        match current {
            ContractState::Fulfilled {
                peg_out_graphs,
                fulfiller,
                active_graph,
                ..
            } => {
                if tx.compute_txid() != active_graph.claim_txid {
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
                    claim_height: height,
                    fulfiller,
                    active_graph,
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_claim_confirmation ({:?})",
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
                "unexpected state in process_claim_verification_failure ({:?})",
                self.state.state
            ))),
        }
    }

    fn process_challenge_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let current = std::mem::replace(&mut self.state.state, ContractState::Resolved {});
        match current {
            ContractState::Claimed {
                peg_out_graphs,
                fulfiller,
                active_graph,
                ..
            } => {
                if !is_challenge(active_graph.claim_txid)(tx) {
                    return Err(TransitionErr(format!(
                        "invalid challenge transaction ({}) in process_challenge_confirmation",
                        tx.compute_txid()
                    )));
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
                    fulfiller,
                    active_graph,
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_challenge_confirmation ({:?})",
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
                fulfiller,
                active_graph,
                ..
            } => {
                if tx.compute_txid() != active_graph.post_assert_txid {
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
                    post_assert_height,
                    fulfiller,
                    active_graph,
                };

                Ok(duty)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_assert_chain_confirmation ({:?})",
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
                "unexpected state in process_assert_verification_failure ({:?})",
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
                if !is_disprove(active_graph.post_assert_txid)(tx) {
                    return Err(TransitionErr(format!(
                        "invalid disprove transaction ({}) in process_disprove_confirmation",
                        tx.compute_txid()
                    )));
                }

                self.state.state = ContractState::Disproved {};

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_disprove_confirmation ({:?})",
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
                if tx.compute_txid() != active_graph.payout_optimistic_txid {
                    return Err(TransitionErr(format!("invalid optimistic payout transaction ({}) in process_optimistic_payout_confirmation", tx.compute_txid())));
                }

                self.state.state = ContractState::Resolved {};

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_optimistic_payout_confirmation ({:?})",
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
                if tx.compute_txid() != active_graph.payout_txid {
                    return Err(TransitionErr(format!(
                        "invalid defended payout transaction ({}) in process_defended_payout_confirmation", tx.compute_txid()
                    )));
                }

                self.state.state = ContractState::Resolved {};

                Ok(None)
            }
            _ => Err(TransitionErr(format!(
                "unexpected state in process_defended_payout_confirmation ({:?})",
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
        self.cfg
            .deposit_tx
            .input
            .first()
            .unwrap()
            .previous_output
            .txid
    }
}
