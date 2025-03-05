//! This module defines the core state machine for the Bridge Deposit Contract. All of the states,
//! events and transition rules are encoded in this structure. When the ContractSM accepts an event
//! it may or may not give back an OperatorDuty to execute as a result of this state transition.
use std::{collections::BTreeMap, fmt::Display, sync::Arc};

use bitcoin::{
    hashes::serde::{Deserialize, Serialize},
    Transaction, Txid,
};
use btc_notify::client::TxPredicate;
use musig2::{PartialSignature, PubNonce};
use strata_bridge_primitives::{
    params::prelude::{PAYOUT_OPTIMISTIC_TIMELOCK, PAYOUT_TIMELOCK},
    types::{BitcoinBlockHeight, OperatorIdx},
};
use strata_bridge_tx_graph::peg_out_graph::PegOutGraphSummary;
use strata_p2p_types::{OperatorPubKey, WotsPublicKeys};
use strata_primitives::bridge::PublickeyTable;
use strata_state::bridge_state::{DepositEntry, DepositState};
use thiserror::Error;

use crate::predicates::{is_challenge, is_disprove, is_fulfillment_tx};

/// This is the unified event type for this state machine.
///
/// Events of this type will be repeatedly fed to the state machine until it terminates.
#[derive(Debug)]
pub enum ContractEvent {
    /// Signifies that we have a new set of WOTS keys from one of our peers.
    WotsKeys(OperatorPubKey, Box<WotsPublicKeys>),

    /// Signifies that we have a new set of nonces for the peg out graph from one of our peers.
    GraphNonces(OperatorPubKey, Vec<PubNonce>),

    /// Signifies that we have a new set of signatures for the peg out graph from one of our peers.
    GraphSigs(OperatorPubKey, Vec<PartialSignature>),

    /// Signifies that we have received a new deposit nonce from one of our peers.
    RootNonce(OperatorPubKey, PubNonce),

    /// Signifies that we have a new deposit signature from one of our peers.
    RootSig(OperatorPubKey, PartialSignature),

    /// Signifies that this withdrawal has been assigned.
    Assignment(DepositEntry),

    /// Signifies that the deposit transaction has been confirmed, the second value is the global
    /// deposit index.
    DepositConfirmation(Transaction, u32),

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
        /// This is the height where the requester can relcaim the request output if it has not yet
        /// been converted to a deposit.
        abort_deadline: BitcoinBlockHeight,

        /// This is a collection of the wots keys we have received from our peers.
        wots_keys: BTreeMap<OperatorPubKey, WotsPublicKeys>,

        /// This is a collection of nonces for the peg-out graph on a per-operator basis.
        graph_nonces: BTreeMap<OperatorPubKey, Vec<PubNonce>>,

        /// This is the collection of signatures for the peg-out graph on a per-operator basis.
        graph_sigs: BTreeMap<OperatorPubKey, Vec<PartialSignature>>,

        /// This is a collection of the nonces for the final musig2 signature needed to sweep the
        /// deposit request transaction to the deposit transaction.
        root_nonces: BTreeMap<OperatorPubKey, PubNonce>,

        /// This is the collection of signatures for the deposit transaction itself on a
        /// per-operator basis.
        root_sigs: BTreeMap<OperatorPubKey, PartialSignature>,
    },

    /// This state describes everything from the moment the deposit confirms, to the moment the
    /// strata state commitment that assigns this deposit confirms.
    Deposited {
        /// The global deposit index of this deposit.
        deposit_idx: u32,
    },

    /// This state describes everything from the moment the withdrawal is assigned, to the moment
    /// the fulfillment transaction confirms.
    Assigned {
        /// The global deposit index of this deposit.
        deposit_idx: u32,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The deadline by which the operator must fulfill the withdrawal before it is reassigned.
        deadline: BitcoinBlockHeight,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the fulfillment transaction confirms, to
    /// the moment the claim transaction confirms.
    Fulfilled {
        /// The global deposit index of this deposit.
        deposit_idx: u32,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the claim transaction confirms, to the
    /// moment either the challenge transaction confirms, or the optimistic payout transaction
    /// confirms.
    Claimed {
        /// The global deposit index of this deposit.
        deposit_idx: u32,

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
        /// The global deposit index of this deposit.
        deposit_idx: u32,

        /// The operator responsible for fulfilling the withdrawal.
        fulfiller: OperatorIdx,

        /// The graph that belongs to the assigned operator.
        active_graph: PegOutGraphSummary,
    },

    /// This state describes everything from the moment the post-assert transaction confirms, to
    /// the moment either the disprove transaction confirms or the payout transaction confirms.
    Asserted {
        /// The global deposit index of this deposit.
        deposit_idx: u32,

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
pub enum OperatorDuty {
    /// Instructs us to terminate this contract.
    Abort,

    /// Instructs us to publish our own wots keys for this contract.
    PublishWOTSKeys,

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
    /// Originates when strata state on L1 is published and assignment is self.
    PublishFulfillment,

    /// Originates when Fulfillment has been completed
    AdvanceStakeChain,

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
pub struct TransitionErr;
impl Display for TransitionErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransitionErr")
    }
}

/// Holds the state machine values that remain static for the lifetime of the contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCfg {
    /// The operator index the state machine is using as its perspective.
    pub perspective: OperatorIdx,

    /// The pointed operator set.
    pub operator_set: PublickeyTable,

    /// The predetermined deposit transaction that the rest of the graph is built from.
    pub deposit_tx: Transaction,

    /// The set of all possible withdrawal graphs indexed by operator.
    pub peg_out_graphs: BTreeMap<OperatorIdx, PegOutGraphSummary>,
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
    pub fn new(
        perspective: OperatorIdx,
        operator_set: PublickeyTable,
        block_height: BitcoinBlockHeight,
        abort_deadline: BitcoinBlockHeight,
        deposit_tx: Transaction,
        peg_out_graphs: BTreeMap<OperatorIdx, PegOutGraphSummary>,
    ) -> (Self, OperatorDuty) {
        let cfg = ContractCfg {
            perspective,
            operator_set,
            deposit_tx,
            peg_out_graphs,
        };
        let state = ContractState::Requested {
            abort_deadline,
            wots_keys: BTreeMap::new(),
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
            OperatorDuty::PublishGraphSignatures,
        )
    }

    /// Restores a [`ContractSM`] from its [`ContractCfg`] and [`MachineState`]
    pub fn restore(cfg: ContractCfg, state: MachineState) -> Self {
        ContractSM { cfg, state }
    }

    /// Filter that specifies which transactions should be delivered to this state machine.
    pub fn transaction_filter(&self) -> TxPredicate {
        let deposit_txid = self.cfg.deposit_tx.compute_txid();
        let graphs = self
            .cfg
            .peg_out_graphs
            .iter()
            .map(|a| a.1)
            .cloned()
            .collect::<Vec<PegOutGraphSummary>>();
        Arc::new(move |tx: &Transaction| {
            let txid = tx.compute_txid();
            graphs.iter().any(|g| {
                deposit_txid == txid
                    || g.claim_txid == txid
                    || g.payout_optimistic_txid == txid
                    || g.post_assert_txid == txid
                    || g.payout_txid == txid
                    || is_challenge(g.claim_txid)(tx)
                    || is_disprove(g.post_assert_txid)(tx)
                    || is_fulfillment_tx(deposit_txid)(tx)
            })
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
            ContractEvent::WotsKeys(op, keys) => self.process_wots_public_keys(op, *keys),
            ContractEvent::GraphNonces(op, nonces) => self.process_graph_nonces(op, nonces),
            ContractEvent::GraphSigs(op, sigs) => self.process_graph_signatures(op, sigs),
            ContractEvent::RootNonce(op, nonce) => self.process_root_nonce(op, nonce),
            ContractEvent::RootSig(op, sig) => self.process_root_signature(op, sig),
            ContractEvent::DepositConfirmation(tx, deposit_idx) => {
                self.process_deposit_confirmation(tx, deposit_idx)
            }
            ContractEvent::PegOutGraphConfirmation(tx, height) => {
                self.process_peg_out_graph_tx_confirmation(height, &tx)
            }
            ContractEvent::Block(height) => self.notify_new_block(height),
            ContractEvent::ClaimFailure => self.process_claim_verification_failure(),
            ContractEvent::AssertionFailure => self.process_assertion_verification_failure(),
            ContractEvent::Assignment(deposit_entry) => self.process_assignment(&deposit_entry),
        }
    }

    fn process_deposit_confirmation(
        &mut self,
        tx: Transaction,
        deposit_idx: u32,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.state {
            ContractState::Requested { .. }
                if tx.compute_txid() == self.cfg.deposit_tx.compute_txid() =>
            {
                self.state.state = ContractState::Deposited { deposit_idx };
                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }

    /// Processes a transaction that is assumed to be in the peg-out-graph.
    fn process_peg_out_graph_tx_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &self.state.state {
            ContractState::Requested { .. } => Err(TransitionErr),
            ContractState::Deposited { .. } => Err(TransitionErr),
            ContractState::Assigned { .. } => self.process_fulfillment_confirmation(tx),
            ContractState::Fulfilled { .. } => self.process_claim_confirmation(height, tx),
            ContractState::Claimed { .. } => self
                .process_challenge_confirmation(tx)
                .or_else(|_| self.process_optimistic_payout_confirmation(tx)),
            ContractState::Challenged { .. } => self.process_assert_chain_confirmation(height, tx),
            ContractState::Asserted { .. } => self
                .process_disprove_confirmation(tx)
                .or_else(|_| self.process_defended_payout_confirmation(tx)),
            ContractState::Disproved {} => Err(TransitionErr),
            ContractState::Resolved { .. } => Err(TransitionErr),
        }
    }

    fn process_wots_public_keys(
        &mut self,
        signer: OperatorPubKey,
        keys: WotsPublicKeys,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { wots_keys, .. } => {
                wots_keys.insert(signer, keys);
                Ok(if wots_keys.len() == self.cfg.operator_set.0.len() {
                    Some(OperatorDuty::PublishGraphNonces)
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_graph_nonces(
        &mut self,
        signer: OperatorPubKey,
        nonces: Vec<PubNonce>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { graph_nonces, .. } => {
                graph_nonces.insert(signer, nonces);
                Ok(if graph_nonces.len() == self.cfg.operator_set.0.len() {
                    Some(OperatorDuty::PublishGraphNonces)
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    /// Processes a graph signature payload from our peer.
    fn process_graph_signatures(
        &mut self,
        signer: OperatorPubKey,
        sig: Vec<PartialSignature>,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { graph_sigs, .. } => {
                graph_sigs.insert(signer, sig);
                Ok(if graph_sigs.len() == self.cfg.operator_set.0.len() {
                    // we have all the sigs now
                    // issue deposit signature
                    Some(OperatorDuty::PublishRootNonce)
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_root_nonce(
        &mut self,
        signer: OperatorPubKey,
        nonce: PubNonce,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { root_nonces, .. } => {
                root_nonces.insert(signer, nonce);
                Ok(if root_nonces.len() == self.cfg.operator_set.0.len() {
                    // we have all the sigs now
                    // issue deposit signature
                    Some(OperatorDuty::PublishRootSignature)
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    /// Processes a signature for the deposit transaction from our peer.
    fn process_root_signature(
        &mut self,
        signer: OperatorPubKey,
        sig: PartialSignature,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state.state {
            ContractState::Requested { root_sigs, .. } => {
                root_sigs.insert(signer, sig);
                Ok(if root_sigs.len() == self.cfg.operator_set.0.len() {
                    // we have all the deposit sigs now
                    // we can publish the deposit
                    Some(OperatorDuty::PublishDeposit)
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
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
            return Err(TransitionErr);
        }
        Ok(
            match std::mem::replace(
                &mut self.state.state,
                ContractState::Deposited { deposit_idx: 0 },
            ) {
                ContractState::Requested { abort_deadline, .. } => {
                    if self.state.block_height >= abort_deadline {
                        Some(OperatorDuty::Abort)
                    } else {
                        None
                    }
                }
                ContractState::Deposited { .. } => None,
                ContractState::Assigned {
                    deposit_idx,
                    deadline,
                    ..
                } => {
                    if self.state.block_height >= deadline {
                        self.state.state = ContractState::Deposited { deposit_idx };
                    }

                    None
                }
                ContractState::Fulfilled { .. } => None,
                ContractState::Claimed {
                    fulfiller,
                    claim_height,
                    ..
                } => {
                    if self.state.block_height >= claim_height + PAYOUT_OPTIMISTIC_TIMELOCK as u64
                        && fulfiller == self.cfg.perspective
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
                    if self.state.block_height >= post_assert_height + PAYOUT_TIMELOCK as u64
                        && fulfiller == self.cfg.perspective
                    {
                        Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishPayout))
                    } else {
                        None
                    }
                }
                ContractState::Disproved {} => None,
                ContractState::Resolved {} => None,
            },
        )
    }

    /// Processes an assignment from the strata state commitment.
    pub fn process_assignment(
        &mut self,
        assignment: &DepositEntry,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        let deposit_idx = match self.state.state {
            ContractState::Deposited { deposit_idx } => deposit_idx,
            _ => {
                return Err(TransitionErr);
            }
        };

        if assignment.idx() != deposit_idx {
            return Err(TransitionErr);
        }

        match assignment.deposit_state() {
            DepositState::Dispatched(dispatched_state) => {
                let fulfiller = dispatched_state.assignee();
                let deadline = dispatched_state.exec_deadline();
                let active_graph = self
                    .cfg
                    .peg_out_graphs
                    .get(&fulfiller)
                    .ok_or(TransitionErr)?
                    .to_owned();
                self.state.state = ContractState::Assigned {
                    deposit_idx,
                    fulfiller,
                    deadline,
                    active_graph,
                };
                Ok(if fulfiller == self.cfg.perspective {
                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishFulfillment,
                    ))
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_fulfillment_confirmation(
        // Analyze fulfillment transaction to determine
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match std::mem::replace(
            &mut self.state.state,
            ContractState::Deposited { deposit_idx: 0 },
        ) {
            ContractState::Assigned {
                deposit_idx,
                fulfiller,
                active_graph,
                ..
            } => {
                // TODO(proofofkeags): we need to verify that this is bound properly to the correct
                // operator.
                if !is_fulfillment_tx(self.cfg.deposit_tx.compute_txid())(tx) {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Fulfilled {
                    deposit_idx,
                    fulfiller,
                    active_graph,
                };

                Ok(if fulfiller == self.cfg.perspective {
                    Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishClaim))
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_claim_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match std::mem::replace(
            &mut self.state.state,
            ContractState::Deposited { deposit_idx: 0 },
        ) {
            ContractState::Fulfilled {
                deposit_idx,
                fulfiller,
                active_graph,
                ..
            } => {
                if tx.compute_txid() != active_graph.claim_txid {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Claimed {
                    deposit_idx,
                    claim_height: height,
                    fulfiller,
                    active_graph,
                };

                Ok(if fulfiller != self.cfg.perspective {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyClaim))
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
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
            _ => Err(TransitionErr),
        }
    }

    fn process_challenge_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match std::mem::replace(
            &mut self.state.state,
            ContractState::Deposited { deposit_idx: 0 },
        ) {
            ContractState::Claimed {
                deposit_idx,
                fulfiller,
                active_graph,
                ..
            } => {
                if !is_challenge(active_graph.claim_txid)(tx) {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Challenged {
                    deposit_idx,
                    fulfiller,
                    active_graph,
                };

                Ok(if fulfiller == self.cfg.perspective {
                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishAssertChain,
                    ))
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_assert_chain_confirmation(
        &mut self,
        post_assert_height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match std::mem::replace(
            &mut self.state.state,
            ContractState::Deposited { deposit_idx: 0 },
        ) {
            ContractState::Challenged {
                deposit_idx,
                fulfiller,
                active_graph,
                ..
            } => {
                if tx.compute_txid() != active_graph.post_assert_txid {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Asserted {
                    deposit_idx,
                    post_assert_height,
                    fulfiller,
                    active_graph,
                };

                Ok(if fulfiller != self.cfg.perspective {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyAssertion))
                } else {
                    None
                })
            }
            _ => Err(TransitionErr),
        }
    }

    /// Tells the state machine that the assertion chain is invalid.
    fn process_assertion_verification_failure(
        &mut self,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match std::mem::replace(
            &mut self.state.state,
            ContractState::Deposited { deposit_idx: 0 },
        ) {
            ContractState::Asserted { .. } => Ok(Some(OperatorDuty::VerifierDuty(
                VerifierDuty::PublishDisprove,
            ))),
            _ => Err(TransitionErr),
        }
    }

    fn process_disprove_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.state.clone() {
            ContractState::Asserted { active_graph, .. } => {
                if !is_disprove(active_graph.post_assert_txid)(tx) {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Disproved {};

                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_optimistic_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.state.clone() {
            ContractState::Claimed { active_graph, .. } => {
                if tx.compute_txid() != active_graph.payout_optimistic_txid {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Resolved {};

                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_defended_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.state.clone() {
            ContractState::Asserted { active_graph, .. } => {
                if tx.compute_txid() != active_graph.payout_txid {
                    return Err(TransitionErr);
                }

                self.state.state = ContractState::Resolved {};

                Ok(None)
            }
            _ => Err(TransitionErr),
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

/// Placeholder struct for the graph signature payload we get from our peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSignatures {}
