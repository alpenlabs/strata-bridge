//! TODO(proofofkeags): docs for crate
#![feature(result_flattening)]
mod predicates;
mod tx_driver;

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{taproot::Signature, Transaction};
use btc_notify::client::TxPredicate;
use predicates::{is_challenge, is_disprove, is_fulfillment_tx, is_txid};
use strata_bridge_primitives::{
    build_context::BuildContext,
    params::prelude::{PAYOUT_OPTIMISTIC_TIMELOCK, PAYOUT_TIMELOCK},
    types::{BitcoinBlockHeight, OperatorIdx},
};
use strata_bridge_tx_graph::{peg_out_graph::PegOutGraph, transactions::prelude::CovenantTx};
use strata_state::bridge_state::{DepositEntry, DepositState};

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
#[derive(Debug, Clone)]
enum ContractState {
    /// This state describes everything from the moment the deposit request confirms, to the moment
    /// the deposit confirms.
    Requested {
        /// This is the height where the requester can relcaim the request output if it has not yet
        /// been converted to a deposit.
        abort_deadline: BitcoinBlockHeight,

        /// This is the collection of signatures for the peg-out graph on a per-operator basis.
        graph_sigs: BTreeMap<OperatorIdx, GraphSignatures>,

        /// This is the collection of signatures for the deposit transaction itself on a
        /// per-operator basis.
        root_sigs: BTreeMap<OperatorIdx, Signature>,
    },

    /// This state describes everything from the moment the deposit confirms, to the moment the
    /// strata state commitment that assigns this deposit confirms.
    Deposited,

    /// This state describes everything from the moment the withdrawal is assigned, to the moment
    /// the fulfillment transaction confirms.
    Assigned {
        fulfiller: OperatorIdx,
        deadline: BitcoinBlockHeight,
        active_graph: PegOutGraph,
    },

    /// This state describes everything from the moment the fulfillment transaction confirms, to
    /// the moment the claim transaction confirms.
    Fulfilled {
        fulfiller: OperatorIdx,
        active_graph: PegOutGraph,
    },

    /// This state describes everything from the moment the claim transaction confirms, to the
    /// moment either the challenge transaction confirms, or the optimistic payout transaction
    /// confirms.
    Claimed {
        claim_height: BitcoinBlockHeight,
        fulfiller: OperatorIdx,
        active_graph: PegOutGraph,
    },

    /// This state describes everything from the moment the challenge transaction confirms, to the
    /// moment the post-assert transaction confirms.
    Challenged {
        fulfiller: OperatorIdx,
        active_graph: PegOutGraph,
    },

    /// This state describes everything from the moment the post-assert transaction confirms, to
    /// the moment either the disprove transaction confirms or the payout transaction confirms.
    Asserted {
        post_assert_height: BitcoinBlockHeight,
        fulfiller: OperatorIdx,
        active_graph: PegOutGraph,
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
    /// Instructs us to send out signatures for the peg out graph.
    PublishGraphSignatures,

    /// Instructs us to send out signatures for the deposit transaction.
    PublishDepositSignature,

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

/// Instructs us what to do and what the state machine wants to hear about next.
pub struct NextStep {
    /// This describes to the caller what action, if any, should be performed next.
    pub action: Option<OperatorDuty>,

    /// This describes to the caller what transactions, if any, should be given to this state
    /// machine.
    pub listen_for: Option<TxPredicate>,
}
impl NextStep {
    fn new(action: Option<OperatorDuty>, listen_for: Option<TxPredicate>) -> Self {
        NextStep { action, listen_for }
    }
}
impl std::fmt::Debug for NextStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NextStep")
            .field("action", &self.action)
            .field(
                "listen_for",
                &format!("{:?}", self.listen_for.as_ref().map(Arc::as_ptr)),
            )
            .finish()
    }
}

/// Error representing an invalid state transition.
#[derive(Debug)]
pub struct TransitionErr;

#[derive(Debug)]
/// This is the core state machine for a given deposit contract.
pub struct ContractSM<PointedOperatorSet: BuildContext> {
    // Readers
    ctx: PointedOperatorSet,
    deposit_tx: Transaction,
    deposit_idx: u32,
    peg_out_graphs: BTreeMap<OperatorIdx, PegOutGraph>,

    // States
    block_height: BitcoinBlockHeight,
    state: ContractState,
}

impl<C: BuildContext> ContractSM<C> {
    /// Builds a new ContractSM around a given deposit transaction.
    ///
    /// This will be constructible once we have a deposit request.
    pub fn new(
        ctx: C,
        block_height: BitcoinBlockHeight,
        abort_deadline: BitcoinBlockHeight,
        deposit_tx: Transaction,
        deposit_idx: u32,
        peg_out_graphs: BTreeMap<OperatorIdx, PegOutGraph>,
    ) -> Result<(Self, OperatorDuty), TransitionErr> {
        let state = ContractState::Requested {
            abort_deadline,
            graph_sigs: BTreeMap::new(),
            root_sigs: BTreeMap::new(),
        };
        Ok((
            ContractSM {
                ctx,
                block_height,
                deposit_tx,
                deposit_idx,
                state,
                peg_out_graphs,
            },
            OperatorDuty::PublishGraphSignatures,
        ))
    }

    /// Gives a transaction filter that matches all of the transactions in the peg-out-graph.
    pub fn peg_out_graph_filter(&self) -> impl Fn(Transaction) -> bool {
        |_| false
    }

    /// Processes a transaction that is assumed to be in the peg-out-graph.
    pub fn process_peg_out_graph_tx_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match &self.state {
            ContractState::Requested { .. } => self.process_deposit_confirmation(tx),
            ContractState::Deposited => Err(TransitionErr),
            ContractState::Assigned { fulfiller, .. } => {
                if is_fulfillment_tx(self.deposit_idx, *fulfiller)(tx) {
                    self.process_fulfillment_confirmation(tx)
                } else {
                    Err(TransitionErr)
                }
            }
            ContractState::Fulfilled { .. } => self.process_claim_confirmation(height, tx),
            ContractState::Claimed { active_graph, .. } => {
                if is_challenge(&active_graph.claim_tx)(tx) {
                    self.process_challenge_confirmation(tx)
                } else if is_txid(active_graph.payout_optimistic.compute_txid())(tx) {
                    self.process_optimistic_payout_confirmation(tx)
                } else {
                    Err(TransitionErr)
                }
            }
            ContractState::Challenged { active_graph, .. } => {
                if is_txid(active_graph.assert_chain.post_assert.compute_txid())(tx) {
                    self.process_assert_chain_confirmation(height, tx)
                } else {
                    Err(TransitionErr)
                }
            }
            ContractState::Asserted { active_graph, .. } => {
                if is_disprove(&active_graph.assert_chain.post_assert)(tx) {
                    self.process_disprove_confirmation(tx)
                } else if is_txid(active_graph.payout_tx.compute_txid())(tx) {
                    self.process_defended_payout_confirmation(tx)
                } else {
                    Err(TransitionErr)
                }
            }
            ContractState::Disproved {} => Err(TransitionErr),
            ContractState::Resolved { .. } => Err(TransitionErr),
        }
    }

    /// Processes a graph signature payload from our peer.
    pub fn process_graph_signature_payload(
        &mut self,
        signer: OperatorIdx,
        sig: GraphSignatures,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state {
            ContractState::Requested { graph_sigs, .. } => {
                graph_sigs.insert(signer, sig);
                if graph_sigs.len() == self.ctx.pubkey_table().0.len() {
                    // we have all the sigs now
                    // issue deposit signature
                    Ok(Some(OperatorDuty::PublishDepositSignature))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    /// Processes a signature for the deposit transaction from our peer.
    pub fn process_root_signature(
        &mut self,
        signer: OperatorIdx,
        sig: Signature,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state {
            ContractState::Requested { root_sigs, .. } => {
                root_sigs.insert(signer, sig);
                if root_sigs.len() == self.ctx.pubkey_table().0.len() {
                    // we have all the deposit sigs now
                    // we can publish the deposit
                    Ok(Some(OperatorDuty::PublishDeposit))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_deposit_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        if tx.compute_txid() != self.deposit_tx.compute_txid() {
            return Err(TransitionErr);
        }

        self.state = ContractState::Deposited;

        Ok(NextStep::new(None, None))
    }

    /// Increment the internally tracked block height.
    pub fn notify_new_block(&mut self) -> Result<Option<NextStep>, TransitionErr> {
        self.block_height += 1;
        match self.state.clone() {
            ContractState::Requested { abort_deadline, .. } => {
                if self.block_height >= abort_deadline {
                    Ok(Some(NextStep::new(None, None)))
                } else {
                    Ok(None)
                }
            }
            ContractState::Deposited => Ok(None),
            ContractState::Assigned {
                fulfiller,
                deadline,
                ..
            } => {
                if self.block_height >= deadline {
                    self.state = ContractState::Deposited;
                }
                Ok(Some(NextStep::new(
                    None,
                    Some(is_fulfillment_tx(self.deposit_idx, fulfiller)),
                )))
            }
            ContractState::Fulfilled { .. } => Ok(None),
            ContractState::Claimed {
                fulfiller,
                claim_height,
                active_graph,
                ..
            } => {
                if self.block_height >= claim_height + PAYOUT_OPTIMISTIC_TIMELOCK as u64
                    && fulfiller == self.ctx.own_index()
                {
                    Ok(Some(NextStep::new(
                        Some(OperatorDuty::FulfillerDuty(
                            FulfillerDuty::PublishPayoutOptimistic,
                        )),
                        Some(is_txid(active_graph.payout_optimistic.compute_txid())),
                    )))
                } else {
                    Ok(None)
                }
            }
            ContractState::Challenged { .. } => Ok(None),
            ContractState::Asserted {
                post_assert_height,
                fulfiller,
                active_graph,
                ..
            } => {
                if self.block_height >= post_assert_height + PAYOUT_TIMELOCK as u64
                    && fulfiller == self.ctx.own_index()
                {
                    Ok(Some(NextStep::new(
                        Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishPayout)),
                        Some(is_txid(active_graph.payout_tx.compute_txid())),
                    )))
                } else {
                    Ok(None)
                }
            }
            ContractState::Disproved {} => Ok(None),
            ContractState::Resolved {} => Ok(None),
        }
    }

    /// Processes an assignment from the strata state commitment.
    pub fn process_assignment(
        &mut self,
        assignment: &DepositEntry,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        if !matches!(self.state, ContractState::Deposited) {
            return Err(TransitionErr);
        }

        if assignment.idx() != self.deposit_idx {
            return Err(TransitionErr);
        }

        match assignment.deposit_state() {
            DepositState::Dispatched(dispatched_state) => {
                let fulfiller = dispatched_state.assignee();
                let deadline = dispatched_state.exec_deadline();
                let active_graph = self
                    .peg_out_graphs
                    .get(&fulfiller)
                    .ok_or(TransitionErr)?
                    .clone();
                self.state = ContractState::Assigned {
                    fulfiller,
                    deadline,
                    active_graph,
                };
                if fulfiller == self.ctx.own_index() {
                    Ok(Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishFulfillment,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_fulfillment_confirmation(
        // Analyze fulfillment transaction to determine
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Assigned {
                fulfiller,
                active_graph,
                ..
            } => {
                if !is_fulfillment_tx(self.deposit_idx, fulfiller)(tx) {
                    return Err(TransitionErr);
                }

                let match_claim = Some(is_txid(active_graph.claim_tx.compute_txid()));

                self.state = ContractState::Fulfilled {
                    fulfiller,
                    active_graph,
                };

                let duty = if fulfiller == self.ctx.own_index() {
                    Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishClaim))
                } else {
                    None
                };

                Ok(NextStep::new(duty, match_claim))
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_claim_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match std::mem::replace(&mut self.state, ContractState::Deposited) {
            ContractState::Fulfilled {
                fulfiller,
                active_graph,
                ..
            } => {
                if tx.compute_txid() != active_graph.claim_tx.compute_txid() {
                    return Err(TransitionErr);
                }

                let match_challenge = is_challenge(&active_graph.claim_tx);

                self.state = ContractState::Claimed {
                    claim_height: height,
                    fulfiller,
                    active_graph,
                };

                let duty = if fulfiller != self.ctx.own_index() {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyClaim))
                } else {
                    None
                };

                Ok(NextStep::new(duty, Some(match_challenge)))
            }
            _ => Err(TransitionErr),
        }
    }

    /// Tells the state machine that the claim was assessed to be fraudulent.
    pub fn process_claim_verification_failure(&mut self) -> Result<NextStep, TransitionErr> {
        match &self.state {
            ContractState::Claimed { active_graph, .. } => Ok(NextStep::new(
                Some(OperatorDuty::VerifierDuty(VerifierDuty::PublishChallenge)),
                Some(is_challenge(&active_graph.claim_tx)),
            )),
            _ => Err(TransitionErr),
        }
    }

    fn process_challenge_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Claimed {
                fulfiller,
                active_graph,
                ..
            } => {
                if !is_challenge(&active_graph.claim_tx)(tx) {
                    return Err(TransitionErr);
                }

                let is_post_assert = is_txid(active_graph.assert_chain.post_assert.compute_txid());

                self.state = ContractState::Challenged {
                    fulfiller,
                    active_graph,
                };

                let duty = if fulfiller == self.ctx.own_index() {
                    Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishAssertChain,
                    ))
                } else {
                    None
                };

                Ok(NextStep::new(duty, Some(is_post_assert)))
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_assert_chain_confirmation(
        &mut self,
        post_assert_height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Challenged {
                fulfiller,
                active_graph,
                ..
            } => {
                if tx.compute_txid() != active_graph.assert_chain.post_assert.compute_txid() {
                    return Err(TransitionErr);
                }

                let match_disprove = is_disprove(&active_graph.assert_chain.post_assert);

                self.state = ContractState::Asserted {
                    post_assert_height,
                    fulfiller,
                    active_graph,
                };

                let duty = if fulfiller != self.ctx.own_index() {
                    Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyAssertion))
                } else {
                    None
                };

                Ok(NextStep::new(duty, Some(match_disprove)))
            }
            _ => Err(TransitionErr),
        }
    }

    /// Tells the state machine that the assertion chain is invalid.
    pub fn process_assertion_verification_failure(
        &mut self,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted { .. } => Ok(Some(OperatorDuty::VerifierDuty(
                VerifierDuty::PublishDisprove,
            ))),
            _ => Err(TransitionErr),
        }
    }

    fn process_disprove_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted { active_graph, .. } => {
                if !is_disprove(&active_graph.assert_chain.post_assert)(tx) {
                    return Err(TransitionErr);
                }

                self.state = ContractState::Disproved {};

                Ok(NextStep::new(None, None))
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_optimistic_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Claimed { active_graph, .. } => {
                if tx.compute_txid() != active_graph.payout_optimistic.compute_txid() {
                    return Err(TransitionErr);
                }

                self.state = ContractState::Resolved {};

                Ok(NextStep::new(None, None))
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_defended_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted { active_graph, .. } => {
                if tx.compute_txid() != active_graph.payout_tx.compute_txid() {
                    return Err(TransitionErr);
                }

                self.state = ContractState::Resolved {};

                Ok(NextStep::new(None, None))
            }
            _ => Err(TransitionErr),
        }
    }
}

/// Placeholder struct for the graph signature payload we get from our peers.
#[derive(Debug, Clone)]
pub struct GraphSignatures {}
