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
    },

    /// This state describes everything from the moment the fulfillment transaction confirms, to
    /// the moment the claim transaction confirms.
    Fulfilled {
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },

    /// This state describes everything from the moment the claim transaction confirms, to the
    /// moment either the challenge transaction confirms, or the optimistic payout transaction
    /// confirms.
    Claimed {
        claim_height: BitcoinBlockHeight,
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },

    /// This state describes everything from the moment the claim transaction confirms, to the
    /// moment the chain dispute transaction confirms.
    ChainDisputed {
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },

    /// This state describes everything from the moment the challenge transaction confirms, to the
    /// moment the post-assert transaction confirms.
    Challenged {
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },

    /// This state describes everything from the moment the post-assert transaction confirms, to
    /// the moment either the disprove transaction confirms or the payout transaction confirms.
    Asserted {
        post_assert_height: BitcoinBlockHeight,
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
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
    action: Option<OperatorDuty>,
    listen_for: Option<TxPredicate>,
}
impl NextStep {
    fn new(action: Option<OperatorDuty>, listen_for: Option<TxPredicate>) -> Self {
        NextStep { action, listen_for }
    }
}

/// Error representing an invalid state transition.
#[derive(Debug)]
pub struct TransitionErr;

#[derive(Debug)]
/// This is the core state machine for a given deposit contract.
pub struct ContractSM<PointedOperatorSet: BuildContext, Db> {
    // Readers
    ctx: PointedOperatorSet,
    deposit_tx: Transaction,
    deposit_idx: u32,
    peg_out_graphs: BTreeMap<OperatorIdx, PegOutGraph>,

    // States
    block_height: BitcoinBlockHeight,
    state: ContractState,

    // Writers
    db: Db,
}

impl<C: BuildContext, Db> ContractSM<C, Db> {
    /// Builds a new ContractSM around a given deposit transaction.
    ///
    /// This will be constructible once we have a deposit request.
    pub fn new(
        ctx: C,
        block_height: BitcoinBlockHeight,
        deposit_tx: Transaction,
        deposit_idx: u32,
        peg_out_graphs: BTreeMap<OperatorIdx, PegOutGraph>,
        db: Db,
    ) -> Result<(Self, OperatorDuty), TransitionErr> {
        let state = ContractState::Requested {
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
                db,
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
                    self.process_fulfillment_confirmation(tx.clone())
                } else {
                    Err(TransitionErr)
                }
            }
            ContractState::Fulfilled { .. } => self.process_claim_confirmation(height, tx),
            ContractState::Claimed { fulfiller, .. } => {
                let graph = match self.peg_out_graphs.get(fulfiller) {
                    None => return Err(TransitionErr),
                    Some(a) => a,
                };

                if is_challenge(&graph.claim_tx)(tx) {
                    self.process_challenge_confirmation(tx)
                } else if is_txid(graph.assert_chain.post_assert.compute_txid())(tx) {
                    self.process_assert_chain_confirmation(height, tx)
                } else {
                    Err(TransitionErr)
                }
            }
            ContractState::ChainDisputed { .. } => Err(TransitionErr),
            ContractState::Challenged { .. } => Err(TransitionErr),
            ContractState::Asserted { fulfiller, .. } => {
                let graph = match self.peg_out_graphs.get(fulfiller) {
                    None => return Err(TransitionErr),
                    Some(a) => a,
                };

                if is_disprove(&graph.assert_chain.post_assert)(tx) {
                    self.process_disprove_confirmation(tx)
                } else if is_txid(graph.payout_tx.compute_txid())(tx) {
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
    pub fn notify_new_block(&mut self) -> Result<NextStep, TransitionErr> {
        self.block_height += 1;
        match self.state.clone() {
            ContractState::Requested { .. } => {
                let request_outpoint = self.deposit_tx.input.first().unwrap().previous_output;
                Ok(NextStep::new(
                    None,
                    Some(Arc::new(move |tx: &Transaction| {
                        tx.input
                            .iter()
                            .any(|txin| txin.previous_output == request_outpoint)
                    })),
                ))
            }
            ContractState::Deposited => todo!(),
            ContractState::Assigned { deadline, .. } => {
                if self.block_height >= deadline {
                    self.state = ContractState::Deposited;
                }
                Ok(NextStep::new(None, todo!()))
            }
            ContractState::Fulfilled { .. } => todo!(),
            ContractState::Claimed { .. } => todo!(),
            ContractState::ChainDisputed { .. } => todo!(),
            ContractState::Challenged { .. } => todo!(),
            ContractState::Asserted { .. } => todo!(),
            ContractState::Disproved {} => todo!(),
            ContractState::Resolved {} => todo!(),
        }
        // Increment tracked height, compare to relative timelocks of current state.
        // Scan for:
        // 1. Deposit Confirmations
        // 2. Rollup Checkpoint Confirmations (Assignments)
        // 3. Fulfillment Confirmations
        // 4. Claim Confirmations
        // 5. Challenge Confirmations
        // 6. Assert Confirmations
        // 7. Disprove Confirmations
        // 8. Payout Optimistic Confirmations
        // 9. Payout Confirmations
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
                self.state = ContractState::Assigned {
                    fulfiller,
                    deadline,
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
        tx: Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state {
            ContractState::Assigned { fulfiller, .. } => {
                // TODO(proofofkeags): validate that this is transaction meets the requirements for
                // a fulfillment transaction.
                self.state = ContractState::Fulfilled {
                    fulfiller,
                    fulfillment_tx: tx,
                };

                if fulfiller == self.ctx.own_index() {
                    Ok(NextStep::new(
                        Some(OperatorDuty::FulfillerDuty(FulfillerDuty::PublishClaim)),
                        todo!(),
                    ))
                } else {
                    Ok(NextStep::new(None, todo!()))
                }
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_claim_confirmation(
        &mut self,
        height: BitcoinBlockHeight,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        // TODO(proofofkeags): figure out why this had to be cloned.
        match self.state.clone() {
            ContractState::Fulfilled {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): Verify that the claim transaction fits the requirements for
                // a valid claim.
                self.state = ContractState::Claimed {
                    claim_height: height,
                    fulfiller,
                    fulfillment_tx,
                };

                if fulfiller != self.ctx.own_index() {
                    // Verify claim
                    Ok(NextStep::new(
                        Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyClaim)),
                        todo!(),
                    ))
                } else {
                    Ok(NextStep::new(todo!(), todo!()))
                }
            }
            _ => Err(TransitionErr),
        }
    }

    /// Tells the state machine that the claim was assessed to be fraudulent.
    pub fn process_claim_verification_failure(&mut self) -> Result<NextStep, TransitionErr> {
        match &self.state {
            ContractState::Claimed { .. } => Ok(NextStep::new(
                Some(OperatorDuty::VerifierDuty(VerifierDuty::PublishChallenge)),
                todo!(),
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
                fulfillment_tx,
                ..
            } => {
                // TODO(proofofkeags): verify that the transaction is the correct challenge
                // transaction.
                self.state = ContractState::Challenged {
                    fulfiller,
                    fulfillment_tx,
                };
                if fulfiller == self.ctx.own_index() {
                    Ok(NextStep::new(
                        Some(OperatorDuty::FulfillerDuty(
                            FulfillerDuty::PublishAssertChain,
                        )),
                        todo!(),
                    ))
                } else {
                    Ok(NextStep::new(None, todo!()))
                }
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
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): verify that the transaction is the correct post-assert
                // transaction.
                self.state = ContractState::Asserted {
                    post_assert_height,
                    fulfiller,
                    fulfillment_tx,
                };

                if fulfiller != self.ctx.own_index() {
                    Ok(NextStep::new(
                        Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyAssertion)),
                        todo!(),
                    ))
                } else {
                    Ok(NextStep::new(None, todo!()))
                }
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
            ContractState::Asserted {
                fulfiller,
                fulfillment_tx,
                ..
            } => {
                // TODO(proofofkeags): Verify that this is the correct disproof transaction.
                self.state = ContractState::Disproved {};

                Ok(NextStep::new(None, todo!()))
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_optimistic_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Claimed { .. } => {
                // TODO(proofofkeags): verify that this is the correct optimistic payout
                self.state = ContractState::Resolved {};

                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_defended_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<NextStep, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted { .. } => {
                // TODO(proofofkeags): verify that this is the correct defended payout
                self.state = ContractState::Resolved {};

                Ok(NextStep::new(None, todo!()))
            }
            _ => Err(TransitionErr),
        }
    }
}

/// Placeholder struct for the graph signature payload we get from our peers.
#[derive(Debug, Clone)]
pub struct GraphSignatures {}
