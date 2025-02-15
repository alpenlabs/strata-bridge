//! TODO(proofofkeags): docs for crate
#![feature(result_flattening)]
mod tx_driver;

use bitcoin::{taproot::Signature, Block, Transaction, Txid};
use strata_bridge_primitives::types::OperatorIdx;
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
pub enum ContractState {
    /// This state describes everything from the moment the deposit request confirms, to the moment
    /// the deposit confirms.
    Requested {
        /// This is the collection of signatures for the peg-out graph on a per-operator basis.
        graph_sigs: Vec<GraphSignatures>,

        /// This is the collection of signatures for the deposit transaction itself on a
        /// per-operator basis.
        root_sigs: Vec<Signature>,
    },

    /// This state describes everything from the moment the deposit confirms, to the moment the
    /// strata state commitment that assigns this deposit confirms.
    Deposited,

    /// This state describes everything from the moment the withdrawal is assigned, to the moment
    /// the fulfillment transaction confirms.
    Assigned { fulfiller: OperatorIdx },

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
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },

    /// This state describes the state after the disprove transaction confirms.
    Disproved {
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },

    /// This state describes the state after either the optimistic or defended payout transactions
    /// confirm.
    Resolved {
        fulfiller: OperatorIdx,
        fulfillment_tx: Transaction,
    },
}

#[derive(Debug)]
pub enum OperatorDuty {
    PublishGraphSignatures,
    PublishDepositSignature,
    PublishDeposit,
    FulfillerDuty(FulfillerDuty),
    VerifierDuty(VerifierDuty),
}

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

#[derive(Debug)]
pub struct TransitionErr;

#[derive(Debug)]
pub struct ContractSM {
    self_idx: OperatorIdx,
    operator_set: Vec<OperatorIdx>,
    deposit_txid: Txid,
    deposit_idx: u32,
    state: ContractState,
}

impl ContractSM {
    pub fn new(
        self_idx: OperatorIdx,
        operator_set: Vec<OperatorIdx>,
        deposit_txid: Txid,
        deposit_idx: u32,
    ) -> (Self, OperatorDuty) {
        let state = ContractState::Requested {
            graph_sigs: Vec::new(),
            root_sigs: Vec::new(),
        };
        (
            ContractSM {
                self_idx,
                operator_set,
                deposit_txid,
                deposit_idx,
                state,
            },
            OperatorDuty::PublishGraphSignatures,
        )
    }

    pub fn process_graph_signature_payload(
        &mut self,
        sig: GraphSignatures,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state {
            ContractState::Requested { graph_sigs, .. } => {
                graph_sigs.push(sig);
                if graph_sigs.len() == self.operator_set.len() {
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

    pub fn process_root_signature(
        &mut self,
        sig: Signature,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match &mut self.state {
            ContractState::Requested { root_sigs, .. } => {
                root_sigs.push(sig);
                if root_sigs.len() == self.operator_set.len() {
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

    fn process_deposit_confirmation(&mut self, tx: &Transaction) -> Result<(), TransitionErr> {
        if tx.compute_txid() != self.deposit_txid {
            return Err(TransitionErr);
        }

        self.state = ContractState::Deposited;

        Ok(())
    }

    pub fn process_new_block(&mut self, block: &Block) -> Result<Vec<OperatorDuty>, TransitionErr> {
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
        todo!()
    }

    fn process_assignment(
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
                self.state = ContractState::Assigned { fulfiller };
                if fulfiller == self.self_idx {
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
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state {
            ContractState::Assigned { fulfiller } => {
                // TODO(proofofkeags): validate that this is transaction meets the requirements for
                // a fulfillment transaction.
                self.state = ContractState::Fulfilled {
                    fulfiller,
                    fulfillment_tx: tx,
                };

                if fulfiller == self.self_idx {
                    Ok(Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishClaim,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_claim_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        // TODO(proofofkeags): figure out why this had to be cloned.
        match self.state.clone() {
            ContractState::Fulfilled {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): Verify that the claim transaction fits the requirements for
                // a valid claim.
                self.state = ContractState::Claimed {
                    fulfiller,
                    fulfillment_tx,
                };

                if fulfiller != self.self_idx {
                    // Verify claim
                    Ok(Some(OperatorDuty::VerifierDuty(VerifierDuty::VerifyClaim)))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    pub fn process_claim_verification_failure(&mut self) -> Result<OperatorDuty, TransitionErr> {
        match &self.state {
            ContractState::Claimed {
                fulfiller,
                fulfillment_tx,
            } => Ok(OperatorDuty::VerifierDuty(VerifierDuty::PublishChallenge)),
            _ => Err(TransitionErr),
        }
    }

    fn process_challenge_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Claimed {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): verify that the transaction is the correct challenge
                // transaction.
                self.state = ContractState::Challenged {
                    fulfiller,
                    fulfillment_tx,
                };
                if fulfiller == self.self_idx {
                    Ok(Some(OperatorDuty::FulfillerDuty(
                        FulfillerDuty::PublishAssertChain,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_assert_chain_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Challenged {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): verify that the transaction is the correct post-assert
                // transaction.
                self.state = ContractState::Asserted {
                    fulfiller,
                    fulfillment_tx,
                };

                if fulfiller != self.self_idx {
                    Ok(Some(OperatorDuty::VerifierDuty(
                        VerifierDuty::VerifyAssertion,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Err(TransitionErr),
        }
    }

    pub fn process_assertion_verification_failure(
        &mut self,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted {
                fulfiller,
                fulfillment_tx,
            } => Ok(Some(OperatorDuty::VerifierDuty(
                VerifierDuty::PublishDisprove,
            ))),
            _ => Err(TransitionErr),
        }
    }

    fn process_disprove_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): Verify that this is the correct disproof transaction.
                self.state = ContractState::Disproved {
                    fulfiller,
                    fulfillment_tx,
                };

                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_optimistic_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Claimed {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): verify that this is the correct optimistic payout
                self.state = ContractState::Resolved {
                    fulfiller,
                    fulfillment_tx,
                };

                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }

    fn process_defended_payout_confirmation(
        &mut self,
        tx: &Transaction,
    ) -> Result<Option<OperatorDuty>, TransitionErr> {
        match self.state.clone() {
            ContractState::Asserted {
                fulfiller,
                fulfillment_tx,
            } => {
                // TODO(proofofkeags): verify that this is the correct defended payout
                self.state = ContractState::Resolved {
                    fulfiller,
                    fulfillment_tx,
                };

                Ok(None)
            }
            _ => Err(TransitionErr),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GraphSignatures {
    operator_idx: OperatorIdx,
}
