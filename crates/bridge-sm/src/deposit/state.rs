//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::{Amount, Network, OutPoint, Transaction, Txid, hashes::Hash};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::schnorr::Signature, verify_partial};
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    operator_table::OperatorTable,
    scripts::prelude::{TaprootWitness, get_aggregated_pubkey},
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};
use strata_bridge_tx_graph2::{
    connectors::prelude::NOfNConnector,
    transactions::{
        PresignedTx,
        prelude::{CooperativePayoutData, CooperativePayoutTx},
    },
};

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
    },
    signals::{DepositSignal, DepositToGraph},
    state_machine::{SMOutput, StateMachine},
};

/// The number of blocks after the fulfillment confirmation after which the cooperative payout path
/// is considered to have failed.
// TODO: (@Rajil1213) Move this to a config
const COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS: u64 = 144; // Approx. 24 hours

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.
// This module will have a
// - `DepositSMCfg` which contains values that are static over the
//  lifetime of a single Deposit State Machine, and a
// - `DepositGlobalCfg` which contains values that are static over the lifetime of all Deposit State
//   Machines
//  (such as timelocks).

/// The static configuration for a Deposit State Machine.
///
/// These configurations are set at the creation of the Deposit State Machine and do not change
/// during any state transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositCfg {
    /// The index of the deposit being tracked in a Deposit State Machine.
    pub(super) deposit_idx: DepositIdx,
    /// The outpoint of the deposit being tracked in a Deposit State Machine.
    pub(super) deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    pub(super) operator_table: OperatorTable,
    /// The network (mainnet, testnet, regtest, etc.) for the deposit.
    pub(super) network: Network,
    /// The amount of the deposit.
    pub(super) deposit_amount: Amount,
}

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositState {
    /// TODO: (@MdTeach)
    Created {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@MdTeach)
    GraphGenerated {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@MdTeach)
    DepositNoncesCollected {
        /// Placeholder docstring as this will be added by @MdTeach
        block_height: u64,
        /// Placeholder docstring as this will be added by @MdTeach
        output_index: u32,
        /// Placeholder docstring as this will be added by @MdTeach
        deposit_request_outpoint: OutPoint,
        /// Placeholder docstring as this will be added by @MdTeach
        deposit_transaction: Transaction,
        /// Placeholder docstring as this will be added by @MdTeach
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,
        /// Placeholder docstring as this will be added by @MdTeach
        agg_nonce: AggNonce,
        /// Placeholder docstring as this will be added by @MdTeach
        partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// TODO: (@MdTeach)
    DepositPartialsCollected {
        /// Placeholder docstring as this will be added by @MdTeach
        block_height: u64,
        /// Placeholder docstring as this will be added by @MdTeach
        output_index: u32,
        /// Placeholder docstring as this will be added by @MdTeach
        deposit_request_outpoint: OutPoint,
        /// Placeholder docstring as this will be added by @MdTeach
        deposit_transaction: Transaction,
        /// Placeholder docstring as this will be added by @MdTeach
        aggregated_signature: Signature,
    },
    /// This state indicates that the deposit transaction has been confirmed on-chain.
    Deposited {
        /// The last block height observed by this state machine.
        block_height: u64,
    },
    /// This state indicates that a withdrawal has been assigned for this deposit.
    Assigned {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The block height by which the operator must fulfill the withdrawal.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// This state indicates that the operator has fronted the user.
    Fulfilled {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The txid of the fulfillment transaction in which the user was fronted.
        fulfillment_txid: Txid,
        /// The block height where the fulfillment transaction was confirmed.
        fulfillment_height: BitcoinBlockHeight,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
    },
    /// This state indicates that the descriptor of the operator for the cooperative payout has been
    /// received.
    PayoutDescriptorReceived {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The operator's descriptor where they want the funds in the cooperative path.
        /// This can only be set once and needs to be provided by the operator.
        operator_desc: Descriptor,
        /// The pubnonces, indexed by operator, required to sign the cooperative payout
        /// transaction.
        payout_nonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state indicates that all pubnonces required for the cooperative payout has been
    /// collected.
    PayoutNoncesCollected {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The operator's descriptor where they want the funds in the cooperative path.
        operator_desc: Descriptor,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The pubnonces, indexed by operator, required to sign the cooperative payout
        /// transaction.
        payout_nonces: BTreeMap<OperatorIdx, PubNonce>,
        /// The aggregated nonce for signing the cooperative payout transaction.
        payout_aggregated_nonce: AggNonce,
        /// The partial signatures, indexed by operator, for signing the cooperative payout
        /// transaction.
        payout_partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This State indicates that all the partial signatures have been collected for cooperative
    /// payout.
    PayoutPartialsCollected {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The txid of the the cooperative payout transaction.
        payout_txid: Txid,
        /// The aggregated signature for the cooperative payout transaction.
        payout_aggregated_signature: Signature,
    },
    /// This state represents the scenario where the cooperative payout path has failed,
    ///
    /// This happens if the assignee was not able to collect the requisite nonces/partials for
    /// the cooperative payout transaction.
    CooperativePathFailed {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// This represents the terminal state where the deposit has been spent.
    Spent,
    /// TODO: (@Rajil1213)
    Aborted,
}

impl Display for DepositState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            DepositState::Created { .. } => "Created",
            DepositState::GraphGenerated { .. } => "GraphGenerated",
            DepositState::DepositNoncesCollected { .. } => "DepositNoncesCollected",
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected",
            DepositState::Deposited { .. } => "Deposited",
            DepositState::Assigned { .. } => "Assigned",
            DepositState::Fulfilled { .. } => "Fulfilled",
            DepositState::PayoutDescriptorReceived { .. } => "PayoutDescriptorReceived",
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesCollected",
            DepositState::PayoutPartialsCollected { .. } => "PayoutPartialsCollected",
            DepositState::CooperativePathFailed { .. } => "CooperativePathFailed",
            DepositState::Spent => "Spent",
            DepositState::Aborted => "Aborted",
        };
        write!(f, "{}", state_str)
    }
}

impl Default for DepositState {
    fn default() -> Self {
        // TODO: (@MdTeach) Remove this impl once `new` starts taking arguments.
        DepositState::new()
    }
}

impl DepositState {
    /// Creates a new Deposit State in the `Created` state.
    pub fn new() -> Self {
        DepositState::Created {
            deposit_request_outpoint: OutPoint::default(),
            block_height: 0,
        }
    }

    /// Returns the height of the last processed Bitcoin block for this deposit state.
    pub const fn last_processed_block_height(&self) -> Option<&BitcoinBlockHeight> {
        match self {
            DepositState::Created { block_height, .. }
            | DepositState::GraphGenerated { block_height, .. }
            | DepositState::DepositNoncesCollected { block_height, .. }
            | DepositState::DepositPartialsCollected { block_height, .. }
            | DepositState::Deposited { block_height, .. }
            | DepositState::Assigned { block_height, .. }
            | DepositState::Fulfilled { block_height, .. }
            | DepositState::PayoutDescriptorReceived { block_height, .. }
            | DepositState::PayoutNoncesCollected { block_height, .. }
            | DepositState::PayoutPartialsCollected { block_height, .. }
            | DepositState::CooperativePathFailed { block_height, .. } => Some(block_height),
            DepositState::Spent | DepositState::Aborted => {
                // Terminal states do not track block height
                None
            }
        }
    }

    // TODO: (@Rajil1213, @MdTeach, @mukeshdroid) Add more introspection methods here
}

// TODO: (@Rajil1213) Move `DepositSM` to a separate `state-machine` module once complete (to avoid
// merge conflicts now).

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSM {
    /// The static configuration for this Deposit State Machine.
    pub(super) cfg: DepositCfg,
    /// The current state of the Deposit State Machine.
    pub(super) state: DepositState,
}

impl StateMachine for DepositSM {
    type Duty = DepositDuty;
    type OutgoingSignal = DepositSignal;
    type Event = DepositEvent;
    type Error = DSMError;

    fn process_event(
        &mut self,
        event: Self::Event,
    ) -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error> {
        let event_description: String = event.to_string();
        match event {
            DepositEvent::DepositRequest => self.process_deposit_request(),
            DepositEvent::UserTakeBack { tx } => self.process_drt_takeback(tx),
            DepositEvent::GraphMessage(_graph_msg) => self.process_graph_available(),
            DepositEvent::NonceReceived => self.process_nonce_received(),
            DepositEvent::PartialReceived => self.process_partial_received(),
            DepositEvent::DepositConfirmed {
                deposit_transaction,
            } => self.process_deposit_confirmed(event_description, deposit_transaction),
            DepositEvent::Assignment {
                assignee,
                deadline,
                recipient_desc,
            } => self.process_assignment(event_description, assignee, deadline, recipient_desc),
            DepositEvent::FulfillmentConfirmed {
                fulfillment_transaction,
                fulfillment_height,
            } => self.process_fulfillment(
                event_description,
                fulfillment_transaction,
                fulfillment_height,
                COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
            ),
            DepositEvent::PayoutDescriptorReceived { operator_desc } => {
                self.process_payout_descriptor_received(event_description, operator_desc)
            }
            DepositEvent::PayoutNonceReceived {
                payout_nonce,
                operator_idx,
            } => self.process_payout_nonce_received(event_description, payout_nonce, operator_idx),
            DepositEvent::PayoutPartialReceived {
                partial_signature,
                operator_idx,
            } => self.process_payout_partial_received(
                event_description,
                partial_signature,
                operator_idx,
            ),
            DepositEvent::PayoutConfirmed { tx } => self.process_payout_confirmed(&tx),
            DepositEvent::NewBlock { block_height } => self.process_new_block(block_height),
        }
    }
}

/// The output of the Deposit State Machine after processing an event.
///
/// This is a type alias for [`SMOutput`] specialized to the Deposit State Machine's
/// duty and signal types. This ensures that the Deposit SM can only emit [`DepositDuty`]
/// duties and [`DepositSignal`] signals.
pub type DSMOutput = SMOutput<DepositDuty, DepositSignal>;

impl DepositSM {
    /// Creates a new Deposit State Machine with the given configuration.
    pub fn new(cfg: DepositCfg) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(),
        }
    }

    /// Returns a reference to the configuration of the Deposit State Machine.
    pub const fn cfg(&self) -> &DepositCfg {
        &self.cfg
    }

    /// Returns a reference to the current state of the Deposit State Machine.
    pub const fn state(&self) -> &DepositState {
        &self.state
    }

    /// Returns a mutable reference to the current state of the Deposit State Machine.
    pub const fn state_mut(&mut self) -> &mut DepositState {
        &mut self.state
    }

    // **DESIGN PRINCIPLE**
    //
    // author: @ProofOfKeags
    //
    // All the state transition functions that handle state machine events have these semantics:
    //
    // If an event cannot be consumed by the SM it should give back an error. If it does get
    // consumed by the SM it should not have the same state prior. Not all errors need to be fatal
    // but semantically there's no difference between rejecting an event because it has the wrong
    // internal state or rejecting an event because the event doesn't apply to the machine. Either
    // way the error semantics should be about whether or not the event was accepted or rejected.
    // We can annotate it with different reasons still if we use errors.

    // NOTE: all of the following functions are placeholders for the actual state transition logic.
    // they each receive the appropriate data required for the state transitions.

    fn process_deposit_request(&self) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        todo!("@MdTeach")
    }

    /// Processes the event where the user takes back the deposit request output.
    ///
    /// This can happen if any of the operators are not operational for the entire duration of the
    /// take back period.
    fn process_drt_takeback(
        &mut self,
        tx: Transaction,
    ) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        match self.state() {
            DepositState::Created {
                deposit_request_outpoint,
                ..
            }
            | DepositState::GraphGenerated {
                deposit_request_outpoint,
                ..
            }
            | DepositState::DepositNoncesCollected {
                deposit_request_outpoint,
                ..
            }
            | DepositState::DepositPartialsCollected {
                deposit_request_outpoint,
                ..
            } => {
                // FIXME: (@Rajil1213) Check if `txid` is not that of a Deposit Transaction instead
                if tx
                    .input
                    .iter()
                    .find(|input| input.previous_output == *deposit_request_outpoint)
                    .is_some_and(|input| input.witness.len() > 1)
                // HACK: (@Rajil1213) `N/N` spend is a keypath spend that only has a single witness
                // element (the `N/N` signature). If it has more than one element, it implies that
                // it is not a keypath spend (since there can only be 1 keypath spend for a taproot
                // output). This implies that if there are more than 1 witness elements, it is not a
                // Deposit Transaction and so must be a takeback (the script-spend path in the DRT
                // output).
                {
                    // Transition to Aborted state
                    self.state = DepositState::Aborted;

                    // This is a terminal state
                    Ok(SMOutput {
                        duties: vec![],
                        signals: vec![],
                    })
                } else {
                    Err(DSMError::Rejected {
                        state: self.state().clone().into(),
                        reason: format!(
                            "Transaction {} is not a take back transaction for the deposit request outpoint {}",
                            tx.compute_txid(),
                            deposit_request_outpoint
                        ),
                        event: DepositEvent::UserTakeBack { tx }.into(),
                    })
                }
            }
            DepositState::Aborted => Err(DSMError::Duplicate {
                state: self.state().clone().into(),
                event: DepositEvent::UserTakeBack { tx }.into(),
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::UserTakeBack { tx }.to_string(),
                state: self.state.to_string(),
                reason: None,
            }),
        }
    }

    fn process_graph_available(&mut self) -> DSMResult<DSMOutput> {
        todo!("@MdTeach")
    }

    fn process_nonce_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@MdTeach")
    }

    fn process_partial_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@MdTeach")
    }

    fn process_deposit_confirmed(
        &mut self,
        event_description: String,
        confirmed_deposit_transaction: Transaction,
    ) -> DSMResult<DSMOutput> {
        match self.state_mut() {
            DepositState::DepositPartialsCollected {
                block_height,
                deposit_transaction,
                ..
            }
             // This can happen if one of the operators withholds their own partial signature
             // while aggregating it with the rest of the collected partials and broadcasts it unilaterally
            | DepositState::DepositNoncesCollected {
                block_height,
                deposit_transaction,
                ..
            } => {
                let block_height = *block_height;
                let deposit_transaction = deposit_transaction.clone();
                // Ensure that the deposit transaction confirmed on-chain is the one we were
                // expecting.
                if confirmed_deposit_transaction.compute_txid() != deposit_transaction.compute_txid(){
                    return Err(DSMError::Rejected {
                        state: self.state().clone().into(),
                        event: DepositEvent::DepositConfirmed { deposit_transaction }.into(),
                        reason: "Transaction confirmed on chain does not match expected deposit transaction".to_string()
                    });
                }
                // Transition to the Deposited State
                self.state = DepositState::Deposited {
                    block_height,
                };
                // No duties or signals required
                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }

    fn process_assignment(
        &mut self,
        event_description: String,
        assignee: OperatorIdx,
        deadline: BitcoinBlockHeight,
        recipient_desc: Descriptor,
    ) -> DSMResult<DSMOutput> {
        match self.state_mut() {
            DepositState::Deposited { block_height } => {
                // Transition to the Assigned State
                self.state = DepositState::Assigned {
                    block_height: *block_height,
                    assignee,
                    deadline,
                    recipient_desc: recipient_desc.clone(),
                };
                // Dispatch the duty to fulfill the assignment if the assignee is the pov operator,
                // otherwise no duties or signals need to be dispatched.
                if self.cfg.operator_table.pov_idx() == assignee {
                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::FulfillWithdrawal {
                            deposit_idx: self.cfg.deposit_idx,
                            deadline,
                            recipient_desc,
                        },
                    ]))
                } else {
                    Ok(DSMOutput::new())
                }
            }

            // Update the state with the details from new assignment event.
            DepositState::Assigned { block_height, .. } => {
                self.state = DepositState::Assigned {
                    block_height: *block_height,
                    assignee,
                    deadline,
                    recipient_desc: recipient_desc.clone(),
                };
                // Dispatch the duty to fulfill the assignment if the assignee is the pov operator,
                // otherwise no duties or signals need to be dispatched.
                if self.cfg.operator_table.pov_idx() == assignee {
                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::FulfillWithdrawal {
                            deposit_idx: self.cfg.deposit_idx,
                            deadline,
                            recipient_desc,
                        },
                    ]))
                } else {
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }

    fn process_fulfillment(
        &mut self,
        event_description: String,
        fulfillment_transaction: Transaction,
        fulfillment_height: BitcoinBlockHeight,
        cooperative_payout_timelock: u64,
    ) -> DSMResult<DSMOutput> {
        match self.state_mut() {
            DepositState::Assigned {
                block_height,
                assignee,
                ..
            } => {
                let block_height = *block_height;
                let assignee = *assignee;

                // Compute the txid of the fulfillemnt Transaction
                let fulfillment_txid: Txid = fulfillment_transaction.compute_txid();

                // Compute the cooperative payout deadline.
                let cooperative_payment_deadline = fulfillment_height + cooperative_payout_timelock;

                // Transition to the Fulfilled State
                self.state = DepositState::Fulfilled {
                    block_height,
                    assignee,
                    fulfillment_txid,
                    fulfillment_height,
                    cooperative_payment_deadline,
                };
                // Dispatch the duty to request the payout nonces if the assignee is the pov
                // operator, otherwise no duties or signals need to be dispatched.
                if self.cfg.operator_table.pov_idx() == assignee {
                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::RequestPayoutNonces {
                            deposit_idx: self.cfg.deposit_idx,
                        },
                    ]))
                } else {
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }

    fn process_payout_descriptor_received(
        &mut self,
        event_description: String,
        operator_desc: Descriptor,
    ) -> DSMResult<DSMOutput> {
        match self.state_mut() {
            DepositState::Fulfilled {
                block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            } => {
                let block_height = *block_height;
                let assignee = *assignee;
                let cooperative_payment_deadline = *cooperative_payment_deadline;

                // Transition to the PayoutDescriptorReceived State
                self.state = DepositState::PayoutDescriptorReceived {
                    block_height,
                    assignee,
                    cooperative_payment_deadline,
                    operator_desc: operator_desc.clone(),
                    payout_nonces: BTreeMap::new(),
                };
                // Dispatch the duty to publish the payout nonce
                Ok(DSMOutput::with_duties(vec![
                    DepositDuty::PublishPayoutNonce {
                        deposit_outpoint: self.cfg.deposit_outpoint,
                        operator_idx: assignee,
                        operator_desc,
                    },
                ]))
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }

    fn process_payout_nonce_received(
        &mut self,
        event_description: String,
        payout_nonce: PubNonce,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        match self.state_mut() {
            DepositState::PayoutDescriptorReceived {
                block_height,
                assignee,
                cooperative_payment_deadline,
                operator_desc,
                payout_nonces,
            } => {
                let block_height = *block_height;
                let assignee = *assignee;
                let cooperative_payment_deadline = *cooperative_payment_deadline;
                let operator_desc = operator_desc.clone();
                let payout_nonces = payout_nonces.clone();

                // Check for duplicate nonce submission. If an entry from the same operator exists,
                // return with an error.
                if payout_nonces.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: self.state().clone().into(),
                        event: DepositEvent::PayoutNonceReceived {
                            payout_nonce,
                            operator_idx,
                        }
                        .into(),
                    });
                }
                // Update the payout nonces with the new nonce just received.
                let mut updated_nonces = payout_nonces.clone();
                updated_nonces.insert(operator_idx, payout_nonce);

                // Transition to the PayoutNoncesCollected State if *all* the nonces have been
                // received and dispatch duty to request for the cooperative payout partials.
                if self.cfg.operator_table.cardinality() == updated_nonces.len() {
                    // Compute the aggregated nonce from the collected nonces.
                    let agg_nonce = AggNonce::sum(updated_nonces.values().cloned());

                    // Transition to the PayoutNoncesCollected State.
                    self.state = DepositState::PayoutNoncesCollected {
                        block_height,
                        assignee,
                        operator_desc,
                        cooperative_payment_deadline,
                        payout_nonces: updated_nonces,
                        payout_aggregated_nonce: agg_nonce.clone(),
                        payout_partial_signatures: BTreeMap::new(),
                    };
                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::PublishPayoutPartial {
                            deposit_outpoint: self.cfg.deposit_outpoint,
                            deposit_idx: self.cfg.deposit_idx,
                            agg_nonce,
                        },
                    ]))
                }
                // If all nonces are not yet collected, update the payout nonces with received
                // nonce and stay in the PayoutDescriptorReceived State and dispatch no duties or
                // signals.
                else {
                    // Stay in the PayoutDescriptorReceived State but with updated nonce map.
                    self.state = DepositState::PayoutDescriptorReceived {
                        block_height,
                        assignee,
                        cooperative_payment_deadline,
                        operator_desc,
                        payout_nonces: updated_nonces,
                    };
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }

    fn process_payout_partial_received(
        &mut self,
        event_description: String,
        partial_signature: PartialSignature,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        match self.state_mut() {
            DepositState::PayoutNoncesCollected {
                block_height,
                assignee,
                cooperative_payment_deadline,
                operator_desc,
                payout_nonces,
                payout_aggregated_nonce,
                payout_partial_signatures,
            } => {
                let block_height = *block_height;
                let assignee = *assignee;
                let cooperative_payment_deadline = *cooperative_payment_deadline;
                let operator_desc = operator_desc.clone();
                let payout_nonces = payout_nonces.clone();
                let payout_aggregated_nonce = payout_aggregated_nonce.clone();
                let payout_partial_signatures = payout_partial_signatures.clone();

                // Check for duplicate Partial Signature submission. If an entry from the same
                // operator exists, return with an error.
                if payout_partial_signatures.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: self.state().clone().into(),
                        event: DepositEvent::PayoutPartialReceived {
                            partial_signature,
                            operator_idx,
                        }
                        .into(),
                    });
                }

                // Construct the N-of-N aggregated pubkey from the operator table
                let n_of_n_pubkey = get_aggregated_pubkey(self.cfg.operator_table.btc_keys());

                // Construct the deposit connector for the cooperative payout transaction
                let deposit_connector =
                    NOfNConnector::new(self.cfg.network, n_of_n_pubkey, self.cfg.deposit_amount);

                // Construct the cooperative payout transaction
                let coop_payout_data = CooperativePayoutData {
                    deposit_outpoint: self.cfg.deposit_outpoint,
                };
                let coop_payout_tx = CooperativePayoutTx::new(
                    coop_payout_data,
                    deposit_connector,
                    operator_desc.clone(),
                );

                // Get the sighash for signature verification
                let signing_info = coop_payout_tx.signing_info();
                let message = signing_info[0].sighash;

                // Generate the key_agg_ctx using the operator table.
                // NOfNConnector uses key-path spend with no script tree, so we use
                // TaprootWitness::Key which applies with_unspendable_taproot_tweak()
                let key_agg_ctx =
                    create_agg_ctx(self.cfg.operator_table.btc_keys(), &TaprootWitness::Key)
                        .expect("must be able to create key aggregation context");

                // Get the operator's public key and pubnonce for verification.
                let operator_pubkey = self
                    .cfg
                    .operator_table
                    .idx_to_btc_key(&operator_idx)
                    .expect("operator must be in table");
                let operator_pubnonce = payout_nonces
                    .get(&operator_idx)
                    .expect("operator must have submitted nonce");

                // Verify the partial signature.
                if verify_partial(
                    &key_agg_ctx,
                    partial_signature,
                    &payout_aggregated_nonce,
                    operator_pubkey,
                    operator_pubnonce,
                    message.as_ref(),
                )
                .is_err()
                {
                    return Err(DSMError::Rejected {
                        state: self.state().clone().into(),
                        reason: "Partial Signature Verification Failed".to_string(),
                        event: DepositEvent::PayoutPartialReceived {
                            partial_signature,
                            operator_idx,
                        }
                        .into(),
                    });
                }

                // Update the partial signatures map with the new partial signature just received.
                let mut updated_payout_partials = payout_partial_signatures.clone();
                updated_payout_partials.insert(operator_idx, partial_signature);

                // Transition to the PayoutPartialsCollected State if *all* the partial signatures
                // for the coooperative payout have been received.
                if self.cfg.operator_table.cardinality() == updated_payout_partials.len() {
                    // Transition to the PayoutPartialsCollected State with dummy payout_txid and
                    // dummy payout aggregate signature.
                    self.state = DepositState::PayoutPartialsCollected {
                        block_height,
                        payout_txid: Txid::all_zeros(),
                        payout_aggregated_signature: Signature::from_slice(&[0u8; 64])
                            .expect("Unable to create dummy signature."),
                    };

                    // Dispatch the duty to publish the Cooperative payout transaction.
                    Ok(DSMOutput::with_duties(vec![DepositDuty::PublishPayout {
                        payout_tx: coop_payout_tx.as_ref().clone(),
                    }]))
                }
                // If all partial signatures are not yet collected, update the payout partial
                // signatures map with received nonce and stay in the PayoutNoncesCollected State.
                else {
                    // Stay in the PayoutNoncesCollected State but with updated nonce map.
                    self.state = DepositState::PayoutNoncesCollected {
                        block_height,
                        assignee,
                        operator_desc,
                        cooperative_payment_deadline,
                        payout_nonces,
                        payout_aggregated_nonce,
                        payout_partial_signatures: updated_payout_partials,
                    };
                    // No duties or signals need to be dispatched until all partials are collected.
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }

    /// Processes the confirmation of a transaction that spends the deposit outpoint being tracked
    /// by this state machine.
    ///
    /// This outpoint can be spent via the following transactions:
    ///
    /// - A cooperative payout transaction, if the cooperative path was successful.
    /// - An uncontested payout transaction, if the assignee published a claim that went
    ///   uncontested.
    /// - A contested payout transaction, if the assignee published a claim that was contested but
    ///   not successfully.
    /// - A sweep transaction in the event of a hard upgrade (migration) of deposited UTXOs
    fn process_payout_confirmed(&mut self, tx: &Transaction) -> DSMResult<DSMOutput> {
        match self.state() {
            // It must be the sweep transaction in case of a hard upgrade
            DepositState::Deposited { .. }
            // It must be the cooperative payout transaction
            | DepositState::PayoutPartialsCollected { .. }
            // It must be a cooperative payout transaction.
            // The assignee can withhold their own partial and broadcast the payout tx themselves,
            // In this case, we still want other nodes' state machines to transition from
            // `PayoutNoncesCollected` to `Spent`. This can also happen if there are network delays.
            | DepositState::PayoutNoncesCollected { .. }
            // It can be a contested/uncontested payout transaction
            // It can also be a cooperative payout transaction due to delayed settlement of the
            // transaction on-chain or because each operator has a different configuration for how
            // long to wait till the cooperative payout path is considered failed.
            | DepositState::CooperativePathFailed { .. } => {
                tx
                .input
                .iter()
                .any(|input| input.previous_output == self.cfg().deposit_outpoint)
                .ok_or(DSMError::InvalidEvent {
                    state: self.state().to_string(),
                    event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.to_string(),
                    reason: format!(
                        "Transaction {} does not spend from the expected deposit outpoint {}",
                        tx.compute_txid(),
                        self.cfg().deposit_outpoint
                        ).into(),
                })?;

                // Transition to Spent state
                self.state = DepositState::Spent;

                // This is a terminal state
                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }
            DepositState::Spent => Err(DSMError::Duplicate {
                state: self.state().clone().into(),
                event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.into()
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.to_string(),
                state: self.state.to_string(),
                reason: None
            }),
        }
    }

    fn process_new_block(&mut self, new_block_height: BitcoinBlockHeight) -> DSMResult<DSMOutput> {
        let last_processed_block_height = self.state().last_processed_block_height();
        if last_processed_block_height.is_some_and(|height| *height >= new_block_height) {
            return Err(DSMError::Duplicate {
                state: self.state().clone().into(),
                event: DepositEvent::NewBlock {
                    block_height: new_block_height,
                }
                .into(),
            });
        }

        match self.state_mut() {
            DepositState::Created { block_height, .. }
            | DepositState::GraphGenerated { block_height, .. }
            | DepositState::DepositNoncesCollected { block_height, .. }
            | DepositState::DepositPartialsCollected { block_height, .. }
            | DepositState::Deposited { block_height, .. }
            | DepositState::Assigned { block_height, .. }
            | DepositState::PayoutPartialsCollected { block_height, .. }
            | DepositState::CooperativePathFailed { block_height, .. } => {
                *block_height = new_block_height;

                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }

            DepositState::Fulfilled {
                block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            }
            | DepositState::PayoutDescriptorReceived {
                block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            }
            | DepositState::PayoutNoncesCollected {
                block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            } => {
                let assignee = *assignee; // reassign to get past the borrow-checker

                // Check for `>=` instead of just `>` to allow disabling cooperative payout by
                // setting this param to zero. This will come into effect after a 1-block delay
                // (when the next block is observed).
                let has_cooperative_payout_timed_out =
                    new_block_height >= *cooperative_payment_deadline;

                if has_cooperative_payout_timed_out {
                    // Transition to CooperativePathFailed state
                    self.state = DepositState::CooperativePathFailed {
                        block_height: new_block_height,
                    };

                    // activate the graph if the cooperative payout path has failed
                    return Ok(SMOutput {
                        duties: vec![],
                        signals: vec![DepositSignal::ToGraph(
                            DepositToGraph::CooperativePayoutFailed {
                                assignee,
                                deposit_idx: self.cfg().deposit_idx,
                            },
                        )],
                    });
                }

                *block_height = new_block_height;

                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }

            DepositState::Spent | DepositState::Aborted => Err(DSMError::Rejected {
                state: self.state().clone().into(),
                reason: "New blocks irrelevant in terminal state".to_string(),
                event: DepositEvent::NewBlock {
                    block_height: new_block_height,
                }
                .into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{collections::BTreeMap, str::FromStr};

    use bitcoin_bosd::Descriptor;
    use proptest::prelude::*;
    use strata_bridge_test_utils::{
        bitcoin::{generate_signature, generate_spending_tx, generate_xonly_pubkey},
        musig2::generate_agg_nonce,
    };

    use super::*;
    use crate::{
        deposit::testing::*,
        prop_deterministic, prop_no_silent_acceptance, prop_terminal_states_reject,
        testing::{fixtures::*, transition::*},
    };

    // ===== Unit Tests for process_drt_takeback =====

    #[test]
    fn test_drt_takeback_from_created() {
        let outpoint = OutPoint::default();
        let state = DepositState::Created {
            deposit_request_outpoint: outpoint,
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        let tx = test_takeback_tx(outpoint);

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::UserTakeBack { tx },
                expected_state: DepositState::Aborted,
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn test_drt_takeback_from_graph_generated() {
        let outpoint = OutPoint::default();
        let state = DepositState::GraphGenerated {
            deposit_request_outpoint: outpoint,
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        let tx = test_takeback_tx(outpoint);

        let mut sm = create_sm(state);
        let result = sm.process_drt_takeback(tx);

        assert!(result.is_ok());
        assert_eq!(sm.state(), &DepositState::Aborted);
    }

    #[test]
    fn test_drt_takeback_invalid_from_deposited() {
        let state = DepositState::Deposited {
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        let tx = test_takeback_tx(OutPoint::default());

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: state,
                event: DepositEvent::UserTakeBack { tx },
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            },
        );
    }

    #[test]
    fn test_drt_takeback_duplicate_in_aborted() {
        let state = DepositState::Aborted;

        let tx = test_takeback_tx(OutPoint::default());

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: state,
                event: DepositEvent::UserTakeBack { tx },
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            },
        );
    }

    #[test]
    fn test_wrong_drt_takeback_tx_rejection() {
        let drt_outpoint = OutPoint::default();
        let initial_state = DepositState::Created {
            deposit_request_outpoint: drt_outpoint,
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        let sm = create_sm(initial_state.clone());
        let mut sequence = EventSequence::new(sm, get_state);

        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();
        let wrong_tx = test_takeback_tx(wrong_outpoint);
        let wrong_tx_event = DepositEvent::UserTakeBack { tx: wrong_tx };

        sequence.process(wrong_tx_event);

        // Create a transaction that spends the outpoint but is not a valid take back transaction
        let witness_elements = [vec![0u8; 1]]; // HACK: single witness element implies key-spend
        let wrong_spend_path = generate_spending_tx(drt_outpoint, &witness_elements[..]);
        let wrong_spend_path_event = DepositEvent::UserTakeBack {
            tx: wrong_spend_path,
        };

        sequence.process(wrong_spend_path_event);

        sequence.assert_final_state(&initial_state);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            2,
            "Expected 2 errors for 2 events, got {}",
            errors.len()
        );
        errors.iter().for_each(|err| {
            assert!(
                matches!(err, DSMError::Rejected { .. }),
                "Expected Rejected error, got {:?}",
                err
            );
        });
    }

    // ===== Unit Tests for process_new_block =====

    #[test]
    fn test_new_block_updates_height_in_deposited() {
        let state = DepositState::Deposited {
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        let block_height = LATER_BLOCK_HEIGHT;

        let mut sm = create_sm(state);
        let result = sm.process_new_block(block_height);

        assert!(result.is_ok());
        assert_eq!(
            sm.state(),
            &DepositState::Deposited {
                block_height: LATER_BLOCK_HEIGHT
            }
        );
    }

    #[test]
    fn test_new_block_triggers_cooperative_timeout() {
        const FULFILLMENT_HEIGHT: u64 = INITIAL_BLOCK_HEIGHT;
        let state = DepositState::Fulfilled {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: Txid::all_zeros(),
            fulfillment_height: FULFILLMENT_HEIGHT,
            cooperative_payment_deadline: FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
        };

        let block_height = FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS;

        let mut sm = create_sm(state);
        let result = sm.process_new_block(block_height);

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::CooperativePathFailed { block_height }
        );

        // Check signal was emitted
        let output = result.unwrap();
        assert_eq!(output.signals.len(), 1);
        assert!(matches!(
            output.signals[0],
            DepositSignal::ToGraph(DepositToGraph::CooperativePayoutFailed { .. })
        ));
    }

    #[test]
    fn test_new_block_rejects_in_terminal_states() {
        let block_height = LATER_BLOCK_HEIGHT;

        for terminal_state in [DepositState::Spent, DepositState::Aborted] {
            let mut sm = create_sm(terminal_state.clone());
            let result = sm.process_new_block(block_height);

            assert!(
                matches!(result, Err(DSMError::Rejected { .. })),
                "Terminal state {:?} should reject new block with Rejected error (event is not relevant in terminal state)",
                terminal_state
            );
        }
    }

    #[test]
    fn test_payout_confirmed_duplicate_in_spent() {
        let tx = test_payout_tx(OutPoint::default());

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: DepositState::Spent,
                event: DepositEvent::PayoutConfirmed { tx },
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            },
        );
    }

    // ===== Unit Tests for process_deposit_confirmed =====

    #[test]
    // tests correct transition from the DepositPartialsCollected to DepositConfirmed state when
    // the DepositConfirmed event is received.
    fn test_deposit_confirmed_from_partials_collected() {
        let outpoint = OutPoint::default();
        let deposit_tx = generate_spending_tx(outpoint, &[]);

        let state = DepositState::DepositPartialsCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            output_index: 0,
            deposit_request_outpoint: outpoint,
            deposit_transaction: deposit_tx.clone(),
            aggregated_signature: generate_signature(),
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::DepositConfirmed {
                    deposit_transaction: deposit_tx,
                },
                expected_state: DepositState::Deposited {
                    block_height: INITIAL_BLOCK_HEIGHT,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    // tests correct transition from DepositNoncesCollected state to the DepositConfirmed state when
    // the DepositConfirmed event is received.
    fn test_deposit_confirmed_from_nonces_collected() {
        let outpoint = OutPoint::default();
        let deposit_tx = generate_spending_tx(outpoint, &[]);

        let state = DepositState::DepositNoncesCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            output_index: 0,
            deposit_request_outpoint: outpoint,
            deposit_transaction: deposit_tx.clone(),
            pubnonces: BTreeMap::new(),
            agg_nonce: generate_agg_nonce(),
            partial_signatures: BTreeMap::new(),
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::DepositConfirmed {
                    deposit_transaction: deposit_tx,
                },
                expected_state: DepositState::Deposited {
                    block_height: INITIAL_BLOCK_HEIGHT,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    // tests that all from states apart from the DepositNoncesCollected and DepositPartialsCollected
    // should NOT accept the DepositConfirmed event
    fn test_deposit_confirmed_invalid_from_other_states() {
        let outpoint = OutPoint::default();
        let tx = generate_spending_tx(outpoint, &[]);
        let desc = Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
            .expect("Failed to generate descriptor");

        let invalid_states = [
            DepositState::Created {
                deposit_request_outpoint: outpoint,
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::GraphGenerated {
                deposit_request_outpoint: outpoint,
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Deposited {
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::Fulfilled {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::PayoutPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                payout_txid: Txid::all_zeros(),
                payout_aggregated_signature: generate_signature(),
            },
            DepositState::CooperativePathFailed {
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Spent,
            DepositState::Aborted,
        ];

        for state in invalid_states {
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                InvalidTransition {
                    from_state: state,
                    event: DepositEvent::DepositConfirmed {
                        deposit_transaction: tx.clone(),
                    },
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }

    #[test]
    // tests that an DepositConfirmed event with a deposit tx that doesn't spend the DRT outpoint
    // is rejected from the DepositPartialsCollected state.
    fn test_deposit_confirmed_wrong_tx_rejection_from_deposit_partials_collected() {
        let outpoint = OutPoint::default();
        let expected_deposit_tx = generate_spending_tx(outpoint, &[]);

        // Create a different transaction (different outpoint)
        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();
        let wrong_tx = generate_spending_tx(wrong_outpoint, &[]);

        let state = DepositState::DepositPartialsCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            output_index: 0,
            deposit_request_outpoint: outpoint,
            deposit_transaction: expected_deposit_tx,
            aggregated_signature: generate_signature(),
        };

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: state,
                event: DepositEvent::DepositConfirmed {
                    deposit_transaction: wrong_tx,
                },
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            },
        );
    }

    #[test]
    // tests that an DepositConfirmed event with a deposit tx that doesn't spend the DRT outpoint
    // is rejected from the DepositNoncesCollected state.
    fn test_deposit_confirmed_wrong_tx_rejection_from_deposit_nonces_collected() {
        let outpoint = OutPoint::default();
        let expected_deposit_tx = generate_spending_tx(outpoint, &[]);

        // Create a different transaction (different outpoint)
        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();
        let wrong_tx = generate_spending_tx(wrong_outpoint, &[]);

        let state = DepositState::DepositNoncesCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            output_index: 0,
            deposit_request_outpoint: outpoint,
            deposit_transaction: expected_deposit_tx,
            pubnonces: BTreeMap::new(),
            agg_nonce: generate_agg_nonce(),
            partial_signatures: BTreeMap::new(),
        };

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: state,
                event: DepositEvent::DepositConfirmed {
                    deposit_transaction: wrong_tx,
                },
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            },
        );
    }

    // ===== Unit Tests for process_fulfillment =====

    #[test]
    // tests correct transition from Assigned to Fulfilled state when FulfillmentConfirmed event
    // is received and POV operator is the assignee (should emit RequestPayoutNonces duty)
    fn test_fulfillment_confirmed_from_assigned_pov_is_assignee() {
        let fulfillment_tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
            .expect("Failed to generate descriptor");

        let state = DepositState::Assigned {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE, // POV operator is 0, assignee is also 0
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: desc,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::FulfillmentConfirmed {
                    fulfillment_transaction: fulfillment_tx.clone(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                },
                expected_state: DepositState::Fulfilled {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: fulfillment_tx.compute_txid(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT
                        + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
                },
                expected_duties: vec![DepositDuty::RequestPayoutNonces { deposit_idx: 0 }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    // tests correct transition from Assigned to Fulfilled state when FulfillmentConfirmed event
    // is received and POV operator is NOT the assignee (should NOT emit any duty)
    fn test_fulfillment_confirmed_from_assigned_pov_is_not_assignee() {
        let fulfillment_tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
            .expect("Failed to generate descriptor");

        const OTHER_OPERATOR: OperatorIdx = 1; // Different from POV operator (0)

        let state = DepositState::Assigned {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: OTHER_OPERATOR, // POV operator is 0, assignee is 1
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: desc,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::FulfillmentConfirmed {
                    fulfillment_transaction: fulfillment_tx.clone(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                },
                expected_state: DepositState::Fulfilled {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: OTHER_OPERATOR,
                    fulfillment_txid: fulfillment_tx.compute_txid(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT
                        + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
                },
                expected_duties: vec![], // No duty since POV is not the assignee
                expected_signals: vec![],
            },
        );
    }

    #[test]
    // tests that all states apart from Assigned should NOT accept the FulfillmentConfirmed event
    fn test_fulfillment_confirmed_invalid_from_other_states() {
        let outpoint = OutPoint::default();
        let tx = generate_spending_tx(outpoint, &[]);
        let desc = Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
            .expect("Failed to generate descriptor");

        let invalid_states = [
            DepositState::Created {
                deposit_request_outpoint: outpoint,
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::GraphGenerated {
                deposit_request_outpoint: outpoint,
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::DepositNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                output_index: 0,
                deposit_request_outpoint: outpoint,
                deposit_transaction: tx.clone(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                output_index: 0,
                deposit_request_outpoint: outpoint,
                deposit_transaction: tx.clone(),
                aggregated_signature: generate_signature(),
            },
            DepositState::Deposited {
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Fulfilled {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::PayoutPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                payout_txid: Txid::all_zeros(),
                payout_aggregated_signature: generate_signature(),
            },
            DepositState::CooperativePathFailed {
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Spent,
            DepositState::Aborted,
        ];

        for state in invalid_states {
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                InvalidTransition {
                    from_state: state,
                    event: DepositEvent::FulfillmentConfirmed {
                        fulfillment_transaction: tx.clone(),
                        fulfillment_height: LATER_BLOCK_HEIGHT,
                    },
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }

    // ===== Property-Based Tests =====

    // Property: State machine is deterministic for the implemented states and events space
    prop_deterministic!(
        DepositSM,
        create_sm,
        get_state,
        any::<DepositState>(),
        arb_handled_events() /* TODO: (@Rajil1213) replace with any::<DepositEvent>() once all
                              * STFs are implemented */
    );

    // Property: No silent acceptance
    prop_no_silent_acceptance!(
        DepositSM,
        create_sm,
        get_state,
        any::<DepositState>(),
        arb_handled_events() /* TODO: (@Rajil1213) replace with any::<DepositEvent>() once all
                              * STFs are implemented */
    );

    // Property: Terminal states reject all events
    prop_terminal_states_reject!(
        DepositSM,
        create_sm,
        arb_terminal_state(),
        arb_handled_events() /* TODO: (@Rajil1213) replace with any::<DepositEvent>() once all
                              * STFs are implemented */
    );

    // ===== Integration Tests (sequence of events) =====

    #[test]
    fn test_cooperative_timeout_sequence() {
        const FULFILLMENT_HEIGHT: u64 = INITIAL_BLOCK_HEIGHT;
        let initial_state = DepositState::Fulfilled {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: Txid::all_zeros(),
            fulfillment_height: FULFILLMENT_HEIGHT,
            cooperative_payment_deadline: FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        // Process blocks up to and past timeout
        let timeout_height = FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS;
        for height in (FULFILLMENT_HEIGHT + 1)..=timeout_height {
            seq.process(DepositEvent::NewBlock {
                block_height: height,
            });
        }

        seq.assert_no_errors();

        // Should transition to CooperativePathFailed at timeout_height
        assert_eq!(
            seq.state(),
            &DepositState::CooperativePathFailed {
                block_height: timeout_height
            }
        );

        // Check that cooperative failure signal was emitted
        let signals = seq.all_signals();
        assert!(
            signals.iter().any(|s| matches!(
                s,
                DepositSignal::ToGraph(DepositToGraph::CooperativePayoutFailed { .. })
            )),
            "Should emit CooperativePayoutFailed signal"
        );
    }
}
