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
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The time lock duration (in blocks) for completing the cooperative payout.
/// TODO:@mukeshdroid This will be later sourced from a config file.
const COOPERATIVE_PAYOUT_TIMELOCK: u64 = 1008;

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.

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
    Created,
    /// TODO: (@MdTeach)
    GraphGenerated,
    /// TODO: (@MdTeach)
    DepositNoncesCollected,
    /// TODO: (@MdTeach)
    DepositPartialsCollected {
        /// Placeholder docstring as this will be added by @MdTeach
        block_height: u32,
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
        block_height: u32,
    },
    /// This state indicates that a withdrawal has been assigned for this deposit.
    Assigned {
        /// The last block height observed by this state machine.
        block_height: u32,
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
        block_height: u32,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The txid of the fulfillment transaction in which the user was fronted.
        fulfillment_txid: Txid,
        /// The block height where the fulfillment transaction was confirmed.
        fulfillment_block_height: BitcoinBlockHeight,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
    },
    /// This state indicates that the descriptor of the operator for the cooperative payout has been
    /// received.
    PayoutDescriptorReceived {
        /// The last block height observed by this state machine.
        block_height: u32,
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
        block_height: u32,
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
        block_height: u32,
        /// The txid of the the cooperative payout transaction.
        payout_txid: Txid,
        /// The aggregated signature for the cooperative payout transaction.
        payout_aggregated_signature: Signature,
    },
    /// TODO: (@Rajil1213)
    CooperativePathFailed,
    /// TODO: (@Rajil1213)
    Spent,
    /// TODO: (@Rajil1213)
    Aborted,
}

impl Display for DepositState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            DepositState::Created => "Created",
            DepositState::GraphGenerated => "GraphGenerated",
            DepositState::DepositNoncesCollected => "DepositNoncesCollected",
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected",
            DepositState::Deposited { .. } => "Deposited",
            DepositState::Assigned { .. } => "Assigned",
            DepositState::Fulfilled { .. } => "Fulfilled",
            DepositState::PayoutDescriptorReceived { .. } => "PayoutDescriptorReceived",
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesCollected",
            DepositState::PayoutPartialsCollected { .. } => "PayoutPartialsCollected",
            DepositState::CooperativePathFailed => "CooperativePathFailed",
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
    pub const fn new() -> Self {
        DepositState::Created
    }

    // TODO: (@Rajil1213, @MdTeach, @mukeshdroid) Add introspection methods here
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
                fulfillment_block_height,
            } => self.process_fulfillment(
                event_description,
                fulfillment_transaction,
                fulfillment_block_height,
                COOPERATIVE_PAYOUT_TIMELOCK,
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
            DepositEvent::PayoutConfirmed => self.process_payout_confirmed(),
            DepositEvent::NewBlock => self.process_new_block(),
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
    pub const fn new(cfg: DepositCfg) -> Self {
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
        match &self.state {
            DepositState::DepositPartialsCollected {
                block_height,
                deposit_transaction,
                ..
            } => {
                // Ensure that the deposit transaction confirmed on-chain is the one we were
                // expecting.
                assert_eq!(
                    confirmed_deposit_transaction.compute_txid(),
                    deposit_transaction.compute_txid(),
                    "Transaction confirmed on chain does not match expected deposit transaction"
                );
                // Transition to the Deposited State
                self.state = DepositState::Deposited {
                    block_height: *block_height,
                };

                // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for now.

                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
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
        match &self.state {
            DepositState::Deposited { block_height } => {
                // Transition to the Assigned State
                self.state = DepositState::Assigned {
                    block_height: *block_height,
                    assignee,
                    deadline,
                    recipient_desc,
                };

                // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for now.

                Ok(DSMOutput::new())
            }

            // Update the state with the details from new assignment event.
            DepositState::Assigned { block_height, .. } => {
                self.state = DepositState::Assigned {
                    block_height: *block_height,
                    assignee,
                    deadline,
                    recipient_desc,
                };

                // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for now.

                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
            }),
        }
    }

    fn process_fulfillment(
        &mut self,
        event_description: String,
        fulfillment_transaction: Transaction,
        fulfillment_block_height: BitcoinBlockHeight,
        cooperative_payout_timelock: u64,
    ) -> DSMResult<DSMOutput> {
        match &self.state {
            DepositState::Assigned {
                block_height,
                assignee,
                ..
            } => {
                // Compute the txid of the fulfillemnt Transaction
                let fulfillment_txid: Txid = fulfillment_transaction.compute_txid();

                // Compute the cooperative payout deadline.
                let cooperative_payment_deadline =
                    fulfillment_block_height + cooperative_payout_timelock;

                // Transition to the Fulfilled State
                self.state = DepositState::Fulfilled {
                    block_height: *block_height,
                    assignee: *assignee,
                    fulfillment_txid,
                    fulfillment_block_height,
                    cooperative_payment_deadline,
                };

                // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for now.

                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
            }),
        }
    }

    fn process_payout_descriptor_received(
        &mut self,
        event_description: String,
        operator_desc: Descriptor,
    ) -> DSMResult<DSMOutput> {
        match &self.state {
            DepositState::Fulfilled {
                block_height,
                assignee,
                cooperative_payment_deadline,
                ..
            } => {
                // Transition to the PayoutDescriptorReceived State
                self.state = DepositState::PayoutDescriptorReceived {
                    block_height: *block_height,
                    assignee: *assignee,
                    cooperative_payment_deadline: *cooperative_payment_deadline,
                    operator_desc,
                    payout_nonces: BTreeMap::new(),
                };

                // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for now.

                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
            }),
        }
    }

    fn process_payout_nonce_received(
        &mut self,
        event_description: String,
        payout_nonce: PubNonce,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        match &self.state {
            DepositState::PayoutDescriptorReceived {
                block_height,
                assignee,
                cooperative_payment_deadline,
                operator_desc,
                payout_nonces,
            } => {
                // Check for duplicate nonce submission. If an entry from the same operator exists,
                // return with an error.
                if payout_nonces.contains_key(&operator_idx) {
                    return Err(DSMError::DuplicateSubmission {
                        item: "payout nonce".to_string(),
                        operator_idx,
                    });
                }
                // Update the payout nonces with the new nonce just received.
                let mut updated_nonces = payout_nonces.clone();
                updated_nonces.insert(operator_idx, payout_nonce);

                // Transition to the PayoutNonceReceived State if *all* the nonces have been
                // received.
                if self.cfg.operator_table.cardinality() == updated_nonces.len() {
                    // Compute the aggregated nonce from the collected nonces.
                    let payout_aggregated_nonce = AggNonce::sum(updated_nonces.values().cloned());

                    // Transition to the PayoutNonceReceived State.
                    self.state = DepositState::PayoutNoncesCollected {
                        block_height: *block_height,
                        assignee: *assignee,
                        operator_desc: operator_desc.clone(),
                        cooperative_payment_deadline: *cooperative_payment_deadline,
                        payout_nonces: updated_nonces,
                        payout_aggregated_nonce,
                        payout_partial_signatures: BTreeMap::new(),
                    };
                    // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for
                    // now.

                    Ok(DSMOutput::new())
                }
                // If all nonces are not yet collected, update the payout nonces with received
                // nonce and stay in the PayoutDescriptorReceived State.
                else {
                    // Stay in the PayoutDescriptorReceived State but with updated nonce map.
                    self.state = DepositState::PayoutDescriptorReceived {
                        block_height: *block_height,
                        assignee: *assignee,
                        cooperative_payment_deadline: *cooperative_payment_deadline,
                        operator_desc: operator_desc.clone(),
                        payout_nonces: updated_nonces,
                    };
                    // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for
                    // now.

                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
            }),
        }
    }

    fn process_payout_partial_received(
        &mut self,
        event_description: String,
        partial_signature: PartialSignature,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        match &self.state {
            DepositState::PayoutNoncesCollected {
                block_height,
                assignee,
                cooperative_payment_deadline,
                operator_desc,
                payout_nonces,
                payout_aggregated_nonce,
                payout_partial_signatures,
            } => {
                // Check for duplicate Partial Signature submission. If an entry from the same
                // operator exists, return with an error.
                if payout_partial_signatures.contains_key(&operator_idx) {
                    return Err(DSMError::DuplicateSubmission {
                        item: "payout partial signature".to_string(),
                        operator_idx,
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
                    payout_aggregated_nonce,
                    operator_pubkey,
                    operator_pubnonce,
                    message.as_ref(),
                )
                .is_err()
                {
                    return Err(DSMError::PartialSignatureVerificationFailed {
                        operator_idx,
                        transaction: "Cooperative Payout Transaction".to_string(),
                    });
                }

                // Update the partial signatures map with the new partial signature just received.
                let mut updated_payout_partials = payout_partial_signatures.clone();
                updated_payout_partials.insert(operator_idx, partial_signature);

                // Transition to the PayoutPartialsCollected State if *all* the partial signatures
                // for the coooperative payout have been received.
                if self.cfg.operator_table.cardinality() == updated_payout_partials.len() {
                    // Transition to the PayoutNonceReceived State with dummy payout_txid and
                    // dummy payout aggregate signature.
                    self.state = DepositState::PayoutPartialsCollected {
                        block_height: *block_height,
                        payout_txid: Txid::all_zeros(),
                        payout_aggregated_signature: Signature::from_slice(&[0u8; 64])
                            .expect("Unable to create dummy signature."),
                    };
                    // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for
                    // now.

                    Ok(DSMOutput::new())
                }
                // If all partial signatures are not yet collected, update the payout partial
                // signatures map with received nonce and stay in the PayoutNoncesCollected State.
                else {
                    // Stay in the PayoutNoncesCollected State but with updated nonce map.
                    self.state = DepositState::PayoutNoncesCollected {
                        block_height: *block_height,
                        assignee: *assignee,
                        operator_desc: operator_desc.clone(),
                        cooperative_payment_deadline: *cooperative_payment_deadline,
                        payout_nonces: payout_nonces.clone(),
                        payout_aggregated_nonce: payout_aggregated_nonce.clone(),
                        payout_partial_signatures: updated_payout_partials,
                    };
                    // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for
                    // now.

                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
            }),
        }
    }

    fn process_payout_confirmed(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }

    fn process_new_block(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }
}
