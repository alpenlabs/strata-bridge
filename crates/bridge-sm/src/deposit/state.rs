//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use bitcoin::{Amount, Network, OutPoint, Transaction, Txid, XOnlyPublicKey, relative::LockTime};
use bitcoin_bosd::Descriptor;
use musig2::{
    AggNonce, PartialSignature, PubNonce, aggregate_partial_signatures, secp256k1::schnorr,
    verify_partial,
};
use strata_bridge_connectors2::{n_of_n::NOfNConnector, prelude::DepositRequestConnector};
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    operator_table::OperatorTable,
    scripts::prelude::{TaprootWitness, get_aggregated_pubkey},
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};
use strata_bridge_tx_graph2::transactions::{
    PresignedTx,
    deposit::DepositTx,
    prelude::{CooperativePayoutData, CooperativePayoutTx, DepositData},
};

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
    },
    signals::{DepositSignal, DepositToGraph, GraphToDeposit},
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
    // FIXME: (@mukeshdroid) network should not be part of state but a static config.
    pub(super) network: Network,
    /// The deposit amount.
    // FIXME: (@mukeshdroid) deposit amount should not be part of state but a static config.
    pub(super) deposit_amount: Amount,
}

impl DepositCfg {
    /// Returns the deposit index.
    pub const fn deposit_idx(&self) -> DepositIdx {
        self.deposit_idx
    }

    /// Returns the outpoint of the deposit transaction.
    pub const fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }
}

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositState {
    /// This state represents the initial phase after deposit request confirmation.
    ///
    /// This happens from the confirmation of the deposit request transaction until all operators
    /// have generated and linked their graphs for this deposit.
    Created {
        /// The unsigned deposit transaction derived from the deposit request.
        deposit_transaction: DepositTx,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Operators whose pegout graphs have been generated for this deposit transaction.
        linked_graphs: BTreeSet<OperatorIdx>,
    },
    /// This state represents the phase where all operator graphs have been generated.
    ///
    /// This happens from the point where all operator graphs are generated until all public nonces
    /// required to sign the deposit transaction are collected.
    GraphGenerated {
        /// The unsigned deposit transaction to be signed.
        deposit_transaction: DepositTx,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state represents the phase where all deposit public nonces have been collected.
    ///
    /// This happens from the collection of all deposit public nonces until all partial signatures
    /// have been received or, possibly, when the deposit transaction appears on chain.
    DepositNoncesCollected {
        /// The deposit transaction being signed.
        deposit_transaction: DepositTx,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Aggregated nonce used to validate partial signatures.
        agg_nonce: AggNonce,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,

        /// Partial signatures from operators for the deposit transaction.
        partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This state represents the phase where all partial signatures have been collected.
    ///
    /// This happens from the collection of all partial signatures until the deposit transaction
    /// is broadcast and confirmed.
    DepositPartialsCollected {
        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// The fully signed deposit transaction.
        deposit_transaction: Transaction,
    },
    /// This state indicates that the deposit transaction has been confirmed on-chain.
    Deposited {
        /// The last block height observed by this state machine.
        block_height: u64,
    },
    /// This state indicates that this deposit has been assigned for withdrawal.
    Assigned {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The block height by which the operator must fulfill the withdrawal request.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// This state indicates that the operator has fronted the user.
    Fulfilled {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The txid of the fulfillment transaction.
        fulfillment_txid: Txid,
        /// The block height where the fulfillment transaction was confirmed.
        fulfillment_height: BitcoinBlockHeight,
        /// The block height by which the cooperative payout is attempted.
        cooperative_payout_deadline: BitcoinBlockHeight,
    },
    /// This state indicates that the descriptor of the operator for the cooperative payout has been
    /// received.
    PayoutDescriptorReceived {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The operator's descriptor to send the funds via the cooperative path.
        /// This can only be set once and needs to be provided by the assigned operator.
        operator_desc: Descriptor,
        /// The pubnonces, indexed by operator, required to sign the cooperative payout
        /// transaction.
        payout_nonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state indicates that all pubnonces required for the cooperative payout have been
    /// collected.
    PayoutNoncesCollected {
        /// The last block height observed by this state machine.
        block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
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
    /// This state represents the scenario where the cooperative payout path has failed.
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
        let display_str = match self {
            DepositState::Created { .. } => "Created".to_string(),
            DepositState::GraphGenerated { .. } => "GraphGenerated".to_string(),
            DepositState::DepositNoncesCollected { .. } => "DepositNoncesCollected".to_string(),
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected".to_string(),
            DepositState::Deposited { .. } => "Deposited".to_string(),
            DepositState::Assigned { .. } => "Assigned".to_string(),
            DepositState::Fulfilled { .. } => "Fulfilled".to_string(),
            DepositState::PayoutDescriptorReceived { .. } => "PayoutDescriptorReceived".to_string(),
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesCollected".to_string(),
            DepositState::CooperativePathFailed { .. } => "CooperativePathFailed".to_string(),
            DepositState::Spent => "Spent".to_string(),
            DepositState::Aborted => "Aborted".to_string(),
        };
        write!(f, "{}", display_str)
    }
}

impl DepositState {
    /// Constructs a new [`DepositState`] in the [`DepositState::Created`] variant.
    ///
    /// Initializes the required connectors and builds the deposit transaction from the provided
    /// deposit parameters, recording the current `block_height`.
    pub fn new(
        deposit_ammount: Amount,
        deposit_time_lock: LockTime,
        network: Network,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        n_of_n_pubkey: XOnlyPublicKey,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        let deposit_request_connetor = DepositRequestConnector::new(
            network,
            n_of_n_pubkey,
            depositor_pubkey,
            deposit_time_lock,
            deposit_ammount,
        );
        let non_connector = NOfNConnector::new(network, n_of_n_pubkey, deposit_ammount);

        let deposit_transaction =
            DepositTx::new(deposit_data, non_connector, deposit_request_connetor);

        DepositState::Created {
            deposit_transaction,
            block_height,
            linked_graphs: BTreeSet::new(),
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
            DepositEvent::UserTakeBack { tx } => self.process_drt_takeback(tx),
            DepositEvent::GraphMessage(graph_msg) => self.process_graph_available(graph_msg),
            DepositEvent::NonceReceived {
                nonce,
                operator_idx,
            } => self.process_nonce_received(nonce, operator_idx),
            DepositEvent::PartialReceived {
                partial_sig,
                operator_idx,
            } => self.process_partial_received(partial_sig, operator_idx),
            DepositEvent::DepositConfirmed {
                deposit_transaction,
            } => self.process_deposit_confirmed(event_description, deposit_transaction),
            DepositEvent::WithdrawalAssigned {
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
    /// Creates a new [`DepositSM`] using the provided configuration and deposit data.
    ///
    /// The state machine starts in [`DepositState::Created`] by constructing an initial
    /// [`DepositState`] via [`DepositState::new`].
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        cfg: DepositCfg,
        deposit_ammount: Amount,
        deposit_time_lock: LockTime,
        network: Network,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        n_of_n_pubkey: XOnlyPublicKey,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(
                deposit_ammount,
                deposit_time_lock,
                network,
                deposit_data,
                depositor_pubkey,
                n_of_n_pubkey,
                block_height,
            ),
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

    /// Returns `true` if the operator index exists in the operator table.
    fn validate_operator_idx(&self, operator_idx: OperatorIdx) -> bool {
        self.cfg()
            .operator_table
            .idx_to_btc_key(&operator_idx)
            .is_some()
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

    /// Processes the event where the user takes back the deposit request output.
    ///
    /// This can happen if any of the operators are not operational for the entire duration of the
    /// take back period.
    // TODO: Add event description as a parameter so that event needn't be recreated to
    //       for the error.
    fn process_drt_takeback(
        &mut self,
        tx: Transaction,
    ) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        let deposit_request_outpoint = &self.cfg().deposit_outpoint;
        match self.state() {
            DepositState::Created { .. }
            | DepositState::GraphGenerated { .. }
            | DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. } => {
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
                        state: Box::new(self.state().clone()),
                        reason: format!(
                            "Transaction {} is not a take back transaction for the deposit request outpoint {}",
                            tx.compute_txid(),
                            deposit_request_outpoint
                        ),
                        event: Box::new(DepositEvent::UserTakeBack { tx }),
                    })
                }
            }
            DepositState::Aborted => Err(DSMError::Duplicate {
                state: Box::new(self.state().clone()),
                event: Box::new(DepositEvent::UserTakeBack { tx }),
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::UserTakeBack { tx }.to_string(),
                state: self.state.to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where an operator's graph becomes available.
    ///
    /// This tracks operators that have successfully generated and linked their spending graphs
    /// for this deposit. When all operators have linked their graphs, transitions to the
    /// [`DepositState::GraphGenerated`] state.
    fn process_graph_available(&mut self, graph_msg: GraphToDeposit) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();
        let deposit_outpoint = self.cfg().deposit_outpoint();

        match graph_msg {
            GraphToDeposit::GraphAvailable { operator_idx } => {
                // Validate operator_idx is in the operator table
                if !self.validate_operator_idx(operator_idx) {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        reason: format!("Operator index {} not in operator table", operator_idx),
                        event: Box::new(DepositEvent::GraphMessage(graph_msg)),
                    });
                }

                match self.state_mut() {
                    DepositState::Created {
                        deposit_transaction,
                        block_height,
                        linked_graphs,
                    } => {
                        // Check for duplicate graph submission
                        if linked_graphs.contains(&operator_idx) {
                            return Err(DSMError::Duplicate {
                                state: Box::new(self.state().clone()),
                                event: Box::new(DepositEvent::GraphMessage(
                                    GraphToDeposit::GraphAvailable { operator_idx },
                                )),
                            });
                        }

                        linked_graphs.insert(operator_idx);

                        if linked_graphs.len() == operator_table_cardinality {
                            // All operators have linked their graphs, transition to GraphGenerated
                            // state
                            let new_state = DepositState::GraphGenerated {
                                deposit_transaction: deposit_transaction.clone(),
                                block_height: *block_height,
                                pubnonces: BTreeMap::new(),
                            };
                            self.state = new_state;

                            // Create the duty to publish deposit nonce
                            let duty = DepositDuty::PublishDepositNonce { deposit_outpoint };

                            return Ok(DSMOutput::with_duties(vec![duty]));
                        }

                        Ok(DSMOutput::new())
                    }
                    _ => Err(DSMError::InvalidEvent {
                        state: self.state().to_string(),
                        event: DepositEvent::GraphMessage(graph_msg).to_string(),
                        reason: None,
                    }),
                }
            }
        }
    }

    /// Processes the event where an operator's nonce is received for the deposit transaction.
    ///
    /// This collects public nonces from operators required for the multisig signing process.
    /// When all operators have provided their nonces, transitions to the
    /// [`DepositState::DepositNoncesCollected`] state and emits a
    /// [`DepositDuty::PublishDepositPartial`] duty.
    fn process_nonce_received(
        &mut self,
        nonce: PubNonce,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();

        // Validate operator_idx is in the operator table
        if !self.validate_operator_idx(operator_idx) {
            return Err(DSMError::Rejected {
                state: Box::new(self.state().clone()),
                reason: format!("Operator index {} not in operator table", operator_idx),
                event: Box::new(DepositEvent::NonceReceived {
                    nonce,
                    operator_idx,
                }),
            });
        }

        match self.state_mut() {
            DepositState::GraphGenerated {
                deposit_transaction,
                block_height,
                pubnonces,
            } => {
                // Check for duplicate nonce submission
                if pubnonces.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::NonceReceived {
                            nonce,
                            operator_idx,
                        }),
                    });
                }

                // Insert the new nonce into the map
                pubnonces.insert(operator_idx, nonce);

                // Check if we have collected all nonces
                if pubnonces.len() == operator_table_cardinality {
                    // All nonces collected, compute the aggregated nonce
                    let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

                    // Derive the sighash message for the deposit transaction
                    let deposit_sighash = deposit_transaction
                        .signing_info()
                        .first()
                        .expect("deposit transaction must have signing info")
                        .sighash;

                    // Transition to DepositNoncesCollected state
                    let new_state = DepositState::DepositNoncesCollected {
                        deposit_transaction: deposit_transaction.clone(),
                        block_height: *block_height,
                        agg_nonce: agg_nonce.clone(),
                        pubnonces: pubnonces.clone(),
                        partial_signatures: BTreeMap::new(),
                    };
                    self.state = new_state;

                    // Create the duty to publish deposit partials
                    let duty = DepositDuty::PublishDepositPartial {
                        deposit_outpoint: self.cfg().deposit_outpoint(),
                        deposit_sighash,
                        deposit_agg_nonce: agg_nonce,
                    };

                    Ok(DSMOutput::with_duties(vec![duty]))
                } else {
                    // Not all nonces collected yet, stay in current state
                    Ok(DSMOutput::new())
                }
            }
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::NonceReceived {
                    nonce,
                    operator_idx,
                }
                .to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where an operator's partial signature is received for the deposit
    /// transaction.
    ///
    /// This collects partial signatures from operators required for the multisig signing process.
    /// When all operators have provided their partial signatures, transitions to the
    /// [`DepositState::DepositPartialsCollected`] state and emits a [`DepositDuty::PublishDeposit`]
    /// duty.
    fn process_partial_received(
        &mut self,
        partial_sig: PartialSignature,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();
        let btc_keys: Vec<_> = self.cfg().operator_table.btc_keys().into_iter().collect();

        // Validate operator_idx is in the operator table
        if !self.validate_operator_idx(operator_idx) {
            return Err(DSMError::Rejected {
                state: Box::new(self.state().clone()),
                reason: format!("Operator index {} not in operator table", operator_idx),
                event: Box::new(DepositEvent::PartialReceived {
                    partial_sig,
                    operator_idx,
                }),
            });
        }

        // Get the operator pubkey (safe after validation)
        let operator_pubkey = self
            .cfg()
            .operator_table
            .idx_to_btc_key(&operator_idx)
            .expect("validated above");

        match self.state_mut() {
            DepositState::DepositNoncesCollected {
                deposit_transaction,
                block_height,
                agg_nonce,
                pubnonces,
                partial_signatures,
            } => {
                // Extract Copy types immediately using dereference pattern to bypass borrow checker
                let blk_height = *block_height;

                // Check for duplicate partial signature submission
                if partial_signatures.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::PartialReceived {
                            partial_sig,
                            operator_idx,
                        }),
                    });
                }

                // Extract signing info once - used for both verification and aggregation
                let signing_info = deposit_transaction
                    .signing_info()
                    .first()
                    .copied()
                    .expect("deposit transaction must have signing info");
                let sighash = signing_info.sighash;
                let tweak = signing_info
                    .tweak
                    .expect("DRT->DT key-path spend must include a taproot tweak")
                    .expect("tweak must be present for deposit transaction");

                let tap_witness = TaprootWitness::Tweaked { tweak };

                // Create key aggregation context once - reused for verification and aggregation
                let key_agg_ctx = create_agg_ctx(btc_keys, &tap_witness)
                    .expect("must be able to create key aggregation context");

                // Verify the partial signature
                let operator_pubnonce = pubnonces
                    .get(&operator_idx)
                    .expect("operator must have submitted nonce")
                    .clone();
                if verify_partial(
                    &key_agg_ctx,
                    partial_sig,
                    agg_nonce,
                    operator_pubkey,
                    &operator_pubnonce,
                    sighash.as_ref(),
                )
                .is_err()
                {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        reason: "Invalid partial signature".to_string(),
                        event: Box::new(DepositEvent::PartialReceived {
                            partial_sig,
                            operator_idx,
                        }),
                    });
                }

                // Insert the new partial signature into the map
                partial_signatures.insert(operator_idx, partial_sig);

                // Check if we have collected all partial signatures
                if partial_signatures.len() == operator_table_cardinality {
                    // Clone deposit transaction for state transition
                    let deposit_tx = deposit_transaction.clone();

                    // Aggregate all partial signatures using the same key_agg_ctx
                    let agg_signature: schnorr::Signature = aggregate_partial_signatures(
                        &key_agg_ctx,
                        agg_nonce,
                        partial_signatures.values().cloned(),
                        sighash.as_ref(),
                    )
                    .expect("partial signatures must be valid");

                    // Build deposit transaction with sigs
                    let deposit_transaction = deposit_tx.finalize(agg_signature);

                    // Transition to DepositPartialsCollected state
                    self.state = DepositState::DepositPartialsCollected {
                        deposit_transaction: deposit_transaction.clone(),
                        block_height: blk_height,
                    };

                    // Create the duty to publish the deposit transaction
                    let duty = DepositDuty::PublishDeposit {
                        deposit_transaction,
                        agg_signature,
                    };

                    Ok(DSMOutput::with_duties(vec![duty]))
                } else {
                    Ok(DSMOutput::new())
                }
            }
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::PartialReceived {
                    partial_sig,
                    operator_idx,
                }
                .to_string(),
                reason: None,
            }),
        }
    }

    fn process_deposit_confirmed(
        &mut self,
        event_description: String,
        confirmed_deposit_transaction: Transaction,
    ) -> DSMResult<DSMOutput> {
        match self.state() {
            DepositState::DepositPartialsCollected {
                block_height,
                deposit_transaction,
                ..
            } => {
                // Ensure that the deposit transaction confirmed on-chain is the one we were
                // expecting.
                if confirmed_deposit_transaction.compute_txid()
                    != deposit_transaction.compute_txid()
                {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::DepositConfirmed {
                            deposit_transaction: deposit_transaction.clone(),
                        }),
                        reason:
                            "Transaction confirmed on chain does not match expected deposit transaction"
                                .to_string(),
                    });
                }
                // Transition to the Deposited State
                self.state = DepositState::Deposited {
                    block_height: *block_height,
                };
                // No duties or signals required
                Ok(DSMOutput::new())
            }

            // This can happen if one of the operators withholds their own partial signature
            // while aggregating it with the rest of the collected partials and broadcasts it
            // unilaterally.
            DepositState::DepositNoncesCollected {
                block_height,
                deposit_transaction,
                ..
            } => {
                // Ensure that the deposit transaction confirmed on-chain is the one we were
                // expecting.
                if confirmed_deposit_transaction.compute_txid()
                    != deposit_transaction.as_ref().compute_txid()
                {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::DepositConfirmed {
                            deposit_transaction: confirmed_deposit_transaction,
                        }),
                        reason:
                            "Transaction confirmed on chain does not match expected deposit transaction"
                                .to_string(),
                    });
                }
                // Transition to the Deposited State
                self.state = DepositState::Deposited {
                    block_height: *block_height,
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
        match self.state() {
            DepositState::Deposited { block_height }
            | DepositState::Assigned { block_height, .. } => {
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
        match self.state() {
            DepositState::Assigned {
                block_height,
                assignee,
                ..
            } => {
                let assignee = *assignee;

                // Compute the txid of the fulfillment transaction
                let fulfillment_txid: Txid = fulfillment_transaction.compute_txid();

                // Compute the cooperative payout deadline.
                let cooperative_payment_deadline = fulfillment_height + cooperative_payout_timelock;

                // Transition to the Fulfilled state
                self.state = DepositState::Fulfilled {
                    block_height: *block_height,
                    assignee,
                    fulfillment_txid,
                    fulfillment_height,
                    cooperative_payout_deadline: cooperative_payment_deadline,
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
        match self.state() {
            DepositState::Fulfilled {
                block_height,
                assignee,
                cooperative_payout_deadline: cooperative_payment_deadline,
                ..
            } => {
                let assignee = *assignee;

                // Transition to the PayoutDescriptorReceived state
                self.state = DepositState::PayoutDescriptorReceived {
                    block_height: *block_height,
                    assignee,
                    cooperative_payment_deadline: *cooperative_payment_deadline,
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
        let operator_table_cardinality = self.cfg.operator_table.cardinality();
        let pov_operator_idx = self.cfg.operator_table.pov_idx();

        match self.state_mut() {
            DepositState::PayoutDescriptorReceived {
                block_height,
                assignee,
                cooperative_payment_deadline,
                operator_desc,
                payout_nonces,
            } => {
                let assignee = *assignee;

                // Check for duplicate nonce submission. If an entry from the same operator exists,
                // return with an error.
                if payout_nonces.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: Box::new(self.state().clone()),
                        event: DepositEvent::PayoutNonceReceived {
                            payout_nonce,
                            operator_idx,
                        }
                        .into(),
                    });
                }
                // Update the payout nonces with the new nonce just received.
                payout_nonces.insert(operator_idx, payout_nonce);

                // Transition to the PayoutNoncesCollected State if *all* the nonces have been
                // received. Dispatch duty to publish the cooperative payout partial signatures
                // unless the pov operator is the assignee.
                if operator_table_cardinality == payout_nonces.len() {
                    // Compute the aggregated nonce from the collected nonces.
                    let agg_nonce = AggNonce::sum(payout_nonces.values());

                    // Transition to the PayoutNoncesCollected State.
                    self.state = DepositState::PayoutNoncesCollected {
                        block_height: *block_height,
                        assignee,
                        operator_desc: operator_desc.clone(),
                        cooperative_payment_deadline: *cooperative_payment_deadline,
                        payout_nonces: payout_nonces.clone(),
                        payout_aggregated_nonce: agg_nonce.clone(),
                        payout_partial_signatures: BTreeMap::new(),
                    };

                    // Dispatch the duty to publish payout partial signature if the pov operator is
                    // NOT the assignee.
                    // The assignee should *NOT* publish their partial signature to prevent payout
                    // hostage attack. If the assignee published their partial, a malicious
                    // coordinator/operator could withhold their own partial and force the
                    // assignee to fall back to posting a claim. If a cooperative payout is later
                    // broadcast, the assignee is unable to spend the contested or uncontested path,
                    // and can be slashed after the timelock expires. By withholding their
                    // partial, only the assignee can finalize and broadcast
                    if pov_operator_idx != assignee {
                        Ok(DSMOutput::with_duties(vec![
                            DepositDuty::PublishPayoutPartial {
                                deposit_outpoint: self.cfg.deposit_outpoint,
                                deposit_idx: self.cfg.deposit_idx,
                                agg_nonce,
                            },
                        ]))
                    } else {
                        Ok(DSMOutput::new())
                    }
                }
                // If all nonces are not yet collected, stay in the PayoutDescriptorReceived State
                // and dispatch no duties or signals.
                else {
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
        // Extract from self.cfg before the match to avoid borrow conflicts
        let operator_table_cardinality = self.cfg.operator_table.cardinality();
        let pov_operator_idx = self.cfg.operator_table.pov_idx();
        let n_of_n_pubkey = get_aggregated_pubkey(self.cfg.operator_table.btc_keys());
        let deposit_connector =
            NOfNConnector::new(self.cfg.network, n_of_n_pubkey, self.cfg.deposit_amount);
        let coop_payout_data = CooperativePayoutData {
            deposit_outpoint: self.cfg.deposit_outpoint,
        };
        // Generate the key_agg_ctx using the operator table.
        // NOfNConnector uses key-path spend with no script tree, so we use
        // TaprootWitness::Key which applies with_unspendable_taproot_tweak()
        let key_agg_ctx = create_agg_ctx(self.cfg.operator_table.btc_keys(), &TaprootWitness::Key)
            .expect("must be able to create key aggregation context");
        let operator_pubkey = self
            .cfg
            .operator_table
            .idx_to_btc_key(&operator_idx)
            .expect("operator must be in table");

        match self.state_mut() {
            DepositState::PayoutNoncesCollected {
                assignee,
                operator_desc,
                payout_nonces,
                payout_aggregated_nonce,
                payout_partial_signatures,
                ..
            } => {
                let assignee = *assignee;

                // Check for duplicate Partial Signature submission. If an entry from the same
                // operator exists, return with an error.
                if payout_partial_signatures.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: Box::new(self.state().clone()),
                        event: DepositEvent::PayoutPartialReceived {
                            partial_signature,
                            operator_idx,
                        }
                        .into(),
                    });
                }

                // Construct the cooperative payout transaction.
                let coop_payout_tx = CooperativePayoutTx::new(
                    coop_payout_data,
                    deposit_connector,
                    operator_desc.clone(),
                );

                // Get the sighash for signature verification
                let signing_info = coop_payout_tx.signing_info();
                let message = signing_info[0].sighash;

                // Get the operator's pubnonce for verification.
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
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        reason: "Partial Signature Verification Failed".to_string(),
                        event: DepositEvent::PayoutPartialReceived {
                            partial_signature,
                            operator_idx,
                        }
                        .into(),
                    });
                }

                // If the partial signature verification passes, add it to state
                payout_partial_signatures.insert(operator_idx, partial_signature);

                // Check that *all* the partial signatures except from the assignee
                // for the cooperative payout have been received.
                // HACK: (mukeshdroid) The stricter check would have been to assert that the
                // partials except from the assignee has been collected. The following check that
                // asserts *any* n-1 partials are collected is enough since the assignee should
                // never send their partials for their own good.
                if operator_table_cardinality - 1 == payout_partial_signatures.len() {
                    // Dispatch the duty to publish payout tx if the pov operator is the assignee.
                    if pov_operator_idx == assignee {
                        Ok(DSMOutput::with_duties(vec![DepositDuty::PublishPayout {
                            payout_tx: coop_payout_tx.as_ref().clone(),
                        }]))
                    } else {
                        Ok(DSMOutput::new())
                    }
                } else {
                    // If there are remaining partial signatures (except the assignee),
                    // stay in same state.
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
    /// - A sweep transaction in the event of a hard upgrade (migration) of deposited UTXOs.
    // TODO: Add event description as a parameter so that event needn't be recreated to
    //       for the error.
    fn process_payout_confirmed(&mut self, tx: &Transaction) -> DSMResult<DSMOutput> {
        match self.state() {
            // It must be the sweep transaction in case of a hard upgrade
            DepositState::Deposited { .. }
            // It must be a cooperative payout transaction.
            // The assignee withholds their own partial and broadcasts the payout tx themselves,
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
                state: Box::new(self.state().clone()),
                event: Box::new(DepositEvent::PayoutConfirmed { tx: tx.clone() })
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.to_string(),
                state: self.state.to_string(),
                reason: None
            }),
        }
    }

    // TODO: Add event description as a parameter so that event needn't be recreated to
    //       for the error.
    fn process_new_block(&mut self, new_block_height: BitcoinBlockHeight) -> DSMResult<DSMOutput> {
        let last_processed_block_height = self.state().last_processed_block_height();
        if last_processed_block_height.is_some_and(|height| *height >= new_block_height) {
            return Err(DSMError::Duplicate {
                state: Box::new(self.state().clone()),
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
                cooperative_payout_deadline: cooperative_payment_deadline,
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
                state: Box::new(self.state().clone()),
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

    use bitcoin::hashes::Hash;
    use bitcoin_bosd::Descriptor;
    use proptest::prelude::*;
    use secp256k1::Message;
    use strata_bridge_test_utils::{
        bitcoin::{generate_spending_tx, generate_txid},
        musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
    };

    use super::*;
    use crate::{
        deposit::testing::*,
        prop_deterministic, prop_no_silent_acceptance, prop_terminal_states_reject,
        testing::{fixtures::*, signer::TestMusigSigner, transition::*},
    };

    // ===== Unit Tests for process_drt_takeback =====

    #[test]
    fn test_drt_takeback_from_created() {
        let outpoint = OutPoint::default();
        let state = DepositState::Created {
            deposit_transaction: test_deposit_txn(),
            block_height: INITIAL_BLOCK_HEIGHT,
            linked_graphs: Default::default(),
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
            deposit_transaction: test_deposit_txn(),
            pubnonces: Default::default(),
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
            deposit_transaction: test_deposit_txn(),
            linked_graphs: Default::default(),
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
            cooperative_payout_deadline: FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
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
        let deposit_request_outpoint = OutPoint::default();
        let deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        let state = DepositState::DepositPartialsCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: deposit_tx.clone(),
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

    /// tests correct transition from DepositNoncesCollected state to the DepositConfirmed state
    /// when the DepositConfirmed event is received.
    #[test]
    fn test_deposit_confirmed_from_nonces_collected() {
        let deposit_tx = test_deposit_txn();

        let state = DepositState::DepositNoncesCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
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
                    deposit_transaction: deposit_tx.as_ref().clone(),
                },
                expected_state: DepositState::Deposited {
                    block_height: INITIAL_BLOCK_HEIGHT,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// tests that all states apart from the DepositNoncesCollected and
    /// DepositPartialsCollected should NOT accept the DepositConfirmed event.
    #[test]
    fn test_deposit_confirmed_invalid_from_other_states() {
        let deposit_request_outpoint = OutPoint::default();
        let tx = generate_spending_tx(deposit_request_outpoint, &[]);
        let desc = random_p2tr_desc();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
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
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
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

    // ===== Process Graph Available Tests =====

    #[test]
    fn test_process_graph_available_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_table = test_operator_table();
        let operator_count = operator_table.cardinality() as u32;

        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            linked_graphs: BTreeSet::new(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        for operator_idx in 0..operator_count {
            seq.process(DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
                operator_idx,
            }));
        }

        seq.assert_no_errors();

        // Should transition to GraphGenerated
        assert!(matches!(seq.state(), DepositState::GraphGenerated { .. }));

        // Check that a PublishDepositNonce duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [DepositDuty::PublishDepositNonce { .. }]
            ),
            "Expected exactly 1 PublishDepositNonce duty to be emitted"
        );
    }

    #[test]
    fn test_duplicate_process_graph_available_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_table = test_operator_table();
        let operator_count = operator_table.cardinality() as u32;

        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            linked_graphs: BTreeSet::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process GraphAvailable messages, all operators except the last one
        for operator_idx in 0..(operator_count - 1) {
            let event = DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable { operator_idx });
            seq.process(event.clone());

            // Process the same event again to simulate duplicate
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                InvalidTransition {
                    from_state: seq.state().clone(),
                    event,
                    expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
                },
            );
        }
    }

    /// tests that a DepositConfirmed event with a deposit tx that doesn't spend the DRT outpoint
    /// is rejected from the DepositPartialsCollected state.
    #[test]
    fn test_deposit_confirmed_wrong_tx_rejection_from_deposit_partials_collected() {
        let deposit_request_outpoint = OutPoint::default();
        let expected_deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        // Create a different transaction (different outpoint)
        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();

        // assert that the deposit request outpoint and the wrong outpoint are not same.
        assert_ne!(
            deposit_request_outpoint, wrong_outpoint,
            "wrong outpoint for test must be different from actual outpoint"
        );

        let wrong_tx = generate_spending_tx(wrong_outpoint, &[]);

        // assert that the deposit tx and the wrong tx for testing are not same.
        assert_ne!(
            expected_deposit_tx, wrong_tx,
            "wrong deposit tx for test must be different from actual deposit tx"
        );

        let state = DepositState::DepositPartialsCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: expected_deposit_tx,
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
    fn test_invalid_operator_idx_in_process_graph_available() {
        let deposit_tx = test_deposit_txn();

        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            linked_graphs: BTreeSet::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process GraphAvailable messages with invalid operator idx
        let event = DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
            operator_idx: u32::MAX,
        });
        seq.process(event.clone());

        // Process the same event again to simulate duplicate
        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: seq.state().clone(),
                event,
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            },
        );
    }

    /// tests that a DepositConfirmed event with a deposit tx that doesn't spend the DRT outpoint
    /// is rejected from the DepositNoncesCollected state.
    #[test]
    fn test_deposit_confirmed_wrong_tx_rejection_from_deposit_nonces_collected() {
        let deposit_request_outpoint = OutPoint::default();
        let expected_deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        // Create a different transaction (different outpoint)
        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();

        // assert that the deposit request outpoint and the wrong outpoint are not same.
        assert_ne!(
            deposit_request_outpoint, wrong_outpoint,
            "wrong outpoint for test must be different from actual outpoint"
        );

        let wrong_tx = generate_spending_tx(wrong_outpoint, &[]);

        // assert that the deposit tx and the wrong tx for testing are not same.
        assert_ne!(
            expected_deposit_tx, wrong_tx,
            "wrong deposit tx for test must be different from actual deposit tx"
        );

        let state = DepositState::DepositNoncesCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: test_deposit_txn(),
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

    // ===== Process Nonce Received Tests =====

    #[test]
    fn test_process_nonce_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, _sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        // Generate nonces using the tweaked aggregated pubkey
        let pubnonces: BTreeMap<u32, PubNonce> = operator_signers
            .iter()
            .enumerate()
            .map(|(operatoridx, s)| {
                (
                    operatoridx as u32,
                    s.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter),
                )
            })
            .collect();

        let initial_state = DepositState::GraphGenerated {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        for (operator_idx, nonce) in &pubnonces {
            seq.process(DepositEvent::NonceReceived {
                nonce: nonce.clone(),
                operator_idx: *operator_idx,
            });
        }

        seq.assert_no_errors();

        // Should transition to DepositNoncesCollected
        assert!(matches!(
            seq.state(),
            DepositState::DepositNoncesCollected { .. }
        ));

        // Check that a PublishDepositPartial duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [DepositDuty::PublishDepositPartial { .. }]
            ),
            "Expected exactly 1 PublishDepositPartial duty to be emitted"
        );
    }

    #[test]
    fn test_duplicate_process_nonce_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, _sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        let initial_state = DepositState::GraphGenerated {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process nonces, all operators except the last one
        for signer in operator_signers
            .iter()
            .take(operator_signers.len().saturating_sub(1))
        {
            let nonce = signer.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter);
            let event = DepositEvent::NonceReceived {
                nonce,
                operator_idx: signer.operator_idx(),
            };
            seq.process(event.clone());

            // Process the same event again to simulate duplicate
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                InvalidTransition {
                    from_state: seq.state().clone(),
                    event,
                    expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
                },
            );
        }
    }

    #[test]
    fn test_invalid_operator_idx_in_process_nonce() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, _sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        let initial_state = DepositState::GraphGenerated {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces: BTreeMap::new(),
        };

        // Process nonces, with invalid operator idex
        let signer = operator_signers.first().expect("singer set empty");
        let nonce = signer.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter);
        let event = DepositEvent::NonceReceived {
            nonce,
            operator_idx: u32::MAX,
        };

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: initial_state,
                event,
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            },
        );
    }
    // ===== Process Partial Received Tests =====
    #[test]
    fn test_process_partial_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        // Generate nonces using the tweaked aggregated pubkey
        let pubnonces: BTreeMap<u32, PubNonce> = operator_signers
            .iter()
            .enumerate()
            .map(|(operatoridx, s)| {
                (
                    operatoridx as u32,
                    s.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter),
                )
            })
            .collect();
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &operator_signers {
            let partial_sig = signer.sign(
                &key_agg_ctx,
                operator_signers_nonce_counter,
                &agg_nonce,
                sighash,
            );
            seq.process(DepositEvent::PartialReceived {
                partial_sig,
                operator_idx: signer.operator_idx(),
            });
        }

        seq.assert_no_errors();

        // Should transition to DepositPartialsCollected
        assert!(matches!(
            seq.state(),
            DepositState::DepositPartialsCollected { .. }
        ));

        // Check that a PublishDeposit duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [DepositDuty::PublishDeposit { .. }]
            ),
            "Expected exactly 1 PublishDeposit duty to be emitted"
        );
    }

    #[test]
    fn test_invalid_process_partial_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let mut operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        // Generate nonces using the tweaked aggregated pubkey
        let pubnonces: BTreeMap<u32, PubNonce> = operator_signers
            .iter()
            .enumerate()
            .map(|(operatoridx, s)| {
                (
                    operatoridx as u32,
                    s.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter),
                )
            })
            .collect();
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Update the nonce counter to simulate invalid signature
        operator_signers_nonce_counter += 1;

        for signer in &operator_signers {
            let partial_sig = signer.sign(
                &key_agg_ctx,
                operator_signers_nonce_counter,
                &agg_nonce,
                sighash,
            );
            seq.process(DepositEvent::PartialReceived {
                partial_sig,
                operator_idx: signer.operator_idx(),
            });
        }

        // Shoudon't have transitioned state
        seq.assert_final_state(&initial_state);

        // Should have errors due to invalid partial signatures
        let errors = seq.all_errors();
        assert_eq!(
            errors.len(),
            operator_signers.len(),
            "Expected {} errors for invalid partial signatures, got {}",
            operator_signers.len(),
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

    #[test]
    fn test_duplicate_process_partial_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        // Generate nonces using the tweaked aggregated pubkey
        let pubnonces: BTreeMap<u32, PubNonce> = operator_signers
            .iter()
            .enumerate()
            .map(|(operatoridx, s)| {
                (
                    operatoridx as u32,
                    s.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter),
                )
            })
            .collect();
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process partial signatures, all operators except the last one
        for signer in operator_signers
            .iter()
            .take(operator_signers.len().saturating_sub(1))
        {
            let partial_sig = signer.sign(
                &key_agg_ctx,
                operator_signers_nonce_counter,
                &agg_nonce,
                sighash,
            );
            let event = DepositEvent::PartialReceived {
                partial_sig,
                operator_idx: signer.operator_idx(),
            };
            seq.process(event.clone());

            // Process the same event again to simulate duplicate
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                InvalidTransition {
                    from_state: seq.state().clone(),
                    event,
                    expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
                },
            );
        }
    }

    #[test]
    fn test_invalid_operator_idx_in_process_partial() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        // Generate nonces using the tweaked aggregated pubkey
        let pubnonces: BTreeMap<u32, PubNonce> = operator_signers
            .iter()
            .enumerate()
            .map(|(operatoridx, s)| {
                (
                    operatoridx as u32,
                    s.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter),
                )
            })
            .collect();
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        // Process partial signatures, with invalid operator idx
        let signer = operator_signers.first().expect("singer set empty");
        let partial_sig = signer.sign(
            &key_agg_ctx,
            operator_signers_nonce_counter,
            &agg_nonce,
            sighash,
        );
        let event = DepositEvent::PartialReceived {
            partial_sig,
            operator_idx: u32::MAX,
        };

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: initial_state,
                event,
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            },
        );
    }

    // ===== Unit Tests for process_assignment =====

    /// tests correct transition from Deposited to Assigned state when Assignment event
    /// is received and POV operator is the assignee (should emit FulfillWithdrawal duty).
    #[test]
    fn test_assignment_from_deposited_pov_is_assignee() {
        let desc = random_p2tr_desc();

        let state = DepositState::Deposited {
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::WithdrawalAssigned {
                    assignee: TEST_POV_IDX,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                },
                expected_state: DepositState::Assigned {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_POV_IDX,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                },
                expected_duties: vec![DepositDuty::FulfillWithdrawal {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// tests correct transition from Deposited to Assigned state when Assignment event
    /// is received and POV operator is NOT the assignee (should NOT emit any duty).
    #[test]
    fn test_assignment_from_deposited_pov_is_not_assignee() {
        let desc = random_p2tr_desc();

        let state = DepositState::Deposited {
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::WithdrawalAssigned {
                    assignee: TEST_NONPOV_IDX,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                },
                expected_state: DepositState::Assigned {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_NONPOV_IDX,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// tests correct re-assignment from Assigned state when Assignment event is received
    /// and POV operator is the new assignee (should emit FulfillWithdrawal duty).
    #[test]
    fn test_reassignment_to_pov() {
        let old_desc = random_p2tr_desc();
        let new_desc = random_p2tr_desc();

        assert_ne!(old_desc, new_desc, "must be diff");

        let state = DepositState::Assigned {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_NONPOV_IDX,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: old_desc,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::WithdrawalAssigned {
                    assignee: TEST_POV_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: new_desc.clone(),
                },
                expected_state: DepositState::Assigned {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_POV_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: new_desc.clone(),
                },
                expected_duties: vec![DepositDuty::FulfillWithdrawal {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: new_desc,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// tests correct re-assignment from Assigned state when Assignment event is received
    /// and POV operator is NOT the new assignee (should NOT emit any duty)
    #[test]
    fn test_reassignment_pov_is_not_assignee() {
        let old_desc = random_p2tr_desc();
        let new_desc = random_p2tr_desc();

        // Start in Assigned state with POV operator
        let state = DepositState::Assigned {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_POV_IDX,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: old_desc,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::WithdrawalAssigned {
                    assignee: TEST_NONPOV_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: new_desc.clone(),
                },
                expected_state: DepositState::Assigned {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_NONPOV_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: new_desc,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// tests that all states apart from Deposited and Assigned should NOT accept the Assignment
    /// event
    #[test]
    fn test_assignment_invalid_from_other_states() {
        let desc = random_p2tr_desc();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Fulfilled {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
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
                    event: DepositEvent::WithdrawalAssigned {
                        assignee: TEST_ASSIGNEE,
                        deadline: LATER_BLOCK_HEIGHT,
                        recipient_desc: desc.clone(),
                    },
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }

    // ===== Unit Tests for process_fulfillment =====

    /// tests correct transition from Assigned to Fulfilled state when FulfillmentConfirmed event
    /// is received and POV operator is the assignee (should emit RequestPayoutNonces duty)
    #[test]
    fn test_fulfillment_confirmed_from_assigned_pov_is_assignee() {
        let fulfillment_tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = random_p2tr_desc();

        let state = DepositState::Assigned {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_POV_IDX,
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
                    assignee: TEST_POV_IDX,
                    fulfillment_txid: fulfillment_tx.compute_txid(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                    cooperative_payout_deadline: LATER_BLOCK_HEIGHT
                        + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
                },
                expected_duties: vec![DepositDuty::RequestPayoutNonces {
                    deposit_idx: TEST_DEPOSIT_IDX,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// tests correct transition from Assigned to Fulfilled state when FulfillmentConfirmed event
    /// is received and POV operator is NOT the assignee (should NOT emit any duty).
    #[test]
    fn test_fulfillment_confirmed_from_assigned_pov_is_not_assignee() {
        let fulfillment_tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = random_p2tr_desc();

        let state = DepositState::Assigned {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_NONPOV_IDX,
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
                    assignee: TEST_NONPOV_IDX,
                    fulfillment_txid: fulfillment_tx.compute_txid(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                    cooperative_payout_deadline: LATER_BLOCK_HEIGHT
                        + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
                },
                expected_duties: vec![], // No duty since POV is not the assignee
                expected_signals: vec![],
            },
        );
    }

    /// tests that all states apart from Assigned should NOT accept the FulfillmentConfirmed event.
    #[test]
    fn test_fulfillment_confirmed_invalid_from_other_states() {
        let tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = random_p2tr_desc();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Fulfilled {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
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

    // ===== Unit Tests for process_payout_descriptor_received =====

    /// Tests correct transition from Fulfilled to PayoutDescriptorReceived state when
    /// PayoutDescriptorReceived event is received (should emit PublishPayoutNonce duty).
    #[test]
    fn test_payout_descriptor_received_from_fulfilled() {
        let operator_desc = random_p2tr_desc();

        let state = DepositState::Fulfilled {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: generate_txid(),
            fulfillment_height: LATER_BLOCK_HEIGHT,
            cooperative_payout_deadline: LATER_BLOCK_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutDescriptorReceived {
                    operator_desc: operator_desc.clone(),
                },
                expected_state: DepositState::PayoutDescriptorReceived {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT
                        + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
                    operator_desc: operator_desc.clone(),
                    payout_nonces: BTreeMap::new(),
                },
                expected_duties: vec![DepositDuty::PublishPayoutNonce {
                    deposit_outpoint: test_cfg().deposit_outpoint,
                    operator_idx: TEST_ASSIGNEE,
                    operator_desc,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// Tests that all states apart from Fulfilled should NOT accept the PayoutDescriptorReceived
    /// event.
    #[test]
    fn test_payout_descriptor_received_invalid_from_other_states() {
        let desc = random_p2tr_desc();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
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
                    event: DepositEvent::PayoutDescriptorReceived {
                        operator_desc: desc.clone(),
                    },
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }

    // ===== Unit Tests for process_payout_nonce_received =====

    /// tests partial collection: first nonce received, stays in PayoutDescriptorReceived state
    #[test]
    fn test_payout_nonce_received_partial_collection() {
        let desc = random_p2tr_desc();

        let nonce = generate_pubnonce();

        let state = DepositState::PayoutDescriptorReceived {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            operator_desc: desc.clone(),
            payout_nonces: BTreeMap::new(),
        };

        let mut expected_nonces = BTreeMap::new();
        expected_nonces.insert(TEST_ARBITRARY_OPERATOR_IDX, nonce.clone());

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutNonceReceived {
                    payout_nonce: nonce,
                    operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
                },
                expected_state: DepositState::PayoutDescriptorReceived {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    operator_desc: desc,
                    payout_nonces: expected_nonces,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// tests partial collection: nonce received with existing nonces (not yet complete),
    /// stays in PayoutDescriptorReceived state
    #[test]
    fn test_payout_nonce_received_second_nonce() {
        let desc = random_p2tr_desc();

        // Generate nonces for all operators except the last one.
        // This ensures collection can never complete in this test.
        let num_operators = test_operator_table().cardinality();
        let nonces: BTreeMap<OperatorIdx, PubNonce> = (0..num_operators - 1)
            .map(|idx| (idx as OperatorIdx, generate_pubnonce()))
            .collect();

        // Split into initial (all but last generated) and incoming (last generated)
        let (&incoming_idx, _) = nonces.iter().last().unwrap();
        let initial_nonces: BTreeMap<_, _> = nonces
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let incoming_nonce = nonces[&incoming_idx].clone();

        let state = DepositState::PayoutDescriptorReceived {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            operator_desc: desc.clone(),
            payout_nonces: initial_nonces,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutNonceReceived {
                    payout_nonce: incoming_nonce,
                    operator_idx: incoming_idx,
                },
                expected_state: DepositState::PayoutDescriptorReceived {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    operator_desc: desc,
                    payout_nonces: nonces,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// tests all nonces collected with POV operator NOT being the assignee - should emit
    /// PublishPayoutPartial duty
    #[test]
    fn test_payout_nonce_received_all_collected_pov_is_not_assignee() {
        let desc = random_p2tr_desc();

        // Generate nonces for all operators
        let num_operators = test_operator_table().cardinality();
        let all_nonces: BTreeMap<OperatorIdx, PubNonce> = (0..num_operators)
            .map(|idx| (idx as OperatorIdx, generate_pubnonce()))
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_nonces.iter().last().unwrap();
        let initial_nonces: BTreeMap<_, _> = all_nonces
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let incoming_nonce = all_nonces[&incoming_idx].clone();

        let state = DepositState::PayoutDescriptorReceived {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_NONPOV_IDX,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            operator_desc: desc.clone(),
            payout_nonces: initial_nonces,
        };

        // Compute expected aggregated nonce
        let expected_agg_nonce = AggNonce::sum(all_nonces.values().cloned());

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutNonceReceived {
                    payout_nonce: incoming_nonce,
                    operator_idx: incoming_idx,
                },
                expected_state: DepositState::PayoutNoncesCollected {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_NONPOV_IDX,
                    operator_desc: desc,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    payout_nonces: all_nonces,
                    payout_aggregated_nonce: expected_agg_nonce.clone(),
                    payout_partial_signatures: BTreeMap::new(),
                },
                expected_duties: vec![DepositDuty::PublishPayoutPartial {
                    deposit_outpoint: OutPoint::default(),
                    deposit_idx: TEST_DEPOSIT_IDX,
                    agg_nonce: expected_agg_nonce,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// tests all nonces collected with POV operator being the assignee - should NOT emit any duty
    #[test]
    fn test_payout_nonce_received_all_collected_pov_is_assignee() {
        let desc = random_p2tr_desc();

        // Generate nonces for all operators
        let num_operators = test_operator_table().cardinality();
        let all_nonces: BTreeMap<OperatorIdx, PubNonce> = (0..num_operators)
            .map(|idx| (idx as OperatorIdx, generate_pubnonce()))
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_nonces.iter().last().unwrap();
        let initial_nonces: BTreeMap<_, _> = all_nonces
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let incoming_nonce = all_nonces[&incoming_idx].clone();

        let state = DepositState::PayoutDescriptorReceived {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_POV_IDX,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            operator_desc: desc.clone(),
            payout_nonces: initial_nonces,
        };

        // Compute expected aggregated nonce
        let expected_agg_nonce = AggNonce::sum(all_nonces.values().cloned());

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutNonceReceived {
                    payout_nonce: incoming_nonce,
                    operator_idx: incoming_idx,
                },
                expected_state: DepositState::PayoutNoncesCollected {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_POV_IDX,
                    operator_desc: desc,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    payout_nonces: all_nonces,
                    payout_aggregated_nonce: expected_agg_nonce,
                    payout_partial_signatures: BTreeMap::new(),
                },
                expected_duties: vec![], // No duty since POV is the assignee
                expected_signals: vec![],
            },
        );
    }

    /// tests duplicate detection: same operator sends same nonce twice
    #[test]
    fn test_payout_nonce_received_duplicate_same_nonce() {
        let desc = random_p2tr_desc();

        let nonce = generate_pubnonce();

        let initial_state = DepositState::PayoutDescriptorReceived {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            operator_desc: desc,
            payout_nonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut sequence = EventSequence::new(sm, get_state);

        let nonce_event = DepositEvent::PayoutNonceReceived {
            payout_nonce: nonce,
            operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
        };

        sequence.process(nonce_event.clone());
        sequence.assert_no_errors();
        // Second submission with same nonce - should fail with Duplicate
        sequence.process(nonce_event);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            1,
            "Expected 1 error (duplicate), got {}",
            errors.len()
        );
        assert!(
            matches!(errors[0], DSMError::Duplicate { .. }),
            "Expected Duplicate error, got {:?}",
            errors[0]
        );
    }

    /// tests duplicate detection: same operator sends different nonce (still duplicate by operator)
    #[test]
    fn test_payout_nonce_received_duplicate_different_nonce() {
        let desc = random_p2tr_desc();

        let first_nonce = generate_pubnonce();
        let duplicate_nonce = generate_pubnonce();

        let initial_state = DepositState::PayoutDescriptorReceived {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            operator_desc: desc,
            payout_nonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut sequence = EventSequence::new(sm, get_state);

        let first_event = DepositEvent::PayoutNonceReceived {
            payout_nonce: first_nonce,
            operator_idx: TEST_POV_IDX,
        };
        let duplicate_event = DepositEvent::PayoutNonceReceived {
            payout_nonce: duplicate_nonce,
            operator_idx: TEST_POV_IDX,
        };

        sequence.process(first_event);
        sequence.assert_no_errors();
        // Second submission with different nonce but same operator - should fail with Duplicate
        sequence.process(duplicate_event);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            1,
            "Expected 1 error (duplicate), got {}",
            errors.len()
        );
        assert!(
            matches!(errors[0], DSMError::Duplicate { .. }),
            "Expected Duplicate error, got {:?}",
            errors[0]
        );
    }

    /// tests that all states except PayoutDescriptorReceived should reject PayoutNonceReceived
    /// event
    #[test]
    fn test_payout_nonce_received_invalid_from_other_states() {
        let desc = random_p2tr_desc();

        let nonce = generate_pubnonce();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
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
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
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
                    event: DepositEvent::PayoutNonceReceived {
                        payout_nonce: nonce.clone(),
                        operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
                    },
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }

    // ===== Unit Tests for process_payout_partial_received =====

    /// Helper to create test setup for payout partial tests.
    /// Returns (state, signers, key_agg_ctx, agg_nonce, message, operator_desc,
    /// expected_payout_tx).
    fn create_payout_partial_test_setup(
        assignee: OperatorIdx,
    ) -> (
        DepositState,
        Vec<TestMusigSigner>,
        musig2::KeyAggContext,
        AggNonce,
        Message,
        Descriptor,
        Transaction, // expected payout_tx for PublishPayout duty
    ) {
        let signers = test_operator_signers();
        let operator_desc = random_p2tr_desc();

        // Build cooperative payout tx and get signing info
        let payout_tx = test_payout_txn(operator_desc.clone());
        let (key_agg_ctx, message) = get_payout_signing_info(&payout_tx, &signers);
        let expected_payout_tx = payout_tx.as_ref().clone();

        // Generate nonces (counter=0 for this signing round)
        let agg_pubkey = key_agg_ctx.aggregated_pubkey();
        let nonce_counter = 0u64;
        let nonces: BTreeMap<OperatorIdx, PubNonce> = signers
            .iter()
            .map(|s| (s.operator_idx(), s.pubnonce(agg_pubkey, nonce_counter)))
            .collect();
        let agg_nonce = AggNonce::sum(nonces.values().cloned());

        let state = DepositState::PayoutNoncesCollected {
            block_height: INITIAL_BLOCK_HEIGHT,
            assignee,
            operator_desc: operator_desc.clone(),
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            payout_nonces: nonces,
            payout_aggregated_nonce: agg_nonce.clone(),
            payout_partial_signatures: BTreeMap::new(),
        };

        (
            state,
            signers,
            key_agg_ctx,
            agg_nonce,
            message,
            operator_desc,
            expected_payout_tx,
        )
    }

    /// tests partial collection: first partial received, stays in PayoutNoncesCollected state
    #[test]
    fn test_payout_partial_received_partial_collection() {
        let (state, signers, key_agg_ctx, agg_nonce, message, operator_desc, _) =
            create_payout_partial_test_setup(TEST_ASSIGNEE);

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::PayoutNoncesCollected { payout_nonces, .. } = &state {
            payout_nonces.clone()
        } else {
            panic!("Expected PayoutNoncesCollected state");
        };

        // Generate valid partial signature from a non-assignee operator
        let nonce_counter = 0u64;
        let partial_sig = signers[TEST_NON_ASSIGNEE_IDX as usize].sign(
            &key_agg_ctx,
            nonce_counter,
            &agg_nonce,
            message,
        );

        let mut expected_partials = BTreeMap::new();
        expected_partials.insert(TEST_NON_ASSIGNEE_IDX, partial_sig);

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutPartialReceived {
                    partial_signature: partial_sig,
                    operator_idx: TEST_NON_ASSIGNEE_IDX,
                },
                expected_state: DepositState::PayoutNoncesCollected {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    operator_desc,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    payout_nonces: nonces,
                    payout_aggregated_nonce: agg_nonce,
                    payout_partial_signatures: expected_partials,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// tests all partials collected when POV is the assignee - should emit
    /// PublishPayout duty
    #[test]
    fn test_payout_partial_received_all_collected_pov_is_assignee() {
        let (
            mut state,
            signers,
            key_agg_ctx,
            agg_nonce,
            message,
            operator_desc,
            expected_payout_tx,
        ) = create_payout_partial_test_setup(TEST_POV_IDX);

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::PayoutNoncesCollected { payout_nonces, .. } = &state {
            payout_nonces.clone()
        } else {
            panic!("Expected PayoutNoncesCollected state");
        };

        // Generate partial signatures for all non-assignee operators
        let nonce_counter = 0u64;
        let all_partials: BTreeMap<OperatorIdx, _> = signers
            .iter()
            .filter(|s| s.operator_idx() != TEST_POV_IDX)
            .map(|s| {
                let sig = s.sign(&key_agg_ctx, nonce_counter, &agg_nonce, message);
                (s.operator_idx(), sig)
            })
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_partials.iter().last().unwrap();
        let initial_partials: BTreeMap<_, _> = all_partials
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, &v)| (k, v))
            .collect();
        let incoming_partial = all_partials[&incoming_idx];

        // Pre-populate state with initial partials
        if let DepositState::PayoutNoncesCollected {
            payout_partial_signatures,
            ..
        } = &mut state
        {
            *payout_partial_signatures = initial_partials;
        }

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutPartialReceived {
                    partial_signature: incoming_partial,
                    operator_idx: incoming_idx,
                },
                expected_state: DepositState::PayoutNoncesCollected {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_POV_IDX,
                    operator_desc,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    payout_nonces: nonces,
                    payout_aggregated_nonce: agg_nonce,
                    payout_partial_signatures: all_partials,
                },
                expected_duties: vec![DepositDuty::PublishPayout {
                    payout_tx: expected_payout_tx,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// tests all partials collected when POV is NOT the assignee - should NOT
    /// emit any duty
    #[test]
    fn test_payout_partial_received_all_collected_pov_is_not_assignee() {
        let (mut state, signers, key_agg_ctx, agg_nonce, message, operator_desc, _) =
            create_payout_partial_test_setup(TEST_NONPOV_IDX);

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::PayoutNoncesCollected { payout_nonces, .. } = &state {
            payout_nonces.clone()
        } else {
            panic!("Expected PayoutNoncesCollected state");
        };

        // Generate partial signatures for all non-assignee operators
        let nonce_counter = 0u64;
        let all_partials: BTreeMap<OperatorIdx, _> = signers
            .iter()
            .filter(|s| s.operator_idx() != TEST_NONPOV_IDX)
            .map(|s| {
                let sig = s.sign(&key_agg_ctx, nonce_counter, &agg_nonce, message);
                (s.operator_idx(), sig)
            })
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_partials.iter().last().unwrap();
        let initial_partials: BTreeMap<_, _> = all_partials
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, &v)| (k, v))
            .collect();
        let incoming_partial = all_partials[&incoming_idx];

        // Pre-populate state with initial partials
        if let DepositState::PayoutNoncesCollected {
            payout_partial_signatures,
            ..
        } = &mut state
        {
            *payout_partial_signatures = initial_partials;
        }

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutPartialReceived {
                    partial_signature: incoming_partial,
                    operator_idx: incoming_idx,
                },
                expected_state: DepositState::PayoutNoncesCollected {
                    block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_NONPOV_IDX,
                    operator_desc,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    payout_nonces: nonces,
                    payout_aggregated_nonce: agg_nonce,
                    payout_partial_signatures: all_partials,
                },
                expected_duties: vec![], // No duty since POV is not assignee
                expected_signals: vec![],
            },
        );
    }

    /// tests duplicate detection: same operator sends same partial signature twice
    #[test]
    fn test_payout_partial_received_duplicate_same_signature() {
        let (state, signers, key_agg_ctx, agg_nonce, message, _, _) =
            create_payout_partial_test_setup(TEST_ASSIGNEE);

        let sm = create_sm(state);
        let mut sequence = EventSequence::new(sm, get_state);

        // Generate valid partial signature from a non-assignee operator
        let nonce_counter = 0u64;
        let partial_sig = signers[TEST_NON_ASSIGNEE_IDX as usize].sign(
            &key_agg_ctx,
            nonce_counter,
            &agg_nonce,
            message,
        );

        let event = DepositEvent::PayoutPartialReceived {
            partial_signature: partial_sig,
            operator_idx: TEST_NON_ASSIGNEE_IDX,
        };

        sequence.process(event.clone());
        sequence.assert_no_errors();
        // Second submission with same signature - should fail with Duplicate
        sequence.process(event);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            1,
            "Expected 1 error (duplicate), got {}",
            errors.len()
        );
        assert!(
            matches!(errors[0], DSMError::Duplicate { .. }),
            "Expected Duplicate error, got {:?}",
            errors[0]
        );
    }

    /// tests duplicate detection: same operator sends different partial signature
    #[test]
    fn test_payout_partial_received_duplicate_different_signature() {
        let (state, signers, key_agg_ctx, agg_nonce, message, _, _) =
            create_payout_partial_test_setup(TEST_ASSIGNEE);

        let sm = create_sm(state);
        let mut sequence = EventSequence::new(sm, get_state);

        // Generate a valid partial signature from a non-assignee operator
        let first_partial =
            signers[TEST_NON_ASSIGNEE_IDX as usize].sign(&key_agg_ctx, 0, &agg_nonce, message);

        // Generate a random (different) partial signature
        let duplicate_partial = generate_partial_signature();

        let first_event = DepositEvent::PayoutPartialReceived {
            partial_signature: first_partial,
            operator_idx: TEST_NON_ASSIGNEE_IDX,
        };
        let duplicate_event = DepositEvent::PayoutPartialReceived {
            partial_signature: duplicate_partial,
            operator_idx: TEST_NON_ASSIGNEE_IDX,
        };

        sequence.process(first_event);
        sequence.assert_no_errors();
        // Second submission with different signature but same operator - should fail with Duplicate
        sequence.process(duplicate_event);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            1,
            "Expected 1 error (duplicate), got {}",
            errors.len()
        );
        assert!(
            matches!(errors[0], DSMError::Duplicate { .. }),
            "Expected Duplicate error, got {:?}",
            errors[0]
        );
    }

    /// tests that invalid partial signature is rejected with Rejected error
    #[test]
    fn test_payout_partial_received_invalid_signature() {
        let (state, _, _, _, _, _, _) = create_payout_partial_test_setup(TEST_ASSIGNEE);

        // Generate an invalid/random partial signature
        let invalid_partial = generate_partial_signature();

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: state,
                event: DepositEvent::PayoutPartialReceived {
                    partial_signature: invalid_partial,
                    operator_idx: TEST_NON_ASSIGNEE_IDX,
                },
                expected_error: |e| {
                    matches!(
                        e,
                        DSMError::Rejected { reason, .. }
                        if reason == "Partial Signature Verification Failed"
                    )
                },
            },
        );
    }

    /// tests that all states except PayoutNoncesCollected should reject PayoutPartialReceived event
    #[test]
    fn test_payout_partial_received_invalid_from_other_states() {
        let desc = random_p2tr_desc();

        let partial_sig = generate_partial_signature();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
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
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
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
                    event: DepositEvent::PayoutPartialReceived {
                        partial_signature: partial_sig,
                        operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
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
            cooperative_payout_deadline: FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
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
