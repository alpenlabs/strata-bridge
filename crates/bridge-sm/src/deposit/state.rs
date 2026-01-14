//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use bitcoin::OutPoint;
use musig2::{
    AggNonce, PartialSignature, PubNonce, aggregate_partial_signatures,
    secp256k1::schnorr::{self, Signature},
};
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    operator_table::OperatorTable,
    scripts::taproot::TaprootWitness,
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};
use strata_bridge_tx_graph2::transactions::{PresignedTx, deposit::DepositTx};

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
}

impl DepositCfg {
    /// Returns the deposit index.
    pub const fn deposit_idx(&self) -> DepositIdx {
        self.deposit_idx
    }

    /// Returns the deposit request outpoint.
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

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Operators whose spending graphs have been generated for this deposit.
        linked_graphs: BTreeSet<OperatorIdx>,
    },
    /// This state represents the phase where all operator graphs have been generated.
    ///
    /// This happens from the point where all operator graphs are generated until all public nonces
    /// required to sign the deposit transaction are collected.
    GraphGenerated {
        /// The unsigned deposit transaction to be signed.
        deposit_transaction: DepositTx,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state represents the phase where all deposit public nonces have been collected.
    ///
    /// This happens from the collection of all deposit public nonces until all partial signatures
    /// have been received.
    DepositNoncesCollected {
        /// The deposit transaction being signed.
        deposit_transaction: DepositTx,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Aggregated nonce used to validate partial signatures.
        agg_nonce: AggNonce,

        /// Partial signatures from operators for the deposit transaction.
        partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This state represents the phase where all partial signatures have been collected.
    ///
    /// This happens from the collection of all partial signatures until the deposit transaction
    /// is broadcast and confirmed.
    DepositPartialsCollected {
        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// The fully signed deposit transaction.
        deposit_transaction: DepositTx,

        /// Aggregated signature for the deposit transaction.
        agg_signature: Signature,
    },
    /// TODO: (@mukeshdroid)
    Deposited {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@mukeshdroid)
    Assigned {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@mukeshdroid)
    Fulfilled {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
        /// The index of the operator assigned to the deposit.
        assignee: OperatorIdx,
        /// The height of the block where the withdrawal fulfillment was confirmed.
        fulfillment_height: u64,
    },
    /// TODO: (@mukeshdroid)
    PayoutNoncesCollected {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
        /// The index of the operator assigned to the deposit.
        assignee: OperatorIdx,
        /// The height of the block where the withdrawal fulfillment was confirmed.
        fulfillment_height: u64,
    },
    /// TODO: (@mukeshdroid)
    PayoutPartialsCollected {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
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
        let display_str = match self {
            DepositState::Created { .. } => "Created".to_string(),
            DepositState::GraphGenerated { .. } => "GraphGenerated".to_string(),
            DepositState::DepositNoncesCollected { .. } => "DepositNoncesCollected".to_string(),
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected".to_string(),
            DepositState::Deposited => "Deposited".to_string(),
            DepositState::Assigned => "Assigned".to_string(),
            DepositState::Fulfilled => "Fulfilled".to_string(),
            DepositState::PayoutNoncesCollected => "PayoutNoncesCollected".to_string(),
            DepositState::PayoutPartialsCollected => "PayoutPartialsCollected".to_string(),
            DepositState::CooperativePathFailed => "CooperativePathFailed".to_string(),
            DepositState::Spent => "Spent".to_string(),
            DepositState::Aborted => "Aborted".to_string(),
        };
        write!(f, "{}", display_str)
    }
}

impl DepositState {
    /// Creates a new Deposit State in the `Created` state.
    pub const fn new(
        deposit_transaction: DepositTx,
        drt_block_height: BitcoinBlockHeight,
        output_index: u32,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositState::Created {
            deposit_transaction,
            drt_block_height,
            output_index,
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
        match event {
            DepositEvent::DepositRequest => self.process_deposit_request(),
            DepositEvent::UserTakeBack { tx } => self.process_drt_takeback(tx),
            DepositEvent::GraphMessage(_graph_msg) => self.process_graph_available(),
            DepositEvent::GraphMessage(graph_msg) => self.process_graph_available(graph_msg),
            DepositEvent::NonceReceived {
                nonce,
                operator_idx,
            } => self.process_nonce_received(nonce, operator_idx),
            DepositEvent::PartialReceived {
                partial_sig,
                operator_idx,
            } => self.process_partial_received(partial_sig, operator_idx),
            DepositEvent::DepositConfirmed => self.process_deposit_confirmed(),
            DepositEvent::Assignment => self.process_assignment(),
            DepositEvent::FulfillmentConfirmed => self.process_fulfillment(),
            DepositEvent::PayoutNonceReceived => self.process_payout_nonce_received(),
            DepositEvent::PayoutPartialReceived => self.process_payout_partial_received(),
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
    pub const fn new(
        cfg: DepositCfg,
        deposit_transaction: DepositTx,
        drt_block_height: BitcoinBlockHeight,
        output_index: u32,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(
                deposit_transaction,
                drt_block_height,
                output_index,
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

    /// Processes the deposit request event.
    ///
    /// This handles the initial deposit request and instructs the operator to publish
    /// their nonce for the deposit transaction signing process.
    fn process_deposit_request(&self) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        match self.state() {
            DepositState::Created { .. } => Ok(DSMOutput::with_duties(vec![
                DepositDuty::PublishDepositNonce {
                    deposit_out_point: self.cfg().deposit_outpoint(),
                },
            ])),
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::DepositRequest.to_string(),
            }),
        }
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
                        state: self.state().clone(),
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
                state: self.state().clone(),
                event: DepositEvent::UserTakeBack { tx }.into(),
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

        match self.state_mut() {
            DepositState::Created {
                deposit_transaction,
                drt_block_height,
                output_index,
                block_height,
                linked_graphs,
            } => match graph_msg {
                GraphToDeposit::GraphAvailable { operator_idx } => {
                    linked_graphs.insert(operator_idx);

                    if linked_graphs.len() == operator_table_cardinality {
                        // All operators have linked their graphs, transition to GraphGenerated
                        // state
                        let new_state = DepositState::GraphGenerated {
                            deposit_transaction: deposit_transaction.clone(),
                            drt_block_height: *drt_block_height,
                            output_index: *output_index,
                            block_height: *block_height,
                            pubnonces: BTreeMap::new(),
                        };
                        self.state = new_state;
                    }

                    Ok(DSMOutput::new())
                }
            },
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::GraphMessage(graph_msg).to_string(),
            }),
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

        match self.state_mut() {
            DepositState::GraphGenerated {
                deposit_transaction,
                drt_block_height,
                output_index,
                block_height,
                pubnonces,
            } => {
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
                        drt_block_height: *drt_block_height,
                        output_index: *output_index,
                        block_height: *block_height,
                        agg_nonce: agg_nonce.clone(),
                        partial_signatures: BTreeMap::new(),
                    };
                    self.state = new_state;

                    // Create the duty to publish deposit partials
                    let duty = DepositDuty::PublishDepositPartial {
                        deposit_out_point: self.cfg().deposit_outpoint(),
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

        match self.state_mut() {
            DepositState::DepositNoncesCollected {
                deposit_transaction,
                drt_block_height,
                output_index,
                block_height,
                agg_nonce,
                partial_signatures,
            } => {
                // Insert the new partial signature into the map
                partial_signatures.insert(operator_idx, partial_sig);

                // Check if we have collected all partial signatures
                if partial_signatures.len() == operator_table_cardinality {
                    // Clone values before transition to avoid borrowing issues
                    let deposit_tx = deposit_transaction.clone();
                    let drt_height = *drt_block_height;
                    let out_idx = *output_index;
                    let blk_height = *block_height;

                    let signing_info = deposit_transaction.signing_info();
                    let info = signing_info
                        .first()
                        .expect("deposit transaction must have signing info");

                    let sighash = info.sighash;
                    let tweak = info
                        .tweak
                        .expect("DRT->DT key-path spend must include a taproot tweak")
                        .expect("tweak must be present for deposit transaction");

                    let tap_witness = TaprootWitness::Tweaked { tweak };

                    let key_agg_ctx = create_agg_ctx(btc_keys, &tap_witness)
                        .expect("must be able to create key aggregation context");

                    let agg_signature: schnorr::Signature = aggregate_partial_signatures(
                        &key_agg_ctx,
                        agg_nonce,
                        partial_signatures.values().cloned(),
                        sighash.as_ref(),
                    )
                    .expect("partial signatures must be valid");

                    // Transition to DepositPartialsCollected state
                    let new_state = DepositState::DepositPartialsCollected {
                        deposit_transaction: deposit_tx.clone(),
                        drt_block_height: drt_height,
                        output_index: out_idx,
                        block_height: blk_height,
                        agg_signature,
                    };
                    self.state = new_state;

                    // Create the duty to publish the deposit transaction
                    let duty = DepositDuty::PublishDeposit {
                        deposit_tx,
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
            }),
        }
    }

    fn process_deposit_confirmed(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_assignment(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_fulfillment(&self) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        todo!("@mukeshdroid")
    }

    fn process_payout_nonce_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_payout_partial_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
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
                state: self.state().clone(),
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
                state: self.state().clone(),
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
                fulfillment_height,
            }
            | DepositState::PayoutNoncesCollected {
                block_height,
                assignee,
                fulfillment_height,
                ..
            } => {
                let assignee = *assignee; // reassign to get past the borrow-checker

                // Check for `>=` instead of just `>` to allow disabling cooperative payout by
                // setting this param to zero. This will come into effect after a 1-block delay
                // (when the next block is observed).
                let has_cooperative_payout_timed_out =
                    new_block_height >= *fulfillment_height + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS;

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
                state: self.state().clone(),
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

    use std::str::FromStr;

    use proptest::prelude::*;
    use strata_bridge_test_utils::prelude::generate_spending_tx;

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
            fulfillment_height: FULFILLMENT_HEIGHT,
        };

        // Block that exceeds timeout (COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS)
        let timeout_height = FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS;
        let block_height = timeout_height;

        let mut sm = create_sm(state);
        let result = sm.process_new_block(block_height);

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::CooperativePathFailed {
                block_height: timeout_height
            }
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
            fulfillment_height: FULFILLMENT_HEIGHT,
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

#[cfg(test)]
mod prop_tests {
    // Strategy generators for individual types
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};
    use proptest::{prelude::*, strategy::ValueTree};
    use strata_bridge_primitives::operator_table::prop_test_generators::arb_operator_table;

    use super::*;

    // Generates bitcoin block heights in a realistic range
    prop_compose! {
        fn arb_block_height()(height in 500_000..800_000u64) -> BitcoinBlockHeight {
            BitcoinBlockHeight::from(height)
        }
    }

    // Generates deposit indices for testing
    prop_compose! {
        fn arb_deposit_idx()(idx in 0u32..1000u32) -> DepositIdx {
            DepositIdx::from(idx)
        }
    }

    // Generates random bitcoin transaction IDs
    prop_compose! {
        fn arb_txid()(bs in any::<[u8; 32]>()) -> Txid {
            Txid::from_raw_hash(*bitcoin::hashes::sha256d::Hash::from_bytes_ref(&bs))
        }
    }

    // Generates bitcoin outpoints with random txid and vout
    prop_compose! {
        fn arb_outpoint()(txid in arb_txid(), vout in 0..10u32) -> OutPoint {
            OutPoint { txid, vout }
        }
    }

    // Generates transaction inputs with random data
    prop_compose! {
        fn arb_input()(
            previous_output in arb_outpoint(),
            script_sig in any::<[u8; 32]>().prop_map(|b| ScriptBuf::from_bytes(b.to_vec())),
            sequence in any::<u32>().prop_map(Sequence::from_consensus),
        ) -> TxIn {
            TxIn {
                previous_output,
                script_sig,
                sequence,
                witness: Witness::new(),
            }
        }
    }

    // Generates transaction outputs with fixed 10 BTC value
    prop_compose! {
        fn arb_output()(
            script_pubkey in any::<[u8; 32]>().prop_map(|b| ScriptBuf::from_bytes(b.to_vec()))
        ) -> TxOut {
            TxOut {
                value: Amount::from_btc(10.0).unwrap(),
                script_pubkey,
            }
        }
    }

    // Generates deposit configuration with random components
    prop_compose! {
        fn arb_deposit_cfg()(
            deposit_idx in arb_deposit_idx(),
            deposit_outpoint in arb_outpoint(),
            operator_table in arb_operator_table()
        ) -> DepositCfg {
            DepositCfg {
                deposit_idx,
                deposit_outpoint,
                operator_table,
            }
        }
    }

    // Generates random transactions with variable input/output counts
    prop_compose! {
        fn arb_deposit_transaction()(
            max_num_ins in 2..10u32,
            max_num_outs in 2..10u32
        )(
            _ins in prop::collection::vec(arb_input(), (1, max_num_ins as usize)),
            _outs in prop::collection::vec(arb_output(), (1, max_num_outs as usize))
        ) -> DepositTx {
           todo!("Implement DepositTx generation logic for prop tests" )
        }
    }

    // Generates a deposit state machine initialized in Created state
    prop_compose! {
        fn arb_deposit_state_machine()(
            cfg in arb_deposit_cfg(),
            deposit_transaction in arb_deposit_transaction(),
            drt_block_height in arb_block_height(),
            output_index in 0u32..10u32,
            block_height in arb_block_height(),
        ) -> DepositSM {
            DepositSM::new(
                cfg,
                deposit_transaction,
                drt_block_height,
                output_index,
                block_height,
            )
        }
    }

    proptest! {
        // run only 32 test cases
        #![proptest_config(ProptestConfig {
            cases: 32,
            .. ProptestConfig::default()
        })]
        #[test]
        fn test_process_deposit_request(mut sm in arb_deposit_state_machine()) {
            // Capture the initial state
            let state_before = sm.state().clone();

            // Extract the expected outpoint from the config
            let expected_outpoint = sm.cfg().deposit_outpoint();

            // Process the DepositRequest event
            let result = sm.process_event(DepositEvent::DepositRequest);

            // Verify the event processing succeeded
            prop_assert!(result.is_ok());
            let output = result.unwrap();

            // Verify exactly one duty is emitted and no signals
            prop_assert!(!output.duties.is_empty(), "Should emit at least one duty");
            prop_assert!(
                matches!(output.duties[0], DepositDuty::PublishDepositNonce { .. }),
                "First duty should be PublishDepositNonce"
            );

            // Verify the duty is the correct type with the correct outpoint
            let DepositDuty::PublishDepositNonce { deposit_out_point } = &output.duties[0] else {
                unreachable!("Already verified duty type above");
            };
            prop_assert_eq!(*deposit_out_point, expected_outpoint,
                "Duty outpoint should match state's deposit_request_outpoint");

            // Verify the state remains unchanged
            let state_after = sm.state().clone();
            prop_assert_eq!(state_before, state_after, "State should remain unchanged");
        }

        #[test]
        fn test_process_graph_available_full_sequence(mut sm in arb_deposit_state_machine()) {
            let operator_indices: Vec<u32> = sm.cfg().operator_table.operator_idxs()
                .into_iter().collect();

            // Skip test if no operators (shouldn't happen, but be defensive)
            prop_assume!(!operator_indices.is_empty(), "Cannot test with empty operator table");

            // Process GraphAvailable for first N-1 operators (should stay in Created state)
            let all_but_last = &operator_indices[..operator_indices.len() - 1];
            for (i, &operator_idx) in all_but_last.iter().enumerate() {
                let graph_msg = GraphToDeposit::GraphAvailable {
                    operator_idx
                };
                let result = sm.process_graph_available(graph_msg);

                // Verify the event processing succeeded
                prop_assert!(result.is_ok());
                let output = result.unwrap();

                // Verify no duties or signals are emitted
                prop_assert!(output.duties.is_empty(), "Expected no duties");
                prop_assert!(output.signals.is_empty(), "Expected no signals");

                // Should remain in Created state
                let state_after = sm.state().clone();
                prop_assert!(matches!(state_after, DepositState::Created { .. }),
                    "Should remain in Created state until all operators linked");

                let DepositState::Created { linked_graphs: new_linked_graphs, .. } = &state_after else {
                    unreachable!("Already verified state type above");
                };

                // Verify the operator was added to linked_graphs
                prop_assert_eq!(new_linked_graphs.len(), i + 1);
                prop_assert!(new_linked_graphs.contains(&operator_idx));
            }

            // Process the last operator (should transition to GraphGenerated state)
            let last_operator_idx = *operator_indices.last().unwrap();
            let graph_msg = GraphToDeposit::GraphAvailable {
                operator_idx: last_operator_idx
            };
            let result = sm.process_graph_available(graph_msg);

            // Verify the event processing succeeded
            prop_assert!(result.is_ok());
            let output = result.unwrap();

            // Verify no duties or signals are emitted
            prop_assert!(output.duties.is_empty(), "Expected no duties");
            prop_assert!(output.signals.is_empty(), "Expected no signals");

            // Should transition to GraphGenerated state
            let state_after = sm.state().clone();
            prop_assert!(matches!(state_after, DepositState::GraphGenerated { .. }),
                "Should transition to GraphGenerated after all operators linked");

            // Test that processing graph_available again returns error and state unchanged
            let state_before_error_test = sm.state().clone();
            let graph_msg_again = GraphToDeposit::GraphAvailable {
                operator_idx: last_operator_idx
            };
            let error_result = sm.process_graph_available(graph_msg_again);

            // Verify the event processing failed with the expected error
            prop_assert!(error_result.is_err(), "Expected error when processing graph_available in GraphGenerated state");
            let error = error_result.unwrap_err();
            prop_assert!(matches!(error, DSMError::InvalidEvent { .. }), "Expected InvalidEvent error");

            // Verify the state remains unchanged
            let state_after_error_test = sm.state().clone();
            prop_assert_eq!(state_before_error_test, state_after_error_test, "State should remain unchanged after error");

        }

        #[test]
        fn test_process_graph_available_with_duplicates(mut sm in arb_deposit_state_machine()) {
            // Get the actual operator indices from the state machine
            let operator_indices: Vec<u32> = sm.cfg().operator_table.operator_idxs()
                .into_iter().collect();

            // Skip test if no operators
            prop_assume!(!operator_indices.is_empty());

            // Generate messages that include all operators with potential duplicates
            let mut test_messages = Vec::new();
            for &idx in &operator_indices {
                test_messages.push(GraphToDeposit::GraphAvailable { operator_idx: idx });
            }

            // Add some duplicates
            for &idx in &operator_indices {
                if idx % 2 == 0 { // Add duplicates for even-indexed operators
                    test_messages.push(GraphToDeposit::GraphAvailable { operator_idx: idx });
                }
            }

            // Shuffle the list using proptest
            let test_messages = Just(test_messages).prop_shuffle().new_tree(&mut Default::default()).unwrap().current();

            // Process messages until we reach the next state
            for message in test_messages {
                let result = sm.process_graph_available(message);

                match sm.state() {
                    DepositState::Created { .. } => {
                        // Still in Created state, message should succeed
                        prop_assert!(result.is_ok(), "Message should succeed in Created state");
                    }
                    DepositState::GraphGenerated { .. } => {
                        // We've transitioned! This is expected.
                        prop_assert!(result.is_ok(), "Transition message should succeed");
                        break;
                    }
                    _ => prop_assert!(false, "Unexpected state during processing")
                }
            }
        }

    }
}
