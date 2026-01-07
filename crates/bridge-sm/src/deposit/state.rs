//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::fmt::Display;

use bitcoin::{Block, OutPoint, Transaction};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{DepositIdx, OperatorIdx},
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
}

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@MdTeach)
    DepositPartialsCollected {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
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
        let state_str = match self {
            DepositState::Created { .. } => "Created",
            DepositState::GraphGenerated { .. } => "GraphGenerated",
            DepositState::DepositNoncesCollected { .. } => "DepositNoncesCollected",
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected",
            DepositState::Deposited { .. } => "Deposited",
            DepositState::Assigned { .. } => "Assigned",
            DepositState::Fulfilled { .. } => "Fulfilled",
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesColletced",
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

    // TODO: (@Rajil1213, @MdTeach, @mukeshdroid) Add introspection methods here
}

// TODO: (@Rajil1213) Move `DepositSM` to a separate `state-machine` module once complete (to avoid
// merge conflicts now).

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            DepositEvent::NonceReceived => self.process_nonce_received(),
            DepositEvent::PartialReceived => self.process_partial_received(),
            DepositEvent::DepositConfirmed => self.process_deposit_confirmed(),
            DepositEvent::Assignment => self.process_assignment(),
            DepositEvent::FulfillmentConfirmed => self.process_fulfillment(),
            DepositEvent::PayoutNonceReceived => self.process_payout_nonce_received(),
            DepositEvent::PayoutPartialReceived => self.process_payout_partial_received(),
            DepositEvent::PayoutConfirmed { tx } => self.process_payout_confirmed(&tx),
            DepositEvent::NewBlock { block } => self.process_new_block(&block),
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
                if tx
                    .input
                    .iter()
                    .find(|input| input.previous_output == *deposit_request_outpoint)
                    .is_some_and(|input| input.witness.len() > 1)
                // HACK: (@Rajil1213) take back path is a script-spend and so has multiple witness
                // elements, as opposed to the Deposit Transaction which is a key-spend and has only
                // one witness element (the schnorr signature). The proper way to check this is to
                // see if the witness contains the takeback script as the script
                // being used. But a length-check is both simpler and sufficient.
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
                    })
                }
            }
            DepositState::Aborted => Err(DSMError::Duplicate {
                state: self.state().clone(),
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
    /// - A sweep transaction in the event of a hard upgrade (migration) of deposited UTXOs
    /// - A cooperative payout transaction, if the cooperative path was successful.
    /// - An uncontested payout transaction, if the assignee published a claim that went
    ///   uncontested.
    /// - A contested payout transaction, if the assignee published a claim that was contested but
    ///   not successfully.
    fn process_payout_confirmed(&mut self, tx: &Transaction) -> DSMResult<DSMOutput> {
        match self.state() {
            // It must be the sweep transaction in case of a hard upgrade
            DepositState::Deposited { .. }
            // It must be the cooperative payout transaction
            | DepositState::PayoutPartialsCollected { .. }
            // It can be a contested/uncontested payout transaction
            // This can also be a coopertive payout transaction due to delayed settlement of the
            // transaction on-chain or because each operator has a different configuration for how
            // long to wait till the cooperative payout path is considered failed.
            | DepositState::CooperativePathFailed { .. }
            // The assignee can withhold their own partial and broadcast the payout tx themselves,
            // In this case, we still want other nodes' state machines to transition properly.
            // This can also happen if there are network delays.
            | DepositState::PayoutNoncesCollected { .. } => {
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
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.to_string(),
                state: self.state.to_string(),
                reason: None
            }),
        }
    }

    fn process_new_block(&mut self, block: &Block) -> DSMResult<DSMOutput> {
        let new_block_height = block.bip34_block_height().unwrap_or(0);

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

                // Check for `=` instead of just `>` to allow disabling cooperative payout by
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
            }),
        }
    }
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;
    use strata_bridge_test_utils::prelude::generate_block_with_height;

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

    // ===== Unit Tests for process_new_block =====

    #[test]
    fn test_new_block_updates_height_in_deposited() {
        let state = DepositState::Deposited {
            block_height: INITIAL_BLOCK_HEIGHT,
        };

        let block = generate_block_with_height(LATER_BLOCK_HEIGHT);

        let mut sm = create_sm(state);
        let result = sm.process_new_block(&block);

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
        let timeout_height = FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS + 1;
        let block = generate_block_with_height(timeout_height);

        let mut sm = create_sm(state);
        let result = sm.process_new_block(&block);

        assert!(result.is_ok());
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
        let block = generate_block_with_height(LATER_BLOCK_HEIGHT);

        for terminal_state in [DepositState::Spent, DepositState::Aborted] {
            let mut sm = create_sm(terminal_state.clone());
            let result = sm.process_new_block(&block);

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

    // Property: State machine is deterministic
    prop_deterministic!(
        DepositSM,
        create_sm,
        get_state,
        any::<DepositState>(),
        any::<DepositEvent>()
    );

    // Property: No silent acceptance
    prop_no_silent_acceptance!(
        DepositSM,
        create_sm,
        get_state,
        any::<DepositState>(),
        any::<DepositEvent>()
    );

    // Property: Terminal states reject all events
    prop_terminal_states_reject!(
        DepositSM,
        create_sm,
        arb_terminal_state(),
        any::<DepositEvent>()
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
        let timeout_height = FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS + 1;
        for height in (FULFILLMENT_HEIGHT + 1)..=timeout_height {
            seq.process(DepositEvent::NewBlock {
                block: generate_block_with_height(height),
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
