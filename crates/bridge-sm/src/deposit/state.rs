//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use bitcoin::{OutPoint, Transaction};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::schnorr::Signature};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
    },
    signals::{DepositSignal, GraphToDeposit},
    state_machine::{SMOutput, StateMachine},
};

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.

/// The static configuration for a Deposit State Machine.
///
/// These configurations are set at the creation of the Deposit State Machine and do not change
/// during any state transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositCfg {
    /// The index of the deposit being tracked in a Deposit State Machine.
    deposit_idx: DepositIdx,
    /// The outpoint of the deposit being tracked in a Deposit State Machine.
    deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    operator_table: OperatorTable,
}

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositState {
    /// This state represents the initial phase after deposit request confirmation.
    ///
    /// This happens from the confirmation of the deposit request transaction until all operators
    /// have generated and linked their graphs for this deposit.
    Created {
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// The unsigned deposit transaction derived from the deposit request.
        deposit_transaction: Transaction,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO, used for abort handling.
        deposit_request_outpoint: OutPoint,

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
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// The unsigned deposit transaction to be signed.
        deposit_transaction: Transaction,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO.
        deposit_request_outpoint: OutPoint,

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
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// The deposit transaction being signed.
        deposit_transaction: Transaction,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO.
        deposit_request_outpoint: OutPoint,

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
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO.
        deposit_request_outpoint: OutPoint,

        /// The fully signed deposit transaction.
        deposit_transaction: Transaction,

        /// Aggregated signature for the deposit transaction.
        agg_signature: Signature,
    },
    /// TODO: (@mukeshdroid)
    Deposited,
    /// TODO: (@mukeshdroid)
    Assigned,
    /// TODO: (@mukeshdroid)
    Fulfilled,
    /// TODO: (@mukeshdroid)
    PayoutNoncesCollected,
    /// TODO: (@mukeshdroid)
    PayoutPartialsCollected,
    /// TODO: (@Rajil1213)
    CooperativePathFailed,
    /// TODO: (@Rajil1213)
    Spent,
    /// TODO: (@Rajil1213)
    Aborted,
}

impl Display for DepositState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            DepositState::Created {
                deposit_idx,
                block_height,
                ..
            } => format!("Created (deposit: {deposit_idx}, height: {block_height})"),
            DepositState::GraphGenerated {
                deposit_idx,
                block_height,
                ..
            } => format!("GraphGenerated (deposit: {deposit_idx}, height: {block_height})"),
            DepositState::DepositNoncesCollected {
                deposit_idx,
                block_height,
                ..
            } => format!("DepositNoncesCollected (deposit: {deposit_idx}, height: {block_height})"),
            DepositState::DepositPartialsCollected {
                deposit_idx,
                block_height,
                ..
            } => {
                format!("DepositPartialsCollected (deposit: {deposit_idx}, height: {block_height})")
            }
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
        deposit_idx: u32,
        deposit_transaction: Transaction,
        drt_block_height: BitcoinBlockHeight,
        deposit_request_outpoint: OutPoint,
        output_index: u32,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositState::Created {
            deposit_idx,
            deposit_transaction,
            drt_block_height,
            deposit_request_outpoint,
            output_index,
            block_height,
            linked_graphs: BTreeSet::new(),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSM {
    /// The static configuration for this Deposit State Machine.
    cfg: DepositCfg,
    /// The current state of the Deposit State Machine.
    state: DepositState,
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
            DepositEvent::GraphMessage(graph_msg) => self.process_graph_available(graph_msg),
            DepositEvent::NonceReceived => self.process_nonce_received(),
            DepositEvent::PartialReceived => self.process_partial_received(),
            DepositEvent::DepositConfirmed => self.process_deposit_confirmed(),
            DepositEvent::Assignment => self.process_assignment(),
            DepositEvent::FulfillmentConfirmed => self.process_fulfillment(),
            DepositEvent::PayoutNonceReceived => self.process_payout_nonce_received(),
            DepositEvent::PayoutPartialReceived => self.process_payout_partial_received(),
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
    pub const fn new(
        cfg: DepositCfg,
        deposit_idx: u32,
        deposit_transaction: Transaction,
        drt_block_height: BitcoinBlockHeight,
        deposit_request_outpoint: OutPoint,
        output_index: u32,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(
                deposit_idx,
                deposit_transaction,
                drt_block_height,
                deposit_request_outpoint,
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
            DepositState::Created {
                deposit_request_outpoint,
                ..
            } => Ok(DSMOutput::with_duties(vec![
                DepositDuty::PublishDepositNonce {
                    deposit_out_point: *deposit_request_outpoint,
                },
            ])),
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::DepositRequest.to_string(),
            }),
        }
    }

    /// Processes the event where an operator's graph becomes available.
    ///
    /// This tracks operators that have successfully generated and linked their spending graphs
    /// for this deposit. When all operators have linked their graphs, transitions to the
    /// GraphGenerated state.
    fn process_graph_available(&mut self, graph_msg: GraphToDeposit) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();

        match self.state_mut() {
            DepositState::Created {
                deposit_idx,
                deposit_transaction,
                drt_block_height,
                deposit_request_outpoint,
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
                            deposit_idx: *deposit_idx,
                            deposit_transaction: deposit_transaction.clone(),
                            drt_block_height: *drt_block_height,
                            deposit_request_outpoint: *deposit_request_outpoint,
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

    fn process_payout_confirmed(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }

    fn process_new_block(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }
}

#[cfg(test)]
mod prop_tests {
    // Strategy generators for individual types
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::{Height, LockTime},
        transaction,
    };
    use proptest::prelude::*;
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
        fn arb_transaction()(
            max_num_ins in 2..10u32,
            max_num_outs in 2..10u32
        )(
            ins in prop::collection::vec(arb_input(), (1, max_num_ins as usize)),
            outs in prop::collection::vec(arb_output(), (1, max_num_outs as usize))
        ) -> Transaction {
            Transaction {
                version: transaction::Version::TWO,
                lock_time: LockTime::Blocks(Height::ZERO),
                input: ins,
                output: outs,
            }
        }
    }

    // Generates a deposit state machine initialized in Created state
    prop_compose! {
        fn arb_deposit_state_machine()(
            cfg in arb_deposit_cfg(),
            deposit_idx in 0u32..1000u32,
            deposit_transaction in arb_transaction(),
            drt_block_height in arb_block_height(),
            deposit_request_outpoint in arb_outpoint(),
            output_index in 0u32..10u32,
            block_height in arb_block_height(),
        ) -> DepositSM {
            DepositSM::new(
                cfg,
                deposit_idx,
                deposit_transaction,
                drt_block_height,
                deposit_request_outpoint,
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

            // Assume we're in Created state - filter out other states
            prop_assume!(matches!(state_before, DepositState::Created { .. }));

            // Extract the deposit request outpoint from the Created state
            let DepositState::Created { deposit_request_outpoint, .. } = &state_before else {
                unreachable!("prop_assume ensures we're in Created state");
            };
            let expected_outpoint = *deposit_request_outpoint;

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

        }
    }
}
