//! The Deposit State Machine (DSM).
//!
//! Responsible for driving deposit progress by reacting to events and
//! producing the required duties and signals.
use bitcoin::{Amount, Network, XOnlyPublicKey, relative::LockTime};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::transactions::prelude::DepositData;

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::DSMError,
        events::DepositEvent,
        state::{DepositState, config::DepositCfg},
    },
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The number of blocks after the fulfillment confirmation after which the cooperative payout path
/// is considered to have failed.
// TODO: (@Rajil1213) Move this to a config
pub const COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS: u64 = 144; // Approx. 24 hours

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSM {
    /// The static configuration for this Deposit State Machine.
    pub cfg: DepositCfg,
    /// The current state of the Deposit State Machine.
    pub state: DepositState,
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
    pub fn validate_operator_idx(&self, operator_idx: OperatorIdx) -> bool {
        self.cfg()
            .operator_table
            .idx_to_btc_key(&operator_idx)
            .is_some()
    }
}

#[cfg(test)]
mod tests {

    use std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
    };

    use bitcoin::{OutPoint, Transaction, Txid, hashes::Hash};
    use bitcoin_bosd::Descriptor;
    use musig2::{AggNonce, PubNonce};
    use proptest::prelude::*;
    use secp256k1::Message;
    use strata_bridge_test_utils::{
        bitcoin::{generate_spending_tx, generate_txid},
        musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
    };

    use super::*;
    use crate::{
        deposit::state::tests::*,
        prop_deterministic, prop_no_silent_acceptance, prop_terminal_states_reject,
        signals::{DepositToGraph, GraphToDeposit},
        testing::{fixtures::*, signer::TestMusigSigner, transition::*},
    };

    // ===== Unit Tests for process_drt_takeback =====

    #[test]
    fn test_drt_takeback_from_created() {
        let outpoint = OutPoint::default();
        let state = DepositState::Created {
            deposit_transaction: test_deposit_txn(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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

    // ===== Unit Tests for process_deposit_confirmed =====

    #[test]
    // tests correct transition from the DepositPartialsCollected to DepositConfirmed state when
    // the DepositConfirmed event is received.
    fn test_deposit_confirmed_from_partials_collected() {
        let deposit_request_outpoint = OutPoint::default();
        let deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        let state = DepositState::DepositPartialsCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                    last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
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
            last_block_height: INITIAL_BLOCK_HEIGHT,
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
                last_block_height: timeout_height
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
