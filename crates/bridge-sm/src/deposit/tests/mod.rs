//! Testing utilities specific to the Deposit State Machine.
//!
//! This module provides helpers and `Arbitrary` implementations for testing
//! the DepositSM across multiple state transition functions.

mod deposit;
mod duties;
mod handlers;
mod payout;
mod prop_tests;
mod state;
mod sweep;
mod test_new_blocks;
mod test_timeout_sequence;
mod tx_classifier;

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{Amount, Network, OutPoint};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, KeyAggContext, PubNonce};
use proptest::prelude::*;
use secp256k1::{Message, SecretKey};
use strata_bridge_connectors::n_of_n::NOfNConnector;
use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_primitives::{
    covenant::CovenantId,
    key_agg::create_agg_ctx,
    scripts::{prelude::get_aggregated_pubkey, taproot::TaprootTweak},
    secp::EvenSecretKey,
    types::OperatorIdx,
};
use strata_bridge_test_utils::{
    bitcoin::{generate_spending_tx, generate_txid},
    bridge_fixtures::TEST_RECOVERY_DELAY,
    musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
};
use strata_bridge_tx_graph::transactions::{
    PresignedTx,
    deposit::build_test_deposit_tx,
    prelude::{
        CooperativePayoutData, CooperativePayoutTx, DepositData, DepositTx, SweepData, SweepTx,
        WithdrawalFulfillmentData, WithdrawalFulfillmentTx,
    },
};
use strata_l1_txfmt::MagicBytes;

use crate::{
    deposit::{
        config::DepositSMCfg,
        context::DepositSMCtx,
        duties::DepositDuty,
        errors::DSMError,
        events::{
            DepositConfirmedEvent, DepositEvent, FulfillmentConfirmedEvent, NagReceivedEvent,
            NagTickEvent, NewBlockEvent, NonceReceivedEvent, PayoutConfirmedEvent,
            PayoutNonceReceivedEvent, PayoutPartialReceivedEvent, RetryTickEvent,
            SafeHarbourAbortEvent, SweepNonceReceivedEvent, SweepPartialReceivedEvent,
            SweepRequestedEvent, UserTakeBackEvent, WithdrawalAssignedEvent,
        },
        machine::DepositSM,
        state::DepositState,
    },
    signals::{DepositSignal, GraphToDeposit},
    testing::{
        fixtures::{
            LATER_BLOCK_HEIGHT, TEST_ASSIGNEE, TEST_DEPOSIT_AMOUNT, TEST_DEPOSIT_IDX,
            TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX, TEST_SWEEP_FEE_RATE,
            random_p2tr_desc, test_fulfillment_tx, test_operator_table, test_payout_tx,
            test_recipient_desc, test_takeback_tx,
        },
        signer::TestMusigSigner,
        transition::{InvalidTransition, Transition, test_invalid_transition, test_transition},
    },
};

// ===== Test Constants =====

/// Number of operators in the test operator table.
pub(super) const N_TEST_OPERATORS: usize = 3;
/// Block height used as the initial state in tests.
pub(super) const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Block height used to represent a re-assignment deadline in tests.
pub(super) const REASSIGNMENT_DEADLINE: u64 = LATER_BLOCK_HEIGHT + 50;
/// Operator index representing a non-POV operator in tests.
/// Used when testing scenarios where POV is not the assignee.
pub(super) const TEST_NONPOV_IDX: OperatorIdx = 1;
/// Operator index representing a non-assignee operator in tests.
/// Used when testing scenarios where the operator must not be the assignee
pub(super) const TEST_NON_ASSIGNEE_IDX: OperatorIdx = 1;
/// Operator index used when the specific operator doesn't matter for the test.
/// Can be any valid operator (POV, non-POV, assignee, etc.).
pub(super) const TEST_ARBITRARY_OPERATOR_IDX: OperatorIdx = 1;
// Compile-time assertion: TEST_NONPOV_IDX must differ from TEST_POV_IDX
const _: () = assert!(TEST_NONPOV_IDX != TEST_POV_IDX);
// Compile-time assertion: TEST_NON_ASSIGNEE_IDX must differ from TEST_ASSIGNEE
const _: () = assert!(TEST_NON_ASSIGNEE_IDX != TEST_ASSIGNEE);
// TODO: <https://alpenlabs.atlassian.net/browse/STR-2672>
// Remove this once rust-bitcoin@0.33.x lands; it works around rust-bitcoin issue #4148.
const BIP34_MIN_BLOCK_HEIGHT: u64 = 17;
/// Deadline offset (in blocks) used for tests.
const TEST_ASSIGNMENT_DEADLINE_OFFSET: u64 = 15;
/// Cooperative payout timelock (in blocks) used for tests.
const TEST_COOPERATIVE_PAYOUT_TIMELOCK: u64 = 1008;

// ===== Configuration Helpers =====

/// Creates a test bridge-wide configuration.
pub(super) fn test_deposit_sm_cfg() -> Arc<DepositSMCfg> {
    let magic_bytes: MagicBytes = TEST_MAGIC_BYTES.into();

    Arc::new(DepositSMCfg {
        network: Network::Regtest,
        cooperative_payout_timeout_blocks: 144,
        deposit_amount: TEST_DEPOSIT_AMOUNT,
        operator_fee: TEST_OPERATOR_FEE,
        magic_bytes,
        recovery_delay: TEST_RECOVERY_DELAY,
        sweep_fee_rate: TEST_SWEEP_FEE_RATE,
    })
}

/// Creates a test bridge-wide configuration with a custom cooperative payout timeout.
pub(super) fn test_deposit_sm_cfg_with_timeout(timeout: u64) -> Arc<DepositSMCfg> {
    let base_cfg = test_deposit_sm_cfg();
    Arc::new(DepositSMCfg {
        cooperative_payout_timeout_blocks: timeout,
        ..(*base_cfg).clone()
    })
}

/// Creates a test per-instance context for DepositSM.
pub(super) fn test_sm_ctx() -> DepositSMCtx {
    let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
    DepositSMCtx {
        covenant: CovenantId::from_operator_table(&operator_table, 100).unwrap(),
        deposit_idx: TEST_DEPOSIT_IDX,
        deposit_request_outpoint: OutPoint::default(),
        deposit_outpoint: test_deposit_outpoint(),
        operator_table,
    }
}

/// Helper function to get the outpoint of the test deposit transaction.
pub(super) fn test_deposit_outpoint() -> OutPoint {
    OutPoint {
        txid: test_deposit_txn().as_ref().compute_txid(),
        vout: 0,
    }
}

// ===== Signer Helpers =====

/// Creates test musig signers for the operators.
pub(super) fn test_operator_signers() -> Vec<TestMusigSigner> {
    let sk1 = EvenSecretKey::from(SecretKey::from_slice(&[1u8; 32]).unwrap());
    let sk2 = EvenSecretKey::from(SecretKey::from_slice(&[2u8; 32]).unwrap());
    let sk3 = EvenSecretKey::from(SecretKey::from_slice(&[3u8; 32]).unwrap());

    vec![
        TestMusigSigner::new(0, *sk1),
        TestMusigSigner::new(1, *sk2),
        TestMusigSigner::new(2, *sk3),
    ]
}

/// Retrieves the key aggregation context and message for signing a deposit transaction.
pub(super) fn get_deposit_signing_info(
    deposit_tx: &DepositTx,
    operator_signers: &[TestMusigSigner],
) -> (KeyAggContext, Message) {
    let signing_info = deposit_tx.signing_info();
    let info = signing_info
        .first()
        .expect("deposit transaction must have signing info");

    let sighash = info.sighash;

    let btc_keys: Vec<_> = operator_signers.iter().map(|s| s.pubkey()).collect();

    let key_agg_ctx = create_agg_ctx(btc_keys, &info.tweak)
        .expect("must be able to create key aggregation context");

    (key_agg_ctx, sighash)
}

/// Creates a test deposit transaction with deterministic values.
pub(super) fn test_deposit_txn() -> DepositTx {
    build_test_deposit_tx(
        &test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX),
        DepositData {
            deposit_idx: 0,
            deposit_request_outpoint: OutPoint::default(),
            magic_bytes: TEST_MAGIC_BYTES.into(),
        },
        Amount::from_btc(10.0).expect("valid amount"),
    )
}

// ===== Payout Transaction Helpers =====

/// Creates a test cooperative payout transaction with deterministic values.
pub(super) fn test_cooperative_payout_txn(operator_desc: Descriptor) -> CooperativePayoutTx {
    let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
    let n_of_n_pubkey = get_aggregated_pubkey(operator_table.btc_keys());
    let deposit_connector = NOfNConnector::new(
        Network::Regtest,
        n_of_n_pubkey,
        Amount::from_sat(10_000_000),
    );

    CooperativePayoutTx::new(
        CooperativePayoutData {
            deposit_outpoint: test_deposit_outpoint(),
        },
        deposit_connector,
        operator_desc,
    )
}

/// Retrieves the key aggregation context and message for signing a payout transaction.
pub(super) fn get_payout_signing_info(
    payout_tx: &CooperativePayoutTx,
    operator_signers: &[TestMusigSigner],
) -> (KeyAggContext, musig2::secp256k1::Message) {
    let btc_keys: Vec<_> = operator_signers.iter().map(|s| s.pubkey()).collect();
    let key_agg_ctx = create_agg_ctx(btc_keys, &TaprootTweak::Key { tweak: None })
        .expect("must create key agg context");
    let message = payout_tx.signing_info()[0].sighash;
    (key_agg_ctx, message)
}

/// Helper to create test setup for payout partial tests.
/// Returns (state, signers, key_agg_ctx, agg_nonce, message, cooperative_payout_tx).
pub(super) fn create_payout_partial_test_setup(
    assignee: OperatorIdx,
) -> (
    DepositState,
    Vec<TestMusigSigner>,
    KeyAggContext,
    AggNonce,
    Message,
    CooperativePayoutTx,
) {
    let signers = test_operator_signers();
    let operator_desc = random_p2tr_desc();
    let fulfillment_txid = generate_txid();

    // Build cooperative payout tx and get signing info
    let payout_tx = test_cooperative_payout_txn(operator_desc);
    let (key_agg_ctx, message) = get_payout_signing_info(&payout_tx, &signers);

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
        fulfillment_txid,
        cooperative_payout_tx: payout_tx.clone(),
        cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
        payout_nonces: nonces,
        payout_aggregated_nonce: agg_nonce.clone(),
        payout_partial_signatures: BTreeMap::new(),
    };

    (state, signers, key_agg_ctx, agg_nonce, message, payout_tx)
}

/// Creates a `PayoutNoncesCollected` state together with a valid payout partial from every
/// operator other than `assignee`.
pub(super) fn payout_signing_round(assignee: OperatorIdx) -> (DepositState, Vec<DepositEvent>) {
    let (state, signers, key_agg_ctx, agg_nonce, message, _) =
        create_payout_partial_test_setup(assignee);
    let partials = signers
        .iter()
        .filter(|s| s.operator_idx() != assignee)
        .map(|s| {
            DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                partial_signature: s.sign(&key_agg_ctx, 0, &agg_nonce, message),
                operator_idx: s.operator_idx(),
            })
        })
        .collect();

    (state, partials)
}

// ===== Sweep Transaction Helpers =====

/// Creates a test sweep transaction with deterministic values.
pub(super) fn test_sweep_txn(safe_harbour_desc: Descriptor) -> SweepTx {
    let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
    let n_of_n_pubkey = get_aggregated_pubkey(operator_table.btc_keys());
    let deposit_connector =
        NOfNConnector::new(Network::Regtest, n_of_n_pubkey, TEST_DEPOSIT_AMOUNT);
    let operator_pubkeys = operator_table
        .btc_keys()
        .into_iter()
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    SweepTx::new(
        SweepData {
            deposit_outpoint: test_deposit_outpoint(),
        },
        deposit_connector,
        safe_harbour_desc,
        operator_pubkeys,
        TEST_SWEEP_FEE_RATE,
    )
}

/// Retrieves the key aggregation context and message for signing a sweep transaction.
pub(super) fn get_sweep_signing_info(
    sweep_tx: &SweepTx,
    operator_signers: &[TestMusigSigner],
) -> (KeyAggContext, musig2::secp256k1::Message) {
    let btc_keys: Vec<_> = operator_signers.iter().map(|s| s.pubkey()).collect();
    let key_agg_ctx = create_agg_ctx(btc_keys, &TaprootTweak::Key { tweak: None })
        .expect("must create key agg context");
    let message = sweep_tx.signing_info()[0].sighash;
    (key_agg_ctx, message)
}

// ===== State Machine Helpers =====

/// Creates a DepositSM from a given state.
pub(super) fn create_sm(state: DepositState) -> DepositSM {
    DepositSM {
        context: test_sm_ctx(),
        state,
    }
}

/// Gets the state from a DepositSM.
pub(super) const fn get_state(sm: &DepositSM) -> &DepositState {
    sm.state()
}

// ===== Test Transition Helpers =====

/// Type alias for DepositSM transitions.
pub(super) type DepositTransition =
    Transition<DepositState, DepositEvent, DepositDuty, DepositSignal>;

/// Type alias for invalid DepositSM transitions.
pub(super) type DepositInvalidTransition = InvalidTransition<DepositState, DepositEvent, DSMError>;

/// Test a valid DepositSM transition with pre-configured test helpers.
pub(super) fn test_deposit_transition(transition: DepositTransition) {
    test_transition::<DepositSM, _, _, _, _, _, _, _>(
        create_sm,
        get_state,
        test_deposit_sm_cfg(),
        transition,
    );
}

/// Test a valid DepositSM transition with a custom configuration.
pub(super) fn test_deposit_transition_with_cfg(
    cfg: Arc<DepositSMCfg>,
    transition: DepositTransition,
) {
    test_transition::<DepositSM, _, _, _, _, _, _, _>(create_sm, get_state, cfg, transition);
}

/// Test an invalid DepositSM transition with pre-configured test helpers.
pub(super) fn test_deposit_invalid_transition(invalid: DepositInvalidTransition) {
    test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
        create_sm,
        test_deposit_sm_cfg(),
        invalid,
    );
}

/// Configuration for testing handlers that don't mutate state.
/// Unlike transitions, handlers only emit duties without changing state.
pub(super) struct DepositHandlerOutput {
    /// The state (remains unchanged after handler execution)
    pub state: DepositState,
    /// The event that triggers the handler
    pub event: DepositEvent,
    /// The expected duties emitted by the handler
    pub expected_duties: Vec<DepositDuty>,
}

/// Helper for testing handlers that don't mutate state.
/// Unlike transitions, handlers only emit duties without changing state.
pub(super) fn test_handler_output(output: DepositHandlerOutput) {
    test_deposit_transition(DepositTransition {
        from_state: output.state.clone(),
        event: output.event,
        expected_state: output.state,
        expected_duties: output.expected_duties,
        expected_signals: vec![],
    });
}

// ===== Arbitrary Implementations =====

impl Arbitrary for DepositState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let block_height = BIP34_MIN_BLOCK_HEIGHT..1000u64;
        let num_operators =
            test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX).cardinality() as u32;

        prop_oneof![
            (block_height.clone()).prop_map(|height| {
                DepositState::Created {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    claim_txids: BTreeMap::new(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::GraphGenerated {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    claim_txids: BTreeMap::new(),
                    pubnonces: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::DepositNoncesCollected {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    claim_txids: BTreeMap::new(),
                    agg_nonce: generate_agg_nonce(),
                    partial_signatures: Default::default(),
                    pubnonces: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::DepositPartialsCollected {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn().as_ref().clone(),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::Deposited {
                    last_block_height: height,
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::Assigned {
                    last_block_height: height,
                    assignee: TEST_ASSIGNEE,
                    deadline: height + TEST_ASSIGNMENT_DEADLINE_OFFSET,
                    recipient_desc: random_p2tr_desc(),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::Fulfilled {
                    last_block_height: height,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    fulfillment_height: height,
                    cooperative_payout_deadline: height + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                }
            }),
            block_height.clone().prop_map(|height| {
                let operator_desc = random_p2tr_desc();
                DepositState::PayoutDescriptorReceived {
                    last_block_height: height,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    cooperative_payment_deadline: height + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                    cooperative_payout_tx: test_cooperative_payout_txn(operator_desc),
                    payout_nonces: BTreeMap::new(),
                }
            }),
            block_height.clone().prop_map(move |height| {
                // PayoutNoncesCollected requires all nonces to be present
                let nonces: BTreeMap<_, _> = (0..num_operators)
                    .map(|idx| (idx, generate_pubnonce()))
                    .collect();
                let agg_nonce = musig2::AggNonce::sum(nonces.values().cloned());
                let operator_desc = random_p2tr_desc();
                DepositState::PayoutNoncesCollected {
                    last_block_height: height,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    cooperative_payout_tx: test_cooperative_payout_txn(operator_desc),
                    cooperative_payment_deadline: height + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                    payout_nonces: nonces,
                    payout_aggregated_nonce: agg_nonce,
                    payout_partial_signatures: BTreeMap::new(),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::SweepNoncesPending {
                    last_block_height: height,
                    sweep_tx: test_sweep_txn(random_p2tr_desc()),
                    sweep_nonces: BTreeMap::new(),
                }
            }),
            block_height.clone().prop_map(move |height| {
                // SweepNoncesCollected requires all nonces to be present
                let nonces: BTreeMap<_, _> = (0..num_operators)
                    .map(|idx| (idx, generate_pubnonce()))
                    .collect();
                let agg_nonce = musig2::AggNonce::sum(nonces.values().cloned());
                DepositState::SweepNoncesCollected {
                    last_block_height: height,
                    sweep_tx: test_sweep_txn(random_p2tr_desc()),
                    sweep_agg_nonce: agg_nonce,
                    sweep_nonces: nonces,
                    sweep_partials: BTreeMap::new(),
                }
            }),
            block_height.prop_map(|height| DepositState::CooperativePathFailed {
                last_block_height: height,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
            }),
            Just(DepositState::Spent {
                fulfillment_txid: Some(generate_txid()),
                assignee: Some(TEST_ASSIGNEE),
            }),
            Just(DepositState::Aborted),
            Just(DepositState::Skipped),
        ]
        .boxed()
    }
}

impl Arbitrary for DepositEvent {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let outpoint = Just(OutPoint::default());
        let block_height = BIP34_MIN_BLOCK_HEIGHT..1000u64;
        let operator_idx = 0..N_TEST_OPERATORS as u32;

        prop_oneof![
            Just(DepositEvent::UserTakeBack(UserTakeBackEvent {
                tx: test_takeback_tx(OutPoint::default()),
            })),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
                    claim_txid: generate_txid(),
                    operator_idx: idx,
                    deposit_idx: TEST_DEPOSIT_IDX,
                })
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::NonceReceived(NonceReceivedEvent {
                    nonce: generate_pubnonce(),
                    operator_idx: idx,
                })
            }),
            outpoint.prop_map(|outpoint| {
                DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                    deposit_transaction: generate_spending_tx(outpoint, &[]),
                })
            }),
            block_height.clone().prop_map(|height| {
                DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                    assignee: TEST_ASSIGNEE,
                    deadline: height + TEST_ASSIGNMENT_DEADLINE_OFFSET,
                    recipient_desc: random_p2tr_desc(),
                })
            }),
            (outpoint, block_height.clone()).prop_map(|(outpoint, height)| {
                DepositEvent::FulfillmentConfirmed(FulfillmentConfirmedEvent {
                    fulfillment_transaction: generate_spending_tx(outpoint, &[]),
                    fulfillment_height: height,
                })
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
                    payout_nonce: generate_pubnonce(),
                    operator_idx: idx,
                })
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                    partial_signature: generate_partial_signature(),
                    operator_idx: idx,
                })
            }),
            Just(DepositEvent::PayoutConfirmed(PayoutConfirmedEvent {
                tx: test_payout_tx(OutPoint::default())
            })),
            Just(DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent)),
            Just(DepositEvent::SweepRequested(SweepRequestedEvent {
                safe_harbour_desc: random_p2tr_desc(),
            })),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                    sweep_nonce: generate_pubnonce(),
                    operator_idx: idx,
                })
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                    partial_signature: generate_partial_signature(),
                    operator_idx: idx,
                })
            }),
            block_height.prop_map(|height| DepositEvent::NewBlock(NewBlockEvent {
                block_height: height
            })),
            Just(DepositEvent::RetryTick(RetryTickEvent)),
            Just(DepositEvent::NagTick(NagTickEvent)),
        ]
        .boxed()
    }
}

// ===== Strategy Helpers =====

/// Strategy for generating only terminal states.
pub(super) fn arb_terminal_state() -> impl Strategy<Value = DepositState> {
    prop_oneof![
        Just(DepositState::Spent {
            fulfillment_txid: Some(generate_txid()),
            assignee: Some(TEST_ASSIGNEE),
        }),
        Just(DepositState::Spent {
            fulfillment_txid: None,
            assignee: None,
        }),
        Just(DepositState::Aborted),
        Just(DepositState::Skipped),
    ]
}

/// Strategy for generating the tick events, which are handled rather than transitioned on.
///
/// Terminal states ignore these (see `prop_terminal_states_ignore_ticks!`), so they are kept
/// apart from [`arb_stf_events`].
pub(super) fn arb_tick_events() -> impl Strategy<Value = DepositEvent> {
    prop_oneof![
        Just(DepositEvent::NagTick(NagTickEvent)),
        Just(DepositEvent::RetryTick(RetryTickEvent)),
    ]
}

/// Strategy for generating incoming nags.
///
/// Also handled rather than transitioned on, but rejected outside the states that can answer
/// them, so they belong with the rejecting events rather than the ticks.
pub(super) fn arb_nag_received_events() -> impl Strategy<Value = DepositEvent> {
    (0..N_TEST_OPERATORS as u32).prop_map(|idx| {
        DepositEvent::NagReceived(NagReceivedEvent {
            payload: NagRequestPayload::DepositNonce {
                deposit_idx: TEST_DEPOSIT_IDX,
            },
            sender_operator_idx: idx,
        })
    })
}

/// Strategy for generating the events that drive state transitions.
///
/// Ticks are covered separately by [`arb_tick_events`].
pub(super) fn arb_stf_events() -> impl Strategy<Value = DepositEvent> {
    let outpoint = OutPoint::default();
    let num_operators = N_TEST_OPERATORS as u32;
    let operator_idx = 0..num_operators;

    prop_oneof![
        Just(DepositEvent::UserTakeBack(UserTakeBackEvent {
            tx: test_takeback_tx(outpoint)
        })),
        operator_idx.clone().prop_map(|idx| {
            DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
                claim_txid: generate_txid(),
                operator_idx: idx,
                deposit_idx: TEST_DEPOSIT_IDX,
            })
        }),
        operator_idx.clone().prop_map(|idx| {
            DepositEvent::NonceReceived(NonceReceivedEvent {
                nonce: generate_pubnonce(),
                operator_idx: idx,
            })
        }),
        Just(DepositEvent::PayoutConfirmed(PayoutConfirmedEvent {
            tx: test_payout_tx(outpoint)
        })),
        (BIP34_MIN_BLOCK_HEIGHT..1000u64).prop_map(|height| DepositEvent::NewBlock(
            NewBlockEvent {
                block_height: height
            }
        )),
        Just(DepositEvent::DepositConfirmed(DepositConfirmedEvent {
            deposit_transaction: generate_spending_tx(outpoint, &[])
        })),
        Just(DepositEvent::FulfillmentConfirmed(
            FulfillmentConfirmedEvent {
                fulfillment_transaction: generate_spending_tx(outpoint, &[]),
                fulfillment_height: LATER_BLOCK_HEIGHT,
            }
        )),
        Just(DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
            assignee: TEST_ASSIGNEE,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: random_p2tr_desc(),
        })),
        (0..num_operators).prop_map(|idx| DepositEvent::PayoutNonceReceived(
            PayoutNonceReceivedEvent {
                payout_nonce: generate_pubnonce(),
                operator_idx: idx,
            }
        )),
        (0..num_operators).prop_map(|idx| DepositEvent::PayoutPartialReceived(
            PayoutPartialReceivedEvent {
                partial_signature: generate_partial_signature(),
                operator_idx: idx,
            }
        )),
        Just(DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent)),
        Just(DepositEvent::SweepRequested(SweepRequestedEvent {
            safe_harbour_desc: random_p2tr_desc(),
        })),
        (0..num_operators).prop_map(|idx| DepositEvent::SweepNonceReceived(
            SweepNonceReceivedEvent {
                sweep_nonce: generate_pubnonce(),
                operator_idx: idx,
            }
        )),
        (0..num_operators).prop_map(|idx| DepositEvent::SweepPartialReceived(
            SweepPartialReceivedEvent {
                partial_signature: generate_partial_signature(),
                operator_idx: idx,
            }
        )),
    ]
}
