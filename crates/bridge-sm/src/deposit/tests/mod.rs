//! Testing utilities specific to the Deposit State Machine.
//!
//! This module provides helpers and `Arbitrary` implementations for testing
//! the DepositSM across multiple state transition functions.

mod deposit;
mod payout;
mod prop_tests;
mod test_new_blocks;
mod test_timeout_sequence;

use std::collections::BTreeMap;

use bitcoin::{Amount, Network, OutPoint, Transaction, absolute, relative, transaction::Version};
use bitcoin_bosd::Descriptor;
use musig2::KeyAggContext;
use proptest::prelude::*;
use secp256k1::{Message, SECP256K1, SecretKey};
use strata_bridge_connectors2::{n_of_n::NOfNConnector, prelude::DepositRequestConnector};
use strata_bridge_p2p_types::P2POperatorPubKey;
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    operator_table::OperatorTable,
    scripts::prelude::{TaprootWitness, get_aggregated_pubkey},
    secp::EvenSecretKey,
    types::OperatorIdx,
};
use strata_bridge_test_utils::{
    bitcoin::{generate_spending_tx, generate_txid, generate_xonly_pubkey},
    musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
};
use strata_bridge_tx_graph2::transactions::{
    PresignedTx,
    prelude::{CooperativePayoutData, CooperativePayoutTx, DepositData, DepositTx},
};
use strata_l1_txfmt::MagicBytes;

use crate::{
    deposit::{config::DepositCfg, events::DepositEvent, machine::DepositSM, state::DepositState},
    signals::GraphToDeposit,
    testing::{
        fixtures::{test_payout_tx, test_takeback_tx},
        signer::TestMusigSigner,
    },
};

// ===== Test Constants =====

/// Block height used as the initial state in tests.
pub(super) const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Block height used to represent a later block in tests.
pub(super) const LATER_BLOCK_HEIGHT: u64 = 150;
/// Block height used to represent a re-assignment deadline in tests.
pub(super) const REASSIGNMENT_DEADLINE: u64 = LATER_BLOCK_HEIGHT + 50;
/// Operator index used as the assignee in tests.
pub(super) const TEST_ASSIGNEE: OperatorIdx = 2;
/// Operator index of the POV (point of view) operator in tests.
/// This is the operator running the state machine.
pub(super) const TEST_POV_IDX: OperatorIdx = 0;
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
// TODO: (@Rajil1213) once rust-bitcoin@0.33.x lands this isn't necessary anymore. This is
// due to a bug in rust-bitcoin (see <https://github.com/rust-bitcoin/rust-bitcoin/issues/4148>).
const BIP34_MIN_BLOCK_HEIGHT: u64 = 17;
/// Deadline offset (in blocks) used for tests.
const TEST_ASSIGNMENT_DEADLINE_OFFSET: u64 = 15;
/// Cooperative payout timelock (in blocks) used for tests.
const TEST_COOPERATIVE_PAYOUT_TIMELOCK: u64 = 1008;
/// Deposit index used in tests.
pub(super) const TEST_DEPOSIT_IDX: u32 = 0;

// ===== Configuration Helpers =====

/// Creates a test configuration for DepositSM.
pub(super) fn test_cfg() -> DepositCfg {
    DepositCfg {
        deposit_idx: TEST_DEPOSIT_IDX,
        deposit_outpoint: OutPoint::default(),
        operator_table: test_operator_table(),
        network: Network::Regtest,
        deposit_amount: Amount::from_sat(10_000_000),
    }
}

/// Creates a minimal test operator table with 3 operators.
pub(super) fn test_operator_table() -> OperatorTable {
    let sk1 = EvenSecretKey::from(SecretKey::from_slice(&[1u8; 32]).unwrap());
    let sk2 = EvenSecretKey::from(SecretKey::from_slice(&[2u8; 32]).unwrap());
    let sk3 = EvenSecretKey::from(SecretKey::from_slice(&[3u8; 32]).unwrap());

    let operators = vec![
        (
            0,
            P2POperatorPubKey::from(sk1.public_key(SECP256K1).serialize().to_vec()),
            sk1.public_key(SECP256K1),
        ),
        (
            1,
            P2POperatorPubKey::from(sk2.public_key(SECP256K1).serialize().to_vec()),
            sk2.public_key(SECP256K1),
        ),
        (
            2,
            P2POperatorPubKey::from(sk3.public_key(SECP256K1).serialize().to_vec()),
            sk3.public_key(SECP256K1),
        ),
    ];

    OperatorTable::new(operators, |entry| entry.0 == TEST_POV_IDX)
        .expect("Failed to create test operator table")
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

    let tweak = info
        .tweak
        .expect("DRT->DT key-path spend must include a taproot tweak")
        .expect("tweak must be present for deposit transaction");

    let tap_witness = TaprootWitness::Tweaked { tweak };

    let btc_keys: Vec<_> = operator_signers.iter().map(|s| s.pubkey()).collect();

    let key_agg_ctx = create_agg_ctx(btc_keys, &tap_witness)
        .expect("must be able to create key aggregation context");

    (key_agg_ctx, sighash)
}

/// Creates a test deposit transaction with deterministic values.
pub(super) fn test_deposit_txn() -> DepositTx {
    let operator_table = test_operator_table();

    let amount = Amount::from_btc(10.0).expect("valid amount");
    let timelock = relative::LockTime::from_height(144);
    let n_of_n_pubkey = operator_table.aggregated_btc_key().x_only_public_key().0;
    let depositor_pubkey = operator_table.pov_btc_key().x_only_public_key().0;

    // Create DepositData
    let data = DepositData {
        deposit_idx: 0,
        deposit_request_outpoint: OutPoint::default(),
        magic_bytes: MagicBytes::from([0x54, 0x45, 0x53, 0x54]), // "TEST"
    };

    // Create connectors with matching network, internal_key, and value
    let deposit_connector = NOfNConnector::new(Network::Regtest, n_of_n_pubkey, amount);

    let deposit_request_connector = DepositRequestConnector::new(
        Network::Regtest,
        n_of_n_pubkey,
        depositor_pubkey,
        timelock,
        amount,
    );

    DepositTx::new(data, deposit_connector, deposit_request_connector)
}

// ===== Payout Transaction Helpers =====

/// Creates a random P2TR descriptor for use in tests.
pub(super) fn random_p2tr_desc() -> Descriptor {
    Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
        .expect("Failed to generate descriptor")
}

/// Creates a test cooperative payout transaction with deterministic values.
pub(super) fn test_payout_txn(operator_desc: Descriptor) -> CooperativePayoutTx {
    let operator_table = test_operator_table();
    let n_of_n_pubkey = get_aggregated_pubkey(operator_table.btc_keys());
    let deposit_connector = NOfNConnector::new(
        Network::Regtest,
        n_of_n_pubkey,
        Amount::from_sat(10_000_000),
    );

    CooperativePayoutTx::new(
        CooperativePayoutData {
            deposit_outpoint: OutPoint::default(),
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
    let key_agg_ctx =
        create_agg_ctx(btc_keys, &TaprootWitness::Key).expect("must create key agg context");
    let message = payout_tx.signing_info()[0].sighash;
    (key_agg_ctx, message)
}

// ===== State Machine Helpers =====

/// Creates a DepositSM from a given state.
pub(super) fn create_sm(state: DepositState) -> DepositSM {
    DepositSM {
        cfg: test_cfg(),
        state,
    }
}

/// Gets the state from a DepositSM.
pub(super) const fn get_state(sm: &DepositSM) -> &DepositState {
    sm.state()
}

// ===== Arbitrary Implementations =====

impl Arbitrary for DepositState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let block_height = BIP34_MIN_BLOCK_HEIGHT..1000u64;
        let num_operators = test_operator_table().cardinality() as u32;

        prop_oneof![
            (block_height.clone()).prop_map(|height| {
                DepositState::Created {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    linked_graphs: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::GraphGenerated {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    pubnonces: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::DepositNoncesCollected {
                    last_block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    agg_nonce: generate_agg_nonce(),
                    partial_signatures: Default::default(),
                    pubnonces: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::DepositPartialsCollected {
                    last_block_height: height,
                    deposit_transaction: Transaction {
                        input: vec![],
                        output: vec![],
                        version: Version(2),
                        lock_time: absolute::LockTime::ZERO,
                    },
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
                DepositState::PayoutDescriptorReceived {
                    last_block_height: height,
                    assignee: TEST_ASSIGNEE,
                    cooperative_payment_deadline: height + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                    operator_desc: random_p2tr_desc(),
                    payout_nonces: BTreeMap::new(),
                }
            }),
            block_height.clone().prop_map(move |height| {
                // PayoutNoncesCollected requires all nonces to be present
                let nonces: BTreeMap<_, _> = (0..num_operators)
                    .map(|idx| (idx, generate_pubnonce()))
                    .collect();
                let agg_nonce = musig2::AggNonce::sum(nonces.values().cloned());
                DepositState::PayoutNoncesCollected {
                    last_block_height: height,
                    assignee: TEST_ASSIGNEE,
                    operator_desc: random_p2tr_desc(),
                    cooperative_payment_deadline: height + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                    payout_nonces: nonces,
                    payout_aggregated_nonce: agg_nonce,
                    payout_partial_signatures: BTreeMap::new(),
                }
            }),
            block_height.prop_map(|height| DepositState::CooperativePathFailed {
                last_block_height: height
            }),
            Just(DepositState::Spent),
            Just(DepositState::Aborted),
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
        let operator_idx = 0..test_operator_table().cardinality() as u32;

        prop_oneof![
            Just(DepositEvent::UserTakeBack {
                tx: test_takeback_tx(OutPoint::default()),
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable { operator_idx: idx })
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::NonceReceived {
                    nonce: generate_pubnonce(),
                    operator_idx: idx,
                }
            }),
            outpoint.prop_map(|outpoint| {
                DepositEvent::DepositConfirmed {
                    deposit_transaction: generate_spending_tx(outpoint, &[]),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositEvent::WithdrawalAssigned {
                    assignee: TEST_ASSIGNEE,
                    deadline: height + TEST_ASSIGNMENT_DEADLINE_OFFSET,
                    recipient_desc: random_p2tr_desc(),
                }
            }),
            (outpoint, block_height.clone()).prop_map(|(outpoint, height)| {
                DepositEvent::FulfillmentConfirmed {
                    fulfillment_transaction: generate_spending_tx(outpoint, &[]),
                    fulfillment_height: height,
                }
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::PayoutNonceReceived {
                    payout_nonce: generate_pubnonce(),
                    operator_idx: idx,
                }
            }),
            operator_idx.clone().prop_map(|idx| {
                DepositEvent::PayoutPartialReceived {
                    partial_signature: generate_partial_signature(),
                    operator_idx: idx,
                }
            }),
            Just(DepositEvent::PayoutConfirmed {
                tx: test_payout_tx(OutPoint::default())
            }),
            block_height.prop_map(|height| DepositEvent::NewBlock {
                block_height: height
            }),
        ]
        .boxed()
    }
}

/// Strategy for generating only terminal states.
pub(super) fn arb_terminal_state() -> impl Strategy<Value = DepositState> {
    prop_oneof![Just(DepositState::Spent), Just(DepositState::Aborted),]
}

/// Strategy for generating only events which have been handled in STFs.
// TODO: (@Rajil1213) remove this after all STFs have been implemented.
pub(super) fn arb_handled_events() -> impl Strategy<Value = DepositEvent> {
    let outpoint = OutPoint::default();
    let num_operators = test_operator_table().cardinality() as u32;
    let operator_idx = 0..num_operators;

    prop_oneof![
        Just(DepositEvent::UserTakeBack {
            tx: test_takeback_tx(outpoint)
        }),
        operator_idx.clone().prop_map(|idx| {
            DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable { operator_idx: idx })
        }),
        operator_idx.clone().prop_map(|idx| {
            DepositEvent::NonceReceived {
                nonce: generate_pubnonce(),
                operator_idx: idx,
            }
        }),
        Just(DepositEvent::PayoutConfirmed {
            tx: test_payout_tx(outpoint)
        }),
        (BIP34_MIN_BLOCK_HEIGHT..1000u64).prop_map(|height| DepositEvent::NewBlock {
            block_height: height
        }),
        Just(DepositEvent::DepositConfirmed {
            deposit_transaction: generate_spending_tx(outpoint, &[])
        }),
        Just(DepositEvent::FulfillmentConfirmed {
            fulfillment_transaction: generate_spending_tx(outpoint, &[]),
            fulfillment_height: LATER_BLOCK_HEIGHT,
        }),
        Just(DepositEvent::WithdrawalAssigned {
            assignee: TEST_ASSIGNEE,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: random_p2tr_desc(),
        }),
        (0..num_operators).prop_map(|idx| DepositEvent::PayoutNonceReceived {
            payout_nonce: generate_pubnonce(),
            operator_idx: idx,
        }),
        (0..num_operators).prop_map(|idx| DepositEvent::PayoutPartialReceived {
            partial_signature: generate_partial_signature(),
            operator_idx: idx,
        }),
    ]
}
