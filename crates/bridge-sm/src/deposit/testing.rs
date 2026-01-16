//! Testing utilities specific to the Deposit State Machine.
//!
//! This module provides helpers and `Arbitrary` implementations for testing
//! the DepositSM across multiple state transition functions.

use bitcoin::OutPoint;
use proptest::prelude::*;
use secp256k1::{SECP256K1, SecretKey};
use strata_bridge_p2p_types::P2POperatorPubKey;
use strata_bridge_primitives::{
    operator_table::OperatorTable, secp::EvenSecretKey, types::OperatorIdx,
};

use super::{
    events::DepositEvent,
    state::{DepositCfg, DepositSM, DepositState},
};
use crate::testing::{
    fixtures::{test_payout_tx, test_takeback_tx},
    signer::TestMusigSigner,
};

// ===== Test Constants =====

/// Block height used as the initial state in tests.
pub(super) const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Block height used to represent a later block in tests.
pub(super) const LATER_BLOCK_HEIGHT: u64 = 150;
/// Operator index used as the assignee in tests.
pub(super) const TEST_ASSIGNEE: OperatorIdx = 0;
// TODO: (@Rajil1213) once rust-bitcoin@0.33.x lands this isn't necessary anymore. This is
// due to a bug in rust-bitcoin (see <https://github.com/rust-bitcoin/rust-bitcoin/issues/4148>).
const BIP34_MIN_BLOCK_HEIGHT: u64 = 17;

// ===== Configuration Helpers =====

/// Creates a test configuration for DepositSM.
pub(super) fn test_cfg() -> DepositCfg {
    DepositCfg {
        deposit_idx: 0,
        deposit_outpoint: OutPoint::default(),
        operator_table: test_operator_table(),
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

    OperatorTable::new(operators, |entry| entry.0 == 0)
        .expect("Failed to create test operator table")
}

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
        let operator_idx = 0u32..3u32;

        prop_oneof![
            block_height
                .clone()
                .prop_map(|height| DepositState::Deposited {
                    block_height: height
                }),
            block_height
                .clone()
                .prop_map(|height| DepositState::Assigned {
                    block_height: height
                }),
            (block_height.clone(), operator_idx.clone()).prop_map(|(height, assignee)| {
                DepositState::Fulfilled {
                    block_height: height,
                    assignee,
                    fulfillment_height: height,
                }
            }),
            (block_height.clone(), operator_idx).prop_map(|(height, assignee)| {
                DepositState::PayoutNoncesCollected {
                    block_height: height,
                    assignee,
                    fulfillment_height: height,
                }
            }),
            block_height
                .clone()
                .prop_map(|height| DepositState::PayoutPartialsCollected {
                    block_height: height
                }),
            block_height.prop_map(|height| DepositState::CooperativePathFailed {
                block_height: height
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
        // TODO: (@Rajil1213) Can be removed once t
        prop_oneof![
            Just(DepositEvent::DepositRequest),
            Just(DepositEvent::UserTakeBack {
                tx: test_takeback_tx(OutPoint::default())
            }),
            Just(DepositEvent::DepositConfirmed),
            Just(DepositEvent::Assignment),
            Just(DepositEvent::FulfillmentConfirmed),
            Just(DepositEvent::PayoutNonceReceived),
            Just(DepositEvent::PayoutPartialReceived),
            Just(DepositEvent::PayoutConfirmed {
                tx: test_payout_tx(OutPoint::default())
            }),
            (BIP34_MIN_BLOCK_HEIGHT..1000u64).prop_map(|height| DepositEvent::NewBlock {
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

/// Strategy for generating only events which have been handled in STFs
// TODO: (@Rajil1213) remove this after all STFs have been implemented.
pub(super) fn arb_handled_events() -> impl Strategy<Value = DepositEvent> {
    let outpoint = OutPoint::default();

    prop_oneof![
        Just(DepositEvent::UserTakeBack {
            tx: test_takeback_tx(outpoint)
        }),
        Just(DepositEvent::PayoutConfirmed {
            tx: test_payout_tx(outpoint)
        }),
        (BIP34_MIN_BLOCK_HEIGHT..1000u64).prop_map(|height| DepositEvent::NewBlock {
            block_height: height
        }),
    ]
}
