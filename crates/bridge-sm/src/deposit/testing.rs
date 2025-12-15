#![expect(unreachable_pub)] // remove once the testing macros/functions are used
#![expect(unused_imports)] // remove once the testing macros/functions are used
#![expect(unused_variables)] // remove once the testing macros/functions are used
#![expect(dead_code)] // remove once the testing macros/functions are used
//! Testing utilities specific to the Deposit State Machine.
//!
//! This module provides helpers and `Arbitrary` implementations for testing
//! the DepositSM across multiple state transition functions.

use bitcoin::OutPoint;
use p2p_types::P2POperatorPubKey;
use proptest::prelude::*;
use secp256k1::{SECP256K1, SecretKey};
use strata_bridge_primitives::{
    operator_table::OperatorTable, secp::EvenSecretKey, types::OperatorIdx,
};

use super::{
    events::DepositEvent,
    state::{DepositCfg, DepositSM, DepositState},
};
use crate::testing::fixtures::{test_payout_tx, test_takeback_tx};

// ===== Test Constants =====

/// Block height used as the initial state in tests.
pub const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Block height used to represent a later block in tests.
pub const LATER_BLOCK_HEIGHT: u64 = 150;
/// Operator index used as the assignee in tests.
pub const TEST_ASSIGNEE: OperatorIdx = 0;
// TODO: (@Rajil1213) once rust-bitcoin@0.33.x lands this isn't necessary anymore. This is
// due to a bug in rust-bitcoin (see <https://github.com/rust-bitcoin/rust-bitcoin/issues/4148>).
const BIP34_MIN_BLOCK_HEIGHT: u64 = 17;

// ===== Configuration Helpers =====

/// Creates a test configuration for DepositSM.
pub fn test_cfg() -> DepositCfg {
    DepositCfg {
        deposit_idx: 0,
        deposit_outpoint: OutPoint::default(),
        operator_table: test_operator_table(),
    }
}

/// Creates a minimal test operator table with 3 operators.
pub fn test_operator_table() -> OperatorTable {
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

// ===== State Machine Helpers =====

/// Creates a DepositSM from a given state.
pub fn create_sm(state: DepositState) -> DepositSM {
    DepositSM {
        cfg: test_cfg(),
        state,
    }
}

/// Gets the state from a DepositSM.
pub const fn get_state(sm: &DepositSM) -> &DepositState {
    sm.state()
}

// ===== Arbitrary Implementations =====

impl Arbitrary for DepositState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let operator_idx = 0u32..3u32;

        prop_oneof![
            Just(DepositState::Created),
            Just(DepositState::GraphGenerated),
            Just(DepositState::DepositNoncesCollected),
            Just(DepositState::DepositPartialsCollected),
            Just(DepositState::Deposited),
            Just(DepositState::Assigned),
            Just(DepositState::Fulfilled),
            Just(DepositState::PayoutNoncesCollected),
            Just(DepositState::PayoutPartialsCollected),
            Just(DepositState::CooperativePathFailed),
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
        prop_oneof![
            Just(DepositEvent::DepositRequest),
            Just(DepositEvent::NonceReceived),
            Just(DepositEvent::PartialReceived),
            Just(DepositEvent::DepositConfirmed),
            Just(DepositEvent::Assignment),
            Just(DepositEvent::FulfillmentConfirmed),
            Just(DepositEvent::PayoutNonceReceived),
            Just(DepositEvent::PayoutPartialReceived),
            Just(DepositEvent::PayoutConfirmed),
            Just(DepositEvent::NewBlock),
        ]
        .boxed()
    }
}

/// Strategy for generating only terminal states.
pub fn arb_terminal_state() -> impl Strategy<Value = DepositState> {
    prop_oneof![Just(DepositState::Spent), Just(DepositState::Aborted),]
}
