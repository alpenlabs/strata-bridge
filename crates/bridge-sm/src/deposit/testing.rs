#![expect(unreachable_pub)] // remove once the testing macros/functions are used
#![expect(unused_imports)] // remove once the testing macros/functions are used
#![expect(unused_variables)] // remove once the testing macros/functions are used
#![expect(dead_code)] // remove once the testing macros/functions are used
//! Testing utilities specific to the Deposit State Machine.
//!
//! This module provides helpers and `Arbitrary` implementations for testing
//! the DepositSM across multiple state transition functions.

use std::collections::BTreeMap;

use bitcoin::{Amount, Network, OutPoint};
use bitcoin_bosd::Descriptor;
use musig2::secp256k1::schnorr::Signature;
use proptest::prelude::*;
use secp256k1::{SECP256K1, SecretKey};
use strata_bridge_primitives::{
    operator_table::OperatorTable, secp::EvenSecretKey, types::OperatorIdx,
};
use strata_bridge_test_utils::{
    bitcoin::{generate_signature, generate_spending_tx, generate_txid, generate_xonly_pubkey},
    musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
};
use strata_p2p_types::P2POperatorPubKey;

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
/// Deadline offset (in blocks) used for tests.
const TEST_DEADLINE_OFFSET: u64 = 15;
/// Cooperative payout timelock (in blocks) used for tests.
const TEST_COOPERATIVE_PAYOUT_TIMELOCK: u64 = 1008;

// ===== Configuration Helpers =====

/// Creates a test configuration for DepositSM.
pub fn test_cfg() -> DepositCfg {
    DepositCfg {
        deposit_idx: 0,
        deposit_outpoint: OutPoint::default(),
        operator_table: test_operator_table(),
        network: Network::Regtest,
        deposit_amount: Amount::from_sat(10_000_000),
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
        let outpoint = Just(OutPoint::default());
        let block_height = (BIP34_MIN_BLOCK_HEIGHT as u32)..1000u32;

        prop_oneof![
            Just(DepositState::Created),
            Just(DepositState::GraphGenerated),
            (outpoint, block_height.clone()).prop_map(|(outpoint, height)| {
                DepositState::DepositNoncesCollected {
                    block_height: height,
                    output_index: 0,
                    deposit_request_outpoint: outpoint,
                    deposit_transaction: generate_spending_tx(outpoint, &[]),
                    pubnonces: BTreeMap::new(),
                    agg_nonce: generate_agg_nonce(),
                    partial_signatures: BTreeMap::new(),
                }
            }),
            (outpoint, block_height.clone()).prop_map(|(outpoint, height)| {
                DepositState::DepositPartialsCollected {
                    block_height: height,
                    output_index: 0,
                    deposit_request_outpoint: outpoint,
                    deposit_transaction: generate_spending_tx(outpoint, &[]),
                    aggregated_signature: generate_signature(),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::Deposited {
                    block_height: height,
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::Assigned {
                    block_height: height,
                    assignee: TEST_ASSIGNEE,
                    deadline: height as u64 + TEST_DEADLINE_OFFSET,
                    recipient_desc: Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
                        .expect("Failed to generate a random descriptor"),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::Fulfilled {
                    block_height: height,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    fulfillment_block_height: height as u64,
                    cooperative_payment_deadline: height as u64 + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::PayoutNoncesCollected {
                    block_height: height,
                    assignee: TEST_ASSIGNEE,
                    operator_desc: Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
                        .expect("Failed to generate a random descriptor"),
                    cooperative_payment_deadline: height as u64 + TEST_COOPERATIVE_PAYOUT_TIMELOCK,
                    payout_nonces: BTreeMap::new(),
                    payout_aggregated_nonce: generate_agg_nonce(),
                    payout_partial_signatures: BTreeMap::new(),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositState::PayoutPartialsCollected {
                    block_height: height,
                    payout_txid: generate_txid(),
                    payout_aggregated_signature: generate_signature(),
                }
            }),
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
        let outpoint = Just(OutPoint::default());
        let block_height = BIP34_MIN_BLOCK_HEIGHT..1000u64;
        let operator_idx = 0u32..3u32;

        prop_oneof![
            Just(DepositEvent::DepositRequest),
            Just(DepositEvent::NonceReceived),
            Just(DepositEvent::PartialReceived),
            outpoint.prop_map(|outpoint| {
                DepositEvent::DepositConfirmed {
                    deposit_transaction: generate_spending_tx(outpoint, &[]),
                }
            }),
            block_height.clone().prop_map(|height| {
                DepositEvent::Assignment {
                    assignee: TEST_ASSIGNEE,
                    deadline: height + TEST_DEADLINE_OFFSET,
                    recipient_desc: Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
                        .expect("Failed to generate a random descriptor"),
                }
            }),
            (outpoint, block_height.clone()).prop_map(|(outpoint, height)| {
                DepositEvent::FulfillmentConfirmed {
                    fulfillment_transaction: generate_spending_tx(outpoint, &[]),
                    fulfillment_block_height: height,
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
