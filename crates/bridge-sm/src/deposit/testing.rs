//! Testing utilities specific to the Deposit State Machine.
//!
//! This module provides helpers and `Arbitrary` implementations for testing
//! the DepositSM across multiple state transition functions.

use bitcoin::{Amount, Network, OutPoint, Transaction, absolute, relative, transaction::Version};
use musig2::KeyAggContext;
use proptest::prelude::*;
use secp256k1::{Message, SECP256K1, SecretKey};
use strata_bridge_connectors2::{n_of_n::NOfNConnector, prelude::DepositRequestConnector};
use strata_bridge_primitives::{
    key_agg::create_agg_ctx, operator_table::OperatorTable, scripts::taproot::TaprootWitness,
    secp::EvenSecretKey, types::OperatorIdx,
};
use strata_bridge_test_utils::musig2::{generate_agg_nonce, generate_pubnonce};
use strata_bridge_tx_graph2::transactions::{
    PresignedTx,
    prelude::{DepositData, DepositTx},
};
use strata_l1_txfmt::MagicBytes;
use strata_p2p_types::P2POperatorPubKey;

use super::{
    events::DepositEvent,
    state::{DepositCfg, DepositSM, DepositState},
};
use crate::{
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

// ==== Signer Helpers =====

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
            (block_height.clone()).prop_map(|height| {
                DepositState::Created {
                    block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    linked_graphs: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::GraphGenerated {
                    block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    pubnonces: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::DepositNoncesCollected {
                    block_height: height,
                    deposit_transaction: test_deposit_txn(),
                    agg_nonce: generate_agg_nonce(),
                    partial_signatures: Default::default(),
                    pubnonces: Default::default(),
                }
            }),
            (block_height.clone()).prop_map(|height| {
                DepositState::DepositPartialsCollected {
                    block_height: height,
                    deposit_transaction: Transaction {
                        input: vec![],
                        output: vec![],
                        version: Version(2),
                        lock_time: absolute::LockTime::ZERO,
                    },
                }
            }),
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
        let block_height = BIP34_MIN_BLOCK_HEIGHT..1000u64;
        let operator_idx = 0u32..3u32;

        prop_oneof![
            Just(DepositEvent::UserTakeBack {
                tx: test_takeback_tx(OutPoint::default())
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
            Just(DepositEvent::DepositConfirmed),
            Just(DepositEvent::Assignment),
            Just(DepositEvent::FulfillmentConfirmed),
            Just(DepositEvent::PayoutNonceReceived),
            Just(DepositEvent::PayoutPartialReceived),
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

/// Strategy for generating only events which have been handled in STFs
// TODO: (@Rajil1213) remove this after all STFs have been implemented.
pub(super) fn arb_handled_events() -> impl Strategy<Value = DepositEvent> {
    let outpoint = OutPoint::default();
    let operator_idx = 0u32..3u32;

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
    ]
}
