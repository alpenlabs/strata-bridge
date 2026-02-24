//! Universal test fixtures usable by any state machine.
//!
//! Crate-agnostic helpers (operator tables, descriptors, shared constants) live in
//! [`strata_bridge_test_utils::bridge_fixtures`] and are re-exported here for convenience.
//! This file adds bridge-sm–specific fixtures on top.

use bitcoin::{OutPoint, Transaction};
use bitcoin_bosd::Descriptor;
use secp256k1::{SECP256K1, SecretKey};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_test_utils::bitcoin::generate_spending_tx;
// Re-export shared bridge fixtures (constants + helpers) from the central location.
pub use strata_bridge_test_utils::bridge_fixtures::*;
use strata_bridge_tx_graph2::transactions::prelude::{
    WithdrawalFulfillmentData, WithdrawalFulfillmentTx,
};

// ===== bridge-sm–specific Constants =====

/// Block height used to represent a later block in tests.
pub const LATER_BLOCK_HEIGHT: u64 = 150;
/// Deposit index used in tests.
pub const TEST_DEPOSIT_IDX: u32 = 0;
/// Operator index used as the assignee in tests.
pub const TEST_ASSIGNEE: OperatorIdx = 2;

// ===== bridge-sm–specific Helpers =====

/// Returns a deterministic P2TR descriptor for use in fulfillment tests.
///
/// Both [`test_fulfillment_tx`] and the `Assigned` state in TxClassifier tests must use the same
/// recipient descriptor so that [`is_fulfillment`](crate::tx_classifier::is_fulfillment) can match
/// the transaction against the state.
pub fn test_recipient_desc(key_byte: u8) -> Descriptor {
    let sk = SecretKey::from_slice(&[key_byte; 32]).unwrap();
    let pk = sk.public_key(SECP256K1).x_only_public_key().0;
    Descriptor::new_p2tr(&pk.serialize()).expect("valid descriptor")
}

/// Creates a test withdrawal fulfillment transaction with the test deposit index and magic bytes.
///
/// This constructs a properly formatted SPS-50 transaction that the classifier can parse.
pub fn test_fulfillment_tx() -> Transaction {
    let data = WithdrawalFulfillmentData {
        deposit_idx: TEST_DEPOSIT_IDX,
        user_amount: TEST_DEPOSIT_AMOUNT - TEST_OPERATOR_FEE,
        magic_bytes: TEST_MAGIC_BYTES.into(),
    };
    WithdrawalFulfillmentTx::new(data, test_recipient_desc(1)).into_unsigned_tx()
}

// ===== Transaction Fixtures =====

/// Creates a takeback transaction (script-spend with multiple witness elements).
///
/// Takeback transactions are identified by having multiple witness elements,
/// as they use script-path spending (as opposed to key-path spending).
pub fn test_takeback_tx(outpoint: OutPoint) -> Transaction {
    generate_spending_tx(outpoint, &[vec![0u8; 64], vec![1u8; 32]])
}

/// Creates a payout transaction (key-spend with empty/single witness element).
///
/// Payout transactions use key-path spending and have minimal witness data.
pub fn test_payout_tx(outpoint: OutPoint) -> Transaction {
    generate_spending_tx(outpoint, &[])
}
