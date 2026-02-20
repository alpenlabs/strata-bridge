//! Universal test fixtures usable by any state machine.
//!
//! This module provides helpers for creating common test data structures
//! like blocks and transactions that are used across multiple state machines.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxMerkleNode, Witness, XOnlyPublicKey, block, blockdata, hashes::Hash, relative,
    script::Builder, transaction,
};
use bitcoin_bosd::Descriptor;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use strata_bridge_p2p_types::P2POperatorPubKey;
use strata_bridge_primitives::{
    operator_table::OperatorTable, secp::EvenSecretKey, types::OperatorIdx,
};
use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_xonly_pubkey};
use strata_bridge_tx_graph2::transactions::{
    deposit::{DepositData, DepositTx},
    prelude::{WithdrawalFulfillmentData, WithdrawalFulfillmentTx},
};
use strata_l1_txfmt::MagicBytes;

// ===== Shared Test Constants =====

/// Block height used to represent a later block in tests.
pub const LATER_BLOCK_HEIGHT: u64 = 150;
/// Deposit index used in tests.
pub const TEST_DEPOSIT_IDX: u32 = 0;
/// Operator index of the POV (point of view) operator in tests.
pub const TEST_POV_IDX: OperatorIdx = 0;
/// Operator index used as the assignee in tests.
pub const TEST_ASSIGNEE: OperatorIdx = 2;
/// Magic bytes used in tests.
pub const TEST_MAGIC_BYTES: [u8; 4] = [0x54, 0x45, 0x53, 0x54]; // "TEST"
/// Deposit amount used in tests.
pub const TEST_DEPOSIT_AMOUNT: Amount = Amount::from_sat(10_000_000);
/// Operator fee used in tests.
pub const TEST_OPERATOR_FEE: Amount = Amount::from_sat(10_000);

// ===== Shared Test Helpers =====

/// Creates a random P2TR descriptor for use in tests.
pub fn random_p2tr_desc() -> Descriptor {
    Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
        .expect("Failed to generate descriptor")
}

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

/// Creates a deterministic test operator table with `n` operators,
/// and marks `pov_idx` as the POV operator.
pub fn test_operator_table(n: usize, pov_idx: OperatorIdx) -> OperatorTable {
    let operators = (0..n as OperatorIdx)
        .map(|idx| {
            let byte =
                u8::try_from(idx + 1).expect("operator index too large for test key derivation");
            let sk = EvenSecretKey::from(SecretKey::from_slice(&[byte; 32]).unwrap());
            let pk = sk.public_key(SECP256K1);
            let p2p = P2POperatorPubKey::from(pk.serialize().to_vec());

            (idx, p2p, pk)
        })
        .collect();

    OperatorTable::new(operators, move |entry| entry.0 == pov_idx)
        .expect("Failed to create test operator table")
}
