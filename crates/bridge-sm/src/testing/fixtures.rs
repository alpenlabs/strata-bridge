//! Universal test fixtures usable by any state machine.
//!
//! This module provides helpers for creating common test data structures
//! like blocks and transactions that are used across multiple state machines.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxMerkleNode, Witness, block, blockdata, hashes::Hash, relative, script::Builder,
    transaction,
};
use secp256k1::{Keypair, SECP256K1};
use strata_bridge_test_utils::bitcoin::generate_spending_tx;
use strata_bridge_tx_graph2::{
    connectors::{n_of_n::NOfNConnector, timelocked::DepositRequestConnector},
    transactions::deposit::{DepositData, DepositTx},
};
use strata_l1_txfmt::MagicBytes;

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

/// Creates a test deposit transaction with deterministic values.
///
/// This generates a `DepositTx` with fixed keypairs and test parameters:
/// - Network: Regtest
/// - Magic bytes: "TEST" (0x54455354)
///
/// # Arguments
/// * `amount` - The amount for the deposit transaction
/// * `timelock` - The relative locktime for the deposit request connector
pub fn generate_test_deposit_txn(amount: Amount, timelock: relative::LockTime) -> DepositTx {
    // Generate deterministic keypairs for testing
    let n_of_n_keypair = Keypair::from_seckey_slice(SECP256K1, &[1u8; 32])
        .expect("valid key");
    let depositor_keypair = Keypair::from_seckey_slice(SECP256K1, &[2u8; 32])
        .expect("valid key");

    let n_of_n_pubkey = n_of_n_keypair.x_only_public_key().0;
    let depositor_pubkey = depositor_keypair.x_only_public_key().0;

    // Test values
    let network = Network::Regtest;

    // Create DepositData
    let data = DepositData {
        deposit_idx: 0,
        deposit_request_outpoint: OutPoint::default(),
        magic_bytes: MagicBytes::from([0x54, 0x45, 0x53, 0x54]), // "TEST"
    };

    // Create connectors with matching network, internal_key, and value
    let deposit_connector = NOfNConnector::new(network, n_of_n_pubkey, amount);

    let deposit_request_connector = DepositRequestConnector::new(
        network,
        n_of_n_pubkey, // Must match deposit_connector
        depositor_pubkey,
        timelock,
        amount, // Must match deposit_connector
    );

    DepositTx::new(data, deposit_connector, deposit_request_connector)
}
