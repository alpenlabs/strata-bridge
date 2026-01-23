//! Universal test fixtures usable by any state machine.
//!
//! This module provides helpers for creating common test data structures
//! like blocks and transactions that are used across multiple state machines.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxMerkleNode, Witness, XOnlyPublicKey, block, blockdata, hashes::Hash, relative,
    script::Builder, transaction,
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
