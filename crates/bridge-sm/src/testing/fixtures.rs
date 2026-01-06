//! Universal test fixtures usable by any state machine.
//!
//! This module provides helpers for creating common test data structures
//! like blocks and transactions that are used across multiple state machines.

use bitcoin::{
    Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, Witness, block, blockdata, hashes::Hash, script::Builder, transaction,
};

/// Creates a test block with proper BIP34 height encoding.
///
/// BIP34 requires the coinbase transaction to contain the block height
/// in its scriptSig, which allows `block.bip34_block_height()` to work correctly.
pub fn test_block_with_height(height: u64) -> Block {
    // BIP34: coinbase must start with block height
    let height_script = Builder::new().push_int(height as i64).into_script();

    let coinbase_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: height_script,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };

    Block {
        header: block::Header {
            version: block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: height as u32,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txdata: vec![coinbase_tx],
    }
}

/// Creates a test transaction with specified outpoint and witness elements.
///
/// This is a generic transaction builder that can be customized with different
/// witness elements to create different types of transactions.
pub fn test_tx(previous_output: OutPoint, witness_elements: &[Vec<u8>]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness_elements),
        }],
        output: vec![],
    }
}

/// Creates a takeback transaction (script-spend with multiple witness elements).
///
/// Takeback transactions are identified by having multiple witness elements,
/// as they use script-path spending (as opposed to key-path spending).
pub fn test_takeback_tx(outpoint: OutPoint) -> Transaction {
    test_tx(outpoint, &[vec![0u8; 64], vec![1u8; 32]])
}

/// Creates a payout transaction (key-spend with empty/single witness element).
///
/// Payout transactions use key-path spending and have minimal witness data.
pub fn test_payout_tx(outpoint: OutPoint) -> Transaction {
    test_tx(outpoint, &[])
}
