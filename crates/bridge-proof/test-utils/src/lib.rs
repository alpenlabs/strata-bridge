//! Test data module for loading Bitcoin blocks, headers, chain state, and specific
//! transactions.

#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

use std::fs;

use bitcoin::{block::Header, Block};
use borsh::BorshDeserialize;
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_primitives::{
    buf::{Buf32, Buf64},
    params::RollupParams,
};
use strata_state::{
    chain_state::Chainstate,
    l1::{HeaderVerificationState, L1BlockId, TimestampStore},
};

/// Loads and deserializes a list of Bitcoin blocks from a binary test data file.
pub fn load_test_blocks() -> Vec<Block> {
    let blocks_bytes =
        fs::read("../../../test-data/blocks.bin").expect("Failed to read blocks.bin");
    bincode::deserialize(&blocks_bytes).expect("Failed to deserialize blocks")
}

/// Extracts the headers from the test blocks.
pub fn extract_test_headers() -> Vec<Header> {
    load_test_blocks().iter().map(|b| b.header).collect()
}

pub fn header_verification_state() -> HeaderVerificationState {
    let mut timestamps = [
        1739381881, 1739381885, 1739381885, 1739381885, 1739381885, 1739381889, 1739381889,
        1739381889, 1739381889, 1739381893, 1739381881,
    ];
    timestamps.sort();

    HeaderVerificationState {
        last_verified_block_num: 900,
        last_verified_block_hash: L1BlockId::from(
            Buf32::try_from_slice(
                &hex::decode("956869b2bb0b42e737933d6090f0204a804dcddf4ce11f2e8c14036a27344c4c")
                    .unwrap(),
            )
            .unwrap(),
        ),
        next_block_target: 545259519,
        interval_start_timestamp: 1296688602,
        total_accumulated_pow: 0,
        last_11_blocks_timestamps: TimestampStore::new_with_head(timestamps, 10),
    }
}

/// Loads and deserializes the chain state from a Borsh-encoded test data file.
pub fn load_test_chainstate() -> Chainstate {
    let chainstate_bytes =
        fs::read("../../../test-data/chainstate.borsh").expect("Failed to read chainstate.borsh");
    borsh::from_slice(&chainstate_bytes).expect("Failed to deserialize chainstate")
}

/// Loads the RollupParams from the json file.
pub fn load_test_rollup_params() -> RollupParams {
    let json = fs::read_to_string("../../../test-data/rollup_params.json")
        .expect("rollup params file not found");
    let rollup_params: RollupParams = serde_json::from_str(&json).unwrap();
    rollup_params.check_well_formed().unwrap();
    rollup_params
}

/// Loads the operator signature from the binary file.
pub fn load_op_signature() -> Buf64 {
    let sig_bytes: Vec<u8> =
        fs::read("../../../test-data/op_signature.bin").expect("Failed to read op_signature.bin");

    Buf64::try_from_slice(&sig_bytes).unwrap()
}

/// Retrieves the withdrawal fulfillment transaction from test blocks.
///
/// This transaction is found at block height 988, with index 1 in the block's transaction list.
/// Returns the transaction along with the relative block index in the test blocks.
pub fn get_withdrawal_fulfillment_tx() -> (L1TxWithProofBundle, usize) {
    let block_height = 952;
    let tx_index = 1;
    fetch_test_transaction(block_height, tx_index)
}

/// Retrieves the strata checkpoint transaction from test blocks.
///
/// This transaction is found at block height 968, with index 2 in the block's transaction list.
/// Returns the transaction along with the relative block index in the test blocks.
pub fn get_strata_checkpoint_tx() -> (L1TxWithProofBundle, usize) {
    let block_height = 932;
    let tx_index = 2;
    fetch_test_transaction(block_height, tx_index)
}

/// Retrieves a transaction from test blocks given a specific block height and transaction
/// index.
///
/// # Arguments
/// * `block_height` - The height of the block where the transaction is located.
/// * `tx_index` - The index of the transaction in the block's transaction list.
///
/// # Returns
/// A tuple containing:
/// * `L1TxWithProofBundle` - The generated transaction bundle.
/// * `usize` - The relative index of the block in the test blocks list.
fn fetch_test_transaction(block_height: u64, tx_index: u32) -> (L1TxWithProofBundle, usize) {
    let test_blocks = load_test_blocks();
    let first_block_height = test_blocks
        .first()
        .expect("No test blocks found")
        .bip34_block_height()
        .expect("Missing block height from the first block");

    let relative_block_index = (block_height - first_block_height) as usize;
    let block_transactions = &test_blocks[relative_block_index].txdata;

    (
        L1TxWithProofBundle::generate(block_transactions, tx_index),
        relative_block_index,
    )
}
