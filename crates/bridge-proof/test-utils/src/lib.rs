/// Test data module for loading Bitcoin blocks, headers, chain state, and specific
/// transactions.
use std::fs;

use bitcoin::{block::Header, Block};
use borsh::BorshDeserialize;
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_primitives::{buf::Buf32, params::RollupParams};
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
        1738924903, 1738924903, 1738924903, 1738924903, 1738924907, 1738924907, 1738924907,
        1738924907, 1738924911, 1738924899, 1738924899,
    ];
    timestamps.sort();

    HeaderVerificationState {
        last_verified_block_num: 932,
        last_verified_block_hash: L1BlockId::from(
            Buf32::try_from_slice(
                &hex::decode("e2c06d4ff03aadd3ee68c446743bb9ee55a816af8a39b6e393b0bca74d60b753")
                    .unwrap(),
            )
            .unwrap(),
        ),
        next_block_target: 545259519,
        interval_start_timestamp: 1296688602,
        total_accumulated_pow: 0,
        last_11_blocks_timestamps: TimestampStore::new_with_head(timestamps, 9),
    }
}

/// Loads and deserializes the chain state from a Borsh-encoded test data file.
pub fn load_test_chainstate() -> Chainstate {
    let chainstate_bytes =
        fs::read("../../../test-data/chainstate.borsh").expect("Failed to read chainstate.borsh");
    borsh::from_slice::<Chainstate>(&chainstate_bytes).expect("Failed to deserialize chainstate")
}

/// Loads the RollupParams from the json file.
pub fn load_test_rollup_params() -> RollupParams {
    let json = fs::read_to_string("../../../test-data/rollup_params.json")
        .expect("rollup params file not found");
    let rollup_params: RollupParams = serde_json::from_str(&json).unwrap();
    rollup_params.check_well_formed().unwrap();
    rollup_params
}

/// Retrieves the withdrawal fulfillment transaction from test blocks.
///
/// This transaction is found at block height 988, with index 1 in the block's transaction list.
/// Returns the transaction along with the relative block index in the test blocks.
pub fn get_withdrawal_fulfillment_tx() -> (L1TxWithProofBundle, usize) {
    let block_height = 988;
    let tx_index = 1;
    fetch_test_transaction(block_height, tx_index)
}

/// Retrieves the strata checkpoint transaction from test blocks.
///
/// This transaction is found at block height 968, with index 2 in the block's transaction list.
/// Returns the transaction along with the relative block index in the test blocks.
pub fn get_strata_checkpoint_tx() -> (L1TxWithProofBundle, usize) {
    let block_height = 968;
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
