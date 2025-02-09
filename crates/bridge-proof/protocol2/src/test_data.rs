/// Test data module for loading Bitcoin blocks, headers, chain state, and specific transactions.
#[cfg(test)]
pub(crate) mod test_data_loader {
    use std::fs;

    use bitcoin::{block::Header, Block, Transaction};
    use strata_primitives::params::RollupParams;
    use strata_state::chain_state::Chainstate;

    /// Loads and deserializes a list of Bitcoin blocks from a binary test data file.
    pub(crate) fn load_test_blocks() -> Vec<Block> {
        let blocks_bytes =
            fs::read("../../../test-data/blocks.bin").expect("Failed to read blocks.bin");
        bincode::deserialize(&blocks_bytes).expect("Failed to deserialize blocks")
    }

    /// Extracts the headers from the test blocks.
    pub(crate) fn extract_test_headers() -> Vec<Header> {
        load_test_blocks().iter().map(|b| b.header).collect()
    }

    /// Loads and deserializes the chain state from a Borsh-encoded test data file.
    pub(crate) fn load_test_chainstate() -> Chainstate {
        let chainstate_bytes = fs::read("../../../test-data/chainstate.borsh")
            .expect("Failed to read chainstate.borsh");
        borsh::from_slice::<Chainstate>(&chainstate_bytes)
            .expect("Failed to deserialize chainstate")
    }

    /// Loads the RollupParams from the json file.
    pub(crate) fn load_test_rollup_params() -> RollupParams {
        let json = fs::read_to_string("../../../test-data/rollup_params.json")
            .expect("rollup params file not found");
        let rollup_params: RollupParams = serde_json::from_str(&json).unwrap();
        rollup_params.check_well_formed().unwrap();
        rollup_params
    }

    /// Retrieves the withdrawal fulfillment transaction from test blocks.
    ///
    /// This transaction is located at block height 988, index 1 in the block's transaction list.
    pub(crate) fn get_withdrawal_fulfillment_tx() -> Transaction {
        let target_height = 988;
        let tx_index = 1;

        let blocks = load_test_blocks();
        let starting_height = blocks
            .first()
            .expect("No blocks found")
            .bip34_block_height()
            .expect("Missing block height");
        blocks[(target_height - starting_height) as usize].txdata[tx_index].clone()
    }

    /// Retrieves the checkpoint inscription transaction from test blocks.
    ///
    /// This transaction is located at block height 968, index 2 in the block's transaction list.
    pub(crate) fn get_checkpoint_inscription_tx() -> Transaction {
        let target_height = 968;
        let tx_index = 2;

        let blocks = load_test_blocks();
        let starting_height = blocks
            .first()
            .expect("No blocks found")
            .bip34_block_height()
            .expect("Missing block height");
        blocks[(target_height - starting_height) as usize].txdata[tx_index].clone()
    }
}
