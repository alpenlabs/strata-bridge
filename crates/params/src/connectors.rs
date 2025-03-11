//! Params related to the bridge tx graph connectors, specifically the layout of assert-data
//! connectors.
//!
//! The following data was used to determine the layout of the connectors. This data is the output
//! of running `cargo run --bin assert-splitter`.
//!
//! * Average Field Element Max Stack Size: 145
//! * Average Field Element Transaction Size: 6790
//! * Average Hash Max stack size: 97
//! * Average Hash Transaction size: 4608
//!
//! Field Elements Layout:
//! ----------------------------------
//! Max Elements per UTXO: 5
//! Max UTXOs per TX: 1
//! Num TXs: 4
//! Remainder: Some(2)
//! Max Stack Size: 725
//! Transaction Size per UTXO: 31612
//!
//! Hash Layout:
//! ----------------------------------
//! Max Elements per UTXO: 8
//! Max UTXOs per TX: 1
//! Num TXs: 47
//! Remainder: Some(4)
//! Max Stack Size: 776
//! Transaction Size per UTXO: 32772
//!
//! Based on the above data, the elements can be bitcommitted as follows with the constraint that
//! the max stack usage must not exceed 1,000 elements and the max V3 transaction size must not
//! exceed 40,000 weight units:
//!
//! | Element Type  | Elements Per UTXO  |  Connectors | UTXOs Per Tx | Total |
//! | ------------- | ------------------ | ----------- | ------------ | ----- |
//! | Field         | 6                  |  3          | 1            | 18    |
//! | Field         | 3                  |  1          | 1            | 3     |
//! | Hash          | 9                  |  42         | 1            | 378   |
//! | Hash          | 2                  |  1          | 1            | 2     |

use bitvm::chunk::compile::{NUM_U160, NUM_U256};
use serde::{Deserialize, Serialize};

/// The maximum number of field elements that are bitcommitted per UTXO.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1: usize = 6;

/// The number of UTXOs necessary to commit all the required field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_1: usize = 3;

/// The number of remaining field elements.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2: usize = 3;

/// The number of UTXOs necessary to commit all the remaining field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_2: usize = 1;

/// The maximum number of hashes that are bitcommitted per UTXO.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1: usize = 9;

/// The number of UTXOs necessary to commit all the required hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_1: usize = 42;

/// The number of remaining hash elements.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2: usize = 2;

/// The number of UTXOs necessary to commit all the remaining hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_2: usize = 1;

/// The total number of field elements that need to be committed.
pub const NUM_PKS_A256: usize = NUM_U256 + 1; // 20 field elements + 1 proof input
/// The total number of hashes that need to be committed.
pub const NUM_PKS_A160: usize = NUM_U160;

/// The total number of connectors that contain the bitcommitment locking scripts for assertion.
pub const TOTAL_CONNECTORS: usize = NUM_FIELD_CONNECTORS_BATCH_1
    + NUM_FIELD_CONNECTORS_BATCH_2
    + NUM_HASH_CONNECTORS_BATCH_1
    + NUM_HASH_CONNECTORS_BATCH_2;

/// The total number of assert-data transactions.
pub const NUM_ASSERT_DATA_TX: usize = NUM_FIELD_CONNECTORS_BATCH_1
    + NUM_FIELD_CONNECTORS_BATCH_2
    + NUM_HASH_CONNECTORS_BATCH_1
    + NUM_HASH_CONNECTORS_BATCH_2;

/// The total number of field elements that are committed to in the assert-data transactions.
pub const NUM_FIELD_ELEMENTS: usize = NUM_FIELD_CONNECTORS_BATCH_1
    * NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1
    + NUM_FIELD_CONNECTORS_BATCH_2 * NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2;

/// The total number of hashes that are committed to in the assert-data transactions.
pub const NUM_HASH_ELEMENTS: usize = NUM_HASH_CONNECTORS_BATCH_1
    * NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1
    + NUM_HASH_CONNECTORS_BATCH_2 * NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2;

/// The total number of elements that are committed to in the assert-data transactions.
pub const TOTAL_VALUES: usize = NUM_FIELD_ELEMENTS + NUM_HASH_ELEMENTS;

// compile-time checks to ensure that the numbers are sound.
const _: [(); 0] = [(); (NUM_PKS_A256 - NUM_FIELD_ELEMENTS)];
const _: [(); 0] = [(); (NUM_PKS_A160 - NUM_HASH_ELEMENTS)];
const _: [(); 0] = [(); (NUM_PKS_A256 + NUM_PKS_A160 - TOTAL_VALUES)];

/// The consensus-critical parameters that define the locking conditions for each connector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConnectorParams {
    /// The relative timelock (measured in number of blocks) on the [`ClaimTx`] output that is used
    /// to lock funds in the N-of-N and used in the [`PayoutOptimisticTx`].
    pub payout_optimistic_timelock: u32,

    /// The relative timelock (measured in number of blocks) on the [`ClaimTx`] output that is used
    /// to lock funds in the N-of-N and used in the [`PreAssertTx`].
    pub pre_assert_timelock: u32,

    /// The relative timelock (measure in number of blocks) on the [`PostAssertTx`] output that is
    /// used to lock funds in the N-of-N and used in the [`PayoutTx`].
    pub payout_timelock: u32,
}

impl Default for ConnectorParams {
    fn default() -> Self {
        Self {
            payout_optimistic_timelock: 1008, // 1 week's worth of blocks in Mainnet
            pre_assert_timelock: 1152,        // 1 week + 1 day's worth of blocks in Mainnet
            payout_timelock: 1008,            // 1 week's worth of block in Mainnet.
        }
    }
}
