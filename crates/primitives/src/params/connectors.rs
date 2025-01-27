//! Params related to the bridge tx graph connectors, specifically the layout of assert-data
//! connectors.
//!
//! The following data was used to determine the layout of the connectors. This data is the output
//! of running `cargo run --bin assert-splitter`.
//!
//! * Average Field Element Max Stack Size: 151
//! * Average Field Element Transaction Size: 6767
//! * Average Hash Max Stack size: 103
//! * Average Hash Transaction size: 4561
//!
//! Field Elements Layout:
//! ----------------------------------
//! * Max Elements per UTXO: 5
//! * Max UTXOs per TX: 1
//! * Num TXs: 8
//! * Remainder: Some(2)
//! * Max Stack Size: 755
//! * Transaction Size per UTXO: 31498
//!
//! Hash Layout:
//! ----------------------------------
//! * Max Elements per UTXO: 8
//! * Max UTXOs per TX: 1
//! * Num TXs: 71
//! * Remainder: Some(6)
//! * Max Stack Size: 824
//! * Transaction Size per UTXO: 32396
//!
//! Based on the above data, the elements can be bitcommitted as follows with the constraint that
//! the max stack usage must not exceed 1,000 elements and the max V3 transaction size must not
//! exceed 40,000 weight units:
//!
//! | Element Type  | Elements Per UTXO  |  Connectors | UTXOs Per Tx | Total |
//! | ------------- | ------------------ | ----------- | ------------ | ----- |
//! | Field         | 6                  |  7          | 1            | 42    |
//! | Field         | 0                  |  0          | 1            | 0     |
//! | Hash          | 9                  |  63         | 1            | 567   |
//! | Hash          | 7                  |  1          | 1            | 7     |
use std::time::Duration;

/// The maximum number of field elements that are bitcommitted per UTXO.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1: usize = 6;

/// The number of UTXOs necessary to commit all the required field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_1: usize = 7;

/// The number of remaining field elements.
///
/// # NOTE: This constant has been kept around even if it is zero so as to keep the code agnostic to
/// some extent even if the number of field elements change in the future.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2: usize = 0;

/// The number of UTXOs necessary to commit all the remaining field elements evenly.
///
/// # NOTE: This constant has been kept around even if it is zero so as to keep the code agnostic to
/// some extent even if the number of field elements change in the future.
pub const NUM_FIELD_CONNECTORS_BATCH_2: usize = 0;

/// The maximum number of hashes that are bitcommitted per UTXO.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1: usize = 9;

/// The number of UTXOs necessary to commit all the required hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_1: usize = 63;

/// The number of remaining hash elements.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2: usize = 7;

/// The number of UTXOs necessary to commit all the remaining hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_2: usize = 1;

/// The total number of field elements that need to be committed.
pub const NUM_PKS_A256: usize = 42;
/// The total number of hashes that need to be committed.
pub const NUM_PKS_A160: usize = 574;

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

// FIXME: Move the following to configurable params

pub const BLOCK_TIME: Duration = Duration::from_secs(30);

pub const SUPERBLOCK_MEASUREMENT_PERIOD: u32 = 100; // blocks

pub const TS_COMMITMENT_MARGIN: u32 = 288; // 2 days' worth of blocks in mainnet

pub const PAYOUT_OPTIMISTIC_TIMELOCK: u32 = 500;

const _: u32 =
    PAYOUT_OPTIMISTIC_TIMELOCK - (SUPERBLOCK_MEASUREMENT_PERIOD + TS_COMMITMENT_MARGIN + 100); // 100
                                                                                               // is slack

pub const PAYOUT_TIMELOCK: u32 = 288; // 2 day's worth of blocks in mainnet
