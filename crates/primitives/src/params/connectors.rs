//! Params related to the bridge tx graph connectors, specifically the layout of assert-data
//! connectors.
//!
//! The following constants are derived from the `assert-splitter` bin:
//!
//! * Average Field Element Max Stack Size: 151
//! * Average Field Element Transaction Size: 6767
//! * Average Hash Max Stack size: 103
//! * Average Hash Transaction size: 4561
//!
//! # Field Elements Layout:
//! ----------------------------------
//! * Max Elements per UTXO: 5
//! * Max UTXOs per TX: 1
//! * Num TXs: 8
//! * Remainder: Some(2)
//!
//! * Max Stack Size: 755
//! * Transaction Size per UTXO: 31498
//!
//! Hash Layout:
//! ----------------------------------
//! * Max Elements per UTXO: 8
//! * Max UTXOs per TX: 1
//! * Num TXs: 71
//! * Remainder: Some(6)
//!
//! * Max Stack Size: 824
//! * Transaction Size per UTXO: 32396
//!
//! Based on the above data, the elements can be bitcommitted as follows with the constraint that
//! the max stack usage must not exceed 1_000 elements and the max V3 transaction size must not
//! exceed 40_000 weight units:
//!
//! Element Type  | Elements Per UTXO  |  Connectors | UTXOs Per Tx | Total
//! Field         | 5                  |  6          | 1            | 30
//! Field         | 6                  |  2          | 1            | 12
//! Hash          | 8                  |  65         | 1            | 520
//! Hash          | 9                  |  6          | 1            | 54
use std::time::Duration;

/// The maximum number of field elements that are bitcommitted per UTXO.
pub const NUM_PKS256_BATCH_1: usize = 5;

/// The maximum number of field elements that are bitcommitted per UTXO.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1: usize = 5;

/// The number of UTXOs necessary to commit all the required field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_1: usize = 6;

/// The number of remaining field elements.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2: usize = 6;

/// The number of UTXOs necessary to commit all the remaining field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_2: usize = 2;

/// The maximum number of hashes that are bitcommitted per UTXO.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1: usize = 8;

/// The number of UTXOs necessary to commit all the required hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_1: usize = 65;

/// The number of remaining hash elements.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2: usize = 9;

/// The number of UTXOs necessary to commit all the remaining hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_2: usize = 6;

/// The total number of field elements that need to be committed.
pub const NUM_PKS_A256: usize = 42;
/// The number of UTXOs necessary to commit all the required field elements evenly.
pub const NUM_CONNECTOR_A256: usize = NUM_PKS_A256 / NUM_PKS256_BATCH_1;
/// The number of any remaining field elements.
pub const NUM_PKS_A256_RESIDUAL: usize = NUM_PKS_A256 % NUM_PKS256_BATCH_1;

/// The maximum number of hashes that are bitcommitted per UTXO.
pub const NUM_PKS_A160_PER_CONNECTOR: usize = 8;
/// The total number of hashes that need to be committed.
pub const NUM_PKS_A160: usize = 574;
/// The number of UTXOs necessary to commit all the required hashes evenly.
pub const NUM_CONNECTOR_A160: usize = NUM_PKS_A160 / NUM_PKS_A160_PER_CONNECTOR;
/// The number of any remaining hash elements.
pub const NUM_PKS_A160_RESIDUAL: usize = NUM_PKS_A160 % NUM_PKS_A160_PER_CONNECTOR;

/// The total number of connectors that contain the bitcommitment locking scripts for assertion.
pub const TOTAL_CONNECTORS: usize = NUM_FIELD_CONNECTORS_BATCH_1
    + NUM_FIELD_CONNECTORS_BATCH_2
    + NUM_HASH_CONNECTORS_BATCH_1
    + NUM_HASH_CONNECTORS_BATCH_2;

/// The number of first batch of assert-data transactions.
///
/// Each transaction in this batch has [`NUM_ASSERT_DATA_TX1_A256`] UTXOs each of which can commit
/// to [`NUM_PKS_A256_PER_CONNECTOR`] field elements.
pub const NUM_ASSERT_DATA_TX1: usize = 8;
/// The number of UTXOs that commit to [`NUM_PKS_A256_PER_CONNECTOR`] field elements.
///
/// Each such UTXO is used in the first batch of assert-data transactions.
pub const NUM_ASSERT_DATA_TX1_A256: usize = 1;

/// The number of second batch of assert-data transactions.
///
/// Each transaction in this batch has [`NUM_ASSERT_DATA_TX2_A160`] UTXOs each of which can commit
/// to [`NUM_PKS_A160_PER_CONNECTOR`] hashes.
pub const NUM_ASSERT_DATA_TX2: usize = 71;
/// The number of UTXOs that commit to [`NUM_PKS_A160_PER_CONNECTOR`] hashes.
///
/// Each such UTXO is used in the second batch of assert-data transactions.
pub const NUM_ASSERT_DATA_TX2_A160: usize = 1;

/// The number of third batch of assert-data transactions.
///
/// Each transaction in this batch has [`NUM_ASSERT_DATA_TX3_A160`] UTXOs each of which can commit
/// to [`NUM_PKS_A160_RESIDUAL`] hashes.
pub const NUM_ASSERT_DATA_TX3: usize = 1;
/// The number of UTXOs that commit to [`NUM_PKS_A160_RESIDUAL`] hashes.
///
/// Each such UTXO is used in the third batch of assert-data transactions.
pub const NUM_ASSERT_DATA_TX3_A160: usize = 1;

/// The number of fourth batch of assert-data transactions.
///
/// Each transaction in this batch has [`NUM_ASSERT_DATA_TX4_A256`] UTXOs each of which can commit
/// to [`NUM_PKS_A256_RESIDUAL`] field elements.
pub const NUM_ASSERT_DATA_TX4: usize = 1;
/// The number of UTXOs that commit to [`NUM_PKS_A256_RESIDUAL`] field elements.
///
/// Each such UTXO is used in the fourth batch of assert-data transactions.
pub const NUM_ASSERT_DATA_TX4_A256: usize = 1;

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
