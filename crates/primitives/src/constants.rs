//! This module contains constants related to how the transaction graph in the bridge is
//! constructed.
//!
//! These constants are integral to the graph i.e., changing them would change the nature of the
//! graph itself (size, structure, etc.). These values must be known at compile-time.
//!
//! The following data was used to determine the layout of the connectors. This data is the output
//! of running `cargo run --bin assert-splitter`.
//!
//! * Average Field Element Max Stack Size: 145
//! * Average Field Element Transaction Size: 6790
//! * Average Hash Max stack size: 81
//! * Average Hash Transaction size: 3888
//!
//! Field Elements Layout:
//! ----------------------------------
//! Max Elements per UTXO: 5
//! Max UTXOs per TX: 1
//! Num TXs: 3
//! Remainder: None
//! Max Stack Size: 725
//! Transaction Size per UTXO: 31616
//!
//! Hash Layout:
//! ----------------------------------
//! Max Elements per UTXO: 10
//! Max UTXOs per TX: 1
//! Num TXs: 36
//! Remainder: Some(3)
//! Max Stack Size: 810
//! Transaction Size per UTXO: 33618
//!
//! Based on the above data, the elements can be bitcommitted as follows with the constraint that
//! the max stack usage must not exceed 1,000 elements and the max V3 transaction size must not
//! exceed 40,000 weight units:
//!
//! | Element Type  | Elements Per UTXO  |  Connectors | UTXOs Per Tx | Total |
//! | ------------- | ------------------ | ----------- | ------------ | ----- |
//! | Field         | 5                  |  3          | 1            | 15    |
//! | Field         | 0                  |  0          | 0            | 0     |
//! | Hash          | 10                 |  33         | 1            | 330   |
//! | Hash          | 11                 |  3          | 1            | 33    |

use bitcoin::Amount;
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};

/// The maximum number of field elements that are bitcommitted per UTXO.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1: usize = 5;

/// The number of UTXOs necessary to commit all the required field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_1: usize = 3;

/// The number of remaining field elements.
pub const NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2: usize = 0;

/// The number of UTXOs necessary to commit all the remaining field elements evenly.
pub const NUM_FIELD_CONNECTORS_BATCH_2: usize = 0;

/// The maximum number of hashes that are bitcommitted per UTXO.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1: usize = 10;

/// The number of UTXOs necessary to commit all the required hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_1: usize = 33;

/// The number of remaining hash elements.
pub const NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2: usize = 11;

/// The number of UTXOs necessary to commit all the remaining hashes evenly.
pub const NUM_HASH_CONNECTORS_BATCH_2: usize = 3;

/// The total number of field elements that need to be committed.
pub const NUM_PKS_A256: usize = NUM_U256 + NUM_PUBS; // 20 field elements + 1 proof input
/// The total number of hashes that need to be committed.
pub const NUM_PKS_A_HASH: usize = NUM_HASH;

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
const _: [(); 0] = [(); (NUM_PKS_A_HASH - NUM_HASH_ELEMENTS)];
const _: [(); 0] = [(); (NUM_PKS_A256 + NUM_PKS_A_HASH - TOTAL_VALUES)];

/// The minimum value a segwit output script should have in order to be
/// broadcastable on today's Bitcoin network.
///
/// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
/// This function uses the default value of 0.00003 BTC/kB (3 sat/vByte).
pub const SEGWIT_MIN_AMOUNT: Amount = Amount::from_sat(330);

/// The minimum amount required to fund all the dust outputs in the peg-out graph.
///
/// This is calculated as follows:
///
/// | Transaction   | # [`SEGWIT_MIN_AMOUNT`] outputs per tx | # Transactions | Total sats |
/// |---------------|----------------------------------------|----------------|------------|
/// | Assert Data   | 2                                      | 39             | 25740      |
/// | Pre Assert    | 1                                      |  1             |   330      |
/// | Claim         | 3                                      |  1             |   990      |
/// |---------------|----------------------------------------|----------------|------------|
/// | Total         |                                        | 41             | 27060      |
pub const FUNDING_AMOUNT: Amount = Amount::from_sat(2 * 39 * 330 + 330 + 3 * 330);
