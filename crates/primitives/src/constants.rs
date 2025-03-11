//! This module contains contants related to how the transaction graph in the bridge is constructed.
//!
//! These constants are integral to the graph i.e., changing them would change the nature of the
//! graph itself (size, structure, etc.). These values must be known at compile-time.
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

use std::sync::LazyLock;

use bitcoin::{
    hashes::{sha256, Hash},
    Amount,
};
use bitvm::chunk::compile::{NUM_PUBS, NUM_U160, NUM_U256};
use secp256k1::XOnlyPublicKey;

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
pub const NUM_PKS_A256: usize = NUM_U256 + NUM_PUBS; // 20 field elements + 1 proof input
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
/// | Assert Data   | 2                                      | 47             | 31020      |
/// | Pre Assert    | 1                                      |  1             |   330      |
/// | Claim         | 3                                      |  1             |   990      |
/// |---------------|----------------------------------------|----------------|------------|
/// | Total         |                                        | 50             | 32340      |
pub const FUNDING_AMOUNT: Amount = Amount::from_sat(32_340);

const UNSPENDABLE_PUBLIC_KEY_INPUT: &[u8] = b"Strata Bridge Unspendable";

/// A verifiably unspendable public key, produced by hashing a fixed string to a curve group
/// generator.
///
/// This is related to the technique used in [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).
///
/// Note that this is _not_ necessarily a uniformly-sampled curve point!
///
/// But this is fine; we only need a generator with no efficiently-computable discrete logarithm
/// relation against the standard generator.
pub static UNSPENDABLE_INTERNAL_KEY: LazyLock<XOnlyPublicKey> =
    LazyLock::new(|| -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(sha256::Hash::hash(UNSPENDABLE_PUBLIC_KEY_INPUT).as_byte_array())
            .expect("valid xonly public key")
    });
