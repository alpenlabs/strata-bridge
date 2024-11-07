//! Params related to the bridge transactions.

use std::str::FromStr;

use bitcoin::{secp256k1::XOnlyPublicKey, Amount};

/// The value of each UTXO in the Bridge Multisig Address.
pub const BRIDGE_DENOMINATION: Amount = Amount::from_int_btc(10);

/// The min relay fee as defined in bitcoin-core with the unit sats/kvB.
///
/// This is set to a larger value (3 in bitcoin-core) to cross the dust threshold for certain
/// outputs. Setting this to a very high value may alleviate the need for an `anyone_can_pay`
/// output. In its current configuration of `10`, the total transaction fee for withdrawal
/// transaction computes to ~5.5 sats/vB (run integration tests with `RUST_LOG=warn` to verify).
pub const MIN_RELAY_FEE: Amount = Amount::from_sat(5000);

/// The assert data tx is almost as big as the standardness limit allows.
///
/// So, it requires extra fees. Here, we set it to 4 times the normal.
pub const ASSERT_DATA_FEE: Amount = Amount::from_sat(4 * 1000);

pub const OPERATOR_STAKE: Amount = Amount::from_int_btc(5);

/// The fee charged by the operator to process a withdrawal.
///
/// This has the type [`Amount`] for convenience.
pub const OPERATOR_FEE: Amount = Amount::from_int_btc(2);

/// Magic bytes to add to the metadata output in transactions to help identify them.
pub const MAGIC_BYTES: &[u8; 11] = b"alpenstrata";

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// This is generated via <https://github.com/alpenlabs/unspendable-pubkey-gen> following [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs)
    /// with `r = 0x82758434e13488368e0781c4a94019d3d6722f854d26c15d2d157acd1f464723`.
    pub static ref UNSPENDABLE_INTERNAL_KEY: XOnlyPublicKey =
        XOnlyPublicKey::from_str("2be4d02127fedf4c956f8e6d8248420b9af78746232315f72894f0b263c80e81").unwrap();
}
