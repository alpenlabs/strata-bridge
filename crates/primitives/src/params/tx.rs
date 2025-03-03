//! Params related to the bridge transactions.

use std::{sync::LazyLock, time::Duration};

use bitcoin::{
    hashes::{sha256, Hash},
    relative,
    secp256k1::XOnlyPublicKey,
    Amount, FeeRate,
};

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

pub const ASSERT_DATA_FEE_RATE: FeeRate =
    FeeRate::from_sat_per_vb_unchecked(FeeRate::DUST.to_sat_per_vb_ceil() * 80); // 80 is based on
                                                                                 // experiment

/// The minimum value a segwit output script should have in order to be
/// broadcastable on today's Bitcoin network.
///
/// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
/// This function uses the default value of 0.00003 BTC/kB (3 sat/vByte).
pub const SEGWIT_MIN_AMOUNT: Amount = Amount::from_sat(330);

pub const BTC_CONFIRM_PERIOD: Duration = Duration::from_secs(6);

/// The default amount of BTC that is staked by an operator.
pub const OPERATOR_STAKE: Amount = Amount::from_int_btc(3);

/// The default amount of BTC that is burnt when an operator's stake is slashed.
pub const BURN_AMOUNT: Amount = Amount::from_int_btc(1);

/// The default number of blocks between each stake transaction enforced via relative timelocks.
pub const STAKE_TX_DELTA: relative::LockTime = relative::LockTime::from_height(6);

/// The number of ongoing past `Claim` transactions that can be used to slash an operator's stake.
pub const NUM_SLASH_STAKE_TX: usize = 24;

/// The fee charged by the operator to process a withdrawal.
///
/// This has the type [`Amount`] for convenience.
pub const OPERATOR_FEE: Amount = Amount::from_int_btc(2);

pub const CHALLENGE_COST: Amount = Amount::from_int_btc(1);

/// The reward for a successful disprover.
pub const DISPROVER_REWARD: Amount = Amount::from_int_btc(1);

/// The reward for a successful slashing.
pub const SLASH_STAKE_REWARD: Amount = Amount::from_sat(199_999_000); // 2 BTC - 1000 sats

/// Magic bytes to add to the metadata output in transactions to help identify them.
pub const MAGIC_BYTES: &[u8; 11] = b"alpenstrata";

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
pub static UNSPENDABLE_INTERNAL_KEY: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    XOnlyPublicKey::from_slice(sha256::Hash::hash(UNSPENDABLE_PUBLIC_KEY_INPUT).as_byte_array())
        .expect("valid xonly public key")
});
