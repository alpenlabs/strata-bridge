use std::sync::LazyLock;

use alloy::consensus::constants::ETH_TO_WEI;
use bitcoin::{secp256k1::XOnlyPublicKey, Amount, Network};

pub(crate) const AMOUNT: Amount = Amount::from_sat(100_100_000);

// extra amount pays for DT
pub(crate) const NETWORK: Network = Network::Regtest;

pub(crate) const ROLLUP_ADDRESS: &str = "0x5400000000000000000000000000000000000001";

pub(crate) const ETH_RPC_URL: &str = "http://localhost:8545";

pub(crate) const BRIDGE_OUT_AMOUNT: Amount = Amount::from_int_btc(1);

pub(crate) const BTC_TO_WEI: u128 = ETH_TO_WEI;

pub(crate) const SATS_TO_WEI: u128 = BTC_TO_WEI / 100_000_000;

pub(crate) const MAGIC_BYTES: &[u8] = b"strata";

//change to appropriate value
pub(crate) const AGGREGATED_PUBKEY_HEX: &str =
    "68b5503d2b18d0ff78cb06c0ec79613eebd297a6e2f8f4ed8f435641bc087d34";

//change to appropriate value
pub(crate) const LOCKTIME: i64 = 1008;

pub(crate) static AGGREGATED_PUBKEY: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    let pubkey_hex = AGGREGATED_PUBKEY_HEX;
    let pubkey_bytes = hex::decode(pubkey_hex).expect("Decoding hex failed");
    assert_eq!(pubkey_bytes.len(), 32, "XOnlyPublicKey must be 32 bytes");

    XOnlyPublicKey::from_slice(&pubkey_bytes).expect("Failed to create XOnlyPublicKey")
});
