use std::sync::LazyLock;

use alloy::consensus::constants::ETH_TO_WEI;
use bitcoin::{secp256k1::XOnlyPublicKey, Amount, Network};

pub(crate) const AMOUNT: Amount = Amount::from_sat(1_000_100_000);

// extra amount pays for DT
pub(crate) const NETWORK: Network = Network::Regtest;

pub(crate) const ROLLUP_ADDRESS: &str = "0x5400000000000000000000000000000000000001";

pub(crate) const ETH_RPC_URL: &str = "http://localhost:8545";

pub(crate) const BRIDGE_OUT_AMOUNT: Amount = Amount::from_int_btc(10);

pub(crate) const BTC_TO_WEI: u128 = ETH_TO_WEI;

pub(crate) const SATS_TO_WEI: u128 = BTC_TO_WEI / 100_000_000;

//change to appropriate value
pub(crate) const AGGREGATED_PUBKEY_HEX: &str =
    "c46132cbb3ef14caeac8f724fea1449d802133495ef1675f210b0742f5ee8164";

//can remain fixed as is
pub(crate) const NUMS_POINT: &str =
    "0x2be4d02127fedf4c956f8e6d8248420b9af78746232315f72894f0b263c80e81";

//change to appropriate value
pub(crate) const LOCKTIME: i64 = 1008;

pub(crate) static AGGREGATED_PUBKEY: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    let pubkey_hex = AGGREGATED_PUBKEY_HEX;
    let pubkey_bytes = hex::decode(pubkey_hex).expect("Decoding hex failed");
    assert_eq!(pubkey_bytes.len(), 32, "XOnlyPublicKey must be 32 bytes");

    XOnlyPublicKey::from_slice(&pubkey_bytes).expect("Failed to create XOnlyPublicKey")
});
