//! Test utilities for testing out deposit.
//!
//! These utilities are not written in the `test-utils` crate to keep the primtivies crate
//! completely independent.
use std::collections::BTreeMap;

use bitcoin::{secp256k1::PublicKey, taproot::LeafVersion, Network, TapNodeHash, XOnlyPublicKey};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress,
    scripts::{
        general::{drt_take_back, get_aggregated_pubkey},
        prelude::{create_taproot_addr, SpendPath},
    },
    types::OperatorIdx,
};
use strata_primitives::bridge::PublickeyTable;

/// Generates a public key table from a slice of public keys.
pub fn generate_pubkey_table(table: &[PublicKey]) -> PublickeyTable {
    let pubkey_table = table
        .iter()
        .enumerate()
        .map(|(i, pk)| (i as OperatorIdx, *pk))
        .collect::<BTreeMap<OperatorIdx, PublicKey>>();

    PublickeyTable::from(pubkey_table)
}

/// Creates a DRT taproot output.
pub fn create_drt_taproot_output(
    pubkeys: PublickeyTable,
    recovery_xonly_pubkey: XOnlyPublicKey,
    refund_delay: u16,
) -> (BitcoinAddress, TapNodeHash) {
    let aggregated_pubkey = get_aggregated_pubkey(pubkeys.0.into_values());
    let takeback_script = drt_take_back(recovery_xonly_pubkey, refund_delay);
    let takeback_script_hash = TapNodeHash::from_script(&takeback_script, LeafVersion::TapScript);

    let network = Network::Regtest;
    let spend_path = SpendPath::Both {
        internal_key: aggregated_pubkey,
        scripts: &[takeback_script],
    };
    let (address, _spend_info) = create_taproot_addr(&network, spend_path).unwrap();
    let address_str = address.to_string();

    (
        BitcoinAddress::parse(&address_str, network).expect("address should be valid"),
        takeback_script_hash,
    )
}
