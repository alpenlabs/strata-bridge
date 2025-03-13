//! Test utilities for the primitives.
//!
//! These utilities are not written in the `test-utils` crate to keep the primtivies crate
//! completely independent.
use std::collections::{BTreeMap, HashSet};

use bitcoin::{
    key::rand::rngs::OsRng,
    secp256k1::{Keypair, PublicKey, SecretKey, SECP256K1},
    taproot::{LeafVersion, TaprootBuilder},
    Address, Network, TapNodeHash, XOnlyPublicKey,
};
use secp256k1::{rand::thread_rng, Parity};
use strata_primitives::bridge::PublickeyTable;

use crate::{
    bitcoin::BitcoinAddress,
    constants::UNSPENDABLE_INTERNAL_KEY,
    scripts::general::{drt_take_back, get_aggregated_pubkey, metadata_script, n_of_n_script},
    types::OperatorIdx,
};

/// Generate `count` (public key, private key) pairs as two separate [`Vec`].
pub(crate) fn generate_keypairs(count: usize) -> (Vec<PublicKey>, Vec<SecretKey>) {
    let mut secret_keys: Vec<SecretKey> = Vec::with_capacity(count);
    let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(count);

    let mut pubkeys_set: HashSet<PublicKey> = HashSet::new();

    while pubkeys_set.len() != count {
        let sk = SecretKey::new(&mut OsRng);
        let keypair = Keypair::from_secret_key(SECP256K1, &sk);
        let pubkey = PublicKey::from_keypair(&keypair);

        if pubkeys_set.insert(pubkey) {
            secret_keys.push(sk);
            pubkeys.push(pubkey);
        }
    }

    (pubkeys, secret_keys)
}

pub(crate) fn generate_pubkey_table(table: &[PublicKey]) -> PublickeyTable {
    let pubkey_table = table
        .iter()
        .enumerate()
        .map(|(i, pk)| (i as OperatorIdx, *pk))
        .collect::<BTreeMap<OperatorIdx, PublicKey>>();

    PublickeyTable::from(pubkey_table)
}

pub(crate) fn generate_xonly_pubkey() -> XOnlyPublicKey {
    let mut rng = thread_rng();
    let mut sk = SecretKey::new(&mut rng);
    // negate sk if odd
    if sk.x_only_public_key(SECP256K1).1 == Parity::Odd {
        sk = sk.negate();
    }
    sk.x_only_public_key(SECP256K1).0
}

pub(crate) fn create_drt_taproot_output(pubkeys: PublickeyTable) -> (BitcoinAddress, TapNodeHash) {
    let aggregated_pubkey = get_aggregated_pubkey(pubkeys.0.into_values());
    let n_of_n_spend_script = n_of_n_script(&aggregated_pubkey);
    let recovery_xonly_pubkey = generate_xonly_pubkey();
    let refund_delay = 1_008; // Placeholder
    let takeback_script = drt_take_back(recovery_xonly_pubkey, refund_delay);
    let takeback_script_hash = TapNodeHash::from_script(&takeback_script, LeafVersion::TapScript);

    // in actual DRT, this will be the take-back leaf.
    // for testing, this could be any script as we only care about its hash.
    let tag = b"alpen";
    let op_return_script = metadata_script(
        Some(&recovery_xonly_pubkey.serialize()),
        &[0u8; 20],
        &tag[..],
    );

    let taproot_builder = TaprootBuilder::new()
        .add_leaf(1, n_of_n_spend_script.compile())
        .unwrap()
        .add_leaf(1, takeback_script)
        .unwrap()
        .add_leaf(1, op_return_script)
        .unwrap();

    let spend_info = taproot_builder
        .finalize(SECP256K1, *UNSPENDABLE_INTERNAL_KEY)
        .unwrap();

    let network = Network::Regtest;
    let address = Address::p2tr(
        SECP256K1,
        *UNSPENDABLE_INTERNAL_KEY,
        spend_info.merkle_root(),
        network,
    );
    let address_str = address.to_string();

    (
        BitcoinAddress::parse(&address_str, network).expect("address should be valid"),
        takeback_script_hash,
    )
}
