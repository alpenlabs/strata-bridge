//! Test utilities for the primitives.
//!
//! These utilities are not written in the `test-utils` crate to keep the primtivies crate
//! completely independent.
use std::collections::{BTreeMap, HashSet};

use bitcoin::{
    key::rand::rngs::OsRng,
    secp256k1::{Keypair, PublicKey, SecretKey, SECP256K1},
    taproot::LeafVersion,
    Network, TapNodeHash, XOnlyPublicKey,
};
use secp256k1::rand::thread_rng;
use strata_primitives::bridge::PublickeyTable;

use crate::{
    bitcoin::BitcoinAddress,
    scripts::{
        general::{drt_take_back, get_aggregated_pubkey, n_of_n_script},
        prelude::{create_taproot_addr, SpendPath},
    },
    secp::EvenSecretKey,
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
    let sk = SecretKey::new(&mut rng);
    let even_sk: EvenSecretKey = sk.into();
    even_sk.x_only_public_key(SECP256K1).0
}

pub(crate) fn create_drt_taproot_output(
    pubkeys: PublickeyTable,
    recovery_xonly_pubkey: XOnlyPublicKey,
    refund_delay: u16,
) -> (BitcoinAddress, TapNodeHash) {
    let aggregated_pubkey = get_aggregated_pubkey(pubkeys.0.into_values());
    let n_of_n_spend_script = n_of_n_script(&aggregated_pubkey);
    let takeback_script = drt_take_back(recovery_xonly_pubkey, refund_delay);
    let takeback_script_hash = TapNodeHash::from_script(&takeback_script, LeafVersion::TapScript);

    let network = Network::Regtest;
    let spend_path = SpendPath::ScriptSpend {
        scripts: &[n_of_n_spend_script.compile(), takeback_script],
    };
    let (address, _spend_info) = create_taproot_addr(&network, spend_path).unwrap();
    let address_str = address.to_string();

    (
        BitcoinAddress::parse(&address_str, network).expect("address should be valid"),
        takeback_script_hash,
    )
}
