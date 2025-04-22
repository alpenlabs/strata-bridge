use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use bitcoin::{
    address::Address,
    hex::DisplayHex,
    key::Keypair,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::TaprootBuilder,
    ScriptBuf, TapNodeHash,
};
use miniscript::Miniscript;
use strata_primitives::constants::UNSPENDABLE_PUBLIC_KEY;
use tracing::info;

use crate::constants::{AGGREGATED_PUBKEY, LOCKTIME, MAGIC_BYTES, NETWORK};

pub(crate) fn get_aggregated_pubkey() -> XOnlyPublicKey {
    *AGGREGATED_PUBKEY
}

pub(crate) fn generate_taproot_address(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    n_of_n_multisig_script: ScriptBuf,
    timelock_script: ScriptBuf,
) -> (TapNodeHash, Address) {
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(1, n_of_n_multisig_script.clone())
        .expect("failed to add n-of-n multisig script to tree")
        .add_leaf(1, timelock_script.clone())
        .expect("failed to add timelock script");

    let script_hash =
        TapNodeHash::from_script(&timelock_script, bitcoin::taproot::LeafVersion::TapScript);

    let taproot_info = taproot_builder
        .finalize(secp, *UNSPENDABLE_PUBLIC_KEY)
        .unwrap();
    let merkle_root = taproot_info.merkle_root();

    let tr_address = Address::p2tr(secp, *UNSPENDABLE_PUBLIC_KEY, merkle_root, NETWORK);
    (script_hash, tr_address)
}

pub(crate) fn build_n_of_n_multisig_miniscript(aggregated_pubkey: XOnlyPublicKey) -> ScriptBuf {
    let script = format!("pk({})", aggregated_pubkey);
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

pub(crate) fn build_timelock_miniscript(recovery_xonly_pubkey: XOnlyPublicKey) -> ScriptBuf {
    let script = format!("and_v(v:pk({}),older({}))", recovery_xonly_pubkey, LOCKTIME);
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

pub(crate) fn build_op_return_script(
    evm_address: &EvmAddress,
    take_back_key: &XOnlyPublicKey,
) -> Vec<u8> {
    let mut data = MAGIC_BYTES.to_vec();
    data.extend(take_back_key.serialize());
    data.extend(evm_address.as_slice());

    data
}

pub(crate) fn get_recovery_pubkey() -> XOnlyPublicKey {
    let keypair = Keypair::new(
        &bitcoin::secp256k1::Secp256k1::new(),
        &mut bitcoin::key::rand::thread_rng(),
    );
    let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let secret_key = keypair.secret_bytes().to_lower_hex_string();

    info!(event = "generated random x-only pubkey for recovery", %secret_key, %xonly_pubkey);

    xonly_pubkey
}
