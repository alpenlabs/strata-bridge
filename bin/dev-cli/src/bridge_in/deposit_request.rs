use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use bitcoin::{
    address::Address,
    hex::DisplayHex,
    key::Keypair,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::TaprootBuilder,
    ScriptBuf,
};
use miniscript::Miniscript;
use tracing::info;

use crate::constants::{AGGREGATED_PUBKEY, LOCKTIME, MAGIC_BYTES, NETWORK};

pub(crate) fn get_aggregated_pubkey() -> XOnlyPublicKey {
    *AGGREGATED_PUBKEY
}

pub(crate) fn generate_taproot_address(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    timelock_script: ScriptBuf,
) -> Address {
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, timelock_script.clone())
        .expect("failed to add timelock script");

    let agg_pubkey = get_aggregated_pubkey();
    let taproot_info = taproot_builder.finalize(secp, agg_pubkey).unwrap();
    let merkle_root = taproot_info.merkle_root();

    Address::p2tr(secp, agg_pubkey, merkle_root, NETWORK)
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
    let mut data = MAGIC_BYTES.as_bytes().to_vec();
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
