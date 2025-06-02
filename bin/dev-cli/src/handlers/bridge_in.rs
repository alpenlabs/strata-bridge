use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use anyhow::{anyhow, Result};
use bitcoin::{hex::DisplayHex, taproot::TaprootBuilder, Address, ScriptBuf};
use bitcoincore_rpc::{Auth, Client};
use miniscript::Miniscript;
use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
use tracing::info;

use crate::{
    cli,
    constants::{AGGREGATED_PUBKEY, LOCKTIME, MAGIC_BYTES, NETWORK},
    handlers::wallet::{self, PsbtWallet},
};

pub(crate) fn handle_bridge_in(args: cli::BridgeInArgs) -> Result<()> {
    let rpc_auth = Auth::UserPass(args.btc_user, args.btc_pass);
    let rpc_client = Client::new(&args.btc_url, rpc_auth)
        .map_err(|e| anyhow!("Failed to create RPC client: {}", e))?;

    let psbt_wallet = wallet::BitcoinRpcWallet::new(rpc_client);

    info!(action = "Initiating bridge-in", strata_address=%args.strata_address);

    let strata_address = EvmAddress::from_str(&args.strata_address)?;
    let recovery_pubkey = get_recovery_pubkey();
    let metadata = build_op_return_script(&strata_address, &recovery_pubkey);

    let timelock_script = build_timelock_miniscript(recovery_pubkey);
    let taproot_address = generate_taproot_address(timelock_script);

    let psbt = psbt_wallet.create_drt_psbt(&taproot_address, metadata, &NETWORK)?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

fn generate_taproot_address(timelock_script: ScriptBuf) -> Address {
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, timelock_script.clone())
        .expect("failed to add timelock script");

    let taproot_info = taproot_builder
        .finalize(SECP256K1, *AGGREGATED_PUBKEY)
        .unwrap();
    let merkle_root = taproot_info.merkle_root();

    Address::p2tr(SECP256K1, *AGGREGATED_PUBKEY, merkle_root, NETWORK)
}

fn build_timelock_miniscript(recovery_xonly_pubkey: XOnlyPublicKey) -> ScriptBuf {
    let script = format!("and_v(v:pk({}),older({}))", recovery_xonly_pubkey, LOCKTIME);
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

fn build_op_return_script(evm_address: &EvmAddress, take_back_key: &XOnlyPublicKey) -> Vec<u8> {
    let mut data: Vec<u8> = MAGIC_BYTES.into();
    data.extend(take_back_key.serialize());
    data.extend(evm_address.as_slice());

    data
}

fn get_recovery_pubkey() -> XOnlyPublicKey {
    let keypair = Keypair::new(
        &bitcoin::secp256k1::Secp256k1::new(),
        &mut bitcoin::key::rand::thread_rng(),
    );
    let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let secret_key = keypair.secret_bytes().to_lower_hex_string();

    info!(event = "generated random x-only pubkey for recovery", %secret_key, %xonly_pubkey);

    xonly_pubkey
}
