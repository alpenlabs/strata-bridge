use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use alpen_bridge_params::types::Tag;
use anyhow::Result;
use bitcoin::{hex::DisplayHex, taproot::TaprootBuilder, Address, Amount, Network, ScriptBuf};
use miniscript::Miniscript;
use musig2::KeyAggContext;
use secp256k1::{Keypair, Parity, XOnlyPublicKey, SECP256K1};
use tracing::info;

use crate::{
    cli::BridgeInArgs,
    handlers::{
        rpc,
        wallet::{self, PsbtWallet},
    },
    params::Params,
};

pub(crate) fn handle_bridge_in(args: BridgeInArgs) -> Result<()> {
    let BridgeInArgs {
        btc_args,
        ee_address,
        params,
    } = args;
    let rpc_client = rpc::get_btc_client(&btc_args.url, btc_args.user, btc_args.pass)?;
    let params = Params::from_path(params)?;

    let psbt_wallet = wallet::BitcoinRpcWallet::new(rpc_client);

    info!(action = "Initiating bridge-in", %ee_address);

    let ee_address = EvmAddress::from_str(&ee_address)?;
    let recovery_pubkey = get_recovery_pubkey();
    let metadata = build_op_return_script(params.tag, &ee_address, &recovery_pubkey);

    let timelock_script = build_timelock_miniscript(params.refund_delay, recovery_pubkey);

    let agg_key = KeyAggContext::new(
        params
            .musig2_keys
            .into_iter()
            .map(|k| k.public_key(Parity::Even)),
    )
    .expect("must be able to aggregate keys")
    .aggregated_pubkey();
    let taproot_address = generate_taproot_address(params.network, timelock_script, agg_key);

    let deposit_fees = Amount::from_sat(1_000);
    let psbt = psbt_wallet.create_drt_psbt(
        params.deposit_amount + deposit_fees,
        &taproot_address,
        metadata,
        &params.network,
    )?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

fn generate_taproot_address(
    network: Network,
    timelock_script: ScriptBuf,
    agg_pubkey: XOnlyPublicKey,
) -> Address {
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, timelock_script.clone())
        .expect("failed to add timelock script");

    let taproot_info = taproot_builder.finalize(SECP256K1, agg_pubkey).unwrap();
    let merkle_root = taproot_info.merkle_root();

    Address::p2tr(SECP256K1, agg_pubkey, merkle_root, network)
}

fn build_timelock_miniscript(
    refund_delay: u16,
    recovery_xonly_pubkey: XOnlyPublicKey,
) -> ScriptBuf {
    let script = format!(
        "and_v(v:pk({}),older({}))",
        recovery_xonly_pubkey, refund_delay
    );
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

fn build_op_return_script(
    tag: Tag,
    evm_address: &EvmAddress,
    take_back_key: &XOnlyPublicKey,
) -> Vec<u8> {
    let mut data: Vec<u8> = tag.as_bytes().to_vec();
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
