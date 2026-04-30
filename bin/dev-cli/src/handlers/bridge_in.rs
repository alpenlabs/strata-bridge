//! Bridge-in handler using SPS-50 metadata format.

use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use anyhow::Result;
use bitcoin::{hex::DisplayHex, taproot::TaprootBuilder, Address, Amount, Network, ScriptBuf};
use miniscript::Miniscript;
use musig2::KeyAggContext;
use secp256k1::{Keypair, Parity, XOnlyPublicKey, SECP256K1};
use strata_asm_proto_bridge_v1_txs::deposit_request::DrtHeaderAux;
use strata_bridge_common::params::Params;
use strata_identifiers::{AccountSerial, SubjectIdBytes};
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_ol_bridge_types::DepositDescriptor;
use tracing::info;

use crate::{
    cli::BridgeInArgs,
    handlers::{
        rpc,
        wallet::{self, PsbtWallet},
    },
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

    let metadata =
        build_sps50_metadata(params.protocol.magic_bytes, &ee_address, &recovery_pubkey)?;

    let timelock_script =
        build_timelock_miniscript(params.protocol.recovery_delay, recovery_pubkey);

    let musig2_keys: Vec<XOnlyPublicKey> = params.keys.covenant.iter().map(|c| c.musig2).collect();
    let agg_key = KeyAggContext::new(musig2_keys.into_iter().map(|k| k.public_key(Parity::Even)))
        .expect("must be able to aggregate keys")
        .aggregated_pubkey();
    let taproot_address = generate_taproot_address(params.network, timelock_script, agg_key);

    let deposit_fees = Amount::from_sat(1_000);
    let psbt = psbt_wallet.create_drt_psbt(
        params.protocol.deposit_amount + deposit_fees,
        &taproot_address,
        metadata,
        &params.network,
    )?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

/// Builds the SPS-50 OP_RETURN metadata for the deposit request transaction.
///
/// Format: `magic(4) + subprotocol(1) + tx_type(1) + recovery_pk(32) + destination(variable)`
fn build_sps50_metadata(
    magic_bytes: MagicBytes,
    ee_address: &EvmAddress,
    recovery_pubkey: &XOnlyPublicKey,
) -> Result<Vec<u8>> {
    let alpen_subject_bytes =
        SubjectIdBytes::try_new(ee_address.to_vec()).expect("must be valid subject bytes");

    // 0..127 are reserved, 128 is for `Alpen`
    let alpen_account_serial: AccountSerial = AccountSerial::reserved(127).incr();
    let deposit_descriptor = DepositDescriptor::new(alpen_account_serial, alpen_subject_bytes)
        .expect("AccountSerial for Alpen is always within valid range");
    let destination = deposit_descriptor.encode_to_varvec();

    let header_aux = DrtHeaderAux::new(recovery_pubkey.serialize(), destination)
        .expect("header aux creation must succeed");

    let tag_data = header_aux.build_tag_data();
    info!(tag_data=%tag_data.aux_data().to_lower_hex_string(), "built SPS-50 aux data for DRT");

    let config = ParseConfig::new(magic_bytes);
    let encoded = config.encode_tag_buf(&tag_data.as_ref())?;
    info!(encoded=%encoded.to_lower_hex_string(), "encoded SPS-50 metadata for OP_RETURN");

    Ok(encoded)
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
    let script = format!("and_v(v:pk({recovery_xonly_pubkey}),older({refund_delay}))");
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
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
