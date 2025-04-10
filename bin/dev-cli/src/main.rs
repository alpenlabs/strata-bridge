mod bridge_in;
mod bridge_out;

use std::str::FromStr;

use alloy::{
    network::EthereumWallet,
    primitives::{Address as EvmAddress, U256},
    signers::local::PrivateKeySigner,
};
use alloy_signer::k256::ecdsa::SigningKey;
use anyhow::{Context, Error, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin_bosd::Descriptor;
use bridge_in::{deposit_request, wallet};
use clap::Parser;
use strata_common::logging::{self, LoggerConfig};
use tracing::info;

use crate::bridge_in::wallet::PsbtWallet;

mod constants;

mod cli;

fn main() -> Result<(), Error> {
    logging::init(LoggerConfig::new("dev-cli".to_string()));

    let cli = cli::Cli::parse();
    match cli.command {
        cli::Commands::BridgeIn(args) => handle_bridge_in(args),
        cli::Commands::BridgeOut(args) => handle_bridge_out(args),
    }
}

fn handle_bridge_in(args: cli::BridgeInArgs) -> Result<()> {
    let rpc_client =
        bridge_in::bitcoin_rpc_client::setup_rpc(&args.btc_url, args.btc_user, args.btc_pass);
    let psbt_wallet = wallet::BitcoinRpcWallet::new(rpc_client);
    let secp = Secp256k1::new();

    info!(action = "Initiating bridge-in", strata_address=%args.strata_address);

    let strata_address = EvmAddress::from_str(&args.strata_address)?;
    let recovery_pubkey = deposit_request::get_recovery_pubkey();

    let aggregated_pubkey = deposit_request::get_aggregated_pubkey();

    let n_of_n_multisig_script =
        deposit_request::build_n_of_n_multisig_miniscript(aggregated_pubkey);
    let timelock_script = deposit_request::build_timelock_miniscript(recovery_pubkey);

    let (_script_hash, taproot_address) =
        deposit_request::generate_taproot_address(&secp, n_of_n_multisig_script, timelock_script);

    let psbt = psbt_wallet.create_psbt(
        &taproot_address,
        &strata_address,
        &recovery_pubkey,
        &constants::NETWORK,
    )?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    Ok(())
}

fn handle_bridge_out(args: cli::BridgeOutArgs) -> Result<()> {
    let private_key_bytes = hex::decode(args.private_key).context("decode private key")?;
    let signing_key = SigningKey::from_slice(&private_key_bytes).context("signing key")?;

    let signer = PrivateKeySigner::from(signing_key);
    let wallet = EthereumWallet::new(signer);

    let data: [u8; 32] = hex::decode(args.destination_address_pubkey)
        .context("decode address pubkey")?
        .try_into()
        .unwrap();
    let bosd_data = Descriptor::new_p2tr_unchecked(&data).to_bytes();
    let amount = U256::from(constants::BRIDGE_OUT_AMOUNT.to_sat() as u128 * constants::SATS_TO_WEI);
    let rollup_address =
        EvmAddress::from_str(constants::ROLLUP_ADDRESS).context("precompile address")?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(bridge_out::withdrawal::create_withdrawal_transaction(
        rollup_address,
        constants::ETH_RPC_URL,
        bosd_data,
        &wallet,
        amount,
    ))?;

    Ok(())
}
