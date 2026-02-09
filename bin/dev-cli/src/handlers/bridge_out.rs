use std::str::FromStr;

use alloy::{
    consensus::constants::ETH_TO_WEI,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address as EvmAddress, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionInput, TransactionRequest},
    signers::local::PrivateKeySigner,
};
use alloy_signer::k256::ecdsa::SigningKey;
use anyhow::{Context, Result};
use bitcoin_bosd::Descriptor;
use tracing::info;

use crate::{cli::BridgeOutArgs, params::Params};

pub(crate) const BTC_TO_WEI: u128 = ETH_TO_WEI;

pub(crate) const SATS_TO_WEI: u128 = BTC_TO_WEI / 100_000_000;

pub(crate) async fn handle_bridge_out(args: BridgeOutArgs) -> Result<()> {
    let BridgeOutArgs {
        destination_address_pubkey,
        private_key,
        ee_url,
        params,
    } = args;
    let params = Params::from_path(params).context("failed to read params file")?;
    let private_key_bytes = hex::decode(private_key).context("decode private key")?;

    let signing_key = SigningKey::from_slice(&private_key_bytes).context("signing key")?;

    let signer = PrivateKeySigner::from(signing_key);
    let wallet = EthereumWallet::new(signer);

    let data: [u8; 32] = hex::decode(destination_address_pubkey)
        .context("decode address pubkey")?
        .try_into()
        .unwrap();
    let bosd_data = Descriptor::new_p2tr(&data).unwrap().to_bytes();

    let amount = U256::from(params.deposit_amount.to_sat() as u128 * SATS_TO_WEI);
    let rollup_address =
        EvmAddress::from_str(&params.bridge_out_addr).context("precompile address")?;

    create_withdrawal_transaction(rollup_address, ee_url.as_str(), bosd_data, &wallet, amount)
        .await?;

    Ok(())
}

async fn create_withdrawal_transaction(
    rollup_address: EvmAddress,
    eth_rpc_url: &str,
    data: Vec<u8>,
    wallet: &EthereumWallet,
    amount: U256,
) -> Result<()> {
    // Send the transaction and listen for the transaction to be included.
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(eth_rpc_url.parse()?);

    let chain_id = provider.get_chain_id().await?;
    info!(event = "retrieved chain id", %chain_id);

    // Build a transaction to call the withdrawal precompile
    let tx = TransactionRequest::default()
        .with_to(rollup_address)
        .with_value(amount)
        .input(TransactionInput::new(Bytes::from(data)));

    info!(action = "sending withdrawal transaction");
    let pending_tx = provider.send_transaction(tx).await?;

    info!(action = "waiting for transaction to be confirmed");
    let receipt = pending_tx.get_receipt().await?;

    info!(event = "transaction confirmed", ?receipt);

    Ok(())
}
