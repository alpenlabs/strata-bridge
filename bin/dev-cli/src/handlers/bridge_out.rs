use std::str::FromStr;

use alloy::{
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

use crate::{
    cli,
    constants::{self, BRIDGE_OUT_AMOUNT, SATS_TO_WEI},
};

pub(crate) async fn handle_bridge_out(args: cli::BridgeOutArgs) -> Result<()> {
    let private_key_bytes = hex::decode(args.private_key).context("decode private key")?;

    let signing_key = SigningKey::from_slice(&private_key_bytes).context("signing key")?;

    let signer = PrivateKeySigner::from(signing_key);
    let wallet = EthereumWallet::new(signer);

    let data: [u8; 32] = hex::decode(args.destination_address_pubkey)
        .context("decode address pubkey")?
        .try_into()
        .unwrap();
    let bosd_data = Descriptor::new_p2tr_unchecked(&data).to_bytes();
    let amount = U256::from(BRIDGE_OUT_AMOUNT.to_sat() as u128 * SATS_TO_WEI);
    let rollup_address =
        EvmAddress::from_str(constants::ROLLUP_ADDRESS).context("precompile address")?;

    create_withdrawal_transaction(
        rollup_address,
        constants::ETH_RPC_URL,
        bosd_data,
        &wallet,
        amount,
    )
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
        .on_http(eth_rpc_url.parse()?);

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
