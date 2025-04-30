use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address as EvmAddress, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{TransactionInput, TransactionRequest},
};
use anyhow::Result;
use tracing::info;

pub(crate) async fn create_withdrawal_transaction(
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
