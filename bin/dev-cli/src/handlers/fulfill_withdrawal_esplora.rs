use anyhow::{Context, Result};
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_wallet::{
    bitcoin::{bip32::Xpriv, Amount, Network},
    KeychainKind, TxOrdering, Wallet,
};
use tracing::info;

use super::withdrawal_fulfillment::WithdrawalMetadata;
use crate::{cli::FulfillWithdrawalEsploraArgs, params::Params};

/// A hardcoded seed so the wallet address is deterministic across runs.
/// Fund this address once and reuse it for multiple fulfillment transactions.
const WALLET_SEED: [u8; 32] = [
    0xde, 0xad, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
];

fn create_wallet(network: Network) -> Result<Wallet> {
    let xpriv = Xpriv::new_master(network, &WALLET_SEED).context("failed to derive master key")?;
    let base_desc = format!("tr({xpriv}/86h/0h/0h");
    let external_desc = format!("{base_desc}/0/*)");
    let internal_desc = format!("{base_desc}/1/*)");

    Wallet::create(external_desc, internal_desc)
        .network(network)
        .create_wallet_no_persist()
        .context("failed to create wallet")
}

pub(crate) async fn handle_fulfill_withdrawal_esplora(
    args: FulfillWithdrawalEsploraArgs,
) -> Result<()> {
    let FulfillWithdrawalEsploraArgs {
        deposit_idx,
        operator_idx,
        deposit_txid,
        destination,
        params,
        esplora_url,
        network,
    } = args;

    let params = Params::from_path(params)?;
    let mut wallet = create_wallet(network)?;

    let address = wallet.reveal_next_address(KeychainKind::External).address;
    info!(%address, "wallet address (fund this address before running)");

    let esplora = esplora_client::Builder::new(&esplora_url)
        .build_async()
        .context("failed to create Esplora client")?;

    info!("syncing wallet via Esplora...");
    let full_scan_req = wallet.start_full_scan();
    let update = esplora
        .full_scan(full_scan_req, 5, 3)
        .await
        .context("Esplora full scan failed")?;
    wallet
        .apply_update(update)
        .context("failed to apply wallet update")?;

    let balance = wallet.balance();
    info!(
        confirmed = %Amount::from_sat(balance.confirmed.to_sat()),
        trusted_pending = %Amount::from_sat(balance.trusted_pending.to_sat()),
        "wallet balance"
    );

    assert!(
        balance.confirmed.to_sat() > 0,
        "wallet has no confirmed balance to spend for withdrawal fulfillment"
    );

    let withdrawal_metadata = WithdrawalMetadata {
        tag: params.tag,
        operator_idx,
        deposit_idx,
        deposit_txid,
    };

    let op_return_data = withdrawal_metadata.op_return_data();
    info!(metadata=?withdrawal_metadata, "constructed withdrawal metadata");

    let amount = params
        .deposit_amount
        .checked_sub(params.operator_fee)
        .unwrap_or_default();

    let dest_script = destination.to_script();

    info!(
        %deposit_txid,
        %deposit_idx,
        %operator_idx,
        %amount,
        destination = %destination,
        "building withdrawal fulfillment transaction"
    );

    let op_return_script = super::scripts::general::op_return_nonce(&op_return_data);

    let mut builder = wallet.build_tx();
    builder.ordering(TxOrdering::Untouched);
    builder.add_recipient(dest_script, amount);
    builder.add_recipient(op_return_script, Amount::ZERO);

    let mut psbt = builder.finish().context("failed to build transaction")?;

    wallet
        .sign(&mut psbt, Default::default())
        .context("failed to sign transaction")?;

    let tx = psbt
        .extract_tx()
        .context("failed to extract signed transaction")?;
    let txid = tx.compute_txid();

    info!(%txid, "broadcasting withdrawal fulfillment transaction via Esplora");
    esplora
        .broadcast(&tx)
        .await
        .context("failed to broadcast transaction")?;

    info!(%txid, "withdrawal fulfillment transaction broadcasted");

    Ok(())
}
