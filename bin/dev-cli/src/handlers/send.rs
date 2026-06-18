use anyhow::Result;
use bitcoin::Amount;
use tracing::info;

use super::wallet;
use crate::cli::SendArgs;

pub(crate) async fn handle_send(args: SendArgs) -> Result<()> {
    info!(
        command = "send",
        key_file = %args.private_key_file.display(),
        network = %args.network,
        to = %args.to,
        amount_sats = args.amount_sats,
        fee_rate_sat_vb = args.fee_rate_sats_per_vbyte,
        api_url = ?args.esplora_url,
        change_address = ?args.change_address,
        dry_run = args.dry_run,
        "initiating local WIF-backed send"
    );

    let private_key = wallet::read_private_key_file(&args.private_key_file, args.network)?;
    let destination_address = wallet::parse_address(&args.to, args.network)?;
    let wallet = wallet::LocalBridgeInWallet::new(
        private_key,
        args.network,
        args.change_address.as_deref(),
        args.fee_rate_sats_per_vbyte,
        args.esplora_url.as_deref(),
    )?;

    info!(
        command = "send",
        destination = %destination_address,
        amount_sats = args.amount_sats,
        dry_run = args.dry_run,
        "building local payment transaction"
    );

    let outcome = wallet
        .sign_and_maybe_broadcast_payment(
            Amount::from_sat(args.amount_sats),
            &destination_address,
            args.dry_run,
        )
        .await?;

    info!(
        command = "send",
        txid = %outcome.txid,
        tx_url = %outcome.tx_url,
        broadcasted = outcome.broadcasted,
        "send command completed"
    );
    println!("transaction: {}", outcome.tx_url);

    Ok(())
}
