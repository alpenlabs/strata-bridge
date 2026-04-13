use anyhow::{Context, Result};
use strata_bridge_tx_graph::transactions::prelude::WithdrawalMetadata;
use tracing::info;

use crate::{
    cli::FulfillWithdrawalArgs,
    handlers::{
        rpc,
        wallet::{BitcoinRpcWallet, PsbtWallet},
    },
    params::Params,
};

pub(crate) fn handle_fulfill_withdrawal(args: FulfillWithdrawalArgs) -> Result<()> {
    let FulfillWithdrawalArgs {
        deposit_idx,
        operator_idx,
        deposit_txid,
        destination,
        params,
        btc_args,
    } = args;

    let rpc_client = rpc::get_btc_client(&btc_args.url, btc_args.user, btc_args.pass)?;
    let params = Params::from_path(params)?;

    let psbt_wallet = BitcoinRpcWallet::new(rpc_client);

    let withdrawal_metadata = WithdrawalMetadata {
        tag: params.tag,
        operator_idx,
        deposit_idx,
        deposit_txid,
    };

    let op_return_data = withdrawal_metadata.op_return_data();

    let amount = params
        .deposit_amount
        .checked_sub(params.operator_fee)
        .unwrap_or_default();

    let address = destination
        .to_address(params.network)
        .context("failed to convert BOSD descriptor to address")?;

    info!(
        %deposit_txid,
        %deposit_idx,
        %operator_idx,
        %address,
        %amount,
        "creating withdrawal fulfillment transaction"
    );

    let psbt = psbt_wallet.create_drt_psbt(amount, &address, op_return_data, &params.network)?;
    psbt_wallet.sign_and_broadcast_psbt(&psbt)?;

    info!("withdrawal fulfillment transaction broadcasted");

    Ok(())
}
