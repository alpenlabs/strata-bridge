use anyhow::{Context, Result};
use bitcoin::{
    absolute::LockTime, consensus::encode, transaction, Amount, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use bitcoincore_rpc::RpcApi;
use tracing::info;

use super::{scripts::general::op_return_nonce, withdrawal_fulfillment::WithdrawalMetadata};
use crate::{cli::FulfillWithdrawalArgs, handlers::rpc, params::Params};

pub(crate) fn handle_fulfill_withdrawal(args: FulfillWithdrawalArgs) -> Result<()> {
    let FulfillWithdrawalArgs {
        deposit_idx,
        operator_idx,
        deposit_txid,
        destination,
        params,
        btc_args,
    } = args;

    let client = rpc::get_btc_client(&btc_args.url, btc_args.user, btc_args.pass)?;
    let params = Params::from_path(params)?;

    let withdrawal_metadata = WithdrawalMetadata {
        tag: params.tag,
        operator_idx,
        deposit_idx,
        deposit_txid,
    };

    info!(metadata=?withdrawal_metadata, "retrieved withdrawal metadata from parameters");

    let op_return_data = withdrawal_metadata.op_return_data();
    info!(
        ?op_return_data,
        "constructed OP_RETURN data for withdrawal fulfillment"
    );

    let amount = params
        .deposit_amount
        .checked_sub(params.operator_fee)
        .unwrap_or_default();

    info!(
        %deposit_txid,
        %deposit_idx,
        %operator_idx,
        %amount,
        destination = %destination,
        "creating withdrawal fulfillment transaction"
    );

    // Get UTXOs from the wallet to fund the transaction.
    // Try to find a single UTXO that covers the amount.
    // listunspent args: minconf, maxconf, addresses, include_unsafe, query_options
    let utxos: Vec<serde_json::Value> = client
        .call(
            "listunspent",
            &[
                serde_json::json!(1),       // minconf
                serde_json::json!(9999999), // maxconf
                serde_json::json!([]),      // addresses (all)
                serde_json::json!(true),    // include_unsafe
                serde_json::json!({ "minimumAmount": amount.to_btc(), "maximumCount": 1 }),
            ],
        )
        .context("listunspent failed")?;

    // If no single UTXO is large enough, fall back to accumulating multiple.
    let utxos = if utxos.is_empty() {
        info!("no single UTXO covers the amount, accumulating multiple");
        client
            .call("listunspent", &[])
            .context("listunspent (fallback) failed")?
    } else {
        utxos
    };

    let mut selected_utxos = Vec::new();
    let mut total_input = Amount::ZERO;
    for utxo in &utxos {
        let utxo_amount = Amount::from_btc(
            utxo["amount"]
                .as_f64()
                .context("utxo missing amount field")?,
        )
        .context("invalid utxo amount")?;

        let txid: bitcoin::Txid = utxo["txid"]
            .as_str()
            .context("utxo missing txid")?
            .parse()
            .context("invalid utxo txid")?;

        let vout = utxo["vout"].as_u64().context("utxo missing vout")? as u32;

        selected_utxos.push(OutPoint::new(txid, vout));
        total_input = total_input
            .checked_add(utxo_amount)
            .context("utxo total overflow")?;

        if total_input > amount {
            break;
        }
    }

    anyhow::ensure!(
        total_input > amount,
        "insufficient funds: have {total_input}, need {amount}"
    );

    info!(
        %total_input,
        num_utxos = selected_utxos.len(),
        "selected UTXOs for funding"
    );

    let dest_script = destination.to_script();
    let metadata_script = op_return_nonce(&op_return_data);

    let inputs: Vec<TxIn> = selected_utxos
        .iter()
        .map(|outpoint| TxIn {
            previous_output: *outpoint,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        })
        .collect();

    let mut outputs = vec![
        TxOut {
            value: amount,
            script_pubkey: dest_script,
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: metadata_script,
        },
    ];

    // Add change output if there's leftover (ignoring fees for simplicity).
    let change = total_input.checked_sub(amount).unwrap_or_default();
    if change > Amount::from_sat(546) {
        let change_address = client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .context("failed to get change address")?
            .require_network(params.network)
            .context("change address network mismatch")?;

        outputs.push(TxOut {
            value: change,
            script_pubkey: change_address.script_pubkey(),
        });
    }

    let raw_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    let raw_tx_hex = encode::serialize_hex(&raw_tx);

    info!("signing transaction with wallet...");

    let sign_result: serde_json::Value = client
        .call(
            "signrawtransactionwithwallet",
            &[serde_json::to_value(&raw_tx_hex)?],
        )
        .context("signrawtransactionwithwallet failed")?;

    let signed_hex = sign_result["hex"]
        .as_str()
        .context("signrawtransactionwithwallet did not return hex")?;
    let complete = sign_result["complete"].as_bool().unwrap_or(false);
    if !complete {
        anyhow::bail!("transaction signing incomplete: {sign_result}");
    }

    let raw_tx = hex::decode(signed_hex).context("failed to decode signed tx hex")?;
    let tx: Transaction =
        encode::deserialize(&raw_tx).context("failed to deserialize signed transaction")?;
    let txid = tx.compute_txid();

    info!(%txid, transaction=?tx, "broadcasting transaction with maxburnamount");

    let max_burn = amount.to_btc();
    client
        .call::<bitcoin::Txid>(
            "sendrawtransaction",
            &[
                serde_json::to_value(signed_hex)?,
                serde_json::to_value(0)?,        // maxfeerate: 0 = no limit
                serde_json::to_value(max_burn)?, // maxburnamount
            ],
        )
        .context("failed to broadcast transaction")?;

    info!(%txid, "withdrawal fulfillment transaction broadcasted");

    Ok(())
}
