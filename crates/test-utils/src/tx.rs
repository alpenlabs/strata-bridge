//! Module to generate transactions for testing.

use bitcoin::{consensus, Address, Amount, OutPoint, Transaction, TxOut};
use bitcoind_async_client::corepc_types::model::{ListUnspent, SignRawTransactionWithWallet};
use corepc_node::{serde_json, Client};
use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};

/// The fees for a transaction.
///
/// Hardcoded to 1,000 satoshis.
pub const FEES: Amount = Amount::from_sat(1_000);

/// Creates `NUM_LEAVES` transactions that send funds to the given output address.
///
/// Each such transaction has a single output that sends `input_amount` - [`FEES`] to the given
/// output address. To create a zero-amount output, simply set `input_amount` to [`FEES`].
pub fn get_connector_txs<const NUM_LEAVES: usize>(
    btc_client: &Client,
    input_amount: Amount,
    output_address: Address,
) -> [Transaction; NUM_LEAVES] {
    let src = btc_client.new_address().expect("must generate new address");
    btc_client
        .generate_to_address(101, &src)
        .expect("must be able to mine blocks");

    let utxos = btc_client
        .call::<ListUnspent>("listunspent", &[])
        .expect("must be able to get utxos");
    let utxo = utxos.0.first().expect("must have at least one utxo");

    let mut tx = create_tx(
        create_tx_ins([OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        }]),
        create_tx_outs(vec![
            (output_address.script_pubkey(), input_amount,);
            NUM_LEAVES
        ]),
    );

    let change_amount = utxo
        .amount
        .to_unsigned()
        .expect("amount must be valid")
        .checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>() + FEES);

    tx.output.push(TxOut {
        script_pubkey: src.script_pubkey(),
        value: change_amount.expect("amount must be valid"),
    });

    let signed_tx = btc_client
        .call::<SignRawTransactionWithWallet>(
            "signrawtransactionwithwallet",
            &[serde_json::Value::String(consensus::encode::serialize_hex(
                &tx,
            ))],
        )
        .expect("must be able to fund tx")
        .tx;

    let send_to_connector = btc_client
        .send_raw_transaction(&signed_tx)
        .expect("must be able to send tx");

    btc_client
        .generate_to_address(6, &src)
        .expect("must be able to mine blocks");

    let source_txid = send_to_connector.txid().expect("must have txid");
    let send_to_connector_tx = btc_client
        .get_transaction(source_txid)
        .expect("must be able to send funds to source address");
    let send_to_connector_tx: Transaction =
        consensus::encode::deserialize_hex(&send_to_connector_tx.hex)
            .expect("must be able to deserialize tx");

    let tx_outs = create_tx_outs([(
        src.script_pubkey(),
        input_amount.checked_sub(FEES).expect("fees must be valid"),
    )]);

    let locking_script = output_address.script_pubkey();
    send_to_connector_tx
        .output
        .iter()
        .enumerate()
        .take(NUM_LEAVES)
        .filter_map(|(index, output)| {
            if output.script_pubkey == locking_script {
                let txins = create_tx_ins([OutPoint {
                    txid: source_txid,
                    vout: index as u32,
                }]);

                Some(create_tx(txins, tx_outs.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("transaction count must match")
}

/// Creates a mock deposit transaction.
pub fn get_mock_deposit(
    btc_client: &Client,
    deposit_amount: Amount,
    bridge_address: &Address,
) -> Transaction {
    let src = btc_client.new_address().expect("must generate new address");
    btc_client
        .generate_to_address(101, &src)
        .expect("must be able to mine blocks");

    let utxos = btc_client
        .call::<ListUnspent>("listunspent", &[])
        .expect("must be able to get utxos");
    let utxo = utxos
        .0
        .iter()
        .find(|utxo| {
            utxo.amount.to_unsigned().expect("amount must be valid") >= deposit_amount + FEES
        })
        .expect("must have at least one valid utxo");

    let mut tx = create_tx(
        create_tx_ins([OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        }]),
        create_tx_outs(vec![(bridge_address.script_pubkey(), deposit_amount)]),
    );

    let change_amount = utxo
        .amount
        .to_unsigned()
        .expect("amount must be valid")
        .checked_sub(deposit_amount + FEES);

    tx.output.push(TxOut {
        script_pubkey: src.script_pubkey(),
        value: change_amount.expect("amount must be valid"),
    });

    let signed_tx = btc_client
        .call::<SignRawTransactionWithWallet>(
            "signrawtransactionwithwallet",
            &[serde_json::Value::String(consensus::encode::serialize_hex(
                &tx,
            ))],
        )
        .expect("must be able to fund tx");

    let signed_deposit_tx = signed_tx.tx;

    btc_client
        .send_raw_transaction(&signed_deposit_tx)
        .expect("must be able to send deposit tx");

    btc_client
        .generate_to_address(6, &src)
        .expect("must be able to confirm deposit");

    signed_deposit_tx
}
