use bitcoin::{consensus, Address, Amount, OutPoint, Transaction, TxOut};
use corepc_node::{serde_json, Client};
use strata_bridge_btcio::types::{ListUnspent, SignRawTransactionWithWallet};
use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};

pub const FEES: Amount = Amount::from_sat(1_000);

pub fn get_connector_txs<const NUM_LEAVES: usize>(
    btc_client: &Client,
    output_amount: Amount,
    output_address: Address,
) -> [Transaction; NUM_LEAVES] {
    let src = btc_client.new_address().expect("must generate new address");
    btc_client
        .generate_to_address(101, &src)
        .expect("must be able to mine blocks");

    let utxos = btc_client
        .call::<Vec<ListUnspent>>("listunspent", &[])
        .expect("must be able to get utxos");
    let utxo = utxos.first().expect("must have at least one utxo");

    let mut tx = create_tx(
        create_tx_ins([OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        }]),
        create_tx_outs(vec![
            (output_address.script_pubkey(), output_amount,);
            NUM_LEAVES
        ]),
    );

    let change_amount = utxo
        .amount
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
        .expect("must be able to fund tx");

    let send_to_connector = btc_client
        .send_raw_transaction(
            &consensus::encode::deserialize_hex(&signed_tx.hex)
                .expect("must be able to deserialize raw tx"),
        )
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
        output_amount.checked_sub(FEES).expect("fees must be valid"),
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
