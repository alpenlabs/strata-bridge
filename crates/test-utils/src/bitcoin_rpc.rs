//! This module contains types and functions for interacting with the Bitcoin Core RPC
//! interface.
//!
//! Based on <https://github.com/rust-bitcoin/rust-bitcoincore-rpc/tree/master>.
use bitcoin::{consensus, Address, Amount, Transaction, Txid};
use corepc_node::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use strata_btcio::rpc::types::SignRawTransactionWithWallet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionResult {
    #[serde(with = "hex::serde")]
    pub hex: Vec<u8>,
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

/// Used to represent an address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressType {
    Legacy,
    P2shSegwit,
    Bech32,
    Bech32m,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EstimateMode {
    Unset,
    Economical,
    Conservative,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionOptions {
    /// For a transaction with existing inputs, automatically include more if they are not
    /// enough (default true). Added in Bitcoin Core v0.21
    #[serde(rename = "add_inputs", skip_serializing_if = "Option::is_none")]
    pub add_inputs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,
    #[serde(rename = "change_type", skip_serializing_if = "Option::is_none")]
    pub change_type: Option<AddressType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_unspents: Option<bool>,
    /// The fee rate to pay per kvB. NB. This field is converted to camelCase
    /// when serialized, so it is receeived by fundrawtransaction as `feeRate`,
    /// which fee rate per kvB, and *not* `fee_rate`, which is per vB.
    #[serde(
        with = "bitcoin::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub fee_rate: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<EstimateMode>,
}

pub fn fund_and_sign_raw_tx(
    btc_client: &Client,
    tx: &Transaction,
    options: Option<FundRawTransactionOptions>,
    is_witness: Option<bool>,
) -> Transaction {
    let raw_tx = consensus::encode::serialize_hex(tx);
    let args = [
        raw_tx.into(),
        opt_into_json(options),
        opt_into_json(is_witness),
    ];

    let funded_tx = btc_client
        .call::<FundRawTransactionResult>("fundrawtransaction", &args)
        .unwrap();

    let mut funded_tx: Transaction = consensus::encode::deserialize(&funded_tx.hex).unwrap();

    // make sure that the the order of inputs and outputs remains the same after funding.
    let funding_inputs = funded_tx
        .input
        .iter()
        .filter(|input| !tx.input.iter().any(|i| i == *input));
    let funding_outputs = funded_tx
        .output
        .iter()
        .filter(|output| !tx.output.iter().any(|o| o == *output));

    funded_tx.input = [tx.input.clone(), funding_inputs.cloned().collect()].concat();
    funded_tx.output = [tx.output.clone(), funding_outputs.cloned().collect()].concat();

    let signed_tx = btc_client
        .call::<SignRawTransactionWithWallet>(
            "signrawtransactionwithwallet",
            &[json!(consensus::encode::serialize_hex(&funded_tx))],
        )
        .unwrap();

    consensus::encode::deserialize_hex(&signed_tx.hex).unwrap()
}

pub fn get_raw_transaction(btc_client: &Client, txid: &Txid) -> Transaction {
    let txid = txid.to_string();
    let raw_tx = btc_client
        .call::<String>("getrawtransaction", &[json!(txid)])
        .expect("transaction does not exist");

    consensus::encode::deserialize_hex(&raw_tx).unwrap()
}

/// Shorthand for converting a variable into a serde_json::Value.
pub fn into_json<T>(val: T) -> serde_json::Value
where
    T: serde::ser::Serialize,
{
    serde_json::to_value(val).unwrap()
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
pub fn opt_into_json<T>(opt: Option<T>) -> serde_json::Value
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => into_json(val),
        None => serde_json::Value::Null,
    }
}
