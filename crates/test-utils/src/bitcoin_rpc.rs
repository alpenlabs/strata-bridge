//! This module contains types and functions for interacting with the Bitcoin Core RPC
//! interface.
//!
//! Based on <https://github.com/rust-bitcoin/rust-bitcoincore-rpc/tree/master>.
use bitcoin::{consensus, Address, Amount, Transaction, Txid};
use bitcoind_async_client::corepc_types::v29::{GetRawTransaction, SignRawTransactionWithWallet};
use corepc_node::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The result of a `fundrawtransaction` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionResult {
    /// The hex-encoded transaction.
    #[serde(with = "hex::serde")]
    pub hex: Vec<u8>,

    /// The fee for the transaction.
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub fee: Amount,

    /// The position of the change output.
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

/// Address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressType {
    /// Legacy address type.
    Legacy,

    /// P2shSegwit address type.
    P2shSegwit,

    /// Bech32 address type.
    Bech32,

    /// Bech32m address type.
    Bech32m,
}

/// Estimate fee mode.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EstimateMode {
    /// Unset.
    Unset,

    /// Economical.
    Economical,

    /// Conservative.
    Conservative,
}

/// Options for a `fundrawtransaction` call.
#[derive(Serialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionOptions {
    /// For a transaction with existing inputs, automatically include more if they are not
    /// enough (default true). Added in Bitcoin Core v0.21
    #[serde(rename = "add_inputs", skip_serializing_if = "Option::is_none")]
    pub add_inputs: Option<bool>,

    /// The address to use for the change output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_address: Option<Address>,

    /// The position of the change output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,

    /// The type of change output.
    #[serde(rename = "change_type", skip_serializing_if = "Option::is_none")]
    pub change_type: Option<AddressType>,

    /// Whether to include watching addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,

    /// Whether to lock unspent outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_unspents: Option<bool>,

    /// The fee rate to pay per kvB.
    ///
    /// NOTE: This field is converted to camelCase
    /// when serialized, so it is receeived by fundrawtransaction as `feeRate`,
    /// which fee rate per kvB, and *not* `fee_rate`, which is per vB.
    #[serde(
        with = "bitcoin::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub fee_rate: Option<Amount>,

    /// The outputs to subtract the fee from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,

    /// Whether the transaction is replaceable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaceable: Option<bool>,

    /// The confirmation target.
    #[serde(rename = "conf_target", skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u32>,

    /// The estimate mode.
    #[serde(rename = "estimate_mode", skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<EstimateMode>,
}

/// Funds a transaction and signs it.
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
        .unwrap()
        .into_model()
        .expect("must be able to deserialize signed tx");

    signed_tx.tx
}

/// Gets a raw transaction from the Bitcoin Core RPC interface.
pub fn get_raw_transaction(btc_client: &Client, txid: &Txid) -> Transaction {
    let txid = txid.to_string();
    let raw_tx = btc_client
        .call::<GetRawTransaction>("getrawtransaction", &[json!(txid)])
        .expect("transaction does not exist")
        .into_model()
        .expect("must be able to deserialize raw transaction");

    raw_tx.0
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
