//! Publishing a presigned transaction in a package with a CPFP child.
//!
//! A presigned transaction pays no fee of its own, so it relays only with a child that pays the
//! fee of the package. The child spends the CPFP anchor of the parent and one confirmed output of
//! the node's wallet, and pays its change back to that wallet.

use anyhow::{bail, Context, Result};
use bitcoin::{
    absolute,
    consensus::encode::serialize_hex,
    psbt::Input,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, FeeRate, OutPoint, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{
    json::{AddressType, SignRawTransactionInput},
    Client, RpcApi,
};
use secp256k1::Keypair;
use serde_json::{json, Value};
use strata_bridge_connectors::{
    prelude::{
        KeyedAnchor, KeyedAnchorSpend, MultiAnchor, MultiAnchorSpendPath, MultiAnchorWitness,
    },
    Connector, ParentTx,
};

/// The package fee rate above the mempool minimum of the node, in sat/vB.
const PACKAGE_FEE_RATE_HEADROOM_SAT_PER_VB: u64 = 1;

/// The CPFP anchor of a parent transaction.
pub(crate) struct Anchor<C> {
    connector: C,
    outpoint: OutPoint,
    tx_out: TxOut,
}

impl<C: Clone> Anchor<C> {
    /// The anchor of `parent`.
    pub(crate) fn of<T: ParentTx<CpfpConnector = C>>(parent: &T) -> Self {
        Self {
            connector: parent.cpfp_connector().clone(),
            outpoint: parent.cpfp_outpoint(),
            tx_out: parent.cpfp_tx_out(),
        }
    }
}

/// Publishes `parent` with a child that spends its keyed `anchor` with `anchor_keypair`, and
/// returns the txid of `parent`.
pub(crate) fn publish_with_keyed_anchor_child(
    client: &Client,
    parent: &Transaction,
    anchor: &Anchor<KeyedAnchor>,
    anchor_keypair: &Keypair,
) -> Result<Txid> {
    if anchor.connector.internal_key() != anchor_keypair.x_only_public_key().0 {
        bail!(
            "the anchor of {} is keyed to {}, not to the derived key",
            parent.compute_txid(),
            anchor.connector.internal_key()
        );
    }
    publish_with_child(
        client,
        parent,
        anchor.outpoint,
        &anchor.tx_out,
        |child, prevouts| {
            let mut cache = SighashCache::new(child);
            let signature = anchor
                .connector
                .get_signing_info(&mut cache, Prevouts::All(prevouts), KeyedAnchorSpend, 0)
                .sign(anchor_keypair);
            let mut input = Input::default();
            anchor.connector.finalize_input(&mut input, &signature);
            input.final_script_witness
        },
    )
}

/// Publishes `parent` with a child that spends the leaf of `watchtower_index` on its multi-key
/// `anchor` with `watchtower_keypair`, and returns the txid of `parent`.
pub(crate) fn publish_with_multi_anchor_child(
    client: &Client,
    parent: &Transaction,
    anchor: &Anchor<MultiAnchor>,
    watchtower_index: u32,
    watchtower_keypair: &Keypair,
) -> Result<Txid> {
    publish_with_child(
        client,
        parent,
        anchor.outpoint,
        &anchor.tx_out,
        |child, prevouts| {
            let mut cache = SighashCache::new(child);
            let witness = MultiAnchorWitness {
                watchtower_index,
                watchtower_signature: anchor
                    .connector
                    .get_signing_info(
                        &mut cache,
                        Prevouts::All(prevouts),
                        MultiAnchorSpendPath { watchtower_index },
                        0,
                    )
                    .sign(watchtower_keypair),
            };
            let mut input = Input::default();
            anchor.connector.finalize_input(&mut input, &witness);
            input.final_script_witness
        },
    )
}

/// Publishes `parent` in a package with a child that spends `anchor`, which pays `anchor_out`.
/// `sign_anchor` returns the witness of the anchor input of a child, given its prevouts.
fn publish_with_child(
    client: &Client,
    parent: &Transaction,
    anchor: OutPoint,
    anchor_out: &TxOut,
    sign_anchor: impl Fn(&Transaction, &[TxOut]) -> Option<Witness>,
) -> Result<Txid> {
    let parent_fee = fee_paid(client, parent)?;
    let fee_rate = package_fee_rate(client)?;
    let funding = largest_spendable_output(client)?;
    let change_script = client
        .get_new_address(None, Some(AddressType::Bech32m))
        .context("reading a change address from the node's wallet")?
        .assume_checked()
        .script_pubkey();
    let child = |fee: Amount| -> Result<Transaction> {
        let value = (anchor_out.value + funding.1.value)
            .checked_sub(fee)
            .filter(|value| *value >= change_script.minimal_non_dust())
            .context("the node's wallet output cannot pay the package fee")?;
        let unsigned = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: [anchor, funding.0]
                .map(|previous_output| TxIn {
                    previous_output,
                    ..Default::default()
                })
                .to_vec(),
            output: vec![TxOut {
                value,
                script_pubkey: change_script.clone(),
            }],
        };
        sign_child(client, unsigned, anchor_out, &funding.1, &sign_anchor)
    };

    // The fee depends on the size of the signed child, so a first child at no fee measures it.
    let draft = child(Amount::ZERO)?;
    let package_vsize = (parent.vsize() + draft.vsize()) as u64;
    let package_fee = fee_rate
        .fee_vb(package_vsize)
        .context("the package fee overflows")?;
    let child = child(package_fee.checked_sub(parent_fee).unwrap_or(Amount::ZERO))?;

    let response: Value = client
        .call(
            "submitpackage",
            &[json!([serialize_hex(parent), serialize_hex(&child)])],
        )
        .context("submitting the package")?;
    if response["package_msg"] != "success" {
        bail!("the node refused the package: {response}");
    }
    Ok(parent.compute_txid())
}

/// Signs the wallet input of `child` through the node's wallet, and its anchor input through
/// `sign_anchor`.
fn sign_child(
    client: &Client,
    child: Transaction,
    anchor_out: &TxOut,
    funding_out: &TxOut,
    sign_anchor: &impl Fn(&Transaction, &[TxOut]) -> Option<Witness>,
) -> Result<Transaction> {
    let anchor = child.input[0].previous_output;
    let anchor_prevout = SignRawTransactionInput {
        txid: anchor.txid,
        vout: anchor.vout,
        script_pub_key: anchor_out.script_pubkey.clone(),
        redeem_script: None,
        amount: Some(anchor_out.value),
    };
    let mut signed = client
        .sign_raw_transaction_with_wallet(&child, Some(&[anchor_prevout]), None)
        .context("signing the wallet input of the child")?
        .transaction()
        .context("decoding the child that the node's wallet signed")?;
    let prevouts = [anchor_out.clone(), funding_out.clone()];
    signed.input[0].witness =
        sign_anchor(&signed, &prevouts).context("the anchor input has no witness")?;
    Ok(signed)
}

/// The fee that `tx` pays: the value of its prevouts less its outputs.
fn fee_paid(client: &Client, tx: &Transaction) -> Result<Amount> {
    let mut inputs = Amount::ZERO;
    for input in &tx.input {
        let prevout = input.previous_output;
        let funding = client
            .get_raw_transaction(&prevout.txid, None)
            .with_context(|| format!("reading the transaction of prevout {prevout}"))?;
        let value = funding
            .output
            .get(prevout.vout as usize)
            .with_context(|| format!("prevout {prevout} is out of range"))?
            .value;
        inputs = inputs.checked_add(value).context("the prevouts overflow")?;
    }
    let outputs = tx
        .output
        .iter()
        .try_fold(Amount::ZERO, |sum, output| sum.checked_add(output.value))
        .context("the outputs overflow")?;
    inputs
        .checked_sub(outputs)
        .context("the outputs exceed the prevouts")
}

/// The fee rate of a package: the mempool minimum of the node plus a margin.
fn package_fee_rate(client: &Client) -> Result<FeeRate> {
    let minimum_per_kvb = client
        .get_mempool_info()
        .context("reading the mempool minimum fee")?
        .mempool_min_fee;
    let minimum = minimum_per_kvb.to_sat().div_ceil(1_000);
    FeeRate::from_sat_per_vb(minimum + PACKAGE_FEE_RATE_HEADROOM_SAT_PER_VB)
        .context("the package fee rate overflows")
}

/// The confirmed output of the node's wallet with the largest value.
fn largest_spendable_output(client: &Client) -> Result<(OutPoint, TxOut)> {
    let largest = client
        .list_unspent(Some(1), None, None, None, None)
        .context("listing the node's wallet outputs")?
        .into_iter()
        .max_by_key(|entry| entry.amount)
        .context("the node's wallet has no confirmed output")?;
    Ok((
        OutPoint::new(largest.txid, largest.vout),
        TxOut {
            value: largest.amount,
            script_pubkey: largest.script_pub_key,
        },
    ))
}
