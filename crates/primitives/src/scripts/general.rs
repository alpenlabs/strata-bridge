use bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    script::{Builder, PushBytesBuf},
    transaction, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_script::script;
use musig2::KeyAggContext;
use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::params::prelude::MAGIC_BYTES;

/// Create a script with the spending condition that a MuSig2 aggregated signature corresponding to
/// the pubkey set must be provided.
pub fn n_of_n_script(aggregated_pubkey: &XOnlyPublicKey) -> ScriptBuf {
    script! {
        { *aggregated_pubkey }
        OP_CHECKSIG
    }
    .compile()
}

pub fn n_of_n_with_timelock(aggregated_pubkey: &XOnlyPublicKey, timelock: u32) -> ScriptBuf {
    script! {
        { timelock }
        OP_CSV
        OP_DROP
        { *aggregated_pubkey}
        OP_CHECKSIG
    }
    .compile()
}

pub fn op_return_nonce(data: Vec<u8>) -> ScriptBuf {
    let mut push_data = PushBytesBuf::new();
    push_data
        .extend_from_slice(&data[..])
        .expect("data should be within limit");

    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_data)
        .into_script()
}

/// Aggregate the pubkeys using [`musig2`] and return the resulting [`XOnlyPublicKey`].
///
/// Please refer to MuSig2 key aggregation section in
/// [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
pub fn get_aggregated_pubkey(pubkeys: impl IntoIterator<Item = PublicKey>) -> XOnlyPublicKey {
    let key_agg_ctx = KeyAggContext::new(pubkeys).expect("key aggregation of musig2 pubkeys");

    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

    aggregated_pubkey.x_only_public_key().0
}

/// Create the metadata script that "stores" the execution layer address information.
pub fn metadata_script(el_address: &[u8; 20]) -> ScriptBuf {
    let mut data = PushBytesBuf::new();
    data.extend_from_slice(MAGIC_BYTES)
        .expect("MAGIC_BYTES should be within the limit");
    data.extend_from_slice(&el_address[..])
        .expect("el_address should be within the limit");

    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(data)
        .into_script()
}

pub fn anyone_can_spend_script() -> ScriptBuf {
    script! {
        OP_TRUE
    }
    .compile()
}

/// Create an output that can be spent by anyone, i.e. its script contains a single `OP_TRUE`.
pub fn anyone_can_spend_txout() -> TxOut {
    let script = anyone_can_spend_script();
    let script_pubkey = script.to_p2wsh();
    let value = script_pubkey.minimal_non_dust();

    TxOut {
        script_pubkey,
        value,
    }
}

/// Create a bitcoin [`Transaction`] for the given inputs and outputs.
pub fn create_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: LockTime::from_consensus(0),
        input: tx_ins,
        output: tx_outs,
    }
}

/// Create a list of [`TxIn`]'s from given [`OutPoint`]'s.
///
/// This wraps the [`OutPoint`] in a structure that includes an empty `witness`, an empty
/// `script_sig` and the `sequence` set to enable replace-by-fee with no locktime.
pub fn create_tx_ins(utxos: impl IntoIterator<Item = OutPoint>) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();

    for utxo in utxos {
        tx_ins.push(TxIn {
            previous_output: utxo,
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        });
    }

    tx_ins
}

/// Create a list of [`TxOut`]'s' based on pairs of scripts and corresponding amounts.
pub fn create_tx_outs(
    scripts_and_amounts: impl IntoIterator<Item = (ScriptBuf, Amount)>,
) -> Vec<TxOut> {
    scripts_and_amounts
        .into_iter()
        .map(|(script_pubkey, value)| TxOut {
            script_pubkey,
            value,
        })
        .collect()
}
