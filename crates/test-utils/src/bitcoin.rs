//! Module to generate arbitrary values for testing.

use std::collections::HashSet;

use bitcoin::{
    absolute::LockTime,
    consensus,
    hashes::Hash,
    key::rand::{rngs::OsRng, Rng},
    secp256k1::{schnorr::Signature, Keypair, XOnlyPublicKey, SECP256K1},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use corepc_node::{serde_json::json, Client};
use musig2::secp256k1::{schnorr, Message};
use strata_btcio::rpc::types::{ListUnspent, SignRawTransactionWithWallet};

pub fn generate_txid() -> Txid {
    let mut txid = [0u8; 32];
    OsRng.fill(&mut txid);

    Txid::from_slice(&txid).expect("should be able to generate arbitrary txid")
}

pub fn generate_outpoint() -> bitcoin::OutPoint {
    let vout: u32 = OsRng.gen();

    bitcoin::OutPoint {
        txid: generate_txid(),
        vout,
    }
}

pub fn generate_signature() -> Signature {
    let mut sig = [0u8; 64];
    OsRng.fill(&mut sig);

    Signature::from_slice(&sig).expect("should be able to generate arbitrary signature")
}

pub fn generate_keypair() -> Keypair {
    Keypair::new(SECP256K1, &mut OsRng)
}

pub fn generate_xonly_pubkey() -> XOnlyPublicKey {
    let keypair = Keypair::new(SECP256K1, &mut OsRng);
    XOnlyPublicKey::from_keypair(&keypair).0
}

pub fn generate_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
    let inputs = (0..num_inputs)
        .map(|_| TxIn {
            previous_output: generate_outpoint(),
            witness: Witness::new(),
            sequence: Sequence(0),
            script_sig: ScriptBuf::new(),
        })
        .collect();

    let outputs = (0..num_outputs)
        .map(|_| {
            let value: u32 = OsRng.gen();

            bitcoin::TxOut {
                value: Amount::from_sat(value as u64),
                script_pubkey: ScriptBuf::new(),
            }
        })
        .collect();

    Transaction {
        version: Version(1),
        lock_time: LockTime::from_consensus(0),
        input: inputs,
        output: outputs,
    }
}

pub fn find_funding_utxo(
    btc_client: &Client,
    ignore_list: HashSet<OutPoint>,
    total_amount: Amount,
) -> (TxOut, OutPoint) {
    let list_unspent = btc_client
        .call::<Vec<ListUnspent>>("listunspent", &[])
        .expect("must be able to list unspent");

    list_unspent
        .iter()
        .find_map(|utxo| {
            if utxo.amount > total_amount
                && !ignore_list.contains(&OutPoint::new(utxo.txid, utxo.vout))
            {
                Some((
                    TxOut {
                        value: utxo.amount,
                        script_pubkey: ScriptBuf::from_hex(&utxo.script_pubkey)
                            .expect("must be able to parse script pubkey"),
                    },
                    OutPoint {
                        txid: utxo.txid,
                        vout: utxo.vout,
                    },
                ))
            } else {
                None
            }
        })
        .expect("must have a utxo with enough funds")
}

pub fn sign_cpfp_child(
    btc_client: &Client,
    keypair: &Keypair,
    prevouts: &[TxOut],
    unsigned_child_tx: &mut Transaction,
    funding_index: usize,
    parent_index: usize,
) -> (Witness, schnorr::Signature) {
    let signed_child_tx = btc_client
        .call::<SignRawTransactionWithWallet>(
            "signrawtransactionwithwallet",
            &[json!(consensus::encode::serialize_hex(&unsigned_child_tx))],
        )
        .expect("must be able to sign child tx");
    let signed_child_tx = consensus::encode::deserialize_hex::<Transaction>(&signed_child_tx.hex)
        .expect("must be able to deserialize signed child tx");

    let funding_witness = signed_child_tx
        .input
        .get(funding_index)
        .expect("must have funding input")
        .witness
        .clone();

    let prevouts = Prevouts::All(prevouts);

    let mut sighasher = SighashCache::new(unsigned_child_tx);
    let child_tx_hash = sighasher
        .taproot_key_spend_signature_hash(parent_index, &prevouts, TapSighashType::Default)
        .expect("sighash must be valid");

    let child_tx_msg = Message::from_digest_slice(child_tx_hash.as_byte_array())
        .expect("must be able to create tx message");
    let parent_signature = SECP256K1.sign_schnorr(&child_tx_msg, keypair);

    (funding_witness, parent_signature)
}
