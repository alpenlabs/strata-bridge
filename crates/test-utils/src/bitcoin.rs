//! Module to generate arbitrary values for testing.

use std::{collections::HashSet, env, str::FromStr};

use bitcoin::{
    absolute::LockTime,
    consensus,
    hashes::Hash,
    key::rand::{rngs::OsRng, thread_rng, Rng},
    secp256k1::{schnorr::Signature, Keypair, SecretKey, XOnlyPublicKey, SECP256K1},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoind_async_client::{
    types::{ListUnspent, SignRawTransactionWithWallet},
    Client as BitcoinClient,
};
use corepc_node::{serde_json::json, Client, Node};
use musig2::secp256k1::{schnorr, Message};
use secp256k1::PublicKey;
use strata_bridge_primitives::secp::EvenSecretKey;

pub fn get_client_async(bitcoind: &Node) -> BitcoinClient {
    // setting the ENV variable `BITCOIN_XPRIV_RETRIEVABLE` to retrieve the xpriv
    env::set_var("BITCOIN_XPRIV_RETRIEVABLE", "true");
    let url = bitcoind.rpc_url();
    let (user, password) = get_auth(bitcoind);
    BitcoinClient::new(url, user, password, None, None).unwrap()
}

/// Get the authentication credentials for a given `bitcoind` instance.
fn get_auth(bitcoind: &Node) -> (String, String) {
    let params = &bitcoind.params;
    let cookie_values = params.get_cookie_values().unwrap().unwrap();
    (cookie_values.user, cookie_values.password)
}

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

/// Generates a random keypair that is guaranteed to be of even parity.
pub fn generate_keypair() -> Keypair {
    let sk = SecretKey::new(&mut OsRng);
    let sk: EvenSecretKey = sk.into();

    Keypair::from_secret_key(SECP256K1, &sk)
}

/// Generate `count` (public key, private key) pairs as two separate [`Vec`].
pub fn generate_keypairs(count: usize) -> (Vec<PublicKey>, Vec<SecretKey>) {
    let mut secret_keys: Vec<SecretKey> = Vec::with_capacity(count);
    let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(count);

    let mut pubkeys_set: HashSet<PublicKey> = HashSet::new();

    while pubkeys_set.len() != count {
        let sk = SecretKey::new(&mut OsRng);
        let keypair = Keypair::from_secret_key(SECP256K1, &sk);
        let pubkey = PublicKey::from_keypair(&keypair);

        if pubkeys_set.insert(pubkey) {
            secret_keys.push(sk);
            pubkeys.push(pubkey);
        }
    }

    (pubkeys, secret_keys)
}

pub fn generate_xonly_pubkey() -> XOnlyPublicKey {
    let mut rng = thread_rng();
    let sk = SecretKey::new(&mut rng);
    let even_sk: EvenSecretKey = sk.into();
    even_sk.x_only_public_key(SECP256K1).0
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

pub fn get_funding_utxo_exact(btc_client: &Client, target_amount: Amount) -> (TxOut, OutPoint) {
    let funding_address = btc_client
        .new_address()
        .expect("must be able to generate new address");

    let result = btc_client
        .send_to_address(&funding_address, target_amount)
        .expect("must be able to send funds");
    btc_client
        .generate_to_address(6, &funding_address)
        .expect("must be able to generate blocks");

    let result = btc_client
        .get_transaction(Txid::from_str(&result.0).expect("txid must be valid"))
        .expect("must be able to get transaction");
    let tx: Transaction =
        consensus::encode::deserialize_hex(&result.hex).expect("must be able to deserialize tx");

    let vout = tx
        .output
        .iter()
        .position(|out| out.value == target_amount)
        .expect("must have a txout with the target amount");

    let txout = TxOut {
        value: target_amount,
        script_pubkey: tx.output[vout].script_pubkey.clone(),
    };

    let outpoint = OutPoint {
        txid: tx.compute_txid(),
        vout: vout as u32,
    };

    (txout, outpoint)
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

pub fn wait_for_blocks(btc_client: &Client, count: usize) {
    let random_address = btc_client
        .new_address()
        .expect("must be able to generate new address");

    let chunk = 100;
    (0..count).step_by(chunk).for_each(|_| {
        btc_client
            .generate_to_address(chunk, &random_address)
            .expect("must be able to generate blocks");
    });
}

#[cfg(test)]
mod tests {
    use bitcoin::key::Parity;

    use super::*;

    #[test]
    fn even_keypair() {
        (0..100).for_each(|_| {
            let keypair = generate_keypair();
            assert_eq!(keypair.x_only_public_key().1, Parity::Even);
        });
    }
}
