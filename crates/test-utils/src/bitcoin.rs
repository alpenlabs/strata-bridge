//! Module to generate arbitrary values for testing.

use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    key::{
        rand::{rngs::OsRng, Rng},
        XOnlyPublicKey,
    },
    secp256k1::{schnorr::Signature, SECP256K1},
    transaction::Version,
    Amount, ScriptBuf, Sequence, Transaction, TxIn, Txid, Witness,
};

pub fn generate_txid() -> Txid {
    let mut txid = [0u8; 32];
    OsRng.fill(&mut txid);

    Txid::from_slice(&txid).expect("should be able to generate arbitary txid")
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

    Signature::from_slice(&sig).expect("should be able to generate arbitary signature")
}

pub fn generate_xonly_pubkey() -> XOnlyPublicKey {
    let keypair = bitcoin::key::Keypair::new(SECP256K1, &mut OsRng);
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
