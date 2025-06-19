//! Scripts for commitments.

use bitcoin::Txid;
use bitvm::signatures::{Wots, Wots32 as wots256};
use sha2::Digest;

/// Returns the master secret key for a deposit.
pub fn get_deposit_master_secret_key(msk: &str, deposit_txid: Txid) -> String {
    format!("{}:{}", msk, deposit_txid)
}

/// Returns the secret key for a variable from the master secret key.
fn secret_key_from_msk(msk: &str, var: &str) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(format!("{msk}:{var}"));

    hasher.finalize().to_vec()
}

/// Returns the secret key for the bridge out transaction ID.
pub fn secret_key_for_bridge_out_txid(msk: &str) -> Vec<u8> {
    let var = "bridge_out_txid";
    secret_key_from_msk(msk, var)
}

/// Returns the secret key for the public inputs hash.
pub fn secret_key_for_public_inputs_hash(msk: &str) -> Vec<u8> {
    let var = "public_inputs_hash";
    secret_key_from_msk(msk, var)
}

/// Returns the secret key for a proof element.
pub fn secret_key_for_proof_element(msk: &str, id: usize) -> Vec<u8> {
    let var = &format!("proof_element_{}", id);
    secret_key_from_msk(msk, var)
}

/// Returns the public key for the bridge out transaction ID.
pub fn public_key_for_bridge_out_txid(msk: &str) -> <wots256 as Wots>::PublicKey {
    let secret_key = secret_key_for_bridge_out_txid(msk);
    wots256::generate_public_key(&secret_key)
}

/// Returns the public key for the public inputs hash.
pub fn public_key_for_public_inputs_hash(msk: &str) -> <wots256 as Wots>::PublicKey {
    let secret_key = secret_key_for_bridge_out_txid(msk);
    wots256::generate_public_key(&secret_key)
}
