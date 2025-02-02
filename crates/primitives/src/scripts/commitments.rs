use bitcoin::Txid;
use bitvm::signatures::wots::wots256;
use sha2::Digest;

pub fn get_deposit_master_secret_key(msk: &str, deposit_txid: Txid) -> String {
    format!("{}:{}", msk, deposit_txid)
}

fn secret_key_from_msk(msk: &str, var: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(format!("{msk}:{var}"));
    format!("{:x}", hasher.finalize())
}

pub fn secret_key_for_bridge_out_txid(msk: &str) -> String {
    let var = "bridge_out_txid";
    secret_key_from_msk(msk, var)
}

pub fn secret_key_for_public_inputs_hash(msk: &str) -> String {
    let var = "public_inputs_hash";
    secret_key_from_msk(msk, var)
}

pub fn secret_key_for_proof_element(msk: &str, id: usize) -> String {
    let var = &format!("proof_element_{}", id);
    secret_key_from_msk(msk, var)
}

pub fn public_key_for_bridge_out_txid(msk: &str) -> wots256::PublicKey {
    let secret_key = secret_key_for_bridge_out_txid(msk);
    wots256::generate_public_key(&secret_key)
}

pub fn public_key_for_public_inputs_hash(msk: &str) -> wots256::PublicKey {
    let secret_key = secret_key_for_bridge_out_txid(msk);
    wots256::generate_public_key(&secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_from_msk() {
        let msk = "hello";
        let var = "world";

        println!("{}", secret_key_from_msk(msk, var));
    }
}
