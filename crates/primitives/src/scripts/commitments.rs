use bitvm::signatures::wots::{wots160, wots256, wots32};
use sha2::Digest;

fn secret_key_from_msk(msk: &str, var: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(format!("{msk}:{var}"));
    format!("{:x}", hasher.finalize())
}

pub fn secret_key_for_superblock_hash(msk: &str) -> String {
    let var = "superblock_hash";
    secret_key_from_msk(msk, var)
}

pub fn secret_key_for_superblock_period_start_ts(msk: &str) -> String {
    let var = "superblock_period_start_ts";
    secret_key_from_msk(msk, var)
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

pub fn public_key_for_superblock_hash(msk: &str) -> wots256::PublicKey {
    let secret_key = secret_key_for_superblock_hash(msk);
    wots256::generate_public_key(&secret_key)
}

pub fn public_key_for_superblock_period_start_ts(msk: &str) -> wots32::PublicKey {
    let secret_key = secret_key_for_superblock_period_start_ts(msk);
    wots32::generate_public_key(&secret_key)
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
