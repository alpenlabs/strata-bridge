use secp256k1::{SecretKey, SECP256K1};
use strata_primitives::{buf::Buf32, hash::sha256d, utils::get_cohashes};

#[derive(Debug, Clone)]
pub struct AnchorPublicKeyMerkleProof {
    position: usize,
    cohashes: Vec<Buf32>,
    sk: Buf32,
}

impl AnchorPublicKeyMerkleProof {
    pub fn position(&self) -> usize {
        self.position
    }

    pub fn cohashes(&self) -> &[Buf32] {
        &self.cohashes
    }

    pub fn new(position: usize, cohashes: Vec<Buf32>, sk: Buf32) -> Self {
        Self {
            position,
            cohashes,
            sk,
        }
    }

    pub fn generate(keys: &[Buf32], idx: usize, sk: Buf32) -> Self {
        let (cohashes, _root) = get_cohashes(keys, idx as u32);
        AnchorPublicKeyMerkleProof::new(idx, cohashes, sk)
    }

    /// Computes the merkle root for the given key using the proof's cohashes.
    pub fn compute_root(&self, key: &Buf32) -> Buf32 {
        // `cur_hash` represents the intermediate hash at each step. After all cohashes are
        // processed `cur_hash` becomes the root hash
        let mut cur_hash = key.0;

        let mut pos = self.position();
        for cohash in self.cohashes() {
            let mut buf = [0u8; 64];
            if pos & 1 == 0 {
                buf[0..32].copy_from_slice(&cur_hash);
                buf[32..64].copy_from_slice(cohash.as_ref());
            } else {
                buf[0..32].copy_from_slice(cohash.as_ref());
                buf[32..64].copy_from_slice(&cur_hash);
            }
            // NOTE(optimization): can be opted for sha256 instead of sha256d
            cur_hash = sha256d(&buf).0;
            pos >>= 1;
        }
        Buf32::from(cur_hash)
    }

    pub fn verify(&self, root: Buf32) -> bool {
        let sk = SecretKey::from_slice(self.sk.as_bytes()).unwrap();
        let (pk, _) = sk.x_only_public_key(SECP256K1);
        self.compute_root(&pk.into()) == root
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, Rng};
    use secp256k1::{SecretKey, SECP256K1};
    use strata_primitives::{buf::Buf32, utils::get_cohashes};

    use super::AnchorPublicKeyMerkleProof;

    fn get_data(n: usize) -> (Vec<Buf32>, Vec<Buf32>) {
        let mut sks = vec![Buf32::zero(); n];
        let mut pks = vec![Buf32::zero(); n];

        for i in 0..n {
            let sk = SecretKey::new(&mut OsRng);
            let (pk, _) = sk.x_only_public_key(SECP256K1);

            let sk = Buf32::from(*sk.as_ref());
            let pk = Buf32::from(pk.serialize());

            sks[i] = sk;
            pks[i] = pk
        }
        (sks, pks)
    }
    #[test]
    fn test_proof() {
        let n = 2;
        let (sks, pks) = get_data(n);
        let idx = OsRng.gen_range(0..n);
        let (_, root) = get_cohashes(&pks, idx as u32);

        let proof = AnchorPublicKeyMerkleProof::generate(&pks, idx, sks[idx]);
        assert!(proof.verify(root));
    }
}
