//! [`ProofDb`] implementation backed by [sled](https://docs.rs/sled).

use strata_bridge_primitives::proof::{AsmProof, L1Range, MohoProof};
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

use crate::ProofDb;

/// Sled-backed proof database.
///
/// Uses two sled trees — one for ASM step proofs and one for Moho recursive
/// proofs. Keys are encoded with big-endian heights so that sled's
/// lexicographic ordering matches block-height ordering.
#[derive(Debug, Clone)]
pub struct SledProofDb {
    asm_proofs: sled::Tree,
    moho_proofs: sled::Tree,
}

impl SledProofDb {
    /// Opens (or creates) the proof database at the given path.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        let asm_proofs = db.open_tree("asm_proofs")?;
        let moho_proofs = db.open_tree("moho_proofs")?;
        Ok(Self {
            asm_proofs,
            moho_proofs,
        })
    }
}

// ── Key encoding ──────────────────────────────────────────────────────

/// Encodes an ASM proof key as 72 bytes:
/// `[start_height_be(4)][start_blkid(32)][end_height_be(4)][end_blkid(32)]`
fn encode_asm_key(range: &L1Range) -> [u8; 72] {
    let mut key = [0u8; 72];
    key[0..4].copy_from_slice(&range.start().height().to_be_bytes());
    key[4..36].copy_from_slice(range.start().blkid().as_ref());
    key[36..40].copy_from_slice(&range.end().height().to_be_bytes());
    key[40..72].copy_from_slice(range.end().blkid().as_ref());
    key
}

/// Encodes a Moho proof key as 36 bytes:
/// `[height_be(4)][blkid(32)]`
fn encode_moho_key(l1ref: &L1BlockCommitment) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[0..4].copy_from_slice(&l1ref.height().to_be_bytes());
    key[4..36].copy_from_slice(l1ref.blkid().as_ref());
    key
}

/// Decodes a Moho proof key back into an [`L1BlockCommitment`].
fn decode_moho_key(key: &[u8]) -> L1BlockCommitment {
    let height = u32::from_be_bytes(key[0..4].try_into().expect("key is at least 4 bytes"));
    let blkid: [u8; 32] = key[4..36].try_into().expect("key is at least 36 bytes");
    L1BlockCommitment::new(height, L1BlockId::from(Buf32::from(blkid)))
}

impl ProofDb for SledProofDb {
    type Error = sled::Error;

    async fn store_asm_proof(&self, range: L1Range, proof: AsmProof) -> Result<(), Self::Error> {
        self.asm_proofs.insert(encode_asm_key(&range), proof.0)?;
        Ok(())
    }

    async fn get_asm_proof(&self, range: L1Range) -> Result<Option<AsmProof>, Self::Error> {
        Ok(self
            .asm_proofs
            .get(encode_asm_key(&range))?
            .map(|v| AsmProof(v.to_vec())))
    }

    async fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> Result<(), Self::Error> {
        self.moho_proofs.insert(encode_moho_key(&l1ref), proof.0)?;
        Ok(())
    }

    async fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoProof>, Self::Error> {
        Ok(self
            .moho_proofs
            .get(encode_moho_key(&l1ref))?
            .map(|v| MohoProof(v.to_vec())))
    }

    async fn get_latest_moho_proof(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error> {
        Ok(self.moho_proofs.last()?.map(|(k, v)| {
            let commitment = decode_moho_key(&k);
            let proof = MohoProof(v.to_vec());
            (commitment, proof)
        }))
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        let upper: &[u8] = &before_height.to_be_bytes();

        // Remove all moho proofs with height < before_height.
        for entry in self.moho_proofs.range(..upper) {
            let (key, _) = entry?;
            self.moho_proofs.remove(&key)?;
        }

        // Remove all ASM proofs with start_height < before_height.
        for entry in self.asm_proofs.range(..upper) {
            let (key, _) = entry?;
            self.asm_proofs.remove(&key)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_identifiers::{Buf32, L1BlockId};

    use super::*;

    /// Generates an arbitrary L1BlockCommitment.
    /// Heights must be < 500_000_000 (bitcoin LOCK_TIME_THRESHOLD).
    fn arb_l1_block_commitment() -> impl Strategy<Value = L1BlockCommitment> {
        (0u32..500_000_000u32, any::<[u8; 32]>())
            .prop_map(|(h, blkid)| L1BlockCommitment::new(h, L1BlockId::from(Buf32::from(blkid))))
    }

    /// Generates an arbitrary L1Range (end height >= start height).
    fn arb_l1_range() -> impl Strategy<Value = L1Range> {
        (arb_l1_block_commitment(), arb_l1_block_commitment())
            .prop_filter_map("end height must be >= start height", |(a, b)| {
                L1Range::new(a, b)
            })
    }

    fn arb_asm_proof() -> impl Strategy<Value = AsmProof> {
        proptest::collection::vec(any::<u8>(), 0..1024).prop_map(AsmProof)
    }

    fn arb_moho_proof() -> impl Strategy<Value = MohoProof> {
        proptest::collection::vec(any::<u8>(), 0..1024).prop_map(MohoProof)
    }

    /// Creates an isolated [`SledProofDb`] backed by a temporary directory.
    fn temp_db() -> (SledProofDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = SledProofDb::open(dir.path()).expect("failed to open sled db");
        (db, dir)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: any ASM proof stored can be retrieved with the same range key.
        #[test]
        fn asm_proof_roundtrip(
            range in arb_l1_range(),
            proof in arb_asm_proof(),
        ) {
            let (db, _dir) = temp_db();

            tokio::runtime::Runtime::new().unwrap().block_on(async {
                db.store_asm_proof(range, proof.clone()).await.unwrap();

                let retrieved = db.get_asm_proof(range).await.unwrap();

                prop_assert_eq!(Some(proof), retrieved);

                Ok(())
            })?;
        }

        /// Property: any Moho proof stored can be retrieved with the same commitment key.
        #[test]
        fn moho_proof_roundtrip(
            commitment in arb_l1_block_commitment(),
            proof in arb_moho_proof(),
        ) {
            let (db, _dir) = temp_db();

            tokio::runtime::Runtime::new().unwrap().block_on(async {
                db.store_moho_proof(commitment, proof.clone()).await.unwrap();

                let retrieved = db.get_moho_proof(commitment).await.unwrap();

                prop_assert_eq!(Some(proof), retrieved);

                Ok(())
            })?;
        }
    }

    #[test]
    fn get_nonexistent_asm_proof_returns_none() {
        let (db, _dir) = temp_db();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let commitment =
                L1BlockCommitment::new(999_999, L1BlockId::from(Buf32::from([0xffu8; 32])));
            let range = L1Range::single(commitment);

            let result = db.get_asm_proof(range).await.unwrap();
            assert_eq!(result, None);
        });
    }

    #[test]
    fn get_nonexistent_moho_proof_returns_none() {
        let (db, _dir) = temp_db();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let commitment =
                L1BlockCommitment::new(999_998, L1BlockId::from(Buf32::from([0xfeu8; 32])));

            let result = db.get_moho_proof(commitment).await.unwrap();
            assert_eq!(result, None);
        });
    }

    #[test]
    fn get_latest_moho_proof_returns_none_when_empty() {
        let (db, _dir) = temp_db();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let result = db.get_latest_moho_proof().await.unwrap();
            assert_eq!(result, None);
        });
    }

    /// Generates a Vec of (L1BlockCommitment, MohoProof) pairs.
    fn arb_moho_entries() -> impl Strategy<Value = Vec<(L1BlockCommitment, MohoProof)>> {
        proptest::collection::vec((arb_l1_block_commitment(), arb_moho_proof()), 2..10)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Property: after storing multiple Moho proofs, get_latest returns the one
        /// with the highest height.
        #[test]
        fn get_latest_moho_proof_returns_highest(entries in arb_moho_entries()) {
            let (db, _dir) = temp_db();

            tokio::runtime::Runtime::new().unwrap().block_on(async {
                for (commitment, proof) in &entries {
                    db.store_moho_proof(*commitment, proof.clone()).await.unwrap();
                }

                let (latest_commitment, latest_proof) = db
                    .get_latest_moho_proof()
                    .await
                    .unwrap()
                    .expect("should have proofs after storing");

                // Find the entry with the max key (height, then blkid) to match
                // the big-endian lexicographic ordering.
                let expected = entries
                    .iter()
                    .max_by_key(|(c, _)| (c.height(), *c.blkid().as_ref()))
                    .unwrap();

                prop_assert_eq!(latest_commitment.height(), expected.0.height());
                prop_assert_eq!(latest_proof, expected.1.clone());

                Ok(())
            })?;
        }

        /// Property: prune removes entries with height < threshold and preserves
        /// those with height >= threshold, in both the ASM and Moho subspaces.
        #[test]
        fn prune_removes_entries_below_threshold(
            threshold in 100u32..499_999_900u32,
            below_moho in proptest::collection::vec(
                (1u32..100u32, any::<[u8; 32]>(), arb_moho_proof()),
                1..4,
            ),
            above_moho in proptest::collection::vec(
                (0u32..100u32, any::<[u8; 32]>(), arb_moho_proof()),
                1..4,
            ),
            below_asm in proptest::collection::vec(
                (1u32..100u32, any::<[u8; 32]>(), arb_asm_proof()),
                1..4,
            ),
            above_asm in proptest::collection::vec(
                (0u32..100u32, any::<[u8; 32]>(), arb_asm_proof()),
                1..4,
            ),
        ) {
            let (db, _dir) = temp_db();

            tokio::runtime::Runtime::new().unwrap().block_on(async {
                // Store Moho proofs below the threshold.
                let below_moho_entries: Vec<_> = below_moho.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold - offset,
                        L1BlockId::from(Buf32::from(blkid)));
                    (c, proof)
                }).collect();

                // Store Moho proofs at or above the threshold.
                let above_moho_entries: Vec<_> = above_moho.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold + offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (c, proof)
                }).collect();

                for (c, proof) in &below_moho_entries {
                    db.store_moho_proof(*c, proof.clone()).await.unwrap();
                }
                for (c, proof) in &above_moho_entries {
                    db.store_moho_proof(*c, proof.clone()).await.unwrap();
                }

                // Store ASM proofs below the threshold (single-block ranges).
                let below_asm_entries: Vec<_> = below_asm.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold - offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (L1Range::single(c), proof)
                }).collect();

                // Store ASM proofs at or above the threshold.
                let above_asm_entries: Vec<_> = above_asm.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold + offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (L1Range::single(c), proof)
                }).collect();

                for (range, proof) in &below_asm_entries {
                    db.store_asm_proof(*range, proof.clone()).await.unwrap();
                }
                for (range, proof) in &above_asm_entries {
                    db.store_asm_proof(*range, proof.clone()).await.unwrap();
                }

                // Prune at threshold.
                db.prune(threshold).await.unwrap();

                // Moho entries below threshold should be gone.
                for (c, _) in &below_moho_entries {
                    let result = db.get_moho_proof(*c).await.unwrap();
                    prop_assert_eq!(result, None, "moho at height {} should be pruned", c.height());
                }
                // Moho entries at or above threshold should survive.
                for (c, proof) in &above_moho_entries {
                    let result = db.get_moho_proof(*c).await.unwrap();
                    prop_assert_eq!(result, Some(proof.clone()), "moho at height {} should survive", c.height());
                }

                // ASM entries below threshold should be gone.
                for (range, _) in &below_asm_entries {
                    let result = db.get_asm_proof(*range).await.unwrap();
                    prop_assert_eq!(result, None, "asm at height {} should be pruned", range.start().height());
                }
                // ASM entries at or above threshold should survive.
                for (range, proof) in &above_asm_entries {
                    let result = db.get_asm_proof(*range).await.unwrap();
                    prop_assert_eq!(result, Some(proof.clone()), "asm at height {} should survive", range.start().height());
                }

                Ok(())
            })?;
        }
    }
}
