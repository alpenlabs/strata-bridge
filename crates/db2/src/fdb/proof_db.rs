//! Implementation of the [`ProofDb`] trait for FdbClient.

use foundationdb::FdbBindingError;
use strata_bridge_primitives::proof::{AsmProof, L1Range, MohoProof};
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
use terrors::OneOf;

use crate::{
    fdb::{
        client::FdbClient,
        errors::LayerError,
        row_spec::{
            asm_proofs::{AsmProofKey, AsmProofRowSpec},
            kv::{PackableKey, SerializableValue},
            moho_proofs::{MohoProofKey, MohoProofRowSpec},
        },
    },
    traits::ProofDb,
};

impl ProofDb for FdbClient {
    type Error = OneOf<(FdbBindingError, LayerError)>;

    async fn store_asm_proof(&self, range: L1Range, proof: AsmProof) -> Result<(), Self::Error> {
        let key = AsmProofKey {
            start_height: range.start().height_u32(),
            start_blkid: *range.start().blkid().as_ref(),
            end_height: range.end().height_u32(),
            end_blkid: *range.end().blkid().as_ref(),
        };
        self.basic_set::<AsmProofRowSpec>(key, proof).await
    }

    async fn get_asm_proof(&self, range: L1Range) -> Result<Option<AsmProof>, Self::Error> {
        let key = AsmProofKey {
            start_height: range.start().height_u32(),
            start_blkid: *range.start().blkid().as_ref(),
            end_height: range.end().height_u32(),
            end_blkid: *range.end().blkid().as_ref(),
        };
        self.basic_get::<AsmProofRowSpec>(key).await
    }

    async fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> Result<(), Self::Error> {
        let key = MohoProofKey {
            height: l1ref.height_u32(),
            blkid: *l1ref.blkid().as_ref(),
        };
        self.basic_set::<MohoProofRowSpec>(key, proof).await
    }

    async fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoProof>, Self::Error> {
        let key = MohoProofKey {
            height: l1ref.height_u32(),
            blkid: *l1ref.blkid().as_ref(),
        };
        self.basic_get::<MohoProofRowSpec>(key).await
    }

    async fn get_latest_moho_proof(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error> {
        let Some((raw_key, raw_value)) = self
            .basic_get_last(&self.dirs().moho_proofs)
            .await
            .map_err(OneOf::new)?
        else {
            return Ok(None);
        };

        let key = MohoProofKey::unpack(self.dirs(), &raw_key)
            .map_err(LayerError::failed_to_unpack_key)
            .map_err(OneOf::new)?;

        let proof = MohoProof::deserialize(&raw_value)
            .map_err(LayerError::failed_to_deserialize_value)
            .map_err(OneOf::new)?;

        let commitment = L1BlockCommitment::from_height_u64(
            key.height as u64,
            L1BlockId::from(Buf32::from(key.blkid)),
        )
        .expect("height was valid when stored");

        Ok(Some((commitment, proof)))
    }

    async fn prune(&self, before: L1BlockCommitment) -> Result<(), Self::Error> {
        let height = before.height_u32();

        // Pack just the height as the range end (exclusive).
        // All keys with a height strictly less than `height` sort before this
        // in FDB's tuple ordering, so clear_range removes exactly those entries.
        let asm_begin = self.dirs().asm_proofs.range().0;
        let asm_end = self.dirs().asm_proofs.pack::<(u32,)>(&(height,));

        let moho_begin = self.dirs().moho_proofs.range().0;
        let moho_end = self.dirs().moho_proofs.pack::<(u32,)>(&(height,));

        self.db()
            .run(|trx, _| {
                let asm_begin = asm_begin.clone();
                let asm_end = asm_end.clone();
                let moho_begin = moho_begin.clone();
                let moho_end = moho_end.clone();
                async move {
                    trx.clear_range(&asm_begin, &asm_end);
                    trx.clear_range(&moho_begin, &moho_end);
                    Ok(())
                }
            })
            .await
            .map_err(OneOf::new)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_identifiers::{Buf32, L1BlockId};

    use super::*;
    use crate::fdb::test_utils::{block_on, get_client, new_test_client};

    /// Generates an arbitrary L1BlockCommitment.
    /// Heights must be < 500_000_000 (bitcoin LOCK_TIME_THRESHOLD).
    fn arb_l1_block_commitment() -> impl Strategy<Value = L1BlockCommitment> {
        (0u32..500_000_000u32, any::<[u8; 32]>()).prop_map(|(h, blkid)| {
            L1BlockCommitment::from_height_u64(h as u64, L1BlockId::from(Buf32::from(blkid)))
                .expect("valid height")
        })
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: any ASM proof stored can be retrieved with the same range key.
        #[test]
        fn asm_proof_roundtrip(
            range in arb_l1_range(),
            proof in arb_asm_proof(),
        ) {
            block_on(async {
                let client = get_client();

                client.store_asm_proof(range, proof.clone()).await.unwrap();

                let retrieved = client.get_asm_proof(range).await.unwrap();

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
            block_on(async {
                let client = get_client();

                client.store_moho_proof(commitment, proof.clone()).await.unwrap();

                let retrieved = client.get_moho_proof(commitment).await.unwrap();

                prop_assert_eq!(Some(proof), retrieved);

                Ok(())
            })?;
        }
    }

    #[test]
    fn get_nonexistent_asm_proof_returns_none() {
        block_on(async {
            let client = get_client();

            let commitment = L1BlockCommitment::from_height_u64(
                999_999,
                L1BlockId::from(Buf32::from([0xffu8; 32])),
            )
            .unwrap();
            let range = L1Range::single(commitment);

            let result = client.get_asm_proof(range).await.unwrap();
            assert_eq!(result, None);
        });
    }

    #[test]
    fn get_nonexistent_moho_proof_returns_none() {
        block_on(async {
            let client = get_client();

            let commitment = L1BlockCommitment::from_height_u64(
                999_998,
                L1BlockId::from(Buf32::from([0xfeu8; 32])),
            )
            .unwrap();

            let result = client.get_moho_proof(commitment).await.unwrap();
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
            // Each iteration gets its own isolated namespace so
            // get_latest only sees entries from this iteration.
            let client = new_test_client();
            block_on(async {
                for (commitment, proof) in &entries {
                    client.store_moho_proof(*commitment, proof.clone()).await.unwrap();
                }

                let (latest_commitment, latest_proof) = client
                    .get_latest_moho_proof()
                    .await
                    .unwrap()
                    .expect("should have proofs after storing");

                // Find the entry with the max key (height, then blkid) to match
                // FDB's tuple ordering.
                let expected = entries
                    .iter()
                    .max_by_key(|(c, _)| (c.height_u32(), *c.blkid().as_ref()))
                    .unwrap();

                prop_assert_eq!(latest_commitment.height_u32(), expected.0.height_u32());
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
            block_on(async {
            let client = new_test_client();
                // Store Moho proofs below the threshold.
                let below_moho_entries: Vec<_> = below_moho.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::from_height_u64(
                        (threshold - offset) as u64,
                        L1BlockId::from(Buf32::from(blkid)),
                    ).unwrap();
                    (c, proof)
                }).collect();

                // Store Moho proofs at or above the threshold.
                let above_moho_entries: Vec<_> = above_moho.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::from_height_u64(
                        (threshold + offset) as u64,
                        L1BlockId::from(Buf32::from(blkid)),
                    ).unwrap();
                    (c, proof)
                }).collect();

                for (c, proof) in &below_moho_entries {
                    client.store_moho_proof(*c, proof.clone()).await.unwrap();
                }
                for (c, proof) in &above_moho_entries {
                    client.store_moho_proof(*c, proof.clone()).await.unwrap();
                }

                // Store ASM proofs below the threshold (single-block ranges).
                let below_asm_entries: Vec<_> = below_asm.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::from_height_u64(
                        (threshold - offset) as u64,
                        L1BlockId::from(Buf32::from(blkid)),
                    ).unwrap();
                    (L1Range::single(c), proof)
                }).collect();

                // Store ASM proofs at or above the threshold.
                let above_asm_entries: Vec<_> = above_asm.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::from_height_u64(
                        (threshold + offset) as u64,
                        L1BlockId::from(Buf32::from(blkid)),
                    ).unwrap();
                    (L1Range::single(c), proof)
                }).collect();

                for (range, proof) in &below_asm_entries {
                    client.store_asm_proof(*range, proof.clone()).await.unwrap();
                }
                for (range, proof) in &above_asm_entries {
                    client.store_asm_proof(*range, proof.clone()).await.unwrap();
                }

                // Prune at threshold.
                let prune_c = L1BlockCommitment::from_height_u64(
                    threshold as u64,
                    L1BlockId::from(Buf32::from([0u8; 32])),
                ).unwrap();
                client.prune(prune_c).await.unwrap();

                // Moho entries below threshold should be gone.
                for (c, _) in &below_moho_entries {
                    let result = client.get_moho_proof(*c).await.unwrap();
                    prop_assert_eq!(result, None, "moho at height {} should be pruned", c.height_u32());
                }
                // Moho entries at or above threshold should survive.
                for (c, proof) in &above_moho_entries {
                    let result = client.get_moho_proof(*c).await.unwrap();
                    prop_assert_eq!(result, Some(proof.clone()), "moho at height {} should survive", c.height_u32());
                }

                // ASM entries below threshold should be gone.
                for (range, _) in &below_asm_entries {
                    let result = client.get_asm_proof(*range).await.unwrap();
                    prop_assert_eq!(result, None, "asm at height {} should be pruned", range.start().height_u32());
                }
                // ASM entries at or above threshold should survive.
                for (range, proof) in &above_asm_entries {
                    let result = client.get_asm_proof(*range).await.unwrap();
                    prop_assert_eq!(result, Some(proof.clone()), "asm at height {} should survive", range.start().height_u32());
                }

                Ok(())
            })?;
        }
    }
}
