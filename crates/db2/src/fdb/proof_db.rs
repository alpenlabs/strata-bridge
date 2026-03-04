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

    async fn prune(&self, _before: L1BlockCommitment) -> Result<(), Self::Error> {
        todo!("range clear")
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
    }
}
