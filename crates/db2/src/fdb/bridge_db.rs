//! Implementation of the [`BridgeDb`] trait for FdbClient.

use bitcoin::{OutPoint, Txid};
use foundationdb::FdbBindingError;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{deposit::machine::DepositSM, graph::machine::GraphSM};
use terrors::OneOf;

use crate::{
    fdb::{
        client::FdbClient,
        errors::LayerError,
        row_spec::{
            deposits::{DepositStateKey, DepositStateRowSpec},
            signatures::{SignatureKey, SignatureRowSpec},
        },
    },
    traits::BridgeDb,
    types::FundingPurpose,
};

impl BridgeDb for FdbClient {
    type Error = OneOf<(FdbBindingError, LayerError)>;

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Result<Option<Signature>, Self::Error> {
        self.basic_get::<SignatureRowSpec>(SignatureKey {
            operator_idx,
            txid,
            input_index,
        })
        .await
    }

    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> Result<(), Self::Error> {
        self.basic_set::<SignatureRowSpec>(
            SignatureKey {
                operator_idx,
                txid,
                input_index,
            },
            signature,
        )
        .await
    }

    // ── Deposit States ───────────────────────────────────────────────

    async fn get_deposit_state(
        &self,
        deposit_idx: DepositIdx,
    ) -> Result<Option<DepositSM>, Self::Error> {
        self.basic_get::<DepositStateRowSpec>(DepositStateKey { deposit_idx })
            .await
    }

    async fn set_deposit_state(
        &self,
        deposit_idx: DepositIdx,
        state: DepositSM,
    ) -> Result<(), Self::Error> {
        self.basic_set::<DepositStateRowSpec>(DepositStateKey { deposit_idx }, state)
            .await
    }

    async fn get_all_deposit_states(&self) -> Result<Vec<(DepositIdx, DepositSM)>, Self::Error> {
        let pairs = self
            .basic_get_all::<DepositStateRowSpec>(|dirs| &dirs.deposits)
            .await?;
        Ok(pairs.into_iter().map(|(k, v)| (k.deposit_idx, v)).collect())
    }

    async fn delete_deposit_state(&self, deposit_idx: DepositIdx) -> Result<(), Self::Error> {
        self.basic_delete::<DepositStateRowSpec>(DepositStateKey { deposit_idx })
            .await
    }
    }

    async fn get_graph_state(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
    ) -> Result<Option<GraphSM>, Self::Error> {
        todo!()
    }

    async fn set_graph_state(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
        _state: GraphSM,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn get_all_graph_states(&self) -> Result<Vec<(GraphIdx, GraphSM)>, Self::Error> {
        todo!()
    }

    async fn get_funds(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
        _purpose: FundingPurpose,
    ) -> Result<Option<Vec<bitcoin::OutPoint>>, Self::Error> {
        todo!()
    }

    async fn set_funds(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
        _purpose: FundingPurpose,
        _outpoints: Vec<bitcoin::OutPoint>,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn get_all_funds(&self) -> Result<Vec<OutPoint>, Self::Error> {
        todo!()
    }

    async fn delete_funds(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
        _purpose: crate::types::FundingPurpose,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn delete_graph_state(
        &self,
        _deposit_idx: DepositIdx,
        _operator_idx: OperatorIdx,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn delete_deposit(&self, _deposit_idx: DepositIdx) -> Result<(), Self::Error> {
        todo!()
    }

    async fn delete_operator(&self, _operator_idx: OperatorIdx) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use bitcoin::hashes::Hash;
    use proptest::prelude::*;
    use secp256k1::{
        Keypair, Message, Secp256k1,
        rand::{random, thread_rng},
    };
    use strata_bridge_primitives::operator_table::prop_test_generators::arb_operator_table;
    use strata_bridge_sm::deposit::{context::DepositSMCtx, state::DepositState};

    use super::*;
    use crate::fdb::{cfg::Config, client::MustDrop};

    static TEST_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static FDB_CLIENT: OnceLock<(FdbClient, MustDrop)> = OnceLock::new();

    fn get_runtime() -> &'static tokio::runtime::Runtime {
        TEST_RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    /// Runs a future to completion, handling the case where we're already inside a runtime.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // We're inside a runtime, use block_in_place to avoid nested runtime error
            tokio::task::block_in_place(|| handle.block_on(f))
        } else {
            // We're not in a runtime, use our static runtime
            get_runtime().block_on(f)
        }
    }

    fn get_client() -> &'static FdbClient {
        &FDB_CLIENT
            .get_or_init(|| {
                block_on(async {
                    // Use a random root directory name for test isolation
                    let random_suffix: u64 = random();
                    let fdb_config = Config {
                        root_directory: format!("test-{random_suffix}"),
                        ..Default::default()
                    };
                    FdbClient::setup(fdb_config).await.unwrap()
                })
            })
            .0
    }

    /// Generates an arbitrary valid Schnorr signature.
    fn arb_signature() -> impl Strategy<Value = Signature> {
        any::<[u8; 32]>().prop_map(|msg_bytes| {
            let secp = Secp256k1::new();
            let (secret_key, _) = secp.generate_keypair(&mut thread_rng());
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            keypair.sign_schnorr(Message::from_digest(msg_bytes))
        })
    }

    /// Generates an arbitrary Txid.
    fn arb_txid() -> impl Strategy<Value = Txid> {
        any::<[u8; 32]>().prop_map(|bytes| Txid::from_slice(&bytes).unwrap())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: any signature stored in the database can be retrieved with the same key.
        #[test]
        fn signature_roundtrip(
            operator_idx in any::<OperatorIdx>(),
            txid in arb_txid(),
            input_index in any::<u32>(),
            signature in arb_signature(),
        ) {
            block_on(async {
                let client = get_client();

                client
                    .set_signature(operator_idx, txid, input_index, signature)
                    .await
                    .unwrap();

                let retrieved_signature = client
                    .get_signature(operator_idx, txid, input_index)
                    .await
                    .unwrap();

                prop_assert_eq!(Some(signature), retrieved_signature);

                Ok(())
            })?;
        }

        /// Property: any deposit SM stored can be retrieved with the same key.
        #[test]
        fn deposit_state_roundtrip(
            deposit_idx in any::<DepositIdx>(),
            last_block_height in any::<u64>(),
            variant_selector in 0u8..4,
            outpoint_txid in any::<[u8; 32]>(),
            outpoint_vout in any::<u32>(),
            operator_table in arb_operator_table(),
        ) {
            // only uses simple variants for testing, as the more complex ones would require constructing valid DepositSMs.
            // TODO: (@Rajil1213) implement Arbitrary for `DepositSM` to allow testing of all variants.
            let state = match variant_selector {
                0 => DepositState::Deposited { last_block_height },
                1 => DepositState::CooperativePathFailed { last_block_height },
                2 => DepositState::Spent,
                _ => DepositState::Aborted,
            };

            let deposit_sm = DepositSM {
                context: DepositSMCtx {
                    deposit_idx,
                    deposit_outpoint: OutPoint {
                        txid: Txid::from_slice(&outpoint_txid).unwrap(),
                        vout: outpoint_vout,
                    },
                    operator_table,
                },
                state,
            };

            block_on(async {
                let client = get_client();

                client
                    .set_deposit_state(deposit_idx, deposit_sm.clone())
                    .await
                    .unwrap();

                let retrieved = client
                    .get_deposit_state(deposit_idx)
                    .await
                    .unwrap();

                prop_assert_eq!(Some(deposit_sm), retrieved);

                Ok(())
            })?;
        }

        /// Property: `get_all_deposit_states` returns all previously stored deposits.
        #[test]
        fn get_all_deposit_states_test(
            deposit_idx_a in any::<DepositIdx>(),
            deposit_idx_b in any::<DepositIdx>(),
            last_block_height in any::<u64>(),
            outpoint_txid in any::<[u8; 32]>(),
            outpoint_vout in any::<u32>(),
            operator_table in arb_operator_table(),
        ) {
            prop_assume!(deposit_idx_a != deposit_idx_b);

            let make_sm = |idx| DepositSM {
                context: DepositSMCtx {
                    deposit_idx: idx,
                    deposit_outpoint: OutPoint {
                        txid: Txid::from_slice(&outpoint_txid).unwrap(),
                        vout: outpoint_vout,
                    },
                    operator_table: operator_table.clone(),
                },
                state: DepositState::Deposited { last_block_height },
            };

            let sm_a = make_sm(deposit_idx_a);
            let sm_b = make_sm(deposit_idx_b);

            block_on(async {
                let client = get_client();

                client.set_deposit_state(deposit_idx_a, sm_a.clone()).await.unwrap();
                client.set_deposit_state(deposit_idx_b, sm_b.clone()).await.unwrap();

                let all = client.get_all_deposit_states().await.unwrap();

                let found_a = all.iter().any(|(idx, sm)| *idx == deposit_idx_a && *sm == sm_a);
                let found_b = all.iter().any(|(idx, sm)| *idx == deposit_idx_b && *sm == sm_b);

                prop_assert!(found_a, "deposit_idx_a not found in get_all_deposit_states");
                prop_assert!(found_b, "deposit_idx_b not found in get_all_deposit_states");

                Ok(())
            })?;
        }

        /// Property: deleting a deposit state makes it unreadable.
        #[test]
        fn delete_deposit_state_roundtrip(
            deposit_idx in any::<DepositIdx>(),
            last_block_height in any::<u64>(),
            outpoint_txid in any::<[u8; 32]>(),
            outpoint_vout in any::<u32>(),
            operator_table in arb_operator_table(),
        ) {
            let deposit_sm = DepositSM {
                context: DepositSMCtx {
                    deposit_idx,
                    deposit_outpoint: OutPoint {
                        txid: Txid::from_slice(&outpoint_txid).unwrap(),
                        vout: outpoint_vout,
                    },
                    operator_table,
                },
                state: DepositState::Deposited { last_block_height },
            };

            block_on(async {
                let client = get_client();

                client
                    .set_deposit_state(deposit_idx, deposit_sm)
                    .await
                    .unwrap();

                client.delete_deposit_state(deposit_idx).await.unwrap();

                let retrieved = client.get_deposit_state(deposit_idx).await.unwrap();
                prop_assert_eq!(None, retrieved);

                Ok(())
            })?;
        }

    }
}
