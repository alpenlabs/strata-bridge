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
            funds::{FundsKey, FundsRowSpec, FundsValue},
            graphs::{GraphStateKey, GraphStateRowSpec},
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

    // ── Graph States ─────────────────────────────────────────────────

    async fn get_graph_state(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
    ) -> Result<Option<GraphSM>, Self::Error> {
        self.basic_get::<GraphStateRowSpec>(GraphStateKey {
            deposit_idx,
            operator_idx,
        })
        .await
    }

    async fn set_graph_state(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        state: GraphSM,
    ) -> Result<(), Self::Error> {
        self.basic_set::<GraphStateRowSpec>(
            GraphStateKey {
                deposit_idx,
                operator_idx,
            },
            state,
        )
        .await
    }

    async fn get_all_graph_states(&self) -> Result<Vec<(GraphIdx, GraphSM)>, Self::Error> {
        let pairs = self
            .basic_get_all::<GraphStateRowSpec>(|dirs| &dirs.graphs)
            .await?;

        Ok(pairs
            .into_iter()
            .map(|(k, v)| {
                (
                    GraphIdx {
                        deposit: k.deposit_idx,
                        operator: k.operator_idx,
                    },
                    v,
                )
            })
            .collect())
    }

    async fn delete_graph_state(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
    ) -> Result<(), Self::Error> {
        self.basic_delete::<GraphStateRowSpec>(GraphStateKey {
            deposit_idx,
            operator_idx,
        })
        .await
    }

    // ── Funds ─────────────────────────────────────────────────────────

    async fn get_funds(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        purpose: FundingPurpose,
    ) -> Result<Option<Vec<OutPoint>>, Self::Error> {
        let result = self
            .basic_get::<FundsRowSpec>(FundsKey {
                deposit_idx,
                operator_idx,
                purpose,
            })
            .await?;
        Ok(result.map(|v| v.0))
    }

    async fn set_funds(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        purpose: FundingPurpose,
        outpoints: Vec<OutPoint>,
    ) -> Result<(), Self::Error> {
        self.basic_set::<FundsRowSpec>(
            FundsKey {
                deposit_idx,
                operator_idx,
                purpose,
            },
            FundsValue(outpoints),
        )
        .await
    }

    async fn get_all_funds(&self) -> Result<Vec<OutPoint>, Self::Error> {
        let pairs = self
            .basic_get_all::<FundsRowSpec>(|dirs| &dirs.funds)
            .await?;
        Ok(pairs.into_iter().flat_map(|(_k, v)| v.0).collect())
    }

    async fn delete_funds(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        purpose: FundingPurpose,
    ) -> Result<(), Self::Error> {
        self.basic_delete::<FundsRowSpec>(FundsKey {
            deposit_idx,
            operator_idx,
            purpose,
        })
        .await
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

    use bitcoin::hashes::{Hash, sha256};
    use proptest::prelude::*;
    use secp256k1::{
        Keypair, Message, Secp256k1,
        rand::{random, thread_rng},
    };
    use strata_bridge_primitives::operator_table::prop_test_generators::arb_operator_table;
    use strata_bridge_sm::{
        deposit::{context::DepositSMCtx, state::DepositState},
        graph::{context::GraphSMCtx, state::GraphState},
    };
    use strata_bridge_test_utils::arbitrary_generator::arb_outpoints;

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

        /// Property: any graph state stored can be retrieved with the same key.
        #[test]
        fn graph_state_roundtrip(
            deposit_idx in any::<DepositIdx>(),
            operator_idx in any::<OperatorIdx>(),
            block_height in any::<u64>(),
            txid in any::<[u8; 32]>(),
            variant_selector in 0u8..4,
            operator_table in arb_operator_table(),
        ) {
            let test_txid = Txid::from_slice(&txid).unwrap();

            // Only includes simple variants for testing, as the more complex ones would require constructing valid GraphSMs.
            // TODO: (@Rajil1213) implement Arbitrary for GraphSM to allow testing of all variants.
            let state = match variant_selector {
                0 => GraphState::Created { last_block_height: block_height },
                1 => GraphState::Withdrawn { payout_txid: test_txid },
                2 => GraphState::Aborted { payout_connector_spend_txid: test_txid, reason: "test".to_string() },
                _ => GraphState::AllNackd { last_block_height: block_height, contest_block_height: block_height, expected_payout_txid: test_txid, possible_slash_txid: test_txid },
            };

            let ctx = GraphSMCtx {
                graph_idx: GraphIdx {
                    deposit: deposit_idx,
                    operator: operator_idx,
                },
                deposit_outpoint: OutPoint {
                    txid: test_txid,
                    vout: 0,
                },
                stake_outpoint: OutPoint {
                    txid: test_txid,
                    vout: 1,
                },
                unstaking_image: sha256::Hash::from_slice(&txid).unwrap(),
                operator_table,
            };

            let graph_sm  = GraphSM {
                context: ctx,
                state,
            };

            block_on(async {
                let client = get_client();

                client
                    .set_graph_state(deposit_idx, operator_idx, graph_sm.clone())
                    .await
                    .unwrap();

                let retrieved = client
                    .get_graph_state(deposit_idx, operator_idx)
                    .await
                    .unwrap();

                prop_assert_eq!(Some(graph_sm), retrieved);

                Ok(())
            })?;
        }

        /// Property: `get_all_graph_states` returns all previously stored graph states.
        #[test]
        fn get_all_graph_states_test(
            deposit_idx in any::<DepositIdx>(),
            operator_a in any::<OperatorIdx>(),
            operator_b in any::<OperatorIdx>(),
            last_block_height in any::<u64>(),
            txid in any::<[u8; 32]>(),
            operator_table in arb_operator_table(),
        ) {
            prop_assume!(operator_a != operator_b);

            let make_gs = |op| GraphSM {
                context: GraphSMCtx {
                    graph_idx: GraphIdx { deposit: deposit_idx, operator: op },
                    deposit_outpoint: OutPoint {
                        txid: Txid::from_slice(&txid).unwrap(),
                        vout: 0,
                    },
                    stake_outpoint: OutPoint {
                        txid: Txid::from_slice(&txid).unwrap(),
                        vout: 1,
                    },
                    unstaking_image: sha256::Hash::from_slice(&txid).unwrap(),
                    operator_table: operator_table.clone(),
                },
                state: GraphState::Created { last_block_height },
            };

            let gs_a = make_gs(operator_a);
            let gs_b = make_gs(operator_b);

            block_on(async {
                let client = get_client();

                client.set_graph_state(deposit_idx, operator_a, gs_a.clone()).await.unwrap();
                client.set_graph_state(deposit_idx, operator_b, gs_b.clone()).await.unwrap();

                let all = client.get_all_graph_states().await.unwrap();

                let found_a = all.iter().any(|(idx, gs)| idx.deposit == deposit_idx && idx.operator == operator_a && *gs == gs_a);
                let found_b = all.iter().any(|(idx, gs)| idx.deposit == deposit_idx && idx.operator == operator_b && *gs == gs_b);

                prop_assert!(found_a, "graph state A not found in get_all_graph_states");
                prop_assert!(found_b, "graph state B not found in get_all_graph_states");

                Ok(())
            })?;
        }


        /// Property: deleting a graph state makes it unreadable.
        #[test]
        fn delete_graph_state_roundtrip(
            deposit_idx in any::<DepositIdx>(),
            operator_idx in any::<OperatorIdx>(),
            last_block_height in any::<u64>(),
            txid in any::<[u8; 32]>(),
            operator_table in arb_operator_table()
        ) {
            let graph_sm = GraphSM {
                context: GraphSMCtx {
                    graph_idx: GraphIdx {
                        deposit: deposit_idx,
                        operator: operator_idx,
                    },
                    deposit_outpoint: OutPoint {
                        txid: Txid::from_slice(&txid).unwrap(),
                        vout: 0,
                    },
                    stake_outpoint: OutPoint {
                        txid: Txid::from_slice(&txid).unwrap(),
                        vout: 1,
                    },
                    unstaking_image: sha256::Hash::from_slice(&txid).unwrap(),
                    operator_table,
                },
                state: GraphState::Created { last_block_height },
            };

            block_on(async {
                let client = get_client();

                client
                    .set_graph_state(deposit_idx, operator_idx, graph_sm)
                    .await
                    .unwrap();

                client
                    .delete_graph_state(deposit_idx, operator_idx)
                    .await
                    .unwrap();

                let retrieved = client
                    .get_graph_state(deposit_idx, operator_idx)
                    .await
                    .unwrap();
                prop_assert_eq!(None, retrieved);

                Ok(())
            })?;
        }

        /// Property: any funds stored can be retrieved with the same key.
        #[test]
        fn funds_roundtrip(
            deposit_idx in any::<DepositIdx>(),
            operator_idx in any::<OperatorIdx>(),
            purpose in prop_oneof![
                Just(FundingPurpose::WithdrawalFulfillment),
                Just(FundingPurpose::Claim),
            ],
            outpoints in arb_outpoints(),
        ) {
            block_on(async {
                let client = get_client();

                client
                    .set_funds(deposit_idx, operator_idx, purpose, outpoints.clone())
                    .await
                    .unwrap();

                let retrieved = client
                    .get_funds(deposit_idx, operator_idx, purpose)
                    .await
                    .unwrap();

                prop_assert_eq!(Some(outpoints), retrieved);

                Ok(())
            })?;
        }

        /// Property: `get_all_funds` returns all previously stored fund entries.
        #[test]
        fn get_all_funds_test(
            deposit_idx in any::<DepositIdx>(),
            operator_idx in any::<OperatorIdx>(),
            outpoints_wf in arb_outpoints(),
            outpoints_claim in arb_outpoints(),
        ) {
            block_on(async {
                let client = get_client();

                client
                    .set_funds(deposit_idx, operator_idx, FundingPurpose::WithdrawalFulfillment, outpoints_wf.clone())
                    .await
                    .unwrap();
                client
                    .set_funds(deposit_idx, operator_idx, FundingPurpose::Claim, outpoints_claim.clone())
                    .await
                    .unwrap();

                let all = client.get_all_funds().await.unwrap();

                // Check that all outpoints from both entries are present in the combined list.
                for op in outpoints_wf {
                    prop_assert!(all.contains(&op), "get_all_funds missing WithdrawalFulfillment outpoint: {op}");
                }

                for op in outpoints_claim {
                    prop_assert!(all.contains(&op), "get_all_funds missing Claim outpoint: {op}");
                }

                Ok(())
            })?;
        }

        /// Property: deleting funds makes them unreadable.
        #[test]
        fn delete_funds_roundtrip(
            deposit_idx in any::<DepositIdx>(),
            operator_idx in any::<OperatorIdx>(),
            purpose in prop_oneof![
                Just(FundingPurpose::WithdrawalFulfillment),
                Just(FundingPurpose::Claim),
            ],
            outpoints in arb_outpoints(),
        ) {
            block_on(async {
                let client = get_client();

                client
                    .set_funds(deposit_idx, operator_idx, purpose, outpoints)
                    .await
                    .unwrap();

                client
                    .delete_funds(deposit_idx, operator_idx, purpose)
                    .await
                    .unwrap();

                let retrieved = client
                    .get_funds(deposit_idx, operator_idx, purpose)
                    .await
                    .unwrap();
                prop_assert_eq!(None, retrieved);

                Ok(())
            })?;
        }
    }
}
