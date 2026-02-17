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

    async fn delete_deposit(&self, deposit_idx: DepositIdx) -> Result<(), Self::Error> {
        self.delete_deposit_cascade(deposit_idx).await
    }

    async fn delete_operator(&self, operator_idx: OperatorIdx) -> Result<(), Self::Error> {
        self.delete_operator_cascade(operator_idx).await
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
    use strata_bridge_primitives::{
        operator_table::{OperatorTable, prop_test_generators::arb_operator_table},
        types::{DepositIdx, OperatorIdx},
    };
    use strata_bridge_sm::{
        deposit::{context::DepositSMCtx, state::DepositState},
        graph::{context::GraphSMCtx, state::GraphState},
    };
    use strata_bridge_test_utils::arbitrary_generator::{arb_outpoint, arb_outpoints, arb_txid};

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

    /// Builds a [`DepositSM`] from the given components.
    fn make_deposit_sm(
        deposit_idx: DepositIdx,
        outpoint: OutPoint,
        operator_table: OperatorTable,
        state: DepositState,
    ) -> DepositSM {
        DepositSM {
            context: DepositSMCtx {
                deposit_idx,
                deposit_outpoint: outpoint,
                operator_table,
            },
            state,
        }
    }

    /// Builds a [`GraphSM`] from the given components.
    ///
    /// Derives `stake_outpoint` (vout + 1) and `unstaking_image` (from outpoint txid bytes)
    /// automatically.
    fn make_graph_sm(
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        outpoint: OutPoint,
        operator_table: OperatorTable,
        state: GraphState,
    ) -> GraphSM {
        GraphSM {
            context: GraphSMCtx {
                graph_idx: GraphIdx {
                    deposit: deposit_idx,
                    operator: operator_idx,
                },
                deposit_outpoint: outpoint,
                stake_outpoint: OutPoint {
                    txid: outpoint.txid,
                    vout: outpoint.vout + 1,
                },
                unstaking_image: sha256::Hash::from_slice(outpoint.txid.as_ref()).unwrap(),
                operator_table,
            },
            state,
        }
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
            outpoint in arb_outpoint(),
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

            let deposit_sm = make_deposit_sm(deposit_idx, outpoint, operator_table, state);

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
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            prop_assume!(deposit_idx_a != deposit_idx_b);

            let state = DepositState::Deposited { last_block_height };
            let sm_a = make_deposit_sm(deposit_idx_a, outpoint, operator_table.clone(), state.clone());
            let sm_b = make_deposit_sm(deposit_idx_b, outpoint, operator_table, state);

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
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            let deposit_sm = make_deposit_sm(
                deposit_idx,
                outpoint,
                operator_table,
                DepositState::Deposited { last_block_height },
            );

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
            txid in arb_txid(),
            variant_selector in 0u8..4,
            operator_table in arb_operator_table(),
        ) {
            // Only includes simple variants for testing, as the more complex ones would require constructing valid GraphSMs.
            // TODO: (@Rajil1213) implement Arbitrary for GraphSM to allow testing of all variants.
            let state = match variant_selector {
                0 => GraphState::Created { last_block_height: block_height },
                1 => GraphState::Withdrawn { payout_txid: txid },
                2 => GraphState::Aborted { payout_connector_spend_txid: txid, reason: "test".to_string() },
                _ => GraphState::AllNackd { last_block_height: block_height, contest_block_height: block_height, expected_payout_txid: txid, possible_slash_txid: txid },
            };

            let outpoint = OutPoint { txid, vout: 0 };
            let graph_sm = make_graph_sm(deposit_idx, operator_idx, outpoint, operator_table, state);

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
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            prop_assume!(operator_a != operator_b);

            let state = GraphState::Created { last_block_height };
            let gs_a = make_graph_sm(deposit_idx, operator_a, outpoint, operator_table.clone(), state.clone());
            let gs_b = make_graph_sm(deposit_idx, operator_b, outpoint, operator_table, state);

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
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            let graph_sm = make_graph_sm(
                deposit_idx,
                operator_idx,
                outpoint,
                operator_table,
                GraphState::Created { last_block_height },
            );

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

        /// Property: cascade delete removes deposit state and all graph states for
        /// that deposit, but leaves graph states for other deposits untouched.
        #[test]
        fn delete_deposit_cascade_test(
            deposit_idx in any::<DepositIdx>(),
            // Use a different deposit_idx for the "survivor" entry.
            survivor_deposit_idx in any::<DepositIdx>(),
            operator_a in any::<OperatorIdx>(),
            operator_b in any::<OperatorIdx>(),
            last_block_height in any::<u64>(),
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            // Ensure the two deposit indices differ.
            prop_assume!(deposit_idx != survivor_deposit_idx);

            let state = DepositState::Deposited { last_block_height };
            let deposit_sm = make_deposit_sm(deposit_idx, outpoint, operator_table.clone(), state);

            let graph_state = GraphState::Created { last_block_height };
            let graph_sm_a = make_graph_sm(deposit_idx, operator_a, outpoint, operator_table, graph_state);

            let mut graph_sm_b = graph_sm_a.clone();
            graph_sm_b.context.graph_idx.operator = operator_b;

            let mut survivor_state = graph_sm_a.clone();
            survivor_state.context.graph_idx.deposit = survivor_deposit_idx;

            block_on(async {
                let client = get_client();

                // Set deposit state + two graph states for the target deposit.
                client
                    .set_deposit_state(deposit_idx, deposit_sm)
                    .await
                    .unwrap();
                client
                    .set_graph_state(deposit_idx, operator_a, graph_sm_a)
                    .await
                    .unwrap();
                client
                    .set_graph_state(deposit_idx, operator_b, graph_sm_b)
                    .await
                    .unwrap();

                // Set a graph state for a different deposit (the "survivor").
                client
                    .set_graph_state(survivor_deposit_idx, operator_a, survivor_state.clone())
                    .await
                    .unwrap();

                // Cascade delete the target deposit.
                client.delete_deposit(deposit_idx).await.unwrap();

                // All target data should be gone.
                let dep = client.get_deposit_state(deposit_idx).await.unwrap();
                prop_assert_eq!(None, dep);

                let gs_a = client
                    .get_graph_state(deposit_idx, operator_a)
                    .await
                    .unwrap();
                prop_assert_eq!(None, gs_a);

                let gs_b = client
                    .get_graph_state(deposit_idx, operator_b)
                    .await
                    .unwrap();
                prop_assert_eq!(None, gs_b);

                // Survivor should still be present.
                let survivor = client
                    .get_graph_state(survivor_deposit_idx, operator_a)
                    .await
                    .unwrap();
                prop_assert_eq!(Some(survivor_state), survivor);

                Ok(())
            })?;
        }

        /// Property: operator cascade delete removes all graph states for a given
        /// operator across multiple deposits, but leaves other operators' data.
        #[test]
        fn delete_operator_cascade_test(
            deposit_a in any::<DepositIdx>(),
            deposit_b in any::<DepositIdx>(),
            target_op in any::<OperatorIdx>(),
            survivor_op in any::<OperatorIdx>(),
            last_block_height in any::<u64>(),
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            prop_assume!(target_op != survivor_op);

            let state = GraphState::Created { last_block_height };
            let graph_sm_a = make_graph_sm(deposit_a, target_op, outpoint, operator_table, state);

            let mut graph_sm_b = graph_sm_a.clone();
            graph_sm_b.context.graph_idx.deposit = deposit_b;

            let mut survivor_state = graph_sm_a.clone();
            survivor_state.context.graph_idx.operator = survivor_op;

            block_on(async {
                let client = get_client();

                // Set graph states for the target operator under two deposits.
                client
                    .set_graph_state(deposit_a, target_op, graph_sm_a)
                    .await
                    .unwrap();
                client
                    .set_graph_state(deposit_b, target_op, graph_sm_b)
                    .await
                    .unwrap();

                // Set a graph state for a different operator (the "survivor").
                client
                    .set_graph_state(deposit_a, survivor_op, survivor_state.clone())
                    .await
                    .unwrap();

                // Cascade delete the target operator.
                client.delete_operator(target_op).await.unwrap();

                // All target operator data should be gone.
                let gs_a = client
                    .get_graph_state(deposit_a, target_op)
                    .await
                    .unwrap();
                prop_assert_eq!(None, gs_a);

                let gs_b = client
                    .get_graph_state(deposit_b, target_op)
                    .await
                    .unwrap();
                prop_assert_eq!(None, gs_b);

                // Survivor operator's data should still be present.
                let survivor = client
                    .get_graph_state(deposit_a, survivor_op)
                    .await
                    .unwrap();
                prop_assert_eq!(Some(survivor_state), survivor);

                Ok(())
            })?;
        }

        /// Verify that `create_transaction` + `basic_set_in` can batch
        /// multiple writes into a single atomic transaction.
        #[test]
        fn transaction_batch_persist_test(
            deposit_idx in any::<DepositIdx>(),
            operator_idx in any::<OperatorIdx>(),
            last_block_height in any::<u64>(),
            outpoint in arb_outpoint(),
            operator_table in arb_operator_table(),
        ) {
            let deposit_sm = make_deposit_sm(
                deposit_idx,
                outpoint,
                operator_table.clone(),
                DepositState::Deposited { last_block_height },
            );
            let graph_sm = make_graph_sm(
                deposit_idx,
                operator_idx,
                outpoint,
                operator_table,
                GraphState::Created { last_block_height },
            );

            block_on(async {
                let client = get_client();

                // Write both a deposit state and a graph state in one transaction.
                let trx = client.create_transaction().unwrap();
                client
                    .basic_set_in::<DepositStateRowSpec>(
                        &trx,
                        DepositStateKey { deposit_idx },
                        deposit_sm.clone(),
                    )
                    .unwrap();
                client
                    .basic_set_in::<GraphStateRowSpec>(
                        &trx,
                        GraphStateKey {
                            deposit_idx,
                            operator_idx,
                        },
                        graph_sm.clone(),
                    )
                    .unwrap();
                trx.commit().await.unwrap();

                // Both should be readable.
                let retrieved_sm = client
                    .get_deposit_state(deposit_idx)
                    .await
                    .unwrap();
                prop_assert_eq!(Some(deposit_sm), retrieved_sm);

                let retrieved_gs = client
                    .get_graph_state(deposit_idx, operator_idx)
                    .await
                    .unwrap();
                prop_assert_eq!(Some(graph_sm), retrieved_gs);

                Ok(())
            })?;
        }
    }
}
