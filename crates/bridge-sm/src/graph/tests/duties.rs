//! Unit tests for the GraphDuty safe-harbour suppression taxonomy.
#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash, sha256};
    use strata_bridge_test_utils::{bitcoin::generate_txid, prelude::generate_signature};
    use strata_bridge_tx_graph::{
        game_graph::GameConnectors,
        transactions::prelude::{
            CounterproofNackData, CounterproofNackTx, UnstakingBurnData, UnstakingBurnTx,
        },
    };

    use crate::graph::{
        duties::{GraphDuty, NagDuty},
        tests::{
            INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_NONPOV_IDX, TEST_POV_IDX, TestGraphTxKind,
            dummy_proof_receipt, test_completed_signatures, test_deposit_outpoint, test_graph_data,
            test_graph_sm_cfg, test_graph_sm_ctx, test_operator_table, test_stake_outpoint,
        },
    };

    /// Pins the safe-harbour suppression classification of every graph duty.
    ///
    /// Only the duties advancing the owner's claim towards a payout are suppressible under safe
    /// harbour; the defensive duties (contest, counterproof, slash, unstaking burn) and the graph
    /// setup duties must never be.
    #[test]
    fn test_should_suppress_under_safe_harbour_per_graph_duty() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let (deposit_params, game_graph) = test_graph_data(&cfg);
        let setup_params = ctx.generate_setup_params(&cfg, &deposit_params);
        let connectors = GameConnectors::new(
            deposit_params.game_index,
            &cfg.game_graph_params,
            &setup_params,
        );
        let graph_idx = ctx.graph_idx();
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);

        let cases = vec![
            (
                GraphDuty::GenerateGraphData {
                    graph_idx,
                    deposit_outpoint: test_deposit_outpoint(),
                    stake_outpoint: test_stake_outpoint(),
                    unstaking_image: sha256::Hash::hash(&[0u8; 32]),
                    operator_table: operator_table.clone(),
                },
                false,
            ),
            (
                GraphDuty::VerifyAdaptors {
                    graph_idx,
                    watchtower_idx: TEST_NONPOV_IDX,
                    sighashes: vec![],
                    adaptor_pubkey: strata_bridge_test_utils::bitcoin::generate_xonly_pubkey(),
                    fault_pubkey: strata_bridge_test_utils::bitcoin::generate_xonly_pubkey(),
                },
                false,
            ),
            (
                GraphDuty::PublishGraphNonces {
                    graph_idx,
                    graph_inpoints: vec![],
                    graph_tweaks: vec![],
                    sighashes: vec![],
                    ordered_pubkeys: vec![],
                },
                false,
            ),
            (
                GraphDuty::PublishGraphPartials {
                    graph_idx,
                    agg_nonces: vec![],
                    sighashes: vec![],
                    graph_inpoints: vec![],
                    graph_tweaks: vec![],
                    claim_txid: generate_txid(),
                    stake_outpoint: test_stake_outpoint(),
                    ordered_pubkeys: vec![],
                },
                false,
            ),
            (
                GraphDuty::PublishClaim {
                    claim_tx: game_graph.claim,
                },
                true,
            ),
            (
                GraphDuty::PublishUncontestedPayout {
                    signed_uncontested_payout_tx: TestGraphTxKind::UncontestedPayout.into(),
                },
                true,
            ),
            (
                GraphDuty::PublishUnstakingBurn {
                    graph_idx,
                    unstaking_burn_tx: UnstakingBurnTx::new(
                        UnstakingBurnData {
                            claim_txid: generate_txid(),
                        },
                        connectors.claim_payout,
                    ),
                    unstaking_preimage: [0u8; 32],
                },
                false,
            ),
            (
                GraphDuty::PublishContest {
                    contest_tx: game_graph.contest,
                    n_of_n_signature: generate_signature(),
                    watchtower_index: 0,
                },
                false,
            ),
            (
                GraphDuty::GenerateAndPublishBridgeProof {
                    graph_idx,
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    contest_txid: generate_txid(),
                    game_index: deposit_params.game_index,
                    contest_proof_connector: connectors.contest_proof,
                    operator_pubkey: ctx.owner_btc_x_only_key(),
                },
                true,
            ),
            (
                GraphDuty::PublishBridgeProofTimeout {
                    signed_timeout_tx: TestGraphTxKind::BridgeProofTimeout.into(),
                    cpfp_anchor: None,
                },
                false,
            ),
            (
                GraphDuty::PotentialCounterProof {
                    graph_idx,
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    game_index: deposit_params.game_index,
                    counterproof_tx: game_graph.counterproofs[0].counterproof.clone(),
                    n_of_n_signature: generate_signature(),
                    proof: dummy_proof_receipt(),
                    bridge_proof_tx: TestGraphTxKind::Claim.into(),
                    operator_table: operator_table.clone(),
                },
                false,
            ),
            (
                GraphDuty::PublishCounterProofAck {
                    signed_counter_proof_ack_tx: TestGraphTxKind::CounterproofAck.into(),
                    anchor_key: strata_bridge_test_utils::bitcoin::generate_xonly_pubkey(),
                },
                false,
            ),
            (
                GraphDuty::PublishCounterProofNack {
                    deposit_idx: ctx.deposit_idx(),
                    counterprover_idx: TEST_NONPOV_IDX,
                    completed_signatures: test_completed_signatures(),
                    counterproof_nack_tx: CounterproofNackTx::new(
                        CounterproofNackData {
                            counterproof_txid: generate_txid(),
                        },
                        connectors.counterproof[0],
                    ),
                },
                false,
            ),
            (
                GraphDuty::PublishSlash {
                    signed_slash_tx: TestGraphTxKind::Slash.into(),
                },
                false,
            ),
            (
                GraphDuty::PublishContestedPayout {
                    signed_contested_payout_tx: TestGraphTxKind::ContestedPayout.into(),
                },
                true,
            ),
        ];

        for (duty, expected) in cases {
            assert_eq!(
                duty.should_suppress_under_safe_harbour(),
                expected,
                "unexpected safe-harbour suppression for {duty}"
            );
        }
    }

    /// Graph nags solicit graph-setup progress, never withdrawal progress.
    #[test]
    fn test_graph_nags_are_never_suppressed() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let operator_pubkey = operator_table
            .idx_to_p2p_key(&TEST_NONPOV_IDX)
            .expect("operator must be in the table")
            .clone();
        let graph_idx = test_graph_sm_ctx().graph_idx();

        let nags = [
            NagDuty::NagGraphData {
                graph_idx,
                operator_idx: TEST_NONPOV_IDX,
                operator_pubkey: operator_pubkey.clone(),
            },
            NagDuty::NagGraphNonces {
                graph_idx,
                operator_idx: TEST_NONPOV_IDX,
                operator_pubkey: operator_pubkey.clone(),
            },
            NagDuty::NagGraphPartials {
                graph_idx,
                operator_idx: TEST_NONPOV_IDX,
                operator_pubkey,
            },
        ];

        for nag in nags {
            let duty = GraphDuty::Nag { duty: nag };
            assert!(
                !duty.should_suppress_under_safe_harbour(),
                "graph nag must never be suppressed: {duty}"
            );
        }
    }
}
