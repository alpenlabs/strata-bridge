//! Tests for resolving the `MultiAnchor` CPFP leaf a given operator may satisfy.

use bitcoin::{opcodes, script, secp256k1::SECP256K1};
use strata_bridge_connectors::{Connector, ParentTx, prelude::MultiAnchor};
use strata_bridge_primitives::types::GraphIdx;

use crate::graph::{
    context::GraphSMCtx,
    machine::generate_game_graph,
    tests::{
        N_TEST_OPERATORS, TEST_DEPOSIT_IDX, TEST_NONPOV_IDX, TEST_POV_IDX, test_deposit_params,
        test_graph_sm_cfg, test_graph_sm_ctx, test_operator_table,
    },
    watchtower::multi_anchor_spend_for_pov,
};

/// A context for the same graph, but viewed by an operator that does *not* own it.
fn watchtower_pov_ctx() -> GraphSMCtx {
    GraphSMCtx {
        graph_idx: GraphIdx {
            deposit: TEST_DEPOSIT_IDX,
            operator: TEST_POV_IDX,
        },
        operator_table: test_operator_table(N_TEST_OPERATORS, TEST_NONPOV_IDX),
        ..test_graph_sm_ctx()
    }
}

/// An operator is never a watchtower of its own graph, so it holds no leaf on the anchor and
/// cannot bump these transactions at all. This is the case executor-side inference could not
/// express: the transaction bytes are identical whoever is looking at them.
#[test]
fn graph_owner_has_no_leaf() {
    let cfg = test_graph_sm_cfg();
    let ctx = test_graph_sm_ctx();
    let game_graph = generate_game_graph(&cfg, &ctx, &test_deposit_params());

    for (label, spend) in [
        (
            "contest",
            multi_anchor_spend_for_pov(
                &game_graph.contest,
                ctx.operator_idx(),
                ctx.operator_table().pov_idx(),
            ),
        ),
        (
            "bridge_proof_timeout",
            multi_anchor_spend_for_pov(
                &game_graph.bridge_proof_timeout,
                ctx.operator_idx(),
                ctx.operator_table().pov_idx(),
            ),
        ),
    ] {
        assert!(
            spend.is_none(),
            "{label}: graph owner must not resolve a watchtower leaf"
        );
    }
}

/// A watchtower of the graph resolves the leaf at its own dense slot, and the resolved leaf must
/// be the one the anchor actually commits to at that index — a mismatch would produce a witness
/// that fails script validation at broadcast.
#[test]
fn watchtower_resolves_its_own_leaf() {
    let cfg = test_graph_sm_cfg();
    let owner_ctx = test_graph_sm_ctx();
    let wt_ctx = watchtower_pov_ctx();
    let game_graph = generate_game_graph(&cfg, &owner_ctx, &test_deposit_params());

    let expected_slot =
        crate::graph::watchtower::watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)
            .expect("non-owner maps to a watchtower slot");

    for (label, anchor, spend) in [
        (
            "contest",
            game_graph.contest.cpfp_connector(),
            multi_anchor_spend_for_pov(
                &game_graph.contest,
                wt_ctx.operator_idx(),
                wt_ctx.operator_table().pov_idx(),
            ),
        ),
        (
            "bridge_proof_timeout",
            game_graph.bridge_proof_timeout.cpfp_connector(),
            multi_anchor_spend_for_pov(
                &game_graph.bridge_proof_timeout,
                wt_ctx.operator_idx(),
                wt_ctx.operator_table().pov_idx(),
            ),
        ),
    ] {
        let spend = spend.unwrap_or_else(|| panic!("{label}: watchtower must resolve a leaf"));
        let anchor: &MultiAnchor = anchor;

        // Index agreement is necessary but not sufficient — asserting only that we picked
        // `leaf_scripts()[slot]` would just restate what the function computes. What actually
        // matters is that the leaf we will sign commits to *our own* key: a slot/ordering
        // mismatch would still index in range but hand us another watchtower's leaf, and the
        // signature would fail script validation at broadcast.
        let our_key = wt_ctx.operator_table().pov_btc_key().x_only_public_key().0;
        let expected_leaf = script::Builder::new()
            .push_slice(our_key.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        assert_eq!(
            spend.leaf_script, expected_leaf,
            "{label}: resolved leaf must commit to this operator's own key"
        );
        assert_eq!(
            spend.leaf_script,
            anchor.leaf_scripts()[expected_slot],
            "{label}: and must sit at the slot the state machine computed"
        );

        // The control block must verify against the anchor's own output key, otherwise the
        // witness is rejected at broadcast. This is the assertion that would actually catch a
        // tree/ordering mismatch.
        assert!(
            spend.control_block.verify_taproot_commitment(
                SECP256K1,
                anchor.spend_info().output_key().to_x_only_public_key(),
                &spend.leaf_script,
            ),
            "{label}: control block must verify against the anchor's output key"
        );
    }
}
