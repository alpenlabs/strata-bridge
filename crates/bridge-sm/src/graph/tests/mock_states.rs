//! Reusable mock [`GraphState`] constructors for graph SM tests.

use std::{collections::BTreeMap, num::NonZero, sync::LazyLock};

use musig2::secp256k1::schnorr::Signature;
use strata_bridge_tx_graph2::game_graph::{DepositParams, GameGraphSummary};

use super::{
    CLAIM_BLOCK_HEIGHT, FULFILLMENT_BLOCK_HEIGHT, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,
    TEST_ASSIGNEE, create_nonpov_sm, dummy_proof_receipt, test_deposit_params, test_graph_sm_cfg,
    test_graph_summary, test_recipient_desc, utils::NonceContext,
};
use crate::graph::{machine::generate_game_graph, state::GraphState};

pub(super) static TEST_GRAPH_SUMMARY: LazyLock<GameGraphSummary> =
    LazyLock::new(test_graph_summary);

/// Builds a mock `GraphSigned` state.
pub(super) fn graph_signed_state() -> GraphState {
    GraphState::GraphSigned {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: Default::default(),
    }
}

/// Builds a mock `Assigned` state with the given assignment fields.
pub(super) fn assigned_state(
    assignee: u32,
    deadline: u64,
    recipient_desc: bitcoin_bosd::Descriptor,
) -> GraphState {
    GraphState::Assigned {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: Default::default(),
        assignee,
        deadline,
        recipient_desc,
    }
}

/// Builds a mock `Fulfilled` state with default test values.
pub(super) fn fulfilled_state(fulfillment_txid: bitcoin::Txid) -> GraphState {
    GraphState::Fulfilled {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: test_graph_summary(),
        coop_payout_failed: false,
        signatures: Default::default(),
        fulfillment_txid,
        fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
    }
}

/// Builds a mock `AdaptorsVerified` state with the given deposit params and graph summary.
pub(super) fn adaptors_verified_state(
    deposit_params: DepositParams,
    graph_summary: GameGraphSummary,
) -> GraphState {
    GraphState::AdaptorsVerified {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: deposit_params,
        graph_summary,
        pubnonces: BTreeMap::new(),
    }
}

/// Builds a mock `NoncesCollected` state with the given nonce context, deposit params, and graph
/// summary.
pub(super) fn nonces_collected_state(
    nonce_ctx: &NonceContext,
    deposit_params: DepositParams,
    graph_summary: GameGraphSummary,
) -> GraphState {
    GraphState::NoncesCollected {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: deposit_params,
        graph_summary,
        pubnonces: nonce_ctx.pubnonces.clone(),
        agg_nonces: nonce_ctx.agg_nonces.clone(),
        partial_signatures: BTreeMap::new(),
    }
}

/// Builds a mock `Claimed` state with the given parameters.
pub(super) fn claimed_state(
    last_block_height: u64,
    fulfillment_txid: bitcoin::Txid,
    signatures: Vec<Signature>,
) -> GraphState {
    GraphState::Claimed {
        last_block_height,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures,
        fulfillment_txid: Some(fulfillment_txid),
        fulfillment_block_height: Some(140),
        claim_block_height: CLAIM_BLOCK_HEIGHT,
    }
}

/// Builds a mock `Contested` state with default test values.
pub(super) fn contested_state() -> GraphState {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    GraphState::Contested {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: graph_summary.clone(),
        signatures: Default::default(),
        fulfillment_txid: Some(graph_summary.claim),
        fulfillment_block_height: Some(LATER_BLOCK_HEIGHT),
        contest_block_height: LATER_BLOCK_HEIGHT,
    }
}

/// Builds a mock `BridgeProofPosted` state with default test values.
pub(super) fn bridge_proof_posted_state() -> GraphState {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    GraphState::BridgeProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: graph_summary.clone(),
        signatures: Default::default(),
        contest_block_height: LATER_BLOCK_HEIGHT,
        bridge_proof_txid: graph_summary.bridge_proof_timeout,
        bridge_proof_block_height: LATER_BLOCK_HEIGHT,
        proof: dummy_proof_receipt(),
    }
}

/// Builds a mock `BridgeProofTimedout` state with default test values.
pub(super) fn bridge_proof_timedout_state() -> GraphState {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    GraphState::BridgeProofTimedout {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: graph_summary.clone(),
        signatures: Default::default(),
        contest_block_height: LATER_BLOCK_HEIGHT,
        expected_slash_txid: graph_summary.slash,
        claim_txid: graph_summary.claim,
    }
}

/// Builds a mock `CounterProofPosted` state with default test values.
pub(super) fn counter_proof_posted_state() -> GraphState {
    GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: Default::default(),
        contest_block_height: LATER_BLOCK_HEIGHT,
        counterproofs_and_confs: BTreeMap::new(),
        counterproof_nacks: BTreeMap::new(),
    }
}

/// Builds a mock `AllNackd` state with default test values.
pub(super) fn all_nackd_state() -> GraphState {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    GraphState::AllNackd {
        last_block_height: LATER_BLOCK_HEIGHT,
        contest_block_height: LATER_BLOCK_HEIGHT,
        expected_payout_txid: graph_summary.contested_payout,
        possible_slash_txid: graph_summary.slash,
    }
}

/// Builds a mock `Acked` state with default test values.
pub(super) fn acked_state() -> GraphState {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    GraphState::Acked {
        last_block_height: LATER_BLOCK_HEIGHT,
        contest_block_height: LATER_BLOCK_HEIGHT,
        expected_slash_txid: graph_summary.slash,
        claim_txid: graph_summary.claim,
    }
}

/// States that can detect a malicious claim (pre-signing states with a graph_summary).
pub(super) fn pre_signing_states() -> Vec<GraphState> {
    let summary = TEST_GRAPH_SUMMARY.clone();
    let params = test_deposit_params();

    vec![
        GraphState::GraphGenerated {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: params,
            graph_summary: summary.clone(),
        },
        GraphState::AdaptorsVerified {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: params,
            graph_summary: summary.clone(),
            pubnonces: Default::default(),
        },
        GraphState::NoncesCollected {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: params,
            graph_summary: summary.clone(),
            pubnonces: Default::default(),
            agg_nonces: Default::default(),
            partial_signatures: Default::default(),
        },
        GraphState::GraphSigned {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: params,
            graph_summary: summary,
            signatures: Default::default(),
        },
    ]
}

/// Terminal states (Withdrawn, Slashed, Aborted).
pub(super) fn terminal_states() -> Vec<GraphState> {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    vec![
        GraphState::Withdrawn {
            payout_txid: graph_summary.uncontested_payout,
        },
        GraphState::Slashed {
            slash_txid: graph_summary.slash,
        },
        GraphState::Aborted {
            payout_connector_spend_txid: graph_summary.contested_payout,
            reason: "test".to_string(),
        },
    ]
}

/// States that may observe a claim tx.
pub(super) fn claim_detecting_states() -> Vec<GraphState> {
    let mut states = pre_signing_states();
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    states.push(assigned_state(
        TEST_ASSIGNEE,
        LATER_BLOCK_HEIGHT + 15,
        test_recipient_desc(1),
    ));
    states.push(fulfilled_state(graph_summary.claim));
    states
}

/// States that expect uncontested payout via deposit spend.
pub(super) fn uncontested_payout_detecting_states() -> Vec<GraphState> {
    vec![claimed_state(
        LATER_BLOCK_HEIGHT,
        TEST_GRAPH_SUMMARY.claim,
        Default::default(),
    )]
}

/// States that expect contested payout via deposit spend.
pub(super) fn contested_payout_detecting_states() -> Vec<GraphState> {
    vec![bridge_proof_posted_state(), all_nackd_state()]
}

/// States that detect counterproof txids.
pub(super) fn counterproof_detecting_states() -> Vec<GraphState> {
    vec![contested_state(), bridge_proof_posted_state()]
}

/// States that detect a payout connector spend (via admin or unstaking burn txs).
///
/// These states use `graph_summary.claim` or `claim_txid` to identify the payout
/// connector outpoint.
pub(super) fn payout_connector_spent_states() -> Vec<GraphState> {
    vec![
        claimed_state(
            LATER_BLOCK_HEIGHT,
            TEST_GRAPH_SUMMARY.claim,
            Default::default(),
        ),
        contested_state(),
        bridge_proof_posted_state(),
        bridge_proof_timedout_state(),
        counter_proof_posted_state(),
    ]
}

/// One representative of every state variant.
pub(super) fn all_state_variants() -> Vec<GraphState> {
    let graph_summary = TEST_GRAPH_SUMMARY.clone();
    let mut states = vec![GraphState::Created {
        last_block_height: LATER_BLOCK_HEIGHT,
    }];
    states.extend(pre_signing_states());
    states.push(assigned_state(
        TEST_ASSIGNEE,
        LATER_BLOCK_HEIGHT + 15,
        test_recipient_desc(1),
    ));
    states.push(fulfilled_state(graph_summary.claim));
    states.push(claimed_state(
        LATER_BLOCK_HEIGHT,
        graph_summary.claim,
        Default::default(),
    ));
    states.push(contested_state());
    states.push(bridge_proof_posted_state());
    states.push(bridge_proof_timedout_state());
    states.push(counter_proof_posted_state());
    states.push(all_nackd_state());
    states.push(acked_state());
    states.extend(terminal_states());
    states
}

/// Constructs a valid `GraphGenerated` state directly by generating the graph.
pub(super) fn test_graph_generated_state() -> GraphState {
    let cfg = test_graph_sm_cfg();
    let sm = create_nonpov_sm(GraphState::new(INITIAL_BLOCK_HEIGHT));

    let deposit_params = DepositParams {
        game_index: NonZero::new(1).unwrap(),
        claim_funds: Default::default(),
        deposit_outpoint: sm.context.deposit_outpoint(),
    };
    let graph = generate_game_graph(&cfg, sm.context(), deposit_params);

    GraphState::GraphGenerated {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: deposit_params,
        graph_summary: graph.summarize(),
    }
}
