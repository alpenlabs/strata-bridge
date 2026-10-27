//! Property-based tests for the Graph State Machine.

use proptest::prelude::*;
use strata_bridge_test_utils::prelude::generate_txid;

use super::{get_state, mock_states::TEST_GRAPH_SUMMARY, test_graph_sm_cfg};
use crate::graph::{
    events::{GraphEvent, NagTickEvent, RetryTickEvent},
    state::{AbortReason, GraphState},
};

/// Strategy for generating terminal states, covering every abort reason and an abort before any
/// claim.
fn arb_terminal_state() -> impl Strategy<Value = GraphState> {
    let summary = TEST_GRAPH_SUMMARY.clone();
    let spending_txid = generate_txid();
    let aborted = move |claim_txid, reason| GraphState::Aborted { claim_txid, reason };

    prop_oneof![
        Just(GraphState::Withdrawn {
            claim_txid: summary.claim,
            payout_txid: summary.uncontested_payout,
        }),
        Just(GraphState::Slashed {
            claim_txid: summary.claim,
            slash_txid: summary.slash,
        }),
        Just(aborted(
            Some(summary.claim),
            AbortReason::PayoutConnectorSpent { spending_txid }
        )),
        Just(aborted(
            Some(summary.claim),
            AbortReason::StakeSpent { spending_txid }
        )),
        Just(aborted(
            None,
            AbortReason::DepositRequestTakenBack { spending_txid }
        )),
        Just(aborted(
            Some(summary.claim),
            AbortReason::Both {
                payout_connector_spending_txid: spending_txid,
                stake_spending_txid: generate_txid(),
            }
        )),
    ]
}

/// Strategy for generating tick events.
fn arb_tick_events() -> impl Strategy<Value = GraphEvent> {
    prop_oneof![
        Just(GraphEvent::NagTick(NagTickEvent)),
        Just(GraphEvent::RetryTick(RetryTickEvent)),
    ]
}

mod pov {
    use super::*;
    use crate::{graph::tests::create_sm, prop_terminal_states_ignore_ticks};

    // Property: Terminal states ignore ticks on a graph the POV operator owns
    prop_terminal_states_ignore_ticks!(
        crate::graph::machine::GraphSM,
        create_sm,
        get_state,
        test_graph_sm_cfg(),
        arb_terminal_state(),
        arb_tick_events()
    );
}

mod nonpov {
    use super::*;
    use crate::{graph::tests::create_nonpov_sm, prop_terminal_states_ignore_ticks};

    // Property: Terminal states ignore ticks on a graph another operator owns
    prop_terminal_states_ignore_ticks!(
        crate::graph::machine::GraphSM,
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        arb_terminal_state(),
        arb_tick_events()
    );
}
