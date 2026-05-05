//! Unit tests for [`StakeSM::process_nag_received`].

use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_primitives::types::GraphIdx;

use super::*;
use crate::stake::{
    duties::StakeDuty,
    errors::SSMError,
    events::{NagReceivedEvent, StakeEvent},
    state::StakeState,
};

fn create_nag_event(payload: NagRequestPayload) -> NagReceivedEvent {
    NagReceivedEvent {
        payload,
        sender_operator_idx: TEST_NONPOV_IDX,
    }
}

fn expected_publish_unstaking_nonces_duty() -> StakeDuty {
    let graph_inpoints = TEST_GRAPH.musig_inpoints().boxed();
    let graph_tweaks = TEST_GRAPH
        .musig_signing_info()
        .map(|info| info.tweak)
        .boxed();
    let ordered_pubkeys = TEST_CTX
        .operator_table()
        .btc_keys()
        .into_iter()
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    StakeDuty::PublishUnstakingNonces {
        operator_idx: TEST_CTX.operator_idx(),
        graph_inpoints,
        graph_tweaks,
        ordered_pubkeys,
    }
}

fn expected_publish_unstaking_partials_duty() -> StakeDuty {
    let graph_inpoints = TEST_GRAPH.musig_inpoints().boxed();
    let (graph_tweaks, sighashes) = TEST_GRAPH
        .musig_signing_info()
        .map(|info| (info.tweak, info.sighash))
        .unzip();
    let ordered_pubkeys = TEST_CTX
        .operator_table()
        .btc_keys()
        .into_iter()
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    StakeDuty::PublishUnstakingPartials {
        operator_idx: TEST_CTX.operator_idx(),
        graph_inpoints,
        graph_tweaks: graph_tweaks.boxed(),
        sighashes: sighashes.boxed(),
        ordered_pubkeys,
        agg_nonces: TEST_AGG_NONCES.clone().boxed(),
    }
}

#[test]
fn accept_nag_received_stake_data() {
    let accepting_states = [
        StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: Default::default(),
        },
        StakeState::UnstakingNoncesCollected {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone().boxed(),
            partial_signatures: Default::default(),
        },
        StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: (*TEST_FINAL_SIGS).into(),
        },
    ];

    for from_state in accepting_states {
        test_pov_owned_handler_output(StakeHandlerOutput {
            state: from_state,
            event: StakeEvent::NagReceived(create_nag_event(NagRequestPayload::UnstakingData {
                operator_idx: TEST_CTX.operator_idx(),
            })),
            expected_duties: vec![StakeDuty::PublishStakeData {
                operator_idx: TEST_CTX.operator_idx(),
            }],
        });
    }
}

#[test]
fn reject_nag_received_stake_data() {
    let rejecting_states = [
        StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::PreimageRevealed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ];

    for from_state in rejecting_states {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: StakeEvent::NagReceived(create_nag_event(NagRequestPayload::UnstakingData {
                operator_idx: TEST_CTX.operator_idx(),
            })),
            expected_error: |e| {
                matches!(
                    e,
                    SSMError::Rejected { reason, .. }
                        if reason.contains(
                            "expected state(s): Created | StakeGraphGenerated | UnstakingNoncesCollected | UnstakingSigned"
                        )
                )
            },
        });
    }
}

#[test]
fn accept_nag_received_unstaking_nonces() {
    let accepting_states = [
        StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: Default::default(),
        },
        StakeState::UnstakingNoncesCollected {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone().boxed(),
            partial_signatures: Default::default(),
        },
        StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: (*TEST_FINAL_SIGS).into(),
        },
    ];

    for from_state in accepting_states {
        test_pov_owned_handler_output(StakeHandlerOutput {
            state: from_state,
            event: StakeEvent::NagReceived(create_nag_event(NagRequestPayload::UnstakingNonces {
                operator_idx: TEST_CTX.operator_idx(),
            })),
            expected_duties: vec![expected_publish_unstaking_nonces_duty()],
        });
    }
}

#[test]
fn reject_nag_received_unstaking_nonces() {
    let rejecting_states = [
        StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::PreimageRevealed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ];

    for from_state in rejecting_states {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: StakeEvent::NagReceived(create_nag_event(NagRequestPayload::UnstakingNonces {
                operator_idx: TEST_CTX.operator_idx(),
            })),
            expected_error: |e| {
                matches!(
                    e,
                    SSMError::Rejected { reason, .. }
                        if reason.contains(
                            "expected state(s): StakeGraphGenerated | UnstakingNoncesCollected | UnstakingSigned"
                        )
                )
            },
        });
    }
}

#[test]
fn accept_nag_received_unstaking_partials() {
    let accepting_states = [StakeState::UnstakingNoncesCollected {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        summary: *TEST_GRAPH_SUMMARY,
        pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        agg_nonces: TEST_AGG_NONCES.clone().boxed(),
        partial_signatures: Default::default(),
    }];

    for from_state in accepting_states {
        test_pov_owned_handler_output(StakeHandlerOutput {
            state: from_state,
            event: StakeEvent::NagReceived(create_nag_event(
                NagRequestPayload::UnstakingPartials {
                    operator_idx: TEST_CTX.operator_idx(),
                },
            )),
            expected_duties: vec![expected_publish_unstaking_partials_duty()],
        });
    }
}

#[test]
fn reject_nag_received_unstaking_partials() {
    let rejecting_states = [
        StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: Default::default(),
        },
        StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: (*TEST_FINAL_SIGS).into(),
        },
        StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::PreimageRevealed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ];

    for from_state in rejecting_states {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: StakeEvent::NagReceived(create_nag_event(
                NagRequestPayload::UnstakingPartials {
                    operator_idx: TEST_CTX.operator_idx(),
                },
            )),
            expected_error: |e| {
                matches!(
                    e,
                    SSMError::Rejected { reason, .. }
                        if reason.contains("expected state(s): UnstakingNoncesCollected")
                )
            },
        });
    }
}

#[test]
fn reject_nag_received_deposit_domain() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        event: StakeEvent::NagReceived(create_nag_event(NagRequestPayload::DepositNonce {
            deposit_idx: 0,
        })),
        expected_error: |e| {
            matches!(
                e,
                SSMError::Rejected { reason, .. }
                    if reason.contains("Deposit-domain nag is not applicable to StakeSM")
            )
        },
    });
}

#[test]
fn reject_nag_received_graph_domain() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        event: StakeEvent::NagReceived(create_nag_event(NagRequestPayload::GraphData {
            graph_idx: GraphIdx {
                deposit: 0,
                operator: 0,
            },
        })),
        expected_error: |e| {
            matches!(
                e,
                SSMError::Rejected { reason, .. }
                    if reason.contains("Graph-domain nag is not applicable to StakeSM")
            )
        },
    });
}
