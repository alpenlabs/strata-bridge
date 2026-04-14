//! Proptests for the Stake State Machine.

use bitcoin::Transaction;
use proptest::prelude::*;
use strata_bridge_connectors::prelude::UnstakingIntentWitness;

use super::*;
use crate::{
    prop_deterministic, prop_no_silent_acceptance, prop_terminal_states_reject,
    stake::{
        events::{
            NewBlockEvent, PreimageRevealedEvent, StakeConfirmedEvent, StakeDataReceivedEvent,
            StakeEvent, UnstakingConfirmedEvent, UnstakingNoncesReceivedEvent,
            UnstakingPartialsReceivedEvent,
        },
        state::StakeState,
    },
};

// Property: State machines should be deterministic.
prop_deterministic!(
    StakeSM,
    create_state_machine,
    get_state,
    TEST_CFG.clone(),
    any::<StakeState>(),
    any_event()
);

// Property: Events must either transition state or produce error.
prop_no_silent_acceptance!(
    StakeSM,
    create_state_machine,
    get_state,
    TEST_CFG.clone(),
    any::<StakeState>(),
    any_event()
);

// Property: Terminal states should reject all events.
prop_terminal_states_reject!(
    StakeSM,
    create_state_machine,
    TEST_CFG.clone(),
    any_terminal_state(),
    any_event()
);

impl Arbitrary for StakeState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        let last_block_height = 0u64..1_000u64;

        prop_oneof![
            last_block_height
                .clone()
                .prop_map(|last_block_height| StakeState::Created { last_block_height }),
            last_block_height.clone().prop_map(|last_block_height| {
                StakeState::StakeGraphGenerated {
                    last_block_height,
                    stake_data: TEST_STAKE_DATA.clone(),
                    summary: *TEST_GRAPH_SUMMARY,
                    pub_nonces: TEST_PUB_NONCES_MAP.clone(),
                }
            }),
            last_block_height.clone().prop_map(|last_block_height| {
                StakeState::UnstakingNoncesCollected {
                    last_block_height,
                    stake_data: TEST_STAKE_DATA.clone(),
                    summary: *TEST_GRAPH_SUMMARY,
                    pub_nonces: TEST_PUB_NONCES_MAP.clone(),
                    agg_nonces: TEST_AGG_NONCES.clone().boxed(),
                    partial_signatures: TEST_PARTIAL_SIGS_MAP.clone(),
                }
            }),
            last_block_height
                .clone()
                .prop_map(|last_block_height| StakeState::UnstakingSigned {
                    last_block_height,
                    stake_data: TEST_STAKE_DATA.clone(),
                    summary: *TEST_GRAPH_SUMMARY,
                    signatures: Box::new(*TEST_FINAL_SIGS),
                }),
            last_block_height
                .clone()
                .prop_map(|last_block_height| StakeState::Confirmed {
                    last_block_height,
                    stake_data: TEST_STAKE_DATA.clone(),
                    summary: *TEST_GRAPH_SUMMARY,
                    signatures: Box::new(Some(*TEST_FINAL_SIGS)),
                }),
            last_block_height.prop_map(|last_block_height| {
                StakeState::PreimageRevealed {
                    last_block_height,
                    stake_data: TEST_STAKE_DATA.clone(),
                    preimage: TEST_UNSTAKING_PREIMAGE,
                    unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
                    expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
                    signatures: Box::new(Some(*TEST_FINAL_SIGS)),
                }
            }),
            any_terminal_state(),
        ]
        .boxed()
    }
}

fn any_terminal_state() -> impl Strategy<Value = StakeState> {
    Just(StakeState::Unstaked {
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
    })
}

// `impl Arbitrary for StakeEvent` without handlers:
// - `StakeEvent::NagTick`
// - `StakeEvent::RetryTick`
fn any_event() -> impl Strategy<Value = StakeEvent> {
    let block_height = 0u64..1_000u64;
    let operator_idx = 0..TEST_N_OPERATORS as u32;

    prop_oneof![
        Just(StakeEvent::StakeDataReceived(StakeDataReceivedEvent {
            stake_funds: TEST_STAKE_DATA.stake_funds,
            unstaking_image: TEST_STAKE_DATA.unstaking_image,
            unstaking_output_desc: TEST_STAKE_DATA.unstaking_operator_desc.clone(),
        })),
        operator_idx.clone().prop_map(|operator_idx| {
            StakeEvent::UnstakingNoncesReceived(UnstakingNoncesReceivedEvent {
                operator_idx,
                pub_nonces: TEST_PUB_NONCES_MAP[&operator_idx].clone().into(),
            })
        }),
        operator_idx.prop_map(|operator_idx| {
            StakeEvent::UnstakingPartialsReceived(UnstakingPartialsReceivedEvent {
                operator_idx,
                partial_signatures: TEST_PARTIAL_SIGS_MAP[&operator_idx],
            })
        }),
        Just(StakeEvent::StakeConfirmed(StakeConfirmedEvent {
            tx: unsigned_stake_tx(),
        })),
        block_height.clone().prop_map(|block_height| {
            StakeEvent::PreimageRevealed(PreimageRevealedEvent {
                tx: signed_unstaking_intent_tx(),
                block_height,
            })
        }),
        Just(StakeEvent::UnstakingConfirmed(UnstakingConfirmedEvent {
            tx: signed_unstaking_tx(),
        })),
        block_height.prop_map(|block_height| StakeEvent::NewBlock(NewBlockEvent { block_height })),
    ]
}

// NOTE: (@uncomputable) Signing this transaction is complicated,
// so we leave it unsigned here.
fn unsigned_stake_tx() -> Transaction {
    TEST_GRAPH.stake.as_ref().clone()
}

fn signed_unstaking_intent_tx() -> Transaction {
    TEST_GRAPH
        .unstaking_intent
        .clone()
        .finalize(&UnstakingIntentWitness {
            n_of_n_signature: TEST_FINAL_SIGS.unstaking_intent[0],
            unstaking_preimage: TEST_UNSTAKING_PREIMAGE,
        })
}

fn signed_unstaking_tx() -> Transaction {
    TEST_GRAPH
        .unstaking
        .clone()
        .finalize(TEST_FINAL_SIGS.unstaking)
}
