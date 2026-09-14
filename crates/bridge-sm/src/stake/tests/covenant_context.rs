use strata_bridge_primitives::covenant::{CovenantId, StakeKey};

use super::*;
use crate::state_machine::StateMachine;

fn key(height: u64) -> StakeKey {
    StakeKey {
        covenant: CovenantId::from_operator_table(&*TEST_OPERATOR_TABLE, height).unwrap(),
        operator: TEST_POV_IDX,
    }
}

#[test]
fn context_rejects_mismatched_covenant_owner_and_local_member() {
    let table = TEST_OPERATOR_TABLE.clone().into_public();
    let mut wrong = key(101);
    wrong.covenant.aggregate_pubkey = generate_keypair().public_key().x_only_public_key().0;
    assert!(StakeSMCtx::from_public(wrong, table.clone(), None).is_err());
    let mut wrong = key(101);
    wrong.operator = u32::MAX;
    assert!(StakeSMCtx::from_public(wrong, table.clone(), None).is_err());
    assert!(StakeSMCtx::from_public(key(101), table, Some(u32::MAX)).is_err());
}

#[test]
fn observer_tracks_stake_data_without_signing_or_initialization_duties() {
    let ctx =
        StakeSMCtx::from_public(key(101), TEST_OPERATOR_TABLE.clone().into_public(), None).unwrap();
    let (mut sm, duty) = StakeSM::new(ctx, 200);
    assert!(duty.is_none());
    let out = sm
        .process_event(
            TEST_CFG.clone(),
            StakeEvent::StakeDataReceived(crate::stake::events::StakeDataReceivedEvent {
                stake_funds: OutPoint::default(),
                unstaking_image: sha256::Hash::all_zeros(),
                unstaking_output_desc: random_p2tr_desc(),
            }),
        )
        .unwrap();
    assert!(matches!(sm.state(), StakeState::StakeGraphGenerated { .. }));
    assert!(out.duties.is_empty());
    let out = sm
        .process_event(
            TEST_CFG.clone(),
            StakeEvent::RetryTick(crate::stake::events::RetryTickEvent),
        )
        .unwrap();
    assert!(out.duties.is_empty());
    let out = sm
        .process_event(
            TEST_CFG.clone(),
            StakeEvent::NagTick(crate::stake::events::NagTickEvent),
        )
        .unwrap();
    assert!(out.duties.is_empty());
}

#[test]
fn context_preserves_explicit_activation_height_through_serialization() {
    for height in [101, 202] {
        let ctx =
            StakeSMCtx::from_public(key(height), TEST_OPERATOR_TABLE.clone().into_public(), None)
                .unwrap();
        let (sm, _) = StakeSM::new(ctx, 999);
        assert_eq!(sm.context().stake_key(), key(height));
        let bytes = postcard::to_allocvec(&sm).unwrap();
        assert_eq!(postcard::from_bytes::<StakeSM>(&bytes).unwrap(), sm);
    }
}
