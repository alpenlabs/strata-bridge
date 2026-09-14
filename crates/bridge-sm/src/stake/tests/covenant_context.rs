use strata_bridge_primitives::covenant::{CovenantId, StakeKey};

use super::*;
use crate::{stake::events::StakeDataReceivedEvent, state_machine::StateMachine};

fn key(height: u64) -> StakeKey {
    StakeKey {
        covenant: CovenantId::from_operator_table(&*TEST_OPERATOR_TABLE, height).unwrap(),
        operator: TEST_POV_IDX,
    }
}

#[test]
#[should_panic(expected = "The operator index must be included in the operator table")]
fn context_rejects_absent_stake_owner() {
    StakeSMCtx::new(u32::MAX, TEST_OPERATOR_TABLE.clone(), 101);
}

#[test]
fn participants_use_table_pov_for_funding_and_cosigning() {
    for local in [TEST_POV_IDX, TEST_NONPOV_IDX] {
        let table = TEST_OPERATOR_TABLE
            .clone()
            .into_public()
            .with_pov(local)
            .unwrap();
        let ctx = StakeSMCtx::new(TEST_POV_IDX, table, 101);
        let (mut sm, duty) = StakeSM::new(ctx, 200);
        if local == TEST_POV_IDX {
            assert!(
                matches!(duty, Some(StakeDuty::PublishStakeData { operator_idx }) if operator_idx == TEST_POV_IDX)
            );
        } else {
            assert!(duty.is_none());
        }
        let out = sm
            .process_event(
                TEST_CFG.clone(),
                StakeEvent::StakeDataReceived(StakeDataReceivedEvent {
                    stake_funds: OutPoint::default(),
                    unstaking_image: sha256::Hash::all_zeros(),
                    unstaking_output_desc: random_p2tr_desc(),
                }),
            )
            .unwrap();
        assert!(matches!(sm.state(), StakeState::StakeGraphGenerated { .. }));
        assert!(
            matches!(out.duties.as_slice(), [StakeDuty::PublishUnstakingNonces { operator_idx, .. }] if *operator_idx == TEST_POV_IDX)
        );
    }
}

#[test]
fn context_preserves_activation_height_and_table_pov_through_serialization() {
    for height in [101, 202] {
        for local in [TEST_POV_IDX, TEST_NONPOV_IDX] {
            let table = TEST_OPERATOR_TABLE
                .clone()
                .into_public()
                .with_pov(local)
                .unwrap();
            let ctx = StakeSMCtx::new(TEST_POV_IDX, table, height);
            let (sm, _) = StakeSM::new(ctx, 999);
            assert_eq!(sm.context().stake_key(), key(height));
            assert_eq!(sm.context().operator_table().pov_idx(), local);
            let bytes = postcard::to_allocvec(&sm).unwrap();
            assert_eq!(postcard::from_bytes::<StakeSM>(&bytes).unwrap(), sm);
        }
    }
}
