use strata_bridge_primitives::covenant::{CovenantId, StakeKey};

use super::*;
use crate::{
    stake::events::{StakeDataReceivedEvent, UnstakingNoncesReceivedEvent},
    state_machine::StateMachine,
};

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
fn participants_emit_duties_for_their_own_covenant() {
    for (height, members) in [(101, TEST_N_OPERATORS), (202, TEST_N_OPERATORS), (303, 2)] {
        for local in [TEST_POV_IDX, TEST_NONPOV_IDX] {
            let entries = TEST_OPERATOR_TABLE
                .operator_idxs()
                .into_iter()
                .take(members)
                .map(|idx| {
                    (
                        idx,
                        TEST_OPERATOR_TABLE.idx_to_p2p_key(&idx).unwrap().clone(),
                        TEST_OPERATOR_TABLE.idx_to_btc_key(&idx).unwrap(),
                    )
                })
                .collect();
            let table = OperatorTable::new(entries, move |entry| entry.0 == local).unwrap();
            let operator_idxs = table.operator_idxs();
            let expected_keys: Vec<_> = table
                .btc_keys()
                .into_iter()
                .map(|key| key.x_only_public_key().0)
                .collect();
            let ctx = StakeSMCtx::new(TEST_POV_IDX, table, height);
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
                matches!(out.duties.as_slice(), [StakeDuty::PublishUnstakingNonces { operator_idx, ordered_pubkeys, .. }]
                if *operator_idx == TEST_POV_IDX && *ordered_pubkeys == expected_keys)
            );

            for (i, operator_idx) in operator_idxs.into_iter().enumerate() {
                let out = sm
                    .process_event(
                        TEST_CFG.clone(),
                        StakeEvent::UnstakingNoncesReceived(UnstakingNoncesReceivedEvent {
                            operator_idx,
                            pub_nonces: TEST_PUB_NONCES_MAP[&operator_idx].clone().into(),
                        }),
                    )
                    .unwrap();
                if i + 1 == members {
                    assert!(
                        matches!(out.duties.as_slice(), [StakeDuty::PublishUnstakingPartials { operator_idx, ordered_pubkeys, .. }]
                        if *operator_idx == TEST_POV_IDX && *ordered_pubkeys == expected_keys)
                    );
                } else {
                    assert!(out.duties.is_empty());
                }
            }
        }
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
