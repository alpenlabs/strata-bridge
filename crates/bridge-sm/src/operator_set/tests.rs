use std::collections::BTreeSet;

use bitcoin::{
    Txid, XOnlyPublicKey,
    hashes::Hash,
    hex::FromHex,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::{
    covenant::CovenantId,
    operator_set_schedule::{OperatorSetSchedule, ScheduledOperator},
    types::P2POperatorPubKey,
};

use super::{ConfirmedExit, ExitKind, MembershipUpdate, OperatorSetError, OperatorSetSM};

fn operator(index: u32, activation: u64, deactivation: Option<u64>) -> ScheduledOperator {
    let secret = SecretKey::from_slice(&[u8::try_from(index + 1).unwrap(); 32]).unwrap();
    let key: XOnlyPublicKey = PublicKey::from_secret_key(&Secp256k1::new(), &secret)
        .x_only_public_key()
        .0;
    let p2p_hex = [
        "0de7729dcbeb5069136ee4bff1c4f2fd822fe8fbc9b518df434d4f0c6312d8f5",
        "255ab0da6d468a22910a7cf54021763417c63c28bbafd4e2359daf103bb61e9d",
        "aeabd3a377c160590a0927bca0cb315eaebf5acc87476fbb317c6260b6f123c6",
        "5866666666666666666666666666666666666666666666666666666666666666",
    ][index as usize];
    let p2p = Vec::from_hex(p2p_hex).unwrap();
    ScheduledOperator::new(
        index,
        key,
        P2POperatorPubKey::from(p2p),
        Descriptor::new_p2tr(&key.serialize()).unwrap(),
        activation,
        deactivation,
    )
    .unwrap()
}

fn schedule() -> OperatorSetSchedule {
    OperatorSetSchedule::new(vec![
        operator(0, 10, None),
        operator(1, 10, Some(20)),
        operator(2, 20, None),
    ])
    .unwrap()
}

fn update(height: u64, additions: &[u32], removals: &[u32]) -> MembershipUpdate {
    MembershipUpdate {
        activation_height: height,
        additions: additions.iter().copied().collect(),
        removals: removals.iter().copied().collect(),
    }
}

#[test]
fn initialization_retains_history_and_sparse_public_membership() {
    let activation_height = 20;
    let retained_operator = 0;
    let removed_operator = 1;
    let added_operator = 2;

    let registrations = schedule();
    let sm = OperatorSetSM::new(activation_height, registrations.clone(), vec![]).unwrap();
    assert_eq!(
        sm.registrations(),
        &registrations,
        "Initialization must retain inactive registrations alongside active ones"
    );
    let table = sm.current_operator_table().unwrap();
    assert_eq!(
        table.operator_idxs(),
        BTreeSet::from([retained_operator, added_operator]),
        "Membership at height {activation_height} must exclude operator {removed_operator} and retain operators {retained_operator} and {added_operator}"
    );
    assert_eq!(
        sm.exited_operators(),
        &BTreeSet::from([removed_operator]),
        "A configured removal at the starting height must prevent later reactivation"
    );
    assert_eq!(
        sm.current_covenant(),
        CovenantId::from_operator_table(&table, activation_height).unwrap(),
        "The initial covenant must use active membership and the admin boundary at height {activation_height}"
    );
    assert!(table.clone().with_pov(removed_operator).is_none());
    assert_eq!(
        table
            .clone()
            .with_pov(retained_operator)
            .unwrap()
            .into_public(),
        table,
        "Selecting a local participant must not change the public membership table"
    );
}

#[test]
fn admin_boundary_includes_removal_of_latest_registration() {
    let retained_operator = 0;
    let removed_operator = 1;
    let initial_activation_height = 10;
    let later_activation_height = 20;
    let removal_height = 30;
    let initialization_height = removal_height + 1;

    let registrations = OperatorSetSchedule::new(vec![
        operator(retained_operator, initial_activation_height, None),
        operator(
            removed_operator,
            later_activation_height,
            Some(removal_height),
        ),
    ])
    .unwrap();
    let sm = OperatorSetSM::new(initialization_height, registrations, vec![]).unwrap();
    assert_eq!(
        sm.current_covenant().activation_height,
        removal_height,
        "The boundary must be the removal height {removal_height}, although the surviving member activated at {initial_activation_height}"
    );
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([retained_operator]),
        "After removing operator {removed_operator}, only operator {retained_operator} must remain active"
    );
}

#[test]
fn initialization_sorts_updates_stably_and_roundtrips() {
    let activation_height = 20;
    let later_activation_height = 30;
    let initialization_height = activation_height - 1;
    let retained_operator = 0;
    let removed_operator = 1;
    let added_operator = 2;

    let updates = vec![
        update(activation_height, &[added_operator], &[]),
        update(activation_height, &[], &[removed_operator]),
    ];
    let later = update(later_activation_height, &[], &[retained_operator]);
    let supplied = vec![updates[0].clone(), later.clone(), updates[1].clone()];
    let sm = OperatorSetSM::new(initialization_height, schedule(), supplied).unwrap();
    let mut expected = updates;
    expected.push(later);
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([retained_operator, removed_operator]),
        "Updates at height {activation_height} must not affect membership initialized at height {initialization_height}"
    );
    assert_eq!(
        sm.pending_updates(),
        expected,
        "Initialization must sort by height while preserving the supplied order of equal-height updates"
    );
    let bytes = postcard::to_allocvec(&sm).unwrap();
    let restored: OperatorSetSM = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(
        restored, sm,
        "Serialization must preserve the complete membership state and pending schedule"
    );
    assert_eq!(
        restored.current_operator_table().unwrap(),
        sm.current_operator_table().unwrap(),
        "Restoring membership state must reconstruct the same public operator table"
    );
}

#[test]
fn initialization_rejects_empty_membership_and_invalid_schedule() {
    assert_eq!(
        OperatorSetSM::new(9, schedule(), vec![]),
        Err(OperatorSetError::EmptyMembership),
        "Initialization before the first activation must reject empty membership"
    );
    let mut update = update(10, &[2], &[]);
    assert_eq!(
        OperatorSetSM::new(10, schedule(), vec![update.clone()]),
        Err(OperatorSetError::InvalidSchedule(10)),
        "Pending updates must activate strictly after the initialization height"
    );
    update.activation_height = 20;
    update.additions = BTreeSet::from([99]);
    assert_eq!(
        OperatorSetSM::new(10, schedule(), vec![update]),
        Err(OperatorSetError::UnknownOperator(99)),
        "Pending additions must reference an existing registration"
    );
}

fn exit(operator_idx: u32, tx_index: u32) -> ConfirmedExit {
    ConfirmedExit {
        operator_idx,
        tx_index,
        txid: Txid::from_byte_array([tx_index as u8; 32]),
        kind: ExitKind::UnstakingIntent,
    }
}

fn three_members() -> OperatorSetSchedule {
    OperatorSetSchedule::new((0..3).map(|idx| operator(idx, 10, None)).collect()).unwrap()
}

#[test]
fn automatic_exits_retain_admin_height_and_transaction_position_history() {
    let mut sm = OperatorSetSM::new(10, three_members(), vec![]).unwrap();
    assert!(
        sm.apply_block(
            11,
            &[
                exit(1, 2),
                ConfirmedExit {
                    kind: ExitKind::Slash,
                    ..exit(2, 5)
                }
            ]
        )
        .unwrap()
    );
    assert_eq!(
        sm.current_covenant().activation_height,
        10,
        "Automatic exits must retain the prior admin boundary instead of using the exit height"
    );
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([0]),
        "Both exited indices must be absent from the final membership"
    );
    assert_eq!(
        sm.membership_history()
            .iter()
            .map(|snapshot| snapshot.members.clone())
            .collect::<Vec<_>>(),
        vec![
            BTreeSet::from([0, 1, 2]),
            BTreeSet::from([0, 2]),
            BTreeSet::from([0])
        ],
        "History must retain the initial view and each intermediate view in transaction order"
    );
    assert!(sm.transition_at(11));
    assert!(!sm.transition_at(12));
    assert_eq!(
        sm.registrations().len(),
        3,
        "Automatic exits must preserve the complete registration history"
    );
}

#[test]
fn duplicate_exits_and_block_replay_do_not_create_successors() {
    let mut sm = OperatorSetSM::new(10, three_members(), vec![]).unwrap();
    sm.apply_block(11, &[exit(1, 0), exit(1, 1)]).unwrap();
    let history = sm.membership_history().to_vec();
    let covenant = sm.current_covenant();
    assert!(!sm.apply_block(12, &[exit(1, 0)]).unwrap());
    assert_eq!(
        sm.membership_history(),
        history,
        "An exit for an already-removed index must not append another membership snapshot"
    );
    assert_eq!(
        sm.current_covenant(),
        covenant,
        "A duplicate exit must not create a successor covenant"
    );
    let before = sm.clone();
    assert!(sm.apply_block(12, &[]).is_err());
    assert_eq!(
        sm, before,
        "Rejecting a replayed block must leave the entire state unchanged"
    );
}

#[test]
fn exits_precede_admin_changes_without_resurrecting_exited_members() {
    let activation_height = 20;
    let initialization_height = activation_height - 1;
    let stale_update_height = activation_height + 1;
    let retained_operator = 0;
    let exited_operator = 1;
    let added_operator = 2;

    let mut sm = OperatorSetSM::new(
        initialization_height,
        schedule(),
        vec![update(
            activation_height,
            &[exited_operator, added_operator],
            &[],
        )],
    )
    .unwrap();
    assert!(
        sm.apply_block(activation_height, &[exit(exited_operator, 0)])
            .unwrap()
    );
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([retained_operator, added_operator]),
        "The exit must take effect before admin additions, preventing operator {exited_operator} from rejoining"
    );
    assert_eq!(
        sm.current_covenant().activation_height,
        activation_height,
        "The effective addition must advance the admin boundary to height {activation_height}"
    );
    assert!(sm.pending_updates().is_empty());
    let mut restored: OperatorSetSM =
        postcard::from_bytes(&postcard::to_allocvec(&sm).unwrap()).unwrap();
    restored
        .update_operator_table(
            schedule(),
            vec![update(stale_update_height, &[exited_operator], &[])],
        )
        .unwrap();
    assert!(
        !restored
            .apply_block(stale_update_height, &[exit(exited_operator, 0)])
            .unwrap()
    );
    assert_eq!(
        restored.current_covenant(),
        sm.current_covenant(),
        "A stale addition and duplicate exit after restoration must preserve the covenant"
    );
    assert_eq!(
        restored.exited_operators(),
        &BTreeSet::from([exited_operator]),
        "Restoration and stale schedules must preserve the exited-registration set"
    );
}

#[test]
fn intermediate_empty_membership_rejects_the_whole_block() {
    let registrations =
        OperatorSetSchedule::new(vec![operator(0, 10, Some(20)), operator(1, 20, None)]).unwrap();
    for (updates, exits) in [
        (vec![update(20, &[1], &[])], vec![exit(0, 0)]),
        (vec![update(20, &[], &[0]), update(20, &[1], &[])], vec![]),
    ] {
        let mut sm = OperatorSetSM::new(19, registrations.clone(), updates).unwrap();
        let before = sm.clone();
        assert_eq!(
            sm.apply_block(20, &exits),
            Err(OperatorSetError::EmptyMembership),
            "A later addition must not rescue an earlier exit or removal that empties membership"
        );
        assert_eq!(
            sm, before,
            "Rejecting an intermediate empty set must roll back every change from the block"
        );
    }
    let mut sm = OperatorSetSM::new(
        19,
        registrations,
        vec![update(20, &[1], &[]), update(20, &[], &[0])],
    )
    .unwrap();
    assert!(sm.apply_block(20, &[]).unwrap());
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([1]),
        "Adding the replacement before removing the last old member must succeed"
    );
}

#[test]
fn effective_admin_roundtrip_marks_transition_even_with_unchanged_final_keys() {
    let mut sm = OperatorSetSM::new(
        19,
        schedule(),
        vec![update(20, &[2], &[]), update(20, &[], &[2])],
    )
    .unwrap();
    let keys = sm.current_covenant().aggregate_pubkey;
    assert!(sm.apply_block(20, &[]).unwrap());
    assert_eq!(
        sm.current_covenant().aggregate_pubkey,
        keys,
        "Adding and then removing the same operator must restore the original aggregate key"
    );
    assert_eq!(
        sm.current_covenant().activation_height,
        20,
        "Effective admin operations must advance the boundary even when the final keys are unchanged"
    );
    assert!(sm.transition_at(20));
    assert_eq!(
        sm.membership_history().len(),
        3,
        "History must retain both effective admin operations as well as initialization"
    );
}

#[test]
fn old_index_exit_does_not_remove_fresh_key_reentry() {
    let activation_height = 20;
    let initialization_height = activation_height - 1;
    let replay_height = activation_height + 1;
    let retained_operator = 0;
    let old_operator = 1;
    let reentered_operator = 2;

    let mut sm = OperatorSetSM::new(
        initialization_height,
        schedule(),
        vec![update(
            activation_height,
            &[reentered_operator],
            &[old_operator],
        )],
    )
    .unwrap();
    sm.apply_block(activation_height, &[exit(old_operator, 0)])
        .unwrap();
    assert!(
        !sm.apply_block(replay_height, &[exit(old_operator, 0)])
            .unwrap()
    );
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([retained_operator, reentered_operator]),
        "A repeated exit for operator {old_operator} must not remove the fresh registration at index {reentered_operator}"
    );
}

#[test]
fn invalid_event_order_and_unknown_indices_leave_state_unchanged() {
    for exits in [vec![exit(1, 4), exit(2, 3)], vec![exit(1, 0), exit(99, 1)]] {
        let mut sm = OperatorSetSM::new(10, three_members(), vec![]).unwrap();
        let before = sm.clone();
        assert!(sm.apply_block(11, &exits).is_err());
        assert_eq!(
            sm, before,
            "An invalid exit later in the block must roll back any earlier valid exit"
        );
    }
}

#[test]
fn registration_update_inserts_earlier_activation_and_preserves_equal_height_order() {
    let initialization_height = 10;
    let earlier_activation_height = 15;
    let activation_height = 20;
    let retained_operator = 0;
    let removed_operator = 1;
    let added_operator = 2;
    let earlier_operator = 3;
    let unknown_operator = 99;

    let later_addition = update(activation_height, &[added_operator], &[]);
    let later_removal = update(activation_height, &[], &[removed_operator]);
    let mut sm = OperatorSetSM::new(
        initialization_height,
        schedule(),
        vec![later_addition.clone(), later_removal.clone()],
    )
    .unwrap();
    let mut registrations: Vec<_> = schedule().iter().cloned().collect();
    registrations.push(operator(earlier_operator, earlier_activation_height, None));
    let registrations = OperatorSetSchedule::new(registrations).unwrap();
    let earlier = update(earlier_activation_height, &[earlier_operator], &[]);
    let supplied = vec![
        later_addition.clone(),
        earlier.clone(),
        later_removal.clone(),
    ];
    assert!(
        sm.update_operator_table(registrations.clone(), supplied.clone())
            .unwrap()
    );
    assert_eq!(
        sm.pending_updates(),
        &[earlier, later_addition, later_removal],
        "An earlier activation supplied later must move ahead without reordering equal-height operations"
    );
    assert!(
        !sm.update_operator_table(registrations.clone(), supplied)
            .unwrap()
    );

    let saved = sm.clone();
    for (invalid, expected) in [
        (
            update(initialization_height - 1, &[earlier_operator], &[]),
            OperatorSetError::InvalidSchedule(initialization_height),
        ),
        (
            update(initialization_height, &[earlier_operator], &[]),
            OperatorSetError::InvalidSchedule(initialization_height),
        ),
        (
            update(earlier_activation_height, &[unknown_operator], &[]),
            OperatorSetError::UnknownOperator(unknown_operator),
        ),
    ] {
        assert_eq!(
            sm.update_operator_table(registrations.clone(), vec![invalid]),
            Err(expected),
            "Schedule replacement must reject past or current activations and unknown registration indices"
        );
        assert_eq!(
            sm, saved,
            "Rejected schedule replacement must preserve both registrations and pending updates"
        );
    }
    for height in initialization_height + 1..earlier_activation_height {
        assert!(!sm.apply_block(height, &[]).unwrap());
    }
    assert!(sm.apply_block(earlier_activation_height, &[]).unwrap());
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([retained_operator, removed_operator, earlier_operator]),
        "Height {earlier_activation_height} must activate operator {earlier_operator} before the operations at height {activation_height}"
    );
    assert_eq!(
        sm.pending_updates(),
        &[
            update(activation_height, &[added_operator], &[]),
            update(activation_height, &[], &[removed_operator])
        ],
        "Processing height {earlier_activation_height} must leave the operations at height {activation_height} pending in their original order"
    );
    for height in earlier_activation_height + 1..activation_height {
        assert!(!sm.apply_block(height, &[]).unwrap());
    }
    assert!(sm.apply_block(activation_height, &[]).unwrap());
    assert_eq!(
        sm.current_operator_table().unwrap().operator_idxs(),
        BTreeSet::from([retained_operator, added_operator, earlier_operator]),
        "Height {activation_height} must add operator {added_operator} and remove operator {removed_operator} while retaining operator {earlier_operator}"
    );
    assert_eq!(
        sm.membership_history()[2].members,
        BTreeSet::from([
            retained_operator,
            removed_operator,
            added_operator,
            earlier_operator
        ]),
        "History must retain the intermediate view after the addition and before the same-height removal"
    );
    assert!(sm.pending_updates().is_empty());
}

#[test]
fn registration_updates_preserve_membership_and_reject_historical_rewrites() {
    let mut sm = OperatorSetSM::new(10, three_members(), vec![]).unwrap();
    let extra = OperatorSetSchedule::new(
        (0..4)
            .map(|idx| operator(idx, if idx == 3 { 20 } else { 10 }, None))
            .collect(),
    )
    .unwrap();
    let before = sm.current_covenant();
    sm.update_operator_table(extra.clone(), vec![update(20, &[3], &[])])
        .unwrap();
    assert_eq!(
        sm.current_covenant(),
        before,
        "Installing a future registration must not change the current covenant"
    );
    assert_eq!(
        sm.current_operator_table().unwrap().cardinality(),
        3,
        "A future registration must remain outside current membership until activation"
    );
    let saved = sm.clone();
    assert!(sm.update_operator_table(three_members(), vec![]).is_err());
    assert_eq!(
        sm, saved,
        "Rejecting a missing stored registration must preserve the entire state"
    );
    let rewritten = OperatorSetSchedule::new(
        (0..4)
            .map(|idx| operator(idx, if idx == 3 { 21 } else { 10 }, None))
            .collect(),
    )
    .unwrap();
    assert!(sm.update_operator_table(rewritten, vec![]).is_err());
    assert_eq!(
        sm, saved,
        "Rejecting a rewritten original activation height must preserve the entire state"
    );
}
