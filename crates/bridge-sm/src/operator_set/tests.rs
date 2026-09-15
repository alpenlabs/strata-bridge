use std::collections::BTreeSet;

use bitcoin::{
    XOnlyPublicKey,
    hex::FromHex,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::{
    covenant::CovenantId,
    operator_set_schedule::{OperatorSetSchedule, ScheduledOperator},
    types::P2POperatorPubKey,
};

use super::{MembershipUpdate, OperatorSetError, OperatorSetSM};

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
