//! Mapping between watchtower slot indices and operator indices.
//!
//! The counterproof array in a game graph excludes the graph owner, so watchtower slots are the
//! positions of the graph's other members in operator-index order. Indices can have gaps once
//! members leave, so slots are resolved through the graph's own operator table.

use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};

/// Maps a zero-based watchtower slot to the member of `operator_table` that occupies it,
/// excluding the graph owner. Returns `None` for slots beyond the graph's watchtowers.
///
/// Inverse of [`watchtower_slot_for_operator`].
pub(crate) fn watchtower_slot_to_operator_idx<Pov>(
    operator_table: &OperatorTable<Pov>,
    graph_owner_idx: OperatorIdx,
    watchtower_slot: usize,
) -> Option<OperatorIdx> {
    watchtower_idxs(operator_table, graph_owner_idx).nth(watchtower_slot)
}

/// Maps a member of `operator_table` to its zero-based watchtower slot. Returns `None` for the
/// graph owner, who has no watchtower slot, and for operators outside the table.
///
/// Inverse of [`watchtower_slot_to_operator_idx`].
pub(crate) fn watchtower_slot_for_operator<Pov>(
    operator_table: &OperatorTable<Pov>,
    graph_owner_idx: OperatorIdx,
    operator_idx: OperatorIdx,
) -> Option<usize> {
    watchtower_idxs(operator_table, graph_owner_idx).position(|idx| idx == operator_idx)
}

/// The graph's watchtowers in slot order: every member except the owner, by operator index.
fn watchtower_idxs<Pov>(
    operator_table: &OperatorTable<Pov>,
    graph_owner_idx: OperatorIdx,
) -> impl Iterator<Item = OperatorIdx> {
    operator_table
        .operator_idxs()
        .into_iter()
        .filter(move |&idx| idx != graph_owner_idx)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::secp256k1::{PublicKey, SECP256K1, SecretKey};
    use proptest::{prelude::*, proptest};
    use strata_bridge_primitives::{operator_table::PublicOperatorTable, types::P2POperatorPubKey};

    use super::*;
    use crate::graph::tests::test_graph_sm_ctx;

    fn table_with_idxs(idxs: &BTreeSet<OperatorIdx>) -> PublicOperatorTable {
        let entries = idxs
            .iter()
            .enumerate()
            .map(|(position, &idx)| {
                let seed = u8::try_from(position + 1).expect("test tables are small");
                let secret = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
                let public = PublicKey::from_secret_key(SECP256K1, &secret);
                (
                    idx,
                    P2POperatorPubKey::from(public.serialize().to_vec()),
                    public,
                )
            })
            .collect();
        PublicOperatorTable::from_entries(entries).expect("non-empty table with unique keys")
    }

    #[test]
    fn slots_skip_indices_absent_from_the_table() {
        let table = table_with_idxs(&BTreeSet::from([0, 2, 5]));

        assert_eq!(
            watchtower_slot_for_operator(&table, 2, 0),
            Some(0),
            "the first remaining member takes slot 0"
        );
        assert_eq!(
            watchtower_slot_for_operator(&table, 2, 5),
            Some(1),
            "operator 5 is the second watchtower, not the fifth"
        );
        assert_eq!(
            watchtower_slot_to_operator_idx(&table, 2, 1),
            Some(5),
            "slot 1 belongs to operator 5"
        );
        assert_eq!(
            watchtower_slot_to_operator_idx(&table, 2, 2),
            None,
            "a three-member graph has only two watchtower slots"
        );
    }

    #[test]
    fn operators_outside_the_table_have_no_slot() {
        let table = table_with_idxs(&BTreeSet::from([0, 2, 5]));

        assert_eq!(
            watchtower_slot_for_operator(&table, 2, 1),
            None,
            "a removed operator must not map to a slot"
        );
        assert_eq!(
            watchtower_slot_for_operator(&table, 2, 6),
            None,
            "a not-yet-active operator must not map to a slot"
        );
    }

    #[test]
    fn slots_index_the_graph_watchtower_keys() {
        let owner = 5;
        let mut ctx = test_graph_sm_ctx();
        ctx.operator_table = table_with_idxs(&BTreeSet::from([0, 2, 5, 9]))
            .with_pov(2)
            .expect("local operator is a member");
        ctx.graph_idx.operator = owner;

        let watchtower_keys = ctx.watchtower_pubkeys();

        assert_eq!(
            watchtower_keys.len(),
            3,
            "every member except the owner is a watchtower"
        );
        for (slot, key) in watchtower_keys.iter().enumerate() {
            let operator = watchtower_slot_to_operator_idx(ctx.operator_table(), owner, slot)
                .expect("every watchtower key has a slot");
            assert_eq!(
                ctx.operator_table().idx_to_btc_x_only_key(&operator),
                Some(*key),
                "slot {slot} must address the watchtower key at the same position"
            );
        }
    }

    fn table_and_owner() -> impl Strategy<Value = (BTreeSet<OperatorIdx>, OperatorIdx)> {
        prop::collection::btree_set(0..64u32, 2..=12).prop_flat_map(|idxs| {
            let members = idxs.iter().copied().collect::<Vec<_>>();
            (Just(idxs), prop::sample::select(members))
        })
    }

    proptest! {
        #[test]
        fn slots_follow_member_order_without_the_owner((idxs, owner) in table_and_owner()) {
            let table = table_with_idxs(&idxs);
            let watchtowers = idxs.iter().copied().filter(|&idx| idx != owner).collect::<Vec<_>>();

            for (slot, &operator) in watchtowers.iter().enumerate() {
                prop_assert_eq!(
                    watchtower_slot_for_operator(&table, owner, operator),
                    Some(slot),
                    "operator {} must occupy slot {}", operator, slot
                );
                prop_assert_eq!(
                    watchtower_slot_to_operator_idx(&table, owner, slot),
                    Some(operator),
                    "slot {} must belong to operator {}", slot, operator
                );
            }
            prop_assert_eq!(
                watchtower_slot_to_operator_idx(&table, owner, watchtowers.len()),
                None,
                "slots past the last watchtower must not resolve"
            );
        }

        #[test]
        fn owner_has_no_slot((idxs, owner) in table_and_owner()) {
            let table = table_with_idxs(&idxs);

            prop_assert_eq!(
                watchtower_slot_for_operator(&table, owner, owner),
                None,
                "the graph owner never watches its own graph"
            );
        }
    }
}
