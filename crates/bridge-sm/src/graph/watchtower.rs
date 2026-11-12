//! Mapping between watchtower slot indices and operator indices.
//!
//! The counterproof array in a game graph excludes the graph owner, so watchtower slots are the
//! positions of the graph's other members in operator-index order. Indices can have gaps once
//! members leave, so slots are resolved through the graph's own operator table.

use bitcoin::taproot::LeafVersion;
use strata_bridge_connectors::{Connector, ParentTx, prelude::MultiAnchor};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};

use crate::graph::duties::MultiAnchorSpend;

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

/// Resolves the [`MultiAnchorSpend`] this operator may use to bump `tx`.
///
/// Returns `None` when the point-of-view operator owns the graph or sits outside its
/// `operator_table`: an operator is never a watchtower of its own graph, so it holds no leaf.
pub(crate) fn multi_anchor_spend_for_pov<T, Pov>(
    tx: &T,
    operator_table: &OperatorTable<Pov>,
    graph_owner_idx: OperatorIdx,
    pov_idx: OperatorIdx,
) -> Option<MultiAnchorSpend>
where
    T: ParentTx<CpfpConnector = MultiAnchor>,
{
    let leaf_index = watchtower_slot_for_operator(operator_table, graph_owner_idx, pov_idx)?;
    let anchor = tx.cpfp_connector();
    let leaf_script = anchor.leaf_scripts().into_iter().nth(leaf_index)?;
    let control_block = anchor
        .spend_info()
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))?;

    Some(MultiAnchorSpend {
        anchor_vout: tx.cpfp_outpoint().vout,
        leaf_script,
        control_block,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::{
        Address, Amount, FeeRate, Network, OutPoint, XOnlyPublicKey,
        secp256k1::{PublicKey, SECP256K1, SecretKey},
    };
    use bitcoin_bosd::Descriptor;
    use proptest::{prelude::*, proptest};
    use strata_bridge_connectors::prelude::NOfNConnector;
    use strata_bridge_primitives::{operator_table::PublicOperatorTable, types::P2POperatorPubKey};
    use strata_bridge_tx_graph::transactions::prelude::{SweepData, SweepTx};

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

    /// Operator indices can have gaps, so a leaf is addressed by the slot and never by the index.
    #[test]
    fn a_gapped_table_resolves_the_leaf_of_the_watchtower_slot() {
        let owner = 5;
        let mut ctx = test_graph_sm_ctx();
        ctx.operator_table = table_with_idxs(&BTreeSet::from([0, 2, 5, 9]))
            .with_pov(2)
            .expect("local operator is a member");
        ctx.graph_idx.operator = owner;
        let watchtower_keys = ctx.watchtower_pubkeys();
        let parent = parent_with_anchor_keys(watchtower_keys.clone());

        for (slot, operator) in [0, 2, 9].into_iter().enumerate() {
            let spend = multi_anchor_spend_for_pov(&parent, ctx.operator_table(), owner, operator)
                .expect("a watchtower holds a leaf");

            assert_eq!(
                spend.leaf_script,
                parent.cpfp_connector().leaf_scripts()[slot],
                "operator {operator} must resolve the leaf at slot {slot}"
            );
            assert!(
                spend
                    .leaf_script
                    .as_bytes()
                    .windows(32)
                    .any(|window| window == watchtower_keys[slot].serialize()),
                "the leaf at slot {slot} must name the key of operator {operator}"
            );
        }

        assert!(
            multi_anchor_spend_for_pov(&parent, ctx.operator_table(), owner, 1).is_none(),
            "a gap in the table holds no leaf"
        );
        assert!(
            multi_anchor_spend_for_pov(&parent, ctx.operator_table(), owner, owner).is_none(),
            "the owner holds no leaf"
        );
    }

    /// A transaction whose `MultiAnchor` holds one leaf per key of `anchor_keys`, in order. Any
    /// `ParentTx<CpfpConnector = MultiAnchor>` serves; the sweep is the one with the fewest inputs
    /// to construct, and nothing here depends on what it sweeps.
    fn parent_with_anchor_keys(anchor_keys: Vec<XOnlyPublicKey>) -> SweepTx {
        let n_of_n_key = anchor_keys[0];
        let safe_harbour = Address::p2tr(SECP256K1, n_of_n_key, None, Network::Regtest);
        SweepTx::new(
            SweepData {
                deposit_outpoint: OutPoint::null(),
            },
            NOfNConnector::new(Network::Regtest, n_of_n_key, Amount::from_sat(10_000_000)),
            Descriptor::try_from(safe_harbour).expect("standard address"),
            anchor_keys,
            FeeRate::from_sat_per_vb(2).expect("valid rate"),
        )
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
