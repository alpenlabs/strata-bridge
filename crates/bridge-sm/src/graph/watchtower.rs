//! Mapping between watchtower slot indices and operator indices.
//!
//! The counterproof array in a game graph excludes the graph owner,
//! so watchtower slots are a dense 0-based sequence of all operators
//! except the owner. These helpers convert between the two numbering
//! schemes.

use strata_bridge_primitives::types::OperatorIdx;

/// Maps a zero-based watchtower slot back to the full operator index,
/// accounting for the graph owner being excluded from the watchtower list.
///
/// Inverse of [`watchtower_slot_for_operator`].
pub(crate) const fn watchtower_slot_to_operator_idx(
    watchtower_slot: usize,
    graph_owner_idx: OperatorIdx,
) -> OperatorIdx {
    if watchtower_slot < graph_owner_idx as usize {
        watchtower_slot as OperatorIdx
    } else {
        watchtower_slot as OperatorIdx + 1
    }
}

/// Maps an operator index to its zero-based watchtower slot, returning
/// `None` for the graph owner (who has no watchtower slot).
///
/// Inverse of [`watchtower_slot_to_operator_idx`].
pub(crate) const fn watchtower_slot_for_operator(
    graph_owner_idx: OperatorIdx,
    operator_idx: OperatorIdx,
) -> Option<usize> {
    if operator_idx == graph_owner_idx {
        None
    } else if operator_idx < graph_owner_idx {
        Some(operator_idx as usize)
    } else {
        Some(operator_idx as usize - 1)
    }
}

#[cfg(test)]
mod tests {
    use proptest::proptest;

    use super::*;

    #[test]
    fn test_slot_to_operator_exhaustive() {
        const N: u32 = 7;
        for owner in 0..N {
            let expected_watchtowers: Vec<OperatorIdx> = (0..N).filter(|&op| op != owner).collect();
            for (slot, &expected_wt) in expected_watchtowers.iter().enumerate() {
                assert_eq!(
                    watchtower_slot_to_operator_idx(slot, owner),
                    expected_wt,
                    "owner={owner}, slot={slot}"
                );
            }
        }
    }

    #[test]
    fn test_slot_for_operator_exhaustive() {
        const N: u32 = 7;
        for owner in 0..N {
            let mut expected_slot = 0usize;
            for op in 0..N {
                if op == owner {
                    continue;
                }
                assert_eq!(
                    watchtower_slot_for_operator(owner, op),
                    Some(expected_slot),
                    "owner={owner}, op={op}"
                );
                expected_slot += 1;
            }
        }
    }

    proptest! {
        #[test]
        fn roundtrip_slot_to_operator_to_slot(
            num_operators in 2..=20u32,
            owner_frac in 0..20u32,
            slot_frac in 0..19u32,
        ) {
            let owner = owner_frac % num_operators;
            let slot = (slot_frac % (num_operators - 1)) as usize;

            let op = watchtower_slot_to_operator_idx(slot, owner);
            assert_eq!(
                watchtower_slot_for_operator(owner, op),
                Some(slot),
            );
        }

        #[test]
        fn roundtrip_operator_to_slot_to_operator(
            num_operators in 2..=20u32,
            owner_frac in 0..20u32,
            op_frac in 0..19u32,
        ) {
            let owner = owner_frac % num_operators;
            // pick a non-owner operator
            let non_owner_ops: Vec<u32> = (0..num_operators).filter(|&o| o != owner).collect();
            let op = non_owner_ops[(op_frac as usize) % non_owner_ops.len()];

            let slot = watchtower_slot_for_operator(owner, op).unwrap();
            assert_eq!(
                watchtower_slot_to_operator_idx(slot, owner),
                op,
            );
        }

        #[test]
        fn owner_has_no_slot(
            num_operators in 1..=20u32,
            owner_frac in 0..20u32,
        ) {
            let owner = owner_frac % num_operators;
            assert_eq!(watchtower_slot_for_operator(owner, owner), None);
        }
    }
}
