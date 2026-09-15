//! Ordered storage for pending membership updates.

use std::{cmp::Ordering, collections::BTreeSet};

use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};

/// One authorized admin update. Equal-height updates retain their supplied order.
///
/// Additions execute before removals within an update. A removal followed by an addition
/// must be represented as separate ordered updates, so an intermediate empty set is rejected.
/// Registration intervals alone do not encode the execution order of same-height updates.
/// Comparisons use activation height; distinct updates at the same height are unordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipUpdate {
    /// The verified effective height of the admin update.
    pub activation_height: BitcoinBlockHeight,
    /// Permanent registration indices to add, in canonical order.
    pub additions: BTreeSet<OperatorIdx>,
    /// Permanent registration indices to remove, in canonical order.
    pub removals: BTreeSet<OperatorIdx>,
}

impl PartialOrd for MembershipUpdate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.activation_height.cmp(&other.activation_height) {
            Ordering::Equal if self != other => None,
            ordering => Some(ordering),
        }
    }
}

/// Updates ordered by activation height, preserving supplied order at equal heights.
///
/// Construction and deserialization establish the ordering. Elements can only be read or removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<MembershipUpdate>")]
pub(super) struct SortedUpdates(Vec<MembershipUpdate>);

impl SortedUpdates {
    /// Borrows all pending updates in activation order without allowing mutation.
    pub(super) fn as_slice(&self) -> &[MembershipUpdate] {
        &self.0
    }
}

impl From<Vec<MembershipUpdate>> for SortedUpdates {
    /// Sorts updates by ascending activation height, preserving supplied order at equal heights.
    ///
    /// This also establishes ordering during deserialization. Membership validation belongs
    /// to the state machine; this conversion only establishes ordering.
    fn from(mut updates: Vec<MembershipUpdate>) -> Self {
        updates.sort_by(|left, right| left.partial_cmp(right).unwrap_or(Ordering::Equal));
        Self(updates)
    }
}

#[cfg(test)]
mod tests {
    use std::{cmp::Ordering, collections::BTreeSet};

    use super::{MembershipUpdate, SortedUpdates};

    fn update(height: u64, member: u32) -> MembershipUpdate {
        MembershipUpdate {
            activation_height: height,
            additions: BTreeSet::from([member]),
            removals: BTreeSet::new(),
        }
    }

    #[test]
    fn comparison_preserves_structural_equality_and_orders_distinct_heights() {
        let first = update(20, 0);
        let different = update(20, 1);
        let later = update(30, 0);
        assert_eq!(
            first.partial_cmp(&first.clone()),
            Some(Ordering::Equal),
            "Structurally identical updates must compare equal"
        );
        assert_ne!(first, different);
        assert_eq!(
            first.partial_cmp(&different),
            None,
            "Different updates at the same height must be incomparable, not equal"
        );
        assert_eq!(
            different.partial_cmp(&first),
            None,
            "Same-height incomparability must hold in both comparison directions"
        );
        assert_eq!(
            first.partial_cmp(&later),
            Some(Ordering::Less),
            "An earlier activation must compare before a later activation"
        );
        assert_eq!(
            later.partial_cmp(&first),
            Some(Ordering::Greater),
            "A later activation must compare after an earlier activation"
        );
    }

    #[test]
    fn deserialization_sorts_stably_and_preserves_the_vector_wire_format() {
        let later = update(30, 0);
        let first = update(20, 2);
        let second = update(20, 1);
        let input = vec![later.clone(), first.clone(), second.clone(), first.clone()];
        let bytes = postcard::to_allocvec(&input).unwrap();
        let restored: SortedUpdates = postcard::from_bytes(&bytes).unwrap();
        let expected = vec![first.clone(), second, first, later];
        assert_eq!(
            restored.as_slice(),
            expected,
            "Deserialization must sort by height while preserving equal-height order and duplicates"
        );
        assert_eq!(
            restored,
            SortedUpdates::from(input),
            "Deserialization and direct construction must establish the same ordering"
        );
        assert_eq!(
            postcard::to_allocvec(&restored).unwrap(),
            postcard::to_allocvec(&expected).unwrap(),
            "The ordered wrapper must serialize identically to its underlying vector"
        );
    }
}
