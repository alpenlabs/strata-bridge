//! Operator table for the bridge.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
};

use algebra::category;
use bitcoin::{Network, XOnlyPublicKey};
use musig2::KeyAggContext;
use serde::{Deserialize, Serialize};

use crate::{
    build_context::TxBuildContext,
    types::{OperatorIdx, P2POperatorPubKey, PublickeyTable},
};

type OperatorTableEntry = (OperatorIdx, P2POperatorPubKey, secp256k1::PublicKey);

/// Public membership with no local signing participant.
///
/// This uses the same indexed keys and canonical ordering as [`OperatorTable`], but does not
/// expose point-of-view accessors or a participant transaction build context.
pub type PublicOperatorTable = OperatorTable<()>;

/// A table that maps operator indices to their P2P public keys and bitcoin public keys.
///
/// The default view includes a local participant. [`PublicOperatorTable`] represents the same
/// membership on observers and removed nodes without selecting a participant.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-2702>
// Replace the derived serialization; it is about 3x more expensive than optimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct OperatorTable<Pov = OperatorIdx> {
    /// The local operator index, or `()` for a public view with no local participant.
    pov: Pov,

    /// The index to the operator public key.
    idx_key: BTreeMap<OperatorIdx, (P2POperatorPubKey, secp256k1::PublicKey)>,

    /// The operator public key to the index.
    p2p_key: BTreeMap<P2POperatorPubKey, (OperatorIdx, secp256k1::PublicKey)>,

    /// The bitcoin public key to the operator public key.
    btc_key: BTreeMap<secp256k1::PublicKey, (OperatorIdx, P2POperatorPubKey)>,
}
impl OperatorTable {
    /// Creates a participant's operator table, requiring a matching local member and unique
    /// indices, P2P keys, and bitcoin keys.
    pub fn new(
        entries: Vec<OperatorTableEntry>,
        is_us: impl for<'a> FnMut(&'a OperatorTableEntry) -> bool + 'static,
    ) -> Option<Self> {
        let pov = entries
            .iter()
            .find(category::comp_as_ref_mut(Deref::deref, is_us))
            .map(|entry| entry.0)?;
        PublicOperatorTable::from_entries(entries)?.with_pov(pov)
    }

    /// Returns the index of this (point of view) operator
    pub const fn pov_idx(&self) -> OperatorIdx {
        self.pov
    }

    /// Returns the operator public key for this (point of view) operator.
    pub fn pov_p2p_key(&self) -> &P2POperatorPubKey {
        // NOTE: (proofofkeags) unwrap is safe because we assert this key is in the map in the
        // constructor.
        &self.idx_key.get(&self.pov).unwrap().0
    }

    /// Returns the bitcoin public key for this (point of view) operator.
    pub fn pov_btc_key(&self) -> secp256k1::PublicKey {
        // NOTE: (proofofkeags) unwrap is safe because we assert this key is in the map in the
        // constructor.
        self.idx_key.get(&self.pov).unwrap().1
    }

    /// Returns the transaction build context for the operators in the table.
    pub fn tx_build_context(&self, network: Network) -> TxBuildContext {
        TxBuildContext::new(network, self.public_key_table(), self.pov)
    }

    /// Returns a predicate capable of identifying a particular operator index. This is useful to
    /// use in the constructor.
    pub fn select_idx(idx: OperatorIdx) -> impl Fn(&OperatorTableEntry) -> bool {
        move |(i, _, _)| *i == idx
    }

    /// Returns a predicate capable of identifying a particular operator pubkey. This is useful to
    /// use in the constructor.
    pub fn select_p2p(op: P2POperatorPubKey) -> impl Fn(&OperatorTableEntry) -> bool {
        move |(_, o, _)| *o == op
    }

    /// Returns a predicate capable of identifying a particular operator btc key. This is useful to
    /// use in the constructor.
    pub fn select_btc(btc: secp256k1::PublicKey) -> impl Fn(&OperatorTableEntry) -> bool {
        move |(_, _, b)| *b == btc
    }

    /// Returns a predicate capable of identifying a particular operator btc x-only key. This is
    /// useful to use in the constructor.
    pub fn select_btc_x_only(btc: XOnlyPublicKey) -> impl Fn(&OperatorTableEntry) -> bool {
        move |(_, _, b)| b.x_only_public_key().0 == btc
    }
}

impl PublicOperatorTable {
    /// Creates public membership without selecting a local participant.
    ///
    /// Rejects empty membership and duplicate indices, P2P keys, or bitcoin keys.
    pub fn from_entries(entries: Vec<OperatorTableEntry>) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        let mut idx_key = BTreeMap::new();
        let mut p2p_key = BTreeMap::new();
        let mut btc_key = BTreeMap::new();

        for entry in entries {
            if idx_key
                .insert(entry.0, (entry.1.clone(), entry.2))
                .is_some()
                || p2p_key
                    .insert(entry.1.clone(), (entry.0, entry.2))
                    .is_some()
                || btc_key.insert(entry.2, (entry.0, entry.1)).is_some()
            {
                return None;
            }
        }

        Some(Self {
            pov: (),
            idx_key,
            p2p_key,
            btc_key,
        })
    }

    /// Selects a local participant, returning `None` if the index is absent.
    pub fn with_pov(self, pov: OperatorIdx) -> Option<OperatorTable> {
        if !self.contains_idx(&pov) {
            return None;
        }
        Some(OperatorTable {
            pov,
            idx_key: self.idx_key,
            p2p_key: self.p2p_key,
            btc_key: self.btc_key,
        })
    }
}

impl<Pov> OperatorTable<Pov> {
    /// Discards the local point of view while retaining the exact public membership.
    pub fn into_public(self) -> PublicOperatorTable {
        PublicOperatorTable {
            pov: (),
            idx_key: self.idx_key,
            p2p_key: self.p2p_key,
            btc_key: self.btc_key,
        }
    }

    /// Compares indexed signing and P2P keys independently of the local point of view.
    ///
    /// Aggregate-key equality alone does not establish equal membership. Payout descriptors
    /// and protocol settings are not stored in this table and must be checked separately.
    pub fn has_same_membership<OtherPov>(&self, other: &OperatorTable<OtherPov>) -> bool {
        self.idx_key == other.idx_key
    }

    /// Returns the operator public key for the given index.
    pub fn idx_to_p2p_key<'a>(&'a self, idx: &OperatorIdx) -> Option<&'a P2POperatorPubKey> {
        self.idx_key.get(idx).map(|x| &x.0)
    }

    /// Returns the bitcoin public key for the given index.
    pub fn idx_to_btc_key(&self, idx: &OperatorIdx) -> Option<secp256k1::PublicKey> {
        self.idx_key.get(idx).map(|x| x.1)
    }

    /// Returns the bitcoin public key for the given index in BIP-340 x-only form.
    pub fn idx_to_btc_x_only_key(&self, idx: &OperatorIdx) -> Option<XOnlyPublicKey> {
        self.idx_to_btc_key(idx)
            .map(|key| key.x_only_public_key().0)
    }

    /// Returns the index for the given operator public key.
    pub fn p2p_key_to_idx(&self, op_key: &P2POperatorPubKey) -> Option<OperatorIdx> {
        self.p2p_key.get(op_key).map(|x| x.0)
    }

    /// Returns the bitcoin public key for the given operator public key.
    pub fn p2p_key_to_btc_key(&self, op_key: &P2POperatorPubKey) -> Option<secp256k1::PublicKey> {
        self.p2p_key.get(op_key).map(|x| x.1)
    }

    /// Returns the index for the given bitcoin public key.
    pub fn btc_key_to_idx(&self, btc_key: &secp256k1::PublicKey) -> Option<OperatorIdx> {
        self.btc_key.get(btc_key).map(|x| x.0)
    }

    /// Returns the operator public key for the given bitcoin public key.
    pub fn btc_key_to_p2p_key<'a>(
        &'a self,
        btc_key: &secp256k1::PublicKey,
    ) -> Option<&'a P2POperatorPubKey> {
        self.btc_key.get(btc_key).map(|x| &x.1)
    }

    /// Returns the number of operators in the table.
    pub fn cardinality(&self) -> usize {
        self.idx_key.len()
    }

    /// Returns the MuSig2 public keys for the operators in the table in their canonical order
    /// i.e., the order of their indices.
    pub fn btc_keys(&self) -> impl IntoIterator<Item = secp256k1::PublicKey> + use<'_, Pov> {
        self.idx_key.values().map(|(_, btc_key)| *btc_key)
    }

    /// Returns the P2P public keys for the operators in the table.
    pub fn p2p_keys(&self) -> BTreeSet<P2POperatorPubKey> {
        self.p2p_key.keys().cloned().collect()
    }

    /// Returns the indices of the operators in the table.
    pub fn operator_idxs(&self) -> BTreeSet<OperatorIdx> {
        self.idx_key.keys().copied().collect()
    }

    /// Returns the public key table for the operators in the table.
    pub fn public_key_table(&self) -> PublickeyTable {
        PublickeyTable(self.idx_key.iter().map(|(k, v)| (*k, v.1)).collect())
    }

    /// Returns the aggregated bitcoin public key for the operators in the table.
    pub fn aggregated_btc_key(&self) -> secp256k1::PublicKey {
        let pks: Vec<secp256k1::PublicKey> = self.btc_keys().into_iter().collect();

        KeyAggContext::new(pks).unwrap().aggregated_pubkey()
    }

    /// Converts a map from operator public keys to a value to a map from bitcoin public keys to the
    /// same value.
    ///
    /// (p2p, V) -> (btc, V)
    pub fn convert_map_p2p_to_btc<V>(
        &self,
        map: BTreeMap<P2POperatorPubKey, V>,
    ) -> Result<BTreeMap<secp256k1::PublicKey, V>, P2POperatorPubKey> {
        map.into_iter()
            .map(|(op, v)| {
                self.p2p_key_to_btc_key(&op)
                    .map_or(Err(op), |btc| Ok((btc, v)))
            })
            .collect()
    }

    /// Converts a map from bitcoin public keys to a value to a map from operator public keys to the
    /// same value.
    ///
    /// (btc, V) -> (p2p, V)
    pub fn convert_map_btc_to_p2p<V>(
        &self,
        map: BTreeMap<secp256k1::PublicKey, V>,
    ) -> Result<BTreeMap<P2POperatorPubKey, V>, secp256k1::PublicKey> {
        map.into_iter()
            .map(|(btc, v)| {
                self.btc_key_to_p2p_key(&btc)
                    .cloned()
                    .map_or(Err(btc), |op| Ok((op, v)))
            })
            .collect()
    }

    /// Converts a map from operator public keys to a value to a map from operator indices to the
    /// same value.
    ///
    /// (p2p, V) -> (idx, V)
    pub fn convert_map_p2p_to_idx<V>(
        &self,
        map: BTreeMap<P2POperatorPubKey, V>,
    ) -> Result<BTreeMap<OperatorIdx, V>, P2POperatorPubKey> {
        map.into_iter()
            .map(|(op, v)| self.p2p_key_to_idx(&op).map_or(Err(op), |idx| Ok((idx, v))))
            .collect()
    }

    /// Converts a map from operator indices to a value to a map from operator public keys to the
    /// same value.
    ///
    /// (idx, V) -> (p2p, V)
    pub fn convert_map_idx_to_p2p<V>(
        &self,
        map: BTreeMap<OperatorIdx, V>,
    ) -> Result<BTreeMap<P2POperatorPubKey, V>, OperatorIdx> {
        map.into_iter()
            .map(|(idx, v)| {
                self.idx_to_p2p_key(&idx)
                    .map_or(Err(idx), |op| Ok((op.clone(), v)))
            })
            .collect()
    }

    /// Converts a map from bitcoin public keys to a value to a map from operator indices to the
    /// same value.
    ///
    /// (btc, V) -> (idx, V)
    pub fn convert_map_btc_to_idx<V>(
        &self,
        map: BTreeMap<secp256k1::PublicKey, V>,
    ) -> Result<BTreeMap<OperatorIdx, V>, secp256k1::PublicKey> {
        map.into_iter()
            .map(|(btc, v)| {
                self.btc_key_to_idx(&btc)
                    .map_or(Err(btc), |idx| Ok((idx, v)))
            })
            .collect()
    }

    /// Converts a map from bitcoin public keys to a value to a map from operator indices to the
    /// same value.
    ///
    /// (idx, V) -> (btc, V)
    pub fn convert_map_idx_to_btc<V>(
        &self,
        map: BTreeMap<OperatorIdx, V>,
    ) -> Result<BTreeMap<secp256k1::PublicKey, V>, OperatorIdx> {
        map.into_iter()
            .map(|(idx, v)| {
                self.idx_to_btc_key(&idx)
                    .map_or(Err(idx), |btc| Ok((btc, v)))
            })
            .collect()
    }

    /// Returns true if the operator index exists in the table.
    pub fn contains_idx(&self, idx: &OperatorIdx) -> bool {
        self.idx_key.contains_key(idx)
    }
}

/// Proptest generators for the operator table.
#[cfg(feature = "proptest")]
pub mod prop_test_generators {
    use proptest::{prelude::*, prop_compose};

    use super::OperatorTable;
    use crate::{secp::EvenSecretKey, types::P2POperatorPubKey};

    prop_compose! {
        /// Generates a random P2P public key.
        pub fn arb_p2p_key()(pk in arb_btc_key()) -> P2POperatorPubKey {
            P2POperatorPubKey::from(Vec::from(pk.serialize()))
        }
    }

    prop_compose! {
        /// Generates a random bitcoin public key.
        pub fn arb_btc_key()(
            sk in any::<[u8; 32]>()
                .no_shrink()
                .prop_filter_map(
                    "invalid secret key",
                    |bs| secp256k1::SecretKey::from_slice(&bs).ok().map(EvenSecretKey::from)
                )
        ) -> secp256k1::PublicKey {
            sk.public_key(secp256k1::SECP256K1)
        }
    }

    prop_compose! {
        fn arb_operator_table_opt()(
            keys in prop::collection::vec(
                (arb_p2p_key().no_shrink(), arb_btc_key().no_shrink()),
                3..=15
            ),
            pov in 0..15u32,
        ) -> Option<OperatorTable> {
            let size = keys.len() as u32;
            let indexed = keys.into_iter()
                .enumerate()
                .map(|(idx, (p2p, btc))| (idx as u32, p2p, btc))
                .collect();
            OperatorTable::new(indexed, OperatorTable::select_idx(pov % size))
        }
    }

    prop_compose! {
        /// Generates a random operator table.
        pub fn arb_operator_table()(
            table in arb_operator_table_opt()
                .prop_filter_map(
                    "non-unique keys",
                    |x|x),
        ) -> OperatorTable {
            table
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(index: OperatorIdx, seed: u8) -> OperatorTableEntry {
        let secret = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &secret);
        (index, P2POperatorPubKey::from(vec![seed; 32]), public)
    }

    #[test]
    fn public_membership_preserves_sparse_indices_and_canonical_key_order() {
        let first = entry(0, 1);
        let last = entry(2, 2);
        let public = PublicOperatorTable::from_entries(vec![last.clone(), first.clone()])
            .expect("public membership needs no local participant");
        let participant = OperatorTable::new(
            vec![first.clone(), last.clone()],
            OperatorTable::select_idx(2),
        )
        .unwrap();

        assert_eq!(public.operator_idxs(), BTreeSet::from([0, 2]));
        assert_eq!(
            public.btc_keys().into_iter().collect::<Vec<_>>(),
            vec![first.2, last.2]
        );
        assert_eq!(
            public.aggregated_btc_key(),
            participant.aggregated_btc_key()
        );
        assert!(public.has_same_membership(&participant));
        assert_eq!(participant.into_public(), public);
    }

    #[test]
    fn public_membership_rejects_empty_tables_and_conflicting_identities() {
        let first = entry(0, 1);
        let last = entry(2, 2);
        let mut duplicate_index = last.clone();
        duplicate_index.0 = first.0;
        let mut duplicate_p2p = last.clone();
        duplicate_p2p.1 = first.1.clone();
        let mut duplicate_btc = last;
        duplicate_btc.2 = first.2;

        assert!(PublicOperatorTable::from_entries(vec![]).is_none());
        for conflict in [duplicate_index, duplicate_p2p, duplicate_btc] {
            assert!(PublicOperatorTable::from_entries(vec![first.clone(), conflict]).is_none());
        }
    }

    #[test]
    fn selecting_a_local_member_requires_membership() {
        let entries = vec![entry(0, 1), entry(2, 2)];
        let public = PublicOperatorTable::from_entries(entries.clone()).unwrap();

        assert!(public.clone().with_pov(1).is_none());
        assert!(OperatorTable::new(entries, OperatorTable::select_idx(1)).is_none());
        let participant = public.clone().with_pov(2).unwrap();
        assert_eq!(participant.pov_idx(), 2);
        assert_eq!(
            participant.pov_btc_key(),
            public.idx_to_btc_key(&2).unwrap()
        );
        assert_eq!(
            participant.pov_p2p_key(),
            public.idx_to_p2p_key(&2).unwrap()
        );
        assert!(participant.has_same_membership(&public));
    }

    #[test]
    fn membership_comparison_includes_indices_and_keys_but_not_local_pov() {
        let entries = vec![entry(0, 1), entry(2, 2)];
        let public = PublicOperatorTable::from_entries(entries.clone()).unwrap();
        let first = public.clone().with_pov(0).unwrap();
        let second = public.clone().with_pov(2).unwrap();
        assert_ne!(first, second);
        assert!(first.has_same_membership(&second));

        let mut remapped = entries.clone();
        remapped[1].0 = 3;
        let remapped = PublicOperatorTable::from_entries(remapped).unwrap();
        assert_eq!(public.aggregated_btc_key(), remapped.aggregated_btc_key());
        assert!(!public.has_same_membership(&remapped));

        let mut changed_p2p = entries.clone();
        changed_p2p[1].1 = P2POperatorPubKey::from(vec![3; 32]);
        let changed_p2p = PublicOperatorTable::from_entries(changed_p2p).unwrap();
        assert_eq!(
            public.aggregated_btc_key(),
            changed_p2p.aggregated_btc_key()
        );
        assert!(!public.has_same_membership(&changed_p2p));

        let changed_btc =
            PublicOperatorTable::from_entries(vec![entries[0].clone(), entry(2, 3)]).unwrap();
        assert!(!public.has_same_membership(&changed_btc));
    }

    #[test]
    fn participant_serialization_retains_its_numeric_pov() {
        let participant =
            OperatorTable::new(vec![entry(0, 1), entry(2, 2)], OperatorTable::select_idx(2))
                .unwrap();
        let encoded = serde_json::to_value(&participant).unwrap();
        assert_eq!(encoded["pov"], 2);
        assert_eq!(encoded.as_object().unwrap().len(), 4);
        assert_eq!(
            serde_json::from_value::<OperatorTable>(encoded).unwrap(),
            participant
        );

        let public = participant.into_public();
        let encoded = serde_json::to_string(&public).unwrap();
        assert_eq!(
            serde_json::from_str::<PublicOperatorTable>(&encoded).unwrap(),
            public
        );
    }
}
