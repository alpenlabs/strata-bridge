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
    operator_set_schedule::{OperatorSetSchedule, ScheduledOperator},
    types::{BitcoinBlockHeight, OperatorIdx, P2POperatorPubKey, PublickeyTable},
};

type OperatorTableEntry = (OperatorIdx, P2POperatorPubKey, secp256k1::PublicKey);

/// A table that maps operator indices to their P2P public keys and bitcoin public keys.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-2702>
// Replace the derived serialization; it is about 3x more expensive than optimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct OperatorTable {
    /// The index of this operator.
    pov: OperatorIdx,

    /// The index to the operator public key.
    idx_key: BTreeMap<OperatorIdx, (P2POperatorPubKey, secp256k1::PublicKey)>,

    /// The operator public key to the index.
    p2p_key: BTreeMap<P2POperatorPubKey, (OperatorIdx, secp256k1::PublicKey)>,

    /// The bitcoin public key to the operator public key.
    btc_key: BTreeMap<secp256k1::PublicKey, (OperatorIdx, P2POperatorPubKey)>,
}
impl OperatorTable {
    /// Creates a new operator table from a list of entries.
    pub fn new(
        entries: Vec<OperatorTableEntry>,
        is_us: impl for<'a> FnMut(&'a OperatorTableEntry) -> bool + 'static,
    ) -> Option<Self> {
        let mut idx_key = BTreeMap::new();
        let mut p2p_key = BTreeMap::new();
        let mut btc_key = BTreeMap::new();

        let pov = entries
            .iter()
            .find(category::comp_as_ref_mut(Deref::deref, is_us))
            .map(|entry| entry.0)?;

        for entry in entries {
            if idx_key
                .insert(entry.0, (entry.1.clone(), entry.2))
                .is_some()
                || p2p_key
                    .insert(entry.1.clone(), (entry.0, entry.2))
                    .is_some()
                || btc_key.insert(entry.2, (entry.0, entry.1)).is_some()
            {
                // This means we have a duplicate value which indicates a problem.
                return None;
            }
        }

        Some(OperatorTable {
            pov,
            idx_key,
            p2p_key,
            btc_key,
        })
    }

    /// Creates an operator table from scheduled operators using `pov_idx` as this node's index.
    ///
    /// Returns `None` when `pov_idx` is not included in the provided operators or if the operators
    /// do not satisfy [`OperatorTable`] uniqueness invariants.
    pub fn from_scheduled_operators<'a>(
        operators: impl IntoIterator<Item = &'a ScheduledOperator>,
        pov_idx: OperatorIdx,
    ) -> Option<Self> {
        let entries = operators
            .into_iter()
            .map(|operator| {
                (
                    operator.index(),
                    operator.p2p_key().clone(),
                    operator.covenant_public_key(),
                )
            })
            .collect();

        Self::new(entries, Self::select_idx(pov_idx))
    }

    /// Creates this node's active operator table from `schedule` at `height`.
    ///
    /// Returns `None` when the point-of-view operator is not active at `height`.
    pub fn from_schedule_at(
        schedule: &OperatorSetSchedule,
        height: BitcoinBlockHeight,
        pov_idx: OperatorIdx,
    ) -> Option<Self> {
        Self::from_scheduled_operators(schedule.active_at(height), pov_idx)
    }

    /// Returns the operator public key for the given index.
    pub fn idx_to_p2p_key<'a>(&'a self, idx: &OperatorIdx) -> Option<&'a P2POperatorPubKey> {
        self.idx_key.get(idx).map(|x| &x.0)
    }

    /// Returns the bitcoin public key for the given index.
    pub fn idx_to_btc_key(&self, idx: &OperatorIdx) -> Option<secp256k1::PublicKey> {
        self.idx_key.get(idx).map(|x| x.1)
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

    /// Returns the number of operators in the table.
    pub fn cardinality(&self) -> usize {
        self.idx_key.len()
    }

    /// Returns the MuSig2 public keys for the operators in the table in their canonical order
    /// i.e., the order of their indices.
    pub fn btc_keys(&self) -> impl IntoIterator<Item = secp256k1::PublicKey> + use<'_> {
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

    /// Returns the transaction build context for the operators in the table.
    pub fn tx_build_context(&self, network: Network) -> TxBuildContext {
        TxBuildContext::new(network, self.public_key_table(), self.pov)
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

    /// Returns true if the operator index exists in the table.
    pub fn contains_idx(&self, idx: &OperatorIdx) -> bool {
        self.idx_key.contains_key(idx)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin_bosd::Descriptor;
    use libp2p_identity::ed25519::{Keypair as P2pKeypair, SecretKey as P2pSecretKey};
    use secp256k1::{SecretKey, SECP256K1};

    use super::*;
    use crate::secp::EvenSecretKey;

    #[test]
    fn from_schedule_at_respects_rotation_boundary() {
        let schedule = rotating_schedule(3, 100);

        let before_rotation =
            OperatorTable::from_schedule_at(&schedule, 99, 0).expect("pov operator must be active");
        assert_eq!(
            before_rotation.operator_idxs(),
            idxs([0, 1]),
            "height before rotation should include the still-active outgoing operator"
        );

        let after_rotation = OperatorTable::from_schedule_at(&schedule, 100, 0)
            .expect("pov operator must be active");
        assert_eq!(
            after_rotation.operator_idxs(),
            idxs([0, 2]),
            "rotation height should exclude the deactivated operator and include the incoming operator"
        );
    }

    #[cfg(feature = "proptest")]
    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn from_scheduled_operators_matches_scheduled_entries(
                operator_ranges in prop::collection::vec(active_range_strategy(), 1..=16),
                pov_selector in any::<usize>(),
            ) {
                let operators = scheduled_operators(&operator_ranges);
                let operator_count = operators.len();
                let pov_idx = operator_idx(pov_selector % operator_count);
                let table = OperatorTable::from_scheduled_operators(operators.iter(), pov_idx)
                    .expect("generated operator table must include pov operator");

                prop_assert_eq!(
                    table.pov_idx(),
                    pov_idx,
                    "table should record the generated point-of-view operator"
                );
                prop_assert_eq!(
                    table.operator_idxs(),
                    idxs((0..operator_count).map(operator_idx)),
                    "table should contain exactly the generated scheduled operator indices"
                );

                for operator in &operators {
                    prop_assert_eq!(
                        table.idx_to_p2p_key(&operator.index()),
                        Some(operator.p2p_key()),
                        "table should resolve each generated scheduled operator's p2p key by index"
                    );
                    prop_assert_eq!(
                        table.idx_to_btc_key(&operator.index()),
                        Some(operator.covenant_public_key()),
                        "table should resolve each generated scheduled operator's covenant public key by index"
                    );
                }

                let missing_pov_idx = operator_idx(operator_count);
                prop_assert!(
                    OperatorTable::from_scheduled_operators(operators.iter(), missing_pov_idx).is_none(),
                    "operator table construction should fail when the generated pov operator is absent"
                );
            }

            #[test]
            fn from_schedule_at_matches_active_schedule(
                operator_ranges in prop::collection::vec(active_range_strategy(), 1..=16),
                height in 0u64..=2_000_000,
                pov_selector in any::<usize>(),
            ) {
                let schedule = schedule_from_ranges(&operator_ranges);
                let operator_count = operator_ranges.len();
                let pov_idx = operator_idx(pov_selector % operator_count);
                let expected_active_idxs = idxs(schedule.active_at(height).map(ScheduledOperator::index));
                let table = OperatorTable::from_schedule_at(&schedule, height, pov_idx);

                if expected_active_idxs.contains(&pov_idx) {
                    prop_assert!(
                        table.is_some(),
                        "operator table construction should succeed when the pov operator is active at height"
                    );
                    let table = table.expect("table presence checked above");

                    prop_assert_eq!(
                        table.pov_idx(),
                        pov_idx,
                        "active schedule table should record the requested point-of-view operator"
                    );
                    prop_assert_eq!(
                        table.operator_idxs(),
                        expected_active_idxs,
                        "active schedule table should contain exactly the operators active at height"
                    );

                    for operator in schedule.active_at(height) {
                        prop_assert_eq!(
                            table.idx_to_p2p_key(&operator.index()),
                            Some(operator.p2p_key()),
                            "active schedule table should resolve each active operator's p2p key by index"
                        );
                        prop_assert_eq!(
                            table.idx_to_btc_key(&operator.index()),
                            Some(operator.covenant_public_key()),
                            "active schedule table should resolve each active operator's covenant public key by index"
                        );
                    }
                } else {
                    prop_assert!(
                        table.is_none(),
                        "operator table construction should fail when the pov operator is inactive at height"
                    );
                }
            }
        }

        fn active_range_strategy() -> impl Strategy<Value = ActiveRange> {
            (
                0u64..=1_000_000,
                prop_oneof![Just(None), (1u64..=1_000_000).prop_map(Some)],
            )
                .prop_map(|(activation_height, active_span)| {
                    (
                        activation_height,
                        active_span.map(|active_span| activation_height + active_span),
                    )
                })
        }

        fn schedule_from_ranges(ranges: &[ActiveRange]) -> OperatorSetSchedule {
            OperatorSetSchedule::new(scheduled_operators(ranges))
                .expect("generated schedule ranges must be valid")
        }

        fn scheduled_operators(ranges: &[ActiveRange]) -> Vec<ScheduledOperator> {
            ranges
                .iter()
                .copied()
                .enumerate()
                .map(|(idx, (activation_height, deactivation_height))| {
                    scheduled_operator(
                        operator_idx(idx),
                        btc_seed(idx),
                        p2p_seed(idx),
                        activation_height,
                        deactivation_height,
                    )
                })
                .collect()
        }

        type ActiveRange = (BitcoinBlockHeight, Option<BitcoinBlockHeight>);
    }

    fn rotating_schedule(count: usize, rotation_height: BitcoinBlockHeight) -> OperatorSetSchedule {
        OperatorSetSchedule::new(
            (0..count)
                .map(|idx| {
                    let (activation_height, deactivation_height) = if idx == 0 {
                        (0, None)
                    } else if idx % 2 == 1 {
                        (0, Some(rotation_height))
                    } else {
                        (rotation_height, None)
                    };

                    scheduled_operator(
                        operator_idx(idx),
                        btc_seed(idx),
                        p2p_seed(idx),
                        activation_height,
                        deactivation_height,
                    )
                })
                .collect(),
        )
        .expect("generated rotating schedule must be valid")
    }

    fn scheduled_operator(
        index: OperatorIdx,
        btc_seed: u8,
        p2p_seed: u8,
        activation_height: BitcoinBlockHeight,
        deactivation_height: Option<BitcoinBlockHeight>,
    ) -> ScheduledOperator {
        let secret_key =
            SecretKey::from_slice(&[btc_seed; 32]).expect("btc seed must be a secret key");
        let public_key = EvenSecretKey::from(secret_key).public_key(SECP256K1);
        let covenant_key = public_key.x_only_public_key().0;
        let pk_bytes = covenant_key.serialize();
        let payout_descriptor = Descriptor::new_p2tr(&pk_bytes).expect("valid p2tr descriptor");

        ScheduledOperator::new(
            index,
            covenant_key,
            p2p_key(p2p_seed),
            payout_descriptor,
            activation_height,
            deactivation_height,
        )
        .expect("scheduled operator must be valid")
    }

    fn p2p_key(seed: u8) -> P2POperatorPubKey {
        let mut secret_bytes = [seed; 32];
        let secret = P2pSecretKey::try_from_bytes(&mut secret_bytes).expect("valid p2p secret key");

        P2pKeypair::from(secret).public().into()
    }

    fn operator_idx(idx: usize) -> OperatorIdx {
        OperatorIdx::try_from(idx).expect("test operator index must fit in OperatorIdx")
    }

    fn btc_seed(idx: usize) -> u8 {
        u8::try_from(idx + 1).expect("test btc seed must fit in u8")
    }

    fn p2p_seed(idx: usize) -> u8 {
        u8::try_from(idx + 101).expect("test p2p seed must fit in u8")
    }

    fn idxs(indices: impl IntoIterator<Item = OperatorIdx>) -> BTreeSet<OperatorIdx> {
        indices.into_iter().collect()
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
