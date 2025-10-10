//! Operator table for the bridge.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
};

use algebra::category;
use bitcoin::{Network, XOnlyPublicKey};
use musig2::KeyAggContext;
use serde::{Deserialize, Serialize};
use strata_bridge_types::PublickeyTable;
use strata_p2p_types::P2POperatorPubKey;

use crate::{build_context::TxBuildContext, types::OperatorIdx};

type OperatorTableEntry = (OperatorIdx, P2POperatorPubKey, secp256k1::PublicKey);

/// A table that maps operator indices to their P2P public keys and bitcoin public keys.
// TODO(proofofkeags): the derived serialization of this data structure is 3x more expensive than
// optimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Returns the index of the proof of work operator.
    pub const fn pov_idx(&self) -> OperatorIdx {
        self.pov
    }

    /// Returns the operator public key for the proof of work operator.
    pub fn pov_p2p_key(&self) -> &P2POperatorPubKey {
        // NOTE(proofofkeags): unwrap is safe because we assert this key is in the map in the
        // constructor.
        &self.idx_key.get(&self.pov).unwrap().0
    }

    /// Returns the bitcoin public key for the proof of work operator.
    pub fn pov_btc_key(&self) -> secp256k1::PublicKey {
        // NOTE(proofofkeags): unwrap is safe because we assert this key is in the map in the
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
}

/// Proptest generators for the operator table.
pub mod prop_test_generators {
    use proptest::{prelude::*, prop_compose};
    use strata_p2p_types::P2POperatorPubKey;

    use super::OperatorTable;
    use crate::secp::EvenSecretKey;

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
