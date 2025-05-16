use std::collections::{BTreeMap, BTreeSet};

use bitcoin::Network;
use musig2::KeyAggContext;
use serde::{Deserialize, Serialize};
use strata_p2p_types::P2POperatorPubKey;
use strata_primitives::bridge::PublickeyTable;

use crate::{build_context::TxBuildContext, types::OperatorIdx};

// TODO(proofofkeags): the derived serialization of this data structure is 3x more expensive than
// optimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorTable {
    pov: OperatorIdx,
    idx_key: BTreeMap<OperatorIdx, (P2POperatorPubKey, secp256k1::PublicKey)>,
    op_key: BTreeMap<P2POperatorPubKey, (OperatorIdx, secp256k1::PublicKey)>,
    btc_key: BTreeMap<secp256k1::PublicKey, (OperatorIdx, P2POperatorPubKey)>,
}
impl OperatorTable {
    pub fn new(
        entries: Vec<(OperatorIdx, P2POperatorPubKey, secp256k1::PublicKey)>,
        pov: OperatorIdx,
    ) -> Option<Self> {
        let mut idx_key = BTreeMap::new();
        let mut op_key = BTreeMap::new();
        let mut btc_key = BTreeMap::new();
        for entry in entries {
            if idx_key
                .insert(entry.0, (entry.1.clone(), entry.2))
                .is_some()
                || op_key.insert(entry.1.clone(), (entry.0, entry.2)).is_some()
                || btc_key.insert(entry.2, (entry.0, entry.1)).is_some()
            {
                // This means we have a duplicate value which indicates a problem.
                return None;
            }
        }

        // NOTE(proofofkeags): do not remove this without removing unwraps in pov_* functions.
        if !idx_key.contains_key(&pov) {
            // This means that the pov is invalid wrt the table entries.
            return None;
        }

        Some(OperatorTable {
            pov,
            idx_key,
            op_key,
            btc_key,
        })
    }

    pub fn idx_to_op_key<'a>(&'a self, idx: &OperatorIdx) -> Option<&'a P2POperatorPubKey> {
        self.idx_key.get(idx).map(|x| &x.0)
    }

    pub fn idx_to_btc_key(&self, idx: &OperatorIdx) -> Option<secp256k1::PublicKey> {
        self.idx_key.get(idx).map(|x| x.1)
    }

    pub fn op_key_to_idx(&self, op_key: &P2POperatorPubKey) -> Option<OperatorIdx> {
        self.op_key.get(op_key).map(|x| x.0)
    }

    pub fn op_key_to_btc_key(&self, op_key: &P2POperatorPubKey) -> Option<secp256k1::PublicKey> {
        self.op_key.get(op_key).map(|x| x.1)
    }

    pub fn btc_key_to_idx(&self, btc_key: &secp256k1::PublicKey) -> Option<OperatorIdx> {
        self.btc_key.get(btc_key).map(|x| x.0)
    }

    pub fn btc_key_to_op_key<'a>(
        &'a self,
        btc_key: &secp256k1::PublicKey,
    ) -> Option<&'a P2POperatorPubKey> {
        self.btc_key.get(btc_key).map(|x| &x.1)
    }

    pub fn pov_idx(&self) -> OperatorIdx {
        self.pov
    }

    pub fn pov_op_key(&self) -> &P2POperatorPubKey {
        // NOTE(proofofkeags): unwrap is safe because we assert this key is in the map in the
        // constructor.
        &self.idx_key.get(&self.pov).unwrap().0
    }

    pub fn pov_btc_key(&self) -> secp256k1::PublicKey {
        // NOTE(proofofkeags): unwrap is safe because we assert this key is in the map in the
        // constructor.
        self.idx_key.get(&self.pov).unwrap().1
    }

    pub fn cardinality(&self) -> usize {
        self.idx_key.len()
    }

    /// Returns the musig2 public keys for the operators in the table in their canonical order
    /// i.e., the order of their indices.
    pub fn btc_keys(&self) -> impl IntoIterator<Item = secp256k1::PublicKey> + use<'_> {
        self.idx_key.values().map(|(_, btc_key)| *btc_key)
    }

    pub fn p2p_keys(&self) -> BTreeSet<P2POperatorPubKey> {
        self.op_key.keys().cloned().collect()
    }

    pub fn operator_idxs(&self) -> BTreeSet<OperatorIdx> {
        self.idx_key.keys().copied().collect()
    }

    pub fn public_key_table(&self) -> PublickeyTable {
        PublickeyTable(self.idx_key.iter().map(|(k, v)| (*k, v.1)).collect())
    }

    pub fn aggregated_btc_key(&self) -> secp256k1::PublicKey {
        let pks: Vec<secp256k1::PublicKey> = self.btc_keys().into_iter().collect();

        KeyAggContext::new(pks).unwrap().aggregated_pubkey()
    }

    pub fn tx_build_context(&self, network: Network) -> TxBuildContext {
        TxBuildContext::new(network, self.public_key_table(), self.pov)
    }

    pub fn convert_map_op_to_btc<V>(
        &self,
        map: BTreeMap<P2POperatorPubKey, V>,
    ) -> Result<BTreeMap<secp256k1::PublicKey, V>, P2POperatorPubKey> {
        map.into_iter()
            .map(|(op, v)| {
                self.op_key_to_btc_key(&op)
                    .map_or(Err(op), |btc| Ok((btc, v)))
            })
            .collect()
    }
}

pub mod prop_test_generators {
    use proptest::{prelude::*, prop_compose};
    use strata_p2p_types::P2POperatorPubKey;

    use super::OperatorTable;

    prop_compose! {
        pub fn arb_p2p_key()(pk in arb_btc_key()) -> P2POperatorPubKey {
            P2POperatorPubKey::from(Vec::from(pk.serialize()))
        }
    }

    prop_compose! {
        pub fn arb_btc_key()(
            sk in any::<[u8; 32]>()
                .no_shrink()
                .prop_filter_map(
                    "invalid secret key",
                    |bs| secp256k1::SecretKey::from_slice(&bs).ok()
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
            OperatorTable::new(indexed, pov % size)
        }
    }

    prop_compose! {
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
