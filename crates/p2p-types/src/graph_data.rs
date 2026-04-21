//! Primitive types for constructing operator graphs with rkyv serialization support.

use bitcoin::{hashes::Hash as _, OutPoint};
use proptest::arbitrary;
use serde::{Deserialize, Serialize};

use crate::{bitcoin::XOnlyPubKey, rkyv_wrappers::RkyvOutPoint};

/// Deposit-time data required by an operator to construct the transaction graph.
///
/// Produced by the graph owner (the operator whose graph this is) and gossiped to peers.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct GraphData {
    /// UTXO that funds the claim transaction.
    #[rkyv(with = RkyvOutPoint)]
    pub funding_outpoint: OutPoint,

    /// Per-watchtower adaptor pubkeys used in the locking script of the owner's contest
    /// counterproof output. Mosaic produces a distinct adaptor secret per
    /// `(evaluator, garbler)` pair, so there are `n - 1` entries, in operator-table order
    /// with the graph owner skipped.
    pub adaptor_pubkeys: Vec<XOnlyPubKey>,

    /// Per-watchtower fault pubkeys used to lock each counterproof-nack output.
    ///
    /// Entries are in operator-table order with the graph owner skipped, so the length equals
    /// `n - 1` where `n` is the number of operators.
    pub fault_pubkeys: Vec<XOnlyPubKey>,
}

impl GraphData {
    /// Constructs a new [`GraphData`].
    pub const fn new(
        funding_outpoint: OutPoint,
        adaptor_pubkeys: Vec<XOnlyPubKey>,
        fault_pubkeys: Vec<XOnlyPubKey>,
    ) -> Self {
        Self {
            funding_outpoint,
            adaptor_pubkeys,
            fault_pubkeys,
        }
    }
}

impl arbitrary::Arbitrary for GraphData {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<[u8; 32]>(),
            any::<u32>(),
            proptest::collection::vec(any::<XOnlyPubKey>(), 0..8),
            proptest::collection::vec(any::<XOnlyPubKey>(), 0..8),
        )
            .prop_map(|(txid, vout, adaptor_pubkeys, fault_pubkeys)| Self {
                funding_outpoint: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(txid),
                    vout,
                },
                adaptor_pubkeys,
                fault_pubkeys,
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rkyv::{from_bytes, rancor::Error, to_bytes};

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        // Verifies rkyv serialization roundtrip for random GraphData values.
        #[test]
        fn graph_data_rkyv_roundtrip(data: GraphData) {
            let bytes = to_bytes::<Error>(&data).expect("serialize");
            let recovered: GraphData = from_bytes::<GraphData, Error>(&bytes).expect("deserialize");
            prop_assert_eq!(data, recovered);
        }
    }
}
