//! Primitive types for constructing operator graphs with rkyv serialization support.

use bitcoin::{hashes::Hash as _, OutPoint, Txid};
use proptest::arbitrary;
use serde::{Deserialize, Serialize};

/// The input to the claim transaction.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct ClaimInput(#[rkyv(with = RkyvOutPoint)] OutPoint);

/// rkyv remote wrapper for `bitcoin::OutPoint`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(remote = bitcoin::OutPoint)]
#[doc(hidden)]
pub struct RkyvOutPoint {
    #[rkyv(with = RkyvTxid)]
    txid: bitcoin::Txid,
    vout: u32,
}

impl From<bitcoin::OutPoint> for RkyvOutPoint {
    fn from(value: bitcoin::OutPoint) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

impl From<RkyvOutPoint> for bitcoin::OutPoint {
    fn from(value: RkyvOutPoint) -> Self {
        bitcoin::OutPoint {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

/// rkyv remote wrapper for `bitcoin::Txid`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(remote = Txid)]
#[doc(hidden)]
pub struct RkyvTxid(#[rkyv(getter = txid_to_bytes)] [u8; 32]);

impl From<bitcoin::Txid> for RkyvTxid {
    fn from(value: Txid) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<RkyvTxid> for bitcoin::Txid {
    fn from(value: RkyvTxid) -> Self {
        Txid::from_byte_array(value.0)
    }
}

fn txid_to_bytes(txid: &Txid) -> [u8; 32] {
    txid.to_byte_array()
}

impl ClaimInput {
    /// Returns the wrapped Bitcoin outpoint.
    pub const fn inner(&self) -> OutPoint {
        self.0
    }
}

impl From<OutPoint> for ClaimInput {
    fn from(value: OutPoint) -> Self {
        Self(value)
    }
}

impl From<ClaimInput> for OutPoint {
    fn from(value: ClaimInput) -> Self {
        value.0
    }
}

impl arbitrary::Arbitrary for ClaimInput {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<[u8; 32]>(), any::<u32>())
            .prop_map(|(txid, vout)| {
                Self(OutPoint {
                    txid: bitcoin::Txid::from_byte_array(txid),
                    vout,
                })
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

        // Verifies rkyv serialization roundtrip for random ClaimInput values.
        #[test]
        fn claim_input_rkyv_roundtrip(input: ClaimInput) {
            let bytes = to_bytes::<Error>(&input).expect("serialize");
            let recovered: ClaimInput = from_bytes::<ClaimInput, Error>(&bytes).expect("deserialize");
            prop_assert_eq!(input, recovered);
        }
    }
}
