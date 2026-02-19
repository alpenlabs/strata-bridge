//! Types that are used across the bridge.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::XOnlyPublicKey;
use musig2::{errors::KeyAggError, KeyAggContext};
use proptest_derive::Arbitrary;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use strata_primitives::bitcoin_bosd::{Descriptor, DescriptorError, DescriptorType};

/// The index of an operator.
pub type OperatorIdx = u32;

/// The index of a deposit.
pub type DepositIdx = u32;

/// A struct that represents the index of a peg out graph, which is a combination of a deposit index
/// and an operator index.
// NOTE: (@Rajil1213) this uses a struct instead of a tuple struct or newtype for better readability
// and to avoid confusion about the order of the indices as they're both of the same type (u32).
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Arbitrary,
)]
#[rkyv(attr(expect(missing_docs)))]
pub struct GraphIdx {
    /// The index of the deposit that a peg out graph is associated with.
    pub deposit: DepositIdx,
    /// The index of the operator that can initiate unilateral withdrawals using the peg out graph.
    pub operator: OperatorIdx,
}

impl Display for GraphIdx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GraphIdx(deposit: {}, operator: {})",
            self.deposit, self.operator
        )
    }
}

/// The height of a bitcoin block.
pub type BitcoinBlockHeight = u64;

/// A table that maps [`OperatorIdx`] to the corresponding [`PublicKey`].
///
/// We use a [`PublicKey`] instead of an [`secp256k1::XOnlyPublicKey`] for convenience
/// since the [`musig2`] crate has functions that expect a [`PublicKey`] and this table is most
/// useful for interacting with those functions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublickeyTable(pub BTreeMap<OperatorIdx, PublicKey>);

impl From<BTreeMap<OperatorIdx, PublicKey>> for PublickeyTable {
    fn from(value: BTreeMap<OperatorIdx, PublicKey>) -> Self {
        Self(value)
    }
}

impl From<PublickeyTable> for Vec<PublicKey> {
    fn from(value: PublickeyTable) -> Self {
        value.0.values().copied().collect()
    }
}

impl TryFrom<PublickeyTable> for KeyAggContext {
    type Error = KeyAggError;

    fn try_from(value: PublickeyTable) -> Result<Self, Self::Error> {
        KeyAggContext::new(Into::<Vec<PublicKey>>::into(value))
    }
}

/// Convert a [`Descriptor`] into an [`XOnlyPublicKey`].
///
/// # Errors
///
/// If the descriptor is not of type `P2tr`.
pub fn descriptor_to_x_only_pubkey(
    descriptor: &Descriptor,
) -> Result<XOnlyPublicKey, DescriptorError> {
    match descriptor.type_tag() {
        DescriptorType::P2tr => Ok(XOnlyPublicKey::from_slice(descriptor.payload())
            .expect("P2tr payload must be 32 bytes")),
        other => Err(DescriptorError::InvalidDescriptorType(other.to_u8())),
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{rand, Keypair, Secp256k1};

    use super::*;

    #[test]
    fn convert_descriptor_to_x_only_pubkey() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let (expected, _) = XOnlyPublicKey::from_keypair(&keypair);
        let descriptor: Descriptor = expected.into();
        let actual = descriptor_to_x_only_pubkey(&descriptor).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn converting_non_x_only_pubkey_descriptor_fails() {
        let err = descriptor_to_x_only_pubkey(&Descriptor::new_op_return(&[1, 2, 3]).unwrap())
            .unwrap_err();
        assert!(matches!(err, DescriptorError::InvalidDescriptorType(_)));
    }
}
