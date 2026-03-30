//! Primitive types for constructing operator unstaking graphs with rkyv serialization support.

use bitcoin::{hashes::sha256, OutPoint};
use proptest::arbitrary;
use serde::{Deserialize, Serialize};

use crate::{rkyv_wrappers::RkyvOutPoint, PayoutDescriptor};

/// The input to the unstaking transaction.
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
pub struct UnstakingInput {
    /// The input that funds the stake transaction.
    #[rkyv(with = RkyvOutPoint)]
    pub stake_funds: OutPoint,
    /// The unstaking hash image.
    #[rkyv(with = RkyvSha256Hash)]
    pub unstaking_image: sha256::Hash,
    /// The descriptor where the operator wants to receive the unstaked funds.
    pub unstaking_operator_desc: PayoutDescriptor,
}

/// rkyv remote wrapper for `bitcoin::hashes::sha256::Hash`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(remote = sha256::Hash)]
#[doc(hidden)]
pub struct RkyvSha256Hash(#[rkyv(getter = sha256_to_bytes)] [u8; 32]);

impl From<sha256::Hash> for RkyvSha256Hash {
    fn from(value: sha256::Hash) -> Self {
        use bitcoin::hashes::Hash as _;
        Self(value.to_byte_array())
    }
}

impl From<RkyvSha256Hash> for sha256::Hash {
    fn from(value: RkyvSha256Hash) -> Self {
        use bitcoin::hashes::Hash as _;
        sha256::Hash::from_byte_array(value.0)
    }
}

fn sha256_to_bytes(hash: &sha256::Hash) -> [u8; 32] {
    use bitcoin::hashes::Hash as _;
    hash.to_byte_array()
}

impl UnstakingInput {
    /// Returns the stake funds outpoint.
    pub const fn stake_funds(&self) -> OutPoint {
        self.stake_funds
    }

    /// Returns the unstaking hash image.
    pub const fn unstaking_image(&self) -> sha256::Hash {
        self.unstaking_image
    }

    /// Returns a reference to the unstaking operator descriptor.
    pub const fn unstaking_operator_desc(&self) -> &PayoutDescriptor {
        &self.unstaking_operator_desc
    }
}

impl arbitrary::Arbitrary for UnstakingInput {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use bitcoin::hashes::Hash as _;
        use proptest::prelude::*;

        (
            any::<[u8; 32]>(),
            any::<u32>(),
            any::<[u8; 32]>(),
            any::<PayoutDescriptor>(),
        )
            .prop_map(|(txid, vout, image, desc)| Self {
                stake_funds: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(txid),
                    vout,
                },
                unstaking_image: sha256::Hash::from_byte_array(image),
                unstaking_operator_desc: desc,
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

        // Verifies rkyv serialization roundtrip for random UnstakingInput values.
        #[test]
        fn unstaking_input_rkyv_roundtrip(input: UnstakingInput) {
            let bytes = to_bytes::<Error>(&input).expect("serialize");
            let recovered: UnstakingInput = from_bytes::<UnstakingInput, Error>(&bytes).expect("deserialize");
            prop_assert_eq!(input, recovered);
        }
    }
}
