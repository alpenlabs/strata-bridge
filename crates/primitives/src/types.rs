//! Types that are used across the bridge.

use std::{collections::BTreeMap, fmt, fmt::Display, num::NonZero};

use bitcoin::XOnlyPublicKey;
use bitcoin_bosd::{Descriptor, DescriptorError, DescriptorType};
use hex::ToHex;
use libp2p_identity::ed25519::PublicKey as P2pPublicKey;
use musig2::{errors::KeyAggError, KeyAggContext};
#[cfg(feature = "proptest")]
use proptest_derive::Arbitrary;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// The index of an operator.
pub type OperatorIdx = u32;

/// The index of a watchtower.
///
/// Watchtower indices correspond to the watchtower slots in each game graph.
/// The index is relative to the operator index of the graph owner.
pub type WatchtowerIdx = u32;

/// The index of a deposit.
pub type DepositIdx = u32;

/// Bridge v1 game index: [`DepositIdx`] + 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct GameIndex(NonZero<u32>);

impl GameIndex {
    /// Wraps a [`NonZero<u32>`] as a `GameIndex` without conversion.
    pub const fn from_nonzero(value: NonZero<u32>) -> Self {
        Self(value)
    }

    /// Returns the 1-indexed game number as a [`u32`].
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl Display for GameIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl From<NonZero<u32>> for GameIndex {
    fn from(value: NonZero<u32>) -> Self {
        Self(value)
    }
}

impl From<GameIndex> for NonZero<u32> {
    fn from(value: GameIndex) -> Self {
        value.0
    }
}

/// [`DepositIdx`] cannot be mapped to a [`GameIndex`] because `idx + 1` overflows `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("deposit index {0} overflows when mapped to game index")]
pub struct DepositIdxOverflow(pub DepositIdx);

impl TryFrom<DepositIdx> for GameIndex {
    type Error = DepositIdxOverflow;

    fn try_from(idx: DepositIdx) -> Result<Self, Self::Error> {
        idx.checked_add(1)
            .and_then(NonZero::new)
            .map(Self)
            .ok_or(DepositIdxOverflow(idx))
    }
}

impl From<GameIndex> for DepositIdx {
    fn from(value: GameIndex) -> Self {
        value.0.get() - 1
    }
}

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
)]
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
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

/// P2P [`P2POperatorPubKey`] serves as an identifier of protocol entity.
///
/// De facto this is a wrapper over [`PublicKey`].
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
pub struct P2POperatorPubKey(#[serde(with = "hex::serde")] Vec<u8>);

impl fmt::Display for P2POperatorPubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.encode_hex::<String>())
    }
}

impl AsRef<[u8]> for P2POperatorPubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for P2POperatorPubKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<P2POperatorPubKey> for Vec<u8> {
    fn from(value: P2POperatorPubKey) -> Self {
        value.0
    }
}

impl From<P2pPublicKey> for P2POperatorPubKey {
    fn from(value: P2pPublicKey) -> Self {
        Self(value.to_bytes().to_vec())
    }
}

impl P2POperatorPubKey {
    /// Verifies the `message` using the `signature` against this [`P2POperatorPubKey`].
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match P2pPublicKey::try_from_bytes(&self.0) {
            Ok(key) => key.verify(message, signature),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p_identity::ed25519::Keypair as P2pKeypair;
    use secp256k1::{
        rand::{self, rngs::OsRng, Rng},
        Keypair, SECP256K1,
    };

    use super::*;

    // Helper to generate random ed25519 keypair for testing.
    fn test_keypair() -> P2pKeypair {
        let mut secret_bytes: [u8; 32] = OsRng.gen();
        let secret =
            libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes).unwrap();
        P2pKeypair::from(secret)
    }

    // Verifies From<PublicKey> conversion preserves bytes.
    #[test]
    fn from_public_key() {
        let keypair = test_keypair();
        let public_key = keypair.public();
        let p2p_key: P2POperatorPubKey = public_key.clone().into();

        assert_eq!(p2p_key.as_ref(), public_key.to_bytes().as_slice());
    }

    // Verifies Display trait outputs lowercase hex.
    #[test]
    fn display_shows_hex() {
        let bytes = vec![0xAB, 0xCD, 0xEF];
        let p2p_key = P2POperatorPubKey(bytes);

        let display = format!("{}", p2p_key);
        assert_eq!(display, "abcdef");
    }

    // Verifies verification returns false for invalid public key bytes.
    #[test]
    fn verify_fails_with_invalid_key_bytes() {
        let invalid_bytes = vec![0xFF; 32];
        let p2p_key = P2POperatorPubKey(invalid_bytes);

        let message = b"test message";
        let signature = vec![0u8; 64];

        assert!(
            !p2p_key.verify(message, &signature),
            "Invalid key bytes should return false"
        );
    }

    // Verifies DepositIdx <-> GameIndex round-trips and that u32::MAX overflows.
    #[test]
    fn game_index_try_from_deposit_idx() {
        // Boundary: deposit 0 -> game 1.
        let zero = GameIndex::try_from(0u32).expect("0 maps to game 1");
        assert_eq!(zero.get(), 1);
        assert_eq!(DepositIdx::from(zero), 0);

        // Mid-range round-trip.
        let mid = GameIndex::try_from(42u32).expect("42 maps to game 43");
        assert_eq!(mid.get(), 43);
        assert_eq!(DepositIdx::from(mid), 42);

        // Largest valid deposit index: u32::MAX - 1 -> game u32::MAX.
        let max_valid =
            GameIndex::try_from(u32::MAX - 1).expect("u32::MAX - 1 maps to game u32::MAX");
        assert_eq!(max_valid.get(), u32::MAX);
        assert_eq!(DepositIdx::from(max_valid), u32::MAX - 1);

        // Overflow: u32::MAX has no representable game index.
        assert_eq!(
            GameIndex::try_from(u32::MAX),
            Err(DepositIdxOverflow(u32::MAX))
        );
    }

    #[cfg(feature = "proptest")]
    mod proptests {
        use proptest::prelude::*;
        use rkyv::{from_bytes, rancor::Error, to_bytes};

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            // Verifies rkyv serialization roundtrip for random P2POperatorPubKey values.
            #[test]
            fn p2p_operator_pub_key_rkyv_roundtrip(key: P2POperatorPubKey) {
                let bytes = to_bytes::<Error>(&key).expect("serialize");
                let recovered: P2POperatorPubKey = from_bytes::<P2POperatorPubKey, Error>(&bytes).expect("deserialize");
                prop_assert_eq!(key, recovered);
            }

            // Verifies JSON serialization roundtrip for random P2POperatorPubKey values.
            #[test]
            fn p2p_operator_pub_key_json_roundtrip(key: P2POperatorPubKey) {
                let json = serde_json::to_string(&key).expect("serialize");
                let recovered: P2POperatorPubKey = serde_json::from_str(&json).expect("deserialize");
                prop_assert_eq!(key, recovered);
            }

            // Verifies Vec<u8> conversion roundtrip for random bytes.
            #[test]
            fn p2p_operator_pub_key_vec_roundtrip(bytes: Vec<u8>) {
                let key: P2POperatorPubKey = bytes.clone().into();
                let recovered: Vec<u8> = key.into();
                prop_assert_eq!(bytes, recovered);
            }
        }
    }

    #[test]
    fn convert_descriptor_to_x_only_pubkey() {
        let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
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
