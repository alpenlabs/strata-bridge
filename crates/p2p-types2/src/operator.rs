//! Operators need to exchange (authenticated) messages which are signed with P2P
//! [`P2POperatorPubKey`].

use std::fmt;

use hex::ToHex;
use libp2p_identity::ed25519::PublicKey;
use proptest_derive::Arbitrary;

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
    Arbitrary,
)]
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

impl From<strata_bridge_p2p_types::P2POperatorPubKey> for P2POperatorPubKey {
    fn from(value: strata_bridge_p2p_types::P2POperatorPubKey) -> Self {
        Self(value.into())
    }
}

impl From<P2POperatorPubKey> for strata_bridge_p2p_types::P2POperatorPubKey {
    fn from(value: P2POperatorPubKey) -> Self {
        Self::from(Vec::from(value))
    }
}

impl From<PublicKey> for P2POperatorPubKey {
    fn from(value: PublicKey) -> Self {
        Self(value.to_bytes().to_vec())
    }
}

impl P2POperatorPubKey {
    /// Verifies the `message` using the `signature` against this [`P2POperatorPubKey`].
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match PublicKey::try_from_bytes(&self.0) {
            Ok(key) => key.verify(message, signature),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p_identity::ed25519::Keypair;
    use secp256k1::rand::{rngs::OsRng, Rng};

    use super::*;

    // Helper to generate random ed25519 keypair for testing.
    fn test_keypair() -> Keypair {
        let mut secret_bytes: [u8; 32] = OsRng.gen();
        let secret =
            libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes).unwrap();
        Keypair::from(secret)
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
}
