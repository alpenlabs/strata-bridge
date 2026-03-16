use proptest_derive::Arbitrary;

/// Musig2 partial signature.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Arbitrary,
)]
pub struct PartialSignature([u8; 32]);

impl PartialSignature {
    /// Outputs the partial signature as raw bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<musig2::PartialSignature> for PartialSignature {
    fn from(value: musig2::PartialSignature) -> Self {
        Self(value.serialize())
    }
}

impl TryFrom<PartialSignature> for musig2::PartialSignature {
    type Error = musig2::secp::errors::InvalidScalarBytes;

    fn try_from(value: PartialSignature) -> Result<Self, Self::Error> {
        musig2::PartialSignature::from_slice(&value.0)
    }
}

/// Musig2 public nonce.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Arbitrary,
)]
pub struct PubNonce([u8; 66]);

impl PubNonce {
    /// Outputs the public nonce as raw bytes.
    pub const fn to_bytes(&self) -> [u8; 66] {
        self.0
    }
}

impl From<musig2::PubNonce> for PubNonce {
    fn from(value: musig2::PubNonce) -> Self {
        Self(value.serialize())
    }
}

impl TryFrom<PubNonce> for musig2::PubNonce {
    type Error = musig2::errors::DecodeError<musig2::PubNonce>;

    fn try_from(value: PubNonce) -> Result<Self, Self::Error> {
        musig2::PubNonce::try_from(value.0)
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::musig2::{generate_partial_signature, generate_pubnonce};

    use super::*;

    // Verifies to_bytes returns the correct 32-byte representation.
    #[test]
    fn partial_signature_to_bytes() {
        let musig2_partial = generate_partial_signature();
        let original_bytes = musig2_partial.serialize();
        let partial: PartialSignature = musig2_partial.into();

        let bytes = partial.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, original_bytes);
    }

    // Verifies musig2::PartialSignature -> PartialSignature -> musig2::PartialSignature roundtrip.
    #[test]
    fn partial_signature_roundtrip() {
        let original_musig2 = generate_partial_signature();
        let original_bytes = original_musig2.serialize();
        let partial: PartialSignature = original_musig2.into();
        let recovered: musig2::PartialSignature = partial.try_into().unwrap();

        assert_eq!(original_bytes, recovered.serialize());
    }

    // Verifies to_bytes returns the correct 66-byte representation.
    #[test]
    fn pubnonce_to_bytes() {
        let musig2_nonce = generate_pubnonce();
        let nonce: PubNonce = musig2_nonce.into();

        let bytes = nonce.to_bytes();
        assert_eq!(bytes.len(), 66);
    }

    // Verifies musig2::PubNonce -> PubNonce -> musig2::PubNonce roundtrip.
    #[test]
    fn pubnonce_roundtrip() {
        let original_musig2 = generate_pubnonce();
        let original_bytes = original_musig2.serialize();
        let nonce: PubNonce = original_musig2.into();
        let recovered: musig2::PubNonce = nonce.try_into().unwrap();

        assert_eq!(original_bytes, recovered.serialize());
    }

    mod proptests {
        use proptest::prelude::*;
        use rkyv::{from_bytes, rancor::Error, to_bytes};

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            // Verifies rkyv serialization roundtrip for random PartialSignature values.
            #[test]
            fn partial_signature_rkyv_roundtrip(sig: PartialSignature) {
                let bytes = to_bytes::<Error>(&sig).expect("serialize");
                let recovered: PartialSignature = from_bytes::<PartialSignature, Error>(&bytes).expect("deserialize");
                prop_assert_eq!(sig, recovered);
            }

            // Verifies rkyv serialization roundtrip for random PubNonce values.
            #[test]
            fn pubnonce_rkyv_roundtrip(nonce: PubNonce) {
                let bytes = to_bytes::<Error>(&nonce).expect("serialize");
                let recovered: PubNonce = from_bytes::<PubNonce, Error>(&bytes).expect("deserialize");
                prop_assert_eq!(nonce, recovered);
            }
        }
    }
}
