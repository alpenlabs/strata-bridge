//! Payout descriptor type for P2P messaging with rkyv serialization.

use std::fmt;

use bitcoin_bosd::Descriptor;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

/// A payout descriptor serialized as bytes for rkyv compatibility.
///
/// Wraps `bitcoin_bosd::Descriptor` for efficient serialization over P2P.
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Arbitrary,
)]
pub struct PayoutDescriptor(Vec<u8>);

impl PayoutDescriptor {
    /// Creates a new payout descriptor from bytes.
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Parses the descriptor bytes into a `bitcoin_bosd::Descriptor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid descriptor.
    pub fn parse(&self) -> Result<Descriptor, bitcoin_bosd::DescriptorError> {
        Descriptor::from_bytes(&self.0)
    }

    /// Returns the content bytes for signing.
    pub fn content_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PayoutDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.parse() {
            Ok(desc) => write!(f, "{}", desc),
            Err(_) => write!(f, "PayoutDescriptor({} bytes)", self.0.len()),
        }
    }
}

impl From<Descriptor> for PayoutDescriptor {
    fn from(value: Descriptor) -> Self {
        Self(value.to_bytes())
    }
}

impl TryFrom<PayoutDescriptor> for Descriptor {
    type Error = bitcoin_bosd::DescriptorError;

    fn try_from(value: PayoutDescriptor) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Vec<u8>> for PayoutDescriptor {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verifies new() constructor and content_bytes() accessor work correctly.
    #[test]
    fn new_and_content_bytes() {
        let bytes = vec![1, 2, 3, 4, 5];
        let descriptor = PayoutDescriptor::new(bytes.clone());

        assert_eq!(descriptor.content_bytes(), &bytes[..]);
    }

    // Verifies Display shows byte count when descriptor fails to parse.
    #[test]
    fn display_invalid_descriptor_shows_byte_count() {
        let invalid_bytes = vec![0xFF, 0xFE, 0xFD];
        let descriptor = PayoutDescriptor::new(invalid_bytes);

        if descriptor.parse().is_err() {
            let display = format!("{}", descriptor);
            assert!(
                display.contains("3") && display.contains("bytes"),
                "Display should show byte count for invalid descriptor, got: {}",
                display
            );
        } else {
            panic!("Expected descriptor to fail parsing");
        }
    }

    // Verifies empty descriptor is handled correctly.
    #[test]
    fn empty_descriptor() {
        let descriptor = PayoutDescriptor::new(vec![]);

        assert!(descriptor.content_bytes().is_empty());
    }

    mod proptests {
        use proptest::prelude::*;
        use rkyv::{from_bytes, rancor::Error, to_bytes};

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            // Verifies rkyv serialization roundtrip for random PayoutDescriptor values.
            #[test]
            fn payout_descriptor_rkyv_roundtrip(desc: PayoutDescriptor) {
                let bytes = to_bytes::<Error>(&desc).expect("serialize");
                let recovered: PayoutDescriptor = from_bytes::<PayoutDescriptor, Error>(&bytes).expect("deserialize");
                prop_assert_eq!(desc, recovered);
            }

            // Verifies JSON serialization roundtrip for random PayoutDescriptor values.
            #[test]
            fn payout_descriptor_json_roundtrip(desc: PayoutDescriptor) {
                let json = serde_json::to_string(&desc).expect("serialize");
                let recovered: PayoutDescriptor = serde_json::from_str(&json).expect("deserialize");
                prop_assert_eq!(desc, recovered);
            }
        }
    }
}
