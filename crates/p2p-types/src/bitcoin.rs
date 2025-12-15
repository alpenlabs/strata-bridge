use bitcoin::{hashes::Hash, hex::DisplayHex};
use serde::{Deserialize, Serialize};

/// A Bitcoin Schnorr XOnly public key.
#[derive(
    Serialize,
    Deserialize,
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
)]
pub struct XOnlyPublicKey([u8; 32]);

impl XOnlyPublicKey {
    /// Outputs the hexadecimal representation of the XOnly public key in lowercase.
    pub fn to_lower_hex_string(&self) -> String {
        self.0.to_lower_hex_string()
    }

    /// Outputs the XOnly public key as raw bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<bitcoin::XOnlyPublicKey> for XOnlyPublicKey {
    fn from(value: bitcoin::XOnlyPublicKey) -> Self {
        Self(value.serialize())
    }
}

impl TryFrom<XOnlyPublicKey> for bitcoin::XOnlyPublicKey {
    type Error = bitcoin::secp256k1::Error;

    fn try_from(value: XOnlyPublicKey) -> Result<Self, Self::Error> {
        bitcoin::XOnlyPublicKey::from_slice(&value.0)
    }
}

/// A Bitcoin transaction identifier (txid).
#[derive(
    Serialize,
    Deserialize,
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
)]
pub struct Txid([u8; 32]);

impl Txid {
    /// Outputs the hexadecimal representation of the txid in lowercase.
    pub fn to_lower_hex_string(&self) -> String {
        self.0.to_lower_hex_string()
    }

    /// Outputs the txid as raw bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<bitcoin::Txid> for Txid {
    fn from(value: bitcoin::Txid) -> Self {
        Self(value.to_raw_hash().to_byte_array())
    }
}

impl From<Txid> for bitcoin::Txid {
    fn from(value: Txid) -> Self {
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(value.0))
    }
}

/// A SHA-256 hash.
#[derive(
    Serialize,
    Deserialize,
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
)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    /// Outputs the hexadecimal representation of the SHA-256 hash in lowercase.
    pub fn to_lower_hex_string(&self) -> String {
        self.0.to_lower_hex_string()
    }

    /// Outputs the SHA-256 hash as raw bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<bitcoin::hashes::sha256::Hash> for Sha256Hash {
    fn from(value: bitcoin::hashes::sha256::Hash) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<Sha256Hash> for bitcoin::hashes::sha256::Hash {
    fn from(value: Sha256Hash) -> Self {
        bitcoin::hashes::sha256::Hash::from_byte_array(value.0)
    }
}

/// Musig2 partial signature.
#[derive(
    Serialize,
    Deserialize,
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
