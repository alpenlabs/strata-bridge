//! Type specifications for key-value pairs stored in FDB.

use std::fmt::Debug;

use crate::fdb::dirs::Directories;

/// Type specification for a KV pair stored in FDB.
pub trait KVRowSpec {
    /// Type of the key.
    type Key: PackableKey;
    /// Type of the value.
    type Value: SerializableValue;
}

/// A key that can be packed and unpacked into bytes. This is effective
/// serialization and deserialization, using FDB's terminology for keys
/// specifically.
pub trait PackableKey: Sized {
    /// Error type that can occur during packing.
    type PackingError: Debug + Send + Sync + 'static;

    /// Error type that can occur during unpacking.
    type UnpackingError: Debug + Send + Sync + 'static;

    /// Packed representation of the key.
    type Packed: AsRef<[u8]> + Clone + Send + Sync;

    /// Packs the key into bytes. The packing process should be contained within
    /// a relevant directory specified in the `Directories` type.
    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError>;

    /// Unpacks the key from bytes. The bytes provided contain the entire key,
    /// including any directory prefixes.
    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError>;
}

/// A value that can be serialized and deserialized into bytes.
pub trait SerializableValue: Sized {
    /// Error type that can occur during serialization.
    type SerializeError: Debug + Send + Sync + 'static;

    /// Error type that can occur during deserialization.
    type DeserializeError: Debug + Send + Sync + 'static;

    /// Serialized representation of the value.
    type Serialized: AsRef<[u8]> + Clone + Send + Sync;

    /// Serializes self to bytes.
    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError>;

    /// Deserializes self from bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError>;
}
