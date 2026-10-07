//! Storage for the singleton operator set.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_sm::operator_set::OperatorSetSM;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Versioned singleton key.
#[derive(Debug, Clone, Copy)]
pub struct OperatorSetKey;

impl PackableKey for OperatorSetKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.operator_set.pack(&(1u32,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (version,) = dirs.operator_set.unpack::<(u32,)>(bytes)?;
        if version != 1 {
            return Err(PackError::Message(
                format!("unsupported operator_set version {version}").into(),
            ));
        }
        Ok(Self)
    }
}

impl SerializableValue for OperatorSetSM {
    type SerializeError = postcard::Error;
    type DeserializeError = postcard::Error;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        postcard::to_allocvec(self)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        postcard::from_bytes(bytes)
    }
}

/// Row binding for the singleton operator set.
#[derive(Debug)]
pub struct OperatorSetRowSpec;

impl KVRowSpec for OperatorSetRowSpec {
    type Key = OperatorSetKey;
    type Value = OperatorSetSM;
}
