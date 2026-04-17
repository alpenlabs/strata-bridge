//! Row spec for Stake SM states.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_sm::stake::machine::StakeSM;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Key for a stake state row: a single [`OperatorIdx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeStateKey {
    /// Operator index.
    pub operator_idx: OperatorIdx,
}

impl PackableKey for StakeStateKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.stakes.pack::<(u32,)>(&(self.operator_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (operator_idx,) = dirs.stakes.unpack::<(u32,)>(bytes)?;
        Ok(Self { operator_idx })
    }
}

impl SerializableValue for StakeSM {
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

/// ZST for the stake state row spec.
#[derive(Debug)]
pub struct StakeStateRowSpec;

impl KVRowSpec for StakeStateRowSpec {
    type Key = StakeStateKey;
    type Value = StakeSM;
}
