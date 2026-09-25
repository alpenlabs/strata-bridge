//! Row spec for Stake SM states.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::covenant::StakeKey;
use strata_bridge_sm::stake::machine::StakeSM;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Key for a stake state row: a covenant-qualified [`StakeKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeStateKey {
    /// Covenant and permanent stake owner.
    pub stake_key: StakeKey,
}

impl PackableKey for StakeStateKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.stakes.pack(&(self.stake_key.to_bytes().as_slice(),)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (key,) = dirs.stakes.unpack::<(Vec<u8>,)>(bytes)?;
        Ok(Self {
            stake_key: decode_stake_key(key)?,
        })
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

/// Decodes the covenant-qualified storage identity.
pub(super) fn decode_stake_key(bytes: Vec<u8>) -> Result<StakeKey, PackError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| PackError::Message("invalid stake key length".into()))?;
    StakeKey::from_bytes(bytes).map_err(|err| PackError::Message(err.to_string().into()))
}
