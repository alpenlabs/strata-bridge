//! Row spec for Deposit SM states.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::DepositIdx;
use strata_bridge_sm::deposit::machine::DepositSM;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Key for a deposit state row: a single `DepositIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositStateKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
}

impl PackableKey for DepositStateKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.deposits.pack::<(u32,)>(&(self.deposit_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx,) = dirs.deposits.unpack::<(u32,)>(bytes)?;
        Ok(Self { deposit_idx })
    }
}

impl SerializableValue for DepositSM {
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

/// ZST for the deposit state row spec.
#[derive(Debug)]
pub struct DepositStateRowSpec;

impl KVRowSpec for DepositStateRowSpec {
    type Key = DepositStateKey;
    type Value = DepositSM;
}
