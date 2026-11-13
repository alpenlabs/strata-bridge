//! Row specs for state machine configs and the config each deposit is pinned to.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::DepositIdx;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::{
    fdb::dirs::Directories,
    types::{ConfigId, PinnedConfig},
};

/// Key for a config row: the [`ConfigId`] of its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigKey {
    /// Hash of the stored config bytes.
    pub id: ConfigId,
}

impl PackableKey for ConfigKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.configs.pack(&(self.id.0.as_slice(),)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (id,) = dirs.configs.unpack::<(Vec<u8>,)>(bytes)?;
        Ok(Self {
            id: decode_config_id(&id)?,
        })
    }
}

impl SerializableValue for PinnedConfig {
    type SerializeError = Infallible;
    type DeserializeError = postcard::Error;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(self.bytes().to_vec())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        Self::decode(bytes)
    }
}

/// ZST for the config row spec.
#[derive(Debug)]
pub struct ConfigRowSpec;

impl KVRowSpec for ConfigRowSpec {
    type Key = ConfigKey;
    type Value = PinnedConfig;
}

/// Key for a deposit's config reference: a single `DepositIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositConfigKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
}

impl PackableKey for DepositConfigKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.deposit_configs.pack::<(u32,)>(&(self.deposit_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx,) = dirs.deposit_configs.unpack::<(u32,)>(bytes)?;
        Ok(Self { deposit_idx })
    }
}

impl SerializableValue for ConfigId {
    type SerializeError = Infallible;
    type DeserializeError = PackError;
    type Serialized = [u8; 32];

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(self.0)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        decode_config_id(bytes)
    }
}

/// ZST for the deposit config reference row spec.
#[derive(Debug)]
pub struct DepositConfigRowSpec;

impl KVRowSpec for DepositConfigRowSpec {
    type Key = DepositConfigKey;
    type Value = ConfigId;
}

fn decode_config_id(bytes: &[u8]) -> Result<ConfigId, PackError> {
    bytes
        .try_into()
        .map(ConfigId)
        .map_err(|_| PackError::Message("invalid config id length".into()))
}
