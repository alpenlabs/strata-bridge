//! Row specs for the params a state machine was created under.
//!
//! These rows live in their own subspaces, keyed identically to the state machine rows they
//! describe. Keeping them separate is what lets the SM encodings stay untouched: a deposit
//! persisted before per-SM params existed still decodes, and simply has no params row. The
//! recovery path treats a missing row as "use the node's current params", which is exactly how
//! that deposit has been behaving all along.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
use strata_bridge_sm::{deposit::config::DepositSMCfg, graph::config::GraphSMCfg};

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Encoding version of the persisted params rows.
///
/// Unlike the state machine rows, which are pinned so that old rows keep decoding, these configs
/// are expected to gain fields over time. The tag lets a future reader branch on the layout
/// instead of failing recovery, which is a hard startup abort.
pub const SM_PARAMS_VERSION: u16 = 1;

/// Persisted params for one Deposit SM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedDepositParams {
    /// Encoding version; see [`SM_PARAMS_VERSION`].
    pub version: u16,
    /// The params the deposit was created under.
    pub cfg: DepositSMCfg,
}

impl From<DepositSMCfg> for PersistedDepositParams {
    fn from(cfg: DepositSMCfg) -> Self {
        Self {
            version: SM_PARAMS_VERSION,
            cfg,
        }
    }
}

/// Persisted params for one Graph SM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedGraphParams {
    /// Encoding version; see [`SM_PARAMS_VERSION`].
    pub version: u16,
    /// The params the graph was created under.
    pub cfg: GraphSMCfg,
}

impl From<GraphSMCfg> for PersistedGraphParams {
    fn from(cfg: GraphSMCfg) -> Self {
        Self {
            version: SM_PARAMS_VERSION,
            cfg,
        }
    }
}

/// Key for a deposit params row: a single `DepositIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositParamsKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
}

impl PackableKey for DepositParamsKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.deposit_params.pack::<(u32,)>(&(self.deposit_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx,) = dirs.deposit_params.unpack::<(u32,)>(bytes)?;
        Ok(Self { deposit_idx })
    }
}

/// Key for a graph params row: `(DepositIdx, OperatorIdx)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphParamsKey(GraphIdx);

impl From<GraphIdx> for GraphParamsKey {
    fn from(graph_idx: GraphIdx) -> Self {
        Self(graph_idx)
    }
}

impl From<GraphParamsKey> for GraphIdx {
    fn from(key: GraphParamsKey) -> Self {
        key.0
    }
}

impl PackableKey for GraphParamsKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs
            .graph_params
            .pack::<(u32, u32)>(&(self.0.deposit, self.0.operator)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx, operator_idx) = dirs.graph_params.unpack::<(u32, u32)>(bytes)?;
        Ok(Self(GraphIdx {
            deposit: deposit_idx,
            operator: operator_idx,
        }))
    }
}

impl SerializableValue for PersistedDepositParams {
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

impl SerializableValue for PersistedGraphParams {
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

/// ZST for the deposit params row spec.
#[derive(Debug)]
pub struct DepositParamsRowSpec;

impl KVRowSpec for DepositParamsRowSpec {
    type Key = DepositParamsKey;
    type Value = PersistedDepositParams;
}

/// ZST for the graph params row spec.
#[derive(Debug)]
pub struct GraphParamsRowSpec;

impl KVRowSpec for GraphParamsRowSpec {
    type Key = GraphParamsKey;
    type Value = PersistedGraphParams;
}
