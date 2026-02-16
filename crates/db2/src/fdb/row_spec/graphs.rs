//! Row spec for Graph SM states.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};
use strata_bridge_sm::graph::machine::GraphSM;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Key for a graph state row: `(DepositIdx, OperatorIdx)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphStateKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
    /// Operator index.
    pub operator_idx: OperatorIdx,
}

impl PackableKey for GraphStateKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs
            .graphs
            .pack::<(u32, u32)>(&(self.deposit_idx, self.operator_idx)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx, operator_idx) = dirs.graphs.unpack::<(u32, u32)>(bytes)?;
        Ok(Self {
            deposit_idx,
            operator_idx,
        })
    }
}

impl SerializableValue for GraphSM {
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

/// ZST for the graph state row spec.
#[derive(Debug)]
pub struct GraphStateRowSpec;

impl KVRowSpec for GraphStateRowSpec {
    type Key = GraphStateKey;
    type Value = GraphSM;
}
