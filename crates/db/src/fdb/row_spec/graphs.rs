//! Row spec for Graph SM states.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_sm::graph::machine::GraphSM;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Key for a graph state row: `(DepositIdx, OperatorIdx)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphStateKey(GraphIdx);

impl From<GraphIdx> for GraphStateKey {
    fn from(graph_idx: GraphIdx) -> Self {
        Self(graph_idx)
    }
}

impl From<GraphStateKey> for GraphIdx {
    fn from(key: GraphStateKey) -> Self {
        key.0
    }
}

impl PackableKey for GraphStateKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs
            .graphs
            .pack::<(u32, u32)>(&(self.0.deposit, self.0.operator)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx, operator_idx) = dirs.graphs.unpack::<(u32, u32)>(bytes)?;
        Ok(Self(GraphIdx {
            deposit: deposit_idx,
            operator: operator_idx,
        }))
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
