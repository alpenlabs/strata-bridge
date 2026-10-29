//! Row specs for the params a state machine was created under, keyed like its state row.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use serde::{Serialize, de::DeserializeOwned};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
use strata_bridge_sm::{deposit::config::DepositSMCfg, graph::config::GraphSMCfg};

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Encoding version of the persisted params rows.
///
/// The state machine rows carry no version and are pinned instead; these configs are expected to
/// gain fields, so each row leads with this tag and a reader rejects any tag it does not know.
///
/// Rejection fails recovery, so bumping this is forward-only: a node that has written a row under
/// a newer version cannot be rolled back to a binary that predates it.
pub const SM_PARAMS_VERSION: u16 = 1;

/// The params a state machine was created under, prefixed with [`SM_PARAMS_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedParams<T>(pub T);

/// A params row whose version tag this binary does not know.
#[derive(Debug)]
pub enum ParamsDecodeError {
    /// The row was written with a different [`SM_PARAMS_VERSION`].
    UnknownVersion(u16),
    /// The row's bytes did not decode.
    Postcard(postcard::Error),
}

impl<T: Serialize + DeserializeOwned> SerializableValue for PersistedParams<T> {
    type SerializeError = postcard::Error;
    type DeserializeError = ParamsDecodeError;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        postcard::to_allocvec(&(SM_PARAMS_VERSION, &self.0))
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        // Check the tag before decoding the body: postcard ignores trailing bytes, so a newer
        // layout could otherwise decode into this one's fields without error.
        let (version, body) =
            postcard::take_from_bytes::<u16>(bytes).map_err(ParamsDecodeError::Postcard)?;
        if version != SM_PARAMS_VERSION {
            return Err(ParamsDecodeError::UnknownVersion(version));
        }
        postcard::from_bytes(body)
            .map(Self)
            .map_err(ParamsDecodeError::Postcard)
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

/// ZST for the deposit params row spec.
#[derive(Debug)]
pub struct DepositParamsRowSpec;

impl KVRowSpec for DepositParamsRowSpec {
    type Key = DepositParamsKey;
    type Value = PersistedParams<DepositSMCfg>;
}

/// ZST for the graph params row spec.
#[derive(Debug)]
pub struct GraphParamsRowSpec;

impl KVRowSpec for GraphParamsRowSpec {
    type Key = GraphParamsKey;
    type Value = PersistedParams<GraphSMCfg>;
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Network};
    use strata_bridge_test_utils::bridge_fixtures::{TEST_MAGIC_BYTES, TEST_SWEEP_FEE_RATE};

    use super::*;

    fn cfg() -> DepositSMCfg {
        DepositSMCfg {
            network: Network::Regtest,
            cooperative_payout_timeout_blocks: 144,
            deposit_amount: Amount::from_sat(1_000_000_000),
            operator_fee: Amount::from_sat(1_000),
            magic_bytes: TEST_MAGIC_BYTES.into(),
            recovery_delay: 1_008,
            sweep_fee_rate: TEST_SWEEP_FEE_RATE,
        }
    }

    #[test]
    fn current_version_roundtrips() {
        let bytes = PersistedParams(cfg()).serialize().unwrap();
        assert_eq!(
            PersistedParams::<DepositSMCfg>::deserialize(&bytes).unwrap(),
            PersistedParams(cfg())
        );
    }

    /// A newer row must be rejected, not decoded as the current layout.
    #[test]
    fn unknown_version_is_rejected() {
        let bytes = postcard::to_allocvec(&(SM_PARAMS_VERSION + 1, cfg())).unwrap();
        assert!(matches!(
            PersistedParams::<DepositSMCfg>::deserialize(&bytes),
            Err(ParamsDecodeError::UnknownVersion(v)) if v == SM_PARAMS_VERSION + 1
        ));
    }
}
