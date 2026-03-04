//! Row spec for Moho recursive proofs.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::proof::MohoProof;

use crate::fdb::{
    dirs::Directories,
    row_spec::kv::{KVRowSpec, PackableKey, SerializableValue},
};

/// Key for a Moho recursive proof, anchored at an L1 block commitment.
#[derive(Debug)]
pub struct MohoProofKey {
    /// Block height.
    pub height: u32,
    /// Block ID (32 bytes).
    pub blkid: [u8; 32],
}

impl PackableKey for MohoProofKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs
            .moho_proofs
            .pack::<(u32, &[u8])>(&(self.height, self.blkid.as_ref())))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (height, blkid_vec): (u32, Vec<u8>) = dirs.moho_proofs.unpack(bytes)?;

        let blkid: [u8; 32] = blkid_vec.try_into().map_err(|_| PackError::BadPrefix)?;

        Ok(Self { height, blkid })
    }
}

impl SerializableValue for MohoProof {
    type SerializeError = Infallible;
    type DeserializeError = Infallible;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(self.0.clone())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        Ok(MohoProof(bytes.to_vec()))
    }
}

/// ZST for the Moho proof row spec.
#[derive(Debug)]
pub struct MohoProofRowSpec;

impl KVRowSpec for MohoProofRowSpec {
    type Key = MohoProofKey;
    type Value = MohoProof;
}
