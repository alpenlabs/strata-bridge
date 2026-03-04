//! Row spec for ASM step proofs.

use std::convert::Infallible;

use foundationdb::tuple::PackError;
use strata_bridge_primitives::proof::AsmProof;

use crate::fdb::{
    dirs::Directories,
    row_spec::kv::{KVRowSpec, PackableKey, SerializableValue},
};

/// Key for an ASM step proof, representing an L1 range.
#[derive(Debug)]
pub struct AsmProofKey {
    /// Start height of the L1 range.
    pub start_height: u32,
    /// Start block ID (32 bytes).
    pub start_blkid: [u8; 32],
    /// End height of the L1 range.
    pub end_height: u32,
    /// End block ID (32 bytes).
    pub end_blkid: [u8; 32],
}

impl PackableKey for AsmProofKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.asm_proofs.pack::<(u32, &[u8], u32, &[u8])>(&(
            self.start_height,
            self.start_blkid.as_ref(),
            self.end_height,
            self.end_blkid.as_ref(),
        )))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (start_height, start_blkid_vec, end_height, end_blkid_vec): (
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
        ) = dirs.asm_proofs.unpack(bytes)?;

        let start_blkid: [u8; 32] = start_blkid_vec
            .try_into()
            .map_err(|_| PackError::BadPrefix)?;
        let end_blkid: [u8; 32] = end_blkid_vec.try_into().map_err(|_| PackError::BadPrefix)?;

        Ok(Self {
            start_height,
            start_blkid,
            end_height,
            end_blkid,
        })
    }
}

impl SerializableValue for AsmProof {
    type SerializeError = Infallible;
    type DeserializeError = Infallible;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(self.0.clone())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        Ok(AsmProof(bytes.to_vec()))
    }
}

/// ZST for the ASM proof row spec.
#[derive(Debug)]
pub struct AsmProofRowSpec;

impl KVRowSpec for AsmProofRowSpec {
    type Key = AsmProofKey;
    type Value = AsmProof;
}
