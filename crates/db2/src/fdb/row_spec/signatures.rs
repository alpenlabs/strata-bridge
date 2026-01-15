//! Row spec for Schnorr signatures.

use std::convert::Infallible;

use bitcoin::{Txid, hashes::Hash};
use foundationdb::tuple::PackError;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::OperatorIdx;
use terrors::OneOf;

use super::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Key for a Schnorr signature.
#[derive(Debug)]
pub struct SignatureKey {
    /// Operator index.
    pub operator_idx: OperatorIdx,
    /// Transaction ID.
    pub txid: Txid,
    /// Input index.
    pub input_index: u32,
}

impl PackableKey for SignatureKey {
    type PackingError = Infallible;
    type UnpackingError = OneOf<(bitcoin::hashes::FromSliceError, PackError)>;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.signatures.pack::<(u32, &[u8], u32)>(&(
            self.operator_idx,
            self.txid.as_raw_hash().as_ref(),
            self.input_index,
        )))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (operator_idx, txid_bytes, input_index) = dirs
            .signatures
            .unpack::<(u32, Vec<u8>, u32)>(bytes)
            .map_err(OneOf::new)?;
        Ok(SignatureKey {
            operator_idx,
            txid: Txid::from_slice(&txid_bytes).map_err(OneOf::new)?,
            input_index,
        })
    }
}

impl SerializableValue for Signature {
    type SerializeError = Infallible;
    type DeserializeError = secp256k1::Error;
    type Serialized = [u8; 64];

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(self.serialize())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        Self::from_slice(bytes)
    }
}

/// ZST for the signature row spec.
#[derive(Debug)]
pub struct SignatureRowSpec;

impl KVRowSpec for SignatureRowSpec {
    type Key = SignatureKey;
    type Value = Signature;
}
