//! Row spec for the singleton safe-harbour latch.
//!
//! Only one safe-harbour address is ever latched per node, so this uses a
//! singleton key (the empty tuple) under a dedicated subspace. The presence of
//! the row encodes activation: the bridge writes it exactly once, on the first
//! observation of an activated safe harbour, and never clears it.

use foundationdb::tuple::PackError;
use strata_asm_proto_bridge_v1_types::SafeHarbourAddress;

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

/// Singleton key for the safe-harbour row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeHarbourKey;

impl PackableKey for SafeHarbourKey {
    type PackingError = PackError;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.safe_harbour.pack::<()>(&()))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        dirs.safe_harbour.unpack::<()>(bytes)?;
        Ok(Self)
    }
}

impl SerializableValue for SafeHarbourAddress {
    type SerializeError = postcard::Error;
    type DeserializeError = postcard::Error;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        postcard::to_allocvec(self)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        // Deserialization enforces the P2TR invariant via `SafeHarbourAddress`'s
        // custom `Deserialize` impl, so persisted bytes cannot smuggle in a
        // non-taproot descriptor.
        postcard::from_bytes(bytes)
    }
}

/// ZST for the safe-harbour row spec.
#[derive(Debug)]
pub struct SafeHarbourRowSpec;

impl KVRowSpec for SafeHarbourRowSpec {
    type Key = SafeHarbourKey;
    type Value = SafeHarbourAddress;
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;

    use super::*;

    fn p2tr_address() -> SafeHarbourAddress {
        // `[2u8; 32]` is a valid x-only pubkey on secp256k1.
        let descriptor = Descriptor::new_p2tr(&[2u8; 32]).expect("valid x-only public key");
        SafeHarbourAddress::try_from(descriptor).expect("p2tr accepted")
    }

    #[test]
    fn safe_harbour_address_value_roundtrips_through_postcard() {
        let address = p2tr_address();
        let bytes = address.serialize().expect("serialize");
        let decoded = SafeHarbourAddress::deserialize(&bytes).expect("deserialize");
        assert_eq!(address, decoded);
    }
}
