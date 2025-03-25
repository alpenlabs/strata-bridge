//! Primitives for Bridge metadata.

use bitcoin::XOnlyPublicKey;

/// Metadata bytes that the Bridge uses to read information from the bitcoin blockchain and the
/// sidesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxiliaryData<'tag> {
    /// Tag, also known as "magic bytes".
    pub tag: &'tag [u8],

    /// Deposit-specific metadata.
    pub metadata: DepositMetadata,
}

/// Deposit-specific metadata that the Bridge uses to read information from the bitcoin blockchain
/// and the sidesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositMetadata {
    DepositRequestTx {
        /// 32-bit X-only public key.
        // TODO: make this a BOSD Descriptor.
        takeback_pubkey: XOnlyPublicKey,

        /// Execution Environment address.
        ee_address: Vec<u8>,
    },
    DepositTx {
        /// Stake index.
        ///
        /// # Implementation Notes
        ///
        /// This is a 4-byte big-endian encoded unsigned 32-bit integer.
        stake_index: u32,

        /// Execution Environment address.
        ee_address: Vec<u8>,
    },
}

impl<'tag> AuxiliaryData<'tag> {
    /// Extracts the metadata as bytes.
    pub fn to_vec(&'tag self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(self.tag);

        match &self.metadata {
            DepositMetadata::DepositRequestTx {
                takeback_pubkey,
                ee_address,
                ..
            } => {
                bytes.extend_from_slice(&takeback_pubkey.serialize());
                bytes.extend_from_slice(ee_address);
            }
            DepositMetadata::DepositTx {
                stake_index,
                ee_address,
            } => {
                bytes.extend_from_slice(&stake_index.to_be_bytes());
                bytes.extend_from_slice(ee_address);
            }
        }

        bytes
    }
}
