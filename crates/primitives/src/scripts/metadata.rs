//! Primitives for Bridge metadata.

use bitcoin::{Amount, XOnlyPublicKey};

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
        // TODO: (@Rajil1213) make this a BOSD Descriptor.
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

        /// The take back key which is the public key of the depositer included in the Deposit
        /// Request Metadata.
        ///
        /// This information is required to reconstruct the prevout script pubkey on the output in
        /// the Deposit Request Transaction being spent.
        //  TODO: (@Rajil1213) make this a BOSD Descriptor.
        takeback_pubkey: XOnlyPublicKey,

        /// The input amount for the Deposit Transaction.
        ///
        /// This is the amount in the output of the Deposit Request Transaction that is being
        /// spent. This is encoded as an 8-byte big-endian encoded unsigned 64-bit integer.
        ///
        /// This information is required to reconstruct the prevout script pubkey on the output in
        /// the Deposit Request Transaction being spent.
        input_amount: Amount,
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
                takeback_pubkey,
                input_amount,
            } => {
                bytes.extend_from_slice(&stake_index.to_be_bytes());
                bytes.extend_from_slice(ee_address);
                bytes.extend_from_slice(&takeback_pubkey.serialize());
                bytes.extend_from_slice(&input_amount.to_sat().to_be_bytes());
            }
        }

        bytes
    }
}
