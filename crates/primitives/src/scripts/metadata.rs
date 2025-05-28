//! Primitives for Bridge metadata.

use alpen_bridge_params::types::Tag;
use bitcoin::{Amount, TapNodeHash, XOnlyPublicKey};

use crate::errors::{BridgeTxBuilderResult, DepositTransactionError};

/// Metadata bytes that the Bridge uses to read information from the bitcoin blockchain and the
/// sidesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxiliaryData {
    /// Tag, also known as "magic bytes".
    pub tag: Tag,

    /// Deposit-specific metadata.
    pub metadata: DepositMetadata,
}

/// Deposit-specific metadata that the Bridge uses to read information from the bitcoin blockchain
/// and the sidesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositMetadata {
    /// Deposit request transaction.
    DepositRequestTx {
        /// 32-bit X-only public key.
        // TODO: (@Rajil1213) make this a BOSD Descriptor.
        takeback_pubkey: XOnlyPublicKey,

        /// Execution Environment address.
        ee_address: Vec<u8>,
    },

    /// Deposit transaction.
    DepositTx {
        /// Stake index.
        ///
        /// # Implementation Notes
        ///
        /// This is a 4-byte big-endian encoded unsigned 32-bit integer.
        stake_index: u32,

        /// Execution Environment address.
        ee_address: Vec<u8>,

        /// The hash of the takeback script that can be used by the depositer to retrieve their
        /// funds if the deposit is not completed after a certain time.
        ///
        /// This information is required to reconstruct the prevout script pubkey on the output in
        /// the Deposit Request Transaction being spent.
        takeback_hash: TapNodeHash,

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

impl AuxiliaryData {
    /// Validates the OP_RETURN metadata and returns the metadata as bytes.
    ///
    /// This function validates:
    /// - Tag size (must be 4 bytes)
    /// - EE address size (must match expected size)
    ///
    /// Returns the metadata as bytes if validation passes.
    pub fn validate_and_extract(
        tag: Tag,
        ee_address: &[u8],
        expected_ee_address_size: usize,
        metadata: DepositMetadata,
    ) -> BridgeTxBuilderResult<Self> {
        // Validate EE address size
        if ee_address.len() != expected_ee_address_size {
            return Err(DepositTransactionError::InvalidEeAddressSize(
                ee_address.len(),
                expected_ee_address_size,
            )
            .into());
        }

        let auxiliary_data = AuxiliaryData { tag, metadata };

        Ok(auxiliary_data)
    }

    /// Extracts the metadata as bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(self.tag.as_bytes());

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
                takeback_hash,
                input_amount,
            } => {
                bytes.extend_from_slice(&stake_index.to_be_bytes());
                bytes.extend_from_slice(ee_address);
                bytes.extend_from_slice(takeback_hash.as_ref());
                bytes.extend_from_slice(&input_amount.to_sat().to_be_bytes());
            }
        }

        bytes
    }
}
