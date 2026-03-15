//! Input types for the ASM STF Moho program.
//!
//! This module defines [`AsmStepInput`], the per-step input consumed by the
//! [`MohoProgram`](moho_runtime_interface::MohoProgram) implementation.
use std::io::{self, Read, Write};

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    Block,
};
use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::StateReference;
use strata_asm_common::AuxData;

/// Private input for a single ASM STF step.
///
/// Contains the full L1 Bitcoin block and auxiliary data required to execute the state
/// transition.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct AsmStepInput {
    /// The full Bitcoin L1 block
    pub block: L1Block,
    /// Auxiliary data required to run the ASM STF
    pub aux_data: AuxData,
}

impl AsmStepInput {
    /// Computes the state reference.
    ///
    /// In concrete terms, this just computes the blkid/blockhash.
    pub fn compute_ref(&self) -> StateReference {
        let raw_ref = self.block.0.block_hash().to_raw_hash().to_byte_array();
        StateReference::new(raw_ref)
    }

    /// Computes the previous state reference from the input.
    ///
    /// In concrete terms, this just extracts the parent blkid from the block's
    /// header.
    pub fn compute_prev_ref(&self) -> StateReference {
        let parent_ref = self
            .block
            .0
            .header
            .prev_blockhash
            .to_raw_hash()
            .to_byte_array();
        StateReference::new(parent_ref)
    }

    /// Checks that the block's merkle roots are consistent.
    pub fn validate_block(&self) -> bool {
        self.block.0.check_merkle_root() && self.block.0.check_witness_commitment()
    }
}

/// A wrapper around Bitcoin's `Block` to provide Borsh (de)serialization.
#[derive(Debug, Clone, PartialEq)]
pub struct L1Block(pub Block);

impl BorshSerialize for L1Block {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        // Serialize the inner Bitcoin block via consensus encoding
        let serialized_block = serialize(&self.0);
        let len = serialized_block.len() as u32;
        // Write length prefix (little-endian)
        writer.write_all(&len.to_le_bytes())?;
        // Write block bytes
        writer.write_all(&serialized_block)?;
        Ok(())
    }
}

impl BorshDeserialize for L1Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        // Read the length prefix
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Read the serialized block data
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;

        // Deserialize into a Bitcoin block via consensus rules
        let block = deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(L1Block(block))
    }
}
