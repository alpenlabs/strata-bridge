//! Proof-related types used across the bridge.

use strata_identifiers::L1BlockCommitment;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::ProofReceipt;

/// Predicate that determines how bridge proofs are verified.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
pub enum BridgeProofPredicate {
    /// Always accepts the proof without verification. Used for testing/development.
    #[default]
    AlwaysAccept,

    /// Verifies the proof using SP1 Groth16 verification. Used in production.
    Sp1Groth16 {
        /// The SP1 program verifying key hash (32 bytes).
        program_vk_hash: [u8; 32],
    },
}

impl BridgeProofPredicate {
    /// Returns `true` if the proof is valid according to this predicate.
    pub fn verify(&self, proof: &ProofReceipt) -> bool {
        let predicate_key = match self {
            Self::AlwaysAccept => PredicateKey::always_accept(),
            Self::Sp1Groth16 { program_vk_hash } => {
                PredicateKey::new(PredicateTypeId::Sp1Groth16, program_vk_hash.to_vec())
            }
        };

        predicate_key
            .verify_claim_witness(proof.public_values().as_bytes(), proof.proof().as_bytes())
            .is_ok()
    }
}

/// An opaque ASM step proof for a range of L1 blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmProof(pub Vec<u8>);

/// An opaque Moho recursive proof, valid up to some L1 block commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MohoProof(pub Vec<u8>);

/// A range of L1 blocks defined by start and end commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct L1Range {
    /// The start of the range (inclusive).
    start: L1BlockCommitment,
    /// The end of the range (inclusive).
    end: L1BlockCommitment,
}

impl L1Range {
    /// Creates a new `L1Range` from start and end commitments.
    ///
    /// Returns `None` if `end` height is strictly less than `start` height.
    pub fn new(start: L1BlockCommitment, end: L1BlockCommitment) -> Option<Self> {
        if end.height() < start.height() {
            return None;
        }
        Some(Self { start, end })
    }

    /// Creates a range that covers a single block (start == end).
    pub const fn single(block: L1BlockCommitment) -> Self {
        Self {
            start: block,
            end: block,
        }
    }

    /// Returns the start of the range.
    pub const fn start(&self) -> L1BlockCommitment {
        self.start
    }

    /// Returns the end of the range.
    pub const fn end(&self) -> L1BlockCommitment {
        self.end
    }
}
