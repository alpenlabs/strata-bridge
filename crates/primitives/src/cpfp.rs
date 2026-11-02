//! The output of a parent that a CPFP child spends.
//!
//! The publish path, the fee-bump driver, and the wallet all reason about this one input of the
//! child, so they share one description of it.

use bitcoin::{taproot::ControlBlock, transaction::InputWeightPrediction, OutPoint, ScriptBuf};

/// How the child satisfies the output that it spends.
///
/// This describes the output's own script. A spend that [`ChildSigner::GeneralWallet`] signs is
/// priced and signed as an input of the wallet in use, so for it the planner does not read this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildWitness {
    /// A bare key-path spend: one signature.
    KeyPath,
    /// A script-path spend of one leaf of a multi-leaf Taproot output. The witness is a
    /// signature, the leaf script, and the control block.
    ScriptPath {
        /// The leaf script being satisfied.
        leaf_script: ScriptBuf,
        /// Control block proving the membership of `leaf_script` in the tree. Kept typed rather
        /// than pre-serialized so a malformed block cannot reach the chain: the only bytes that
        /// ever get pushed are those of `ControlBlock::serialize`.
        control_block: ControlBlock,
    },
}

impl ChildWitness {
    /// Size of the child input that satisfies this output.
    ///
    /// The script-path figure is exact, because the leaf script and control block are at hand.
    /// A control block grows with tree depth (33 + 32×depth bytes), so a fixed guess drifts with
    /// the watchtower count.
    pub fn input_prediction(&self) -> InputWeightPrediction {
        match self {
            Self::KeyPath => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
            Self::ScriptPath {
                leaf_script,
                control_block,
            } => InputWeightPrediction::new(
                0,
                [64, leaf_script.len(), control_block.serialize().len()],
            ),
        }
    }
}

/// Which key signs the input of the child that spends the parent's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildSigner {
    /// The operator's protocol key. The wallet cannot select this output for another
    /// transaction, so the lease of the child leaves it out.
    Protocol,
    /// The operator's general wallet. The output pays this wallet, so the lease of the child
    /// covers it: a concurrent duty must not select an output that a live child spends.
    GeneralWallet,
}

/// The output of a parent that a CPFP child spends, and how the child spends it.
///
/// The constructors are the only way to build one, because the fields are not independent. Each
/// constructor names one output kind that the protocol has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildSpend {
    outpoint: OutPoint,
    witness: ChildWitness,
    signer: ChildSigner,
}

impl ChildSpend {
    /// A keyed-Taproot anchor: a bare key-path output with no script tree, signed by the
    /// protocol key with a BIP-341 tap-tweak.
    pub const fn keyed_anchor(outpoint: OutPoint) -> Self {
        Self {
            outpoint,
            witness: ChildWitness::KeyPath,
            signer: ChildSigner::Protocol,
        }
    }

    /// One leaf of a multi-leaf Taproot anchor, with one `<watchtower_pubkey> OP_CHECKSIG` leaf
    /// per watchtower so that any watchtower can bump the parent. The signature is untweaked,
    /// because the leaf is satisfied directly.
    pub const fn multi_anchor(
        outpoint: OutPoint,
        leaf_script: ScriptBuf,
        control_block: ControlBlock,
    ) -> Self {
        Self {
            outpoint,
            witness: ChildWitness::ScriptPath {
                leaf_script,
                control_block,
            },
            signer: ChildSigner::Protocol,
        }
    }

    /// An output of the parent that the operator's general wallet signs for. It enters the lease
    /// of the child.
    ///
    /// The witness describes a Taproot key-path spend, which is what an output at the general key
    /// needs. The planner prices this spend as an input of the wallet in use, whatever this says,
    /// because that wallet can be P2WPKH.
    pub const fn owned_output(outpoint: OutPoint) -> Self {
        Self {
            outpoint,
            witness: ChildWitness::KeyPath,
            signer: ChildSigner::GeneralWallet,
        }
    }

    /// The output that the child spends.
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// How the child satisfies the output.
    pub const fn witness(&self) -> &ChildWitness {
        &self.witness
    }

    /// Which key signs the input that spends the output.
    pub const fn signer(&self) -> ChildSigner {
        self.signer
    }
}
