//! States for the Stake State Machine.

use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

use bitcoin::{Txid, secp256k1::schnorr::Signature};
use musig2::{AggNonce, PartialSignature, PubNonce};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph::stake_graph::{StakeData, StakeGraph};

/// The state of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakeState {
    /// Initial state.
    Created {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
    },
    /// The stake graph has been generated.
    StakeGraphGenerated {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
        /// Maps each operator to their public nonces.
        pub_nonces: BTreeMap<OperatorIdx, [PubNonce; StakeGraph::N_MUSIG_INPUTS]>,
    },
    /// All nonces for the stake graph have been collected.
    UnstakingNoncesCollected {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
        /// Maps each operator to their public nonces.
        pub_nonces: BTreeMap<OperatorIdx, [PubNonce; StakeGraph::N_MUSIG_INPUTS]>,
        /// 1 aggregated nonce per musig transaction input.
        agg_nonces: Box<[AggNonce; StakeGraph::N_MUSIG_INPUTS]>,
        /// Maps each operator to their partial signatures.
        partial_signatures: BTreeMap<OperatorIdx, [PartialSignature; StakeGraph::N_MUSIG_INPUTS]>,
    },
    /// All presignatures for the stake graph have been collected.
    ///
    /// (This does not include the stake transaction, because it is not presigned.)
    UnstakingSigned {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
        /// ID of the expected stake transaction.
        expected_stake_txid: Txid,
        /// 1 signature per musig transaction input.
        signatures: Box<[Signature; StakeGraph::N_MUSIG_INPUTS]>,
    },
    /// The stake transaction has been confirmed on the bitcoin blockchain.
    Confirmed {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
        /// ID of the confirmed stake transaction.
        stake_txid: Txid,
    },
    /// The unstaking preimage has been revealed on-chain.
    PreimageRevealed {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
        /// The revealed unstaking preimage.
        preimage: [u8; 32],
        /// Block height where the unstaking intent transaction was confirmed.
        unstaking_intent_block_height: BitcoinBlockHeight,
        /// ID of the expected unstaking transaction.
        expected_unstaking_txid: Txid,
    },
    /// The unstaking transaction has been confirmed on the bitcoin blockchain.
    Unstaked {
        /// The revealed unstaking preimage.
        preimage: [u8; 32],
        /// ID of the confirmed unstaking transaction.
        unstaking_txid: Txid,
    },
}

impl StakeState {
    /// Creates the initial state of the stake state machine, which is [`StakeState::Created`].
    pub const fn new(block_height: BitcoinBlockHeight) -> Self {
        Self::Created {
            last_block_height: block_height,
        }
    }

    /// Returns true if staking has happened.
    ///
    /// This means that other state machines can start working.
    /// This predicate returns true even after unstaking has completed.
    pub const fn has_staked(&self) -> bool {
        matches!(
            self,
            Self::Confirmed { .. } | Self::PreimageRevealed { .. } | Self::Unstaked { .. }
        )
    }

    /// Returns true if the stake is fully unstaked.
    pub const fn is_unstaked(&self) -> bool {
        matches!(self, Self::Unstaked { .. })
    }

    /// Returns the unstaking preimage once revealed.
    pub const fn preimage(&self) -> Option<[u8; 32]> {
        match self {
            Self::PreimageRevealed { preimage, .. } | Self::Unstaked { preimage, .. } => {
                Some(*preimage)
            }
            _ => None,
        }
    }

    /// Returns the height of the last processed block,
    /// if the state contains this information.
    pub const fn last_processed_block_height(&self) -> Option<BitcoinBlockHeight> {
        match self {
            Self::Created {
                last_block_height, ..
            }
            | Self::StakeGraphGenerated {
                last_block_height, ..
            }
            | Self::UnstakingNoncesCollected {
                last_block_height, ..
            }
            | Self::UnstakingSigned {
                last_block_height, ..
            }
            | Self::Confirmed {
                last_block_height, ..
            }
            | Self::PreimageRevealed {
                last_block_height, ..
            } => Some(*last_block_height),
            Self::Unstaked { .. } => None,
        }
    }

    /// Returns a mutable reference to the last processed block height,
    /// if the state contains this information.
    pub const fn last_processed_block_height_mut(&mut self) -> Option<&mut BitcoinBlockHeight> {
        match self {
            Self::Created {
                last_block_height, ..
            }
            | Self::StakeGraphGenerated {
                last_block_height, ..
            }
            | Self::UnstakingNoncesCollected {
                last_block_height, ..
            }
            | Self::UnstakingSigned {
                last_block_height, ..
            }
            | Self::Confirmed {
                last_block_height, ..
            }
            | Self::PreimageRevealed {
                last_block_height, ..
            } => Some(last_block_height),
            Self::Unstaked { .. } => None,
        }
    }
}

impl Display for StakeState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Created { .. } => "Created",
            Self::StakeGraphGenerated { .. } => "StakeGraphGenerated",
            Self::UnstakingNoncesCollected { .. } => "UnstakingNoncesCollected",
            Self::UnstakingSigned { .. } => "UnstakingSigned",
            Self::Confirmed { .. } => "Confirmed",
            Self::PreimageRevealed { .. } => "PreimageRevealed",
            Self::Unstaked { .. } => "Unstaked",
        };

        write!(f, "{label}")
    }
}
