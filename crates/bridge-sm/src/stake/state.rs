//! States for the Stake State Machine.

use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

use bitcoin::{Txid, secp256k1::schnorr::Signature};
use musig2::{AggNonce, PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph::{musig_functor::StakeFunctor, stake_graph::StakeGraphSummary};

use crate::stake::context::MinimumStakeData;

/// The state of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        stake_data: MinimumStakeData,
        /// Collection of all TXIDs in the stake graph.
        summary: StakeGraphSummary,
        /// Maps each operator to their public nonces.
        pub_nonces: BTreeMap<OperatorIdx, StakeFunctor<PubNonce>>,
    },
    /// All nonces for the stake graph have been collected.
    UnstakingNoncesCollected {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: MinimumStakeData,
        /// Collection of all TXIDs in the stake graph.
        summary: StakeGraphSummary,
        /// Maps each operator to their public nonces.
        pub_nonces: BTreeMap<OperatorIdx, StakeFunctor<PubNonce>>,
        /// 1 aggregated nonce per musig transaction input.
        agg_nonces: Box<StakeFunctor<AggNonce>>,
        /// Maps each operator to their partial signatures.
        partial_signatures: BTreeMap<OperatorIdx, StakeFunctor<PartialSignature>>,
    },
    /// All presignatures for the stake graph have been collected.
    ///
    /// (This does not include the stake transaction, because it is not presigned.)
    UnstakingSigned {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: MinimumStakeData,
        /// Collection of all TXIDs in the stake graph.
        summary: StakeGraphSummary,
        /// 1 signature per musig transaction input.
        signatures: Box<StakeFunctor<Signature>>,
    },
    /// The stake transaction has been confirmed on the bitcoin blockchain.
    Confirmed {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: MinimumStakeData,
        /// Collection of all TXIDs in the stake graph.
        summary: StakeGraphSummary,
        /// 1 signature per musig transaction input.
        ///
        /// The signatures may be absent if an operator chooses to withhold their partial signature
        /// or broadcasts is too late.
        signatures: Box<Option<StakeFunctor<Signature>>>,
    },
    /// The unstaking preimage has been revealed on-chain.
    PreimageRevealed {
        /// Latest bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,
        /// Data that is required to construct the stake graph.
        stake_data: MinimumStakeData,
        /// Collection of all TXIDs in the stake graph.
        summary: StakeGraphSummary,
        /// The revealed unstaking preimage.
        preimage: [u8; 32],
        /// Block height where the unstaking intent transaction was confirmed.
        unstaking_intent_block_height: BitcoinBlockHeight,
        /// 1 signature per musig transaction input.
        ///
        /// The signatures may be absent if an operator chose to withhold their partial signature
        /// or broadcasted it too late.
        signatures: Box<Option<StakeFunctor<Signature>>>,
    },
    /// The unstaking transaction has been confirmed on the bitcoin blockchain.
    Unstaked {
        /// The revealed unstaking preimage.
        preimage: [u8; 32],
        /// ID of the confirmed unstaking transaction.
        unstaking_txid: Txid,
    },
    /// The operator's stake has been slashed by another operator.
    ///
    /// A slash transaction is any transaction that spends the stake output of the stake
    /// transaction but is not the legitimate unstaking transaction.
    Slashed {
        /// Collection of all TXIDs in the stake graph.
        summary: StakeGraphSummary,
        /// Txid of the confirmed slash transaction.
        slash_txid: Txid,
        /// The unstaking preimage if the transition occurred from
        /// [`StakeState::PreimageRevealed`].
        ///
        /// This is required by downstream state machines (e.g. for the unstaking burn) when
        /// the operator had already revealed the preimage prior to being slashed.
        preimage: Option<[u8; 32]>,
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
    /// This predicate returns true even after unstaking has completed or after being slashed.
    pub const fn has_staked(&self) -> bool {
        matches!(
            self,
            Self::Confirmed { .. }
                | Self::PreimageRevealed { .. }
                | Self::Unstaked { .. }
                | Self::Slashed { .. }
        )
    }

    /// Returns true if this operator is still eligible to participate in new deposits.
    ///
    /// This is the admission predicate for creating new per-operator
    /// [`GraphSM`](crate::graph::machine::GraphSM) instances. It is stricter than
    /// [`has_staked`](Self::has_staked): an operator whose unstaking preimage has been revealed
    /// (or who has fully unstaked) is excluded because their stake UTXO will soon be spent.
    pub const fn is_stake_available(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Returns true if this operator has been removed from the future covenant.
    ///
    /// Complement of [`is_stake_available`](Self::is_stake_available) for operators that have
    /// already staked: `PreimageRevealed`, `Unstaked` and `Slashed` states indicate the operator
    /// is no longer available and must not be included in future covenant signing sessions.
    pub const fn is_removed_from_future_covenant(&self) -> bool {
        matches!(
            self,
            Self::PreimageRevealed { .. } | Self::Unstaked { .. } | Self::Slashed { .. }
        )
    }

    /// Returns true if the stake is fully unstaked.
    pub const fn is_unstaked(&self) -> bool {
        matches!(self, Self::Unstaked { .. })
    }

    /// Returns true if the stake has been slashed.
    pub const fn is_slashed(&self) -> bool {
        matches!(self, Self::Slashed { .. })
    }

    /// Returns the unstaking preimage once revealed.
    pub const fn preimage(&self) -> Option<[u8; 32]> {
        match self {
            Self::PreimageRevealed { preimage, .. } | Self::Unstaked { preimage, .. } => {
                Some(*preimage)
            }
            Self::Slashed { preimage, .. } => *preimage,
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
            Self::Unstaked { .. } | Self::Slashed { .. } => None,
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
            Self::Unstaked { .. } | Self::Slashed { .. } => None,
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
            Self::Slashed { .. } => "Slashed",
        };

        write!(f, "{label}")
    }
}
