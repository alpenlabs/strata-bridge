//! Events for the Stake State Machine.

use bitcoin::Transaction;
use musig2::{PartialSignature, PubNonce};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph::stake_graph::{StakeData, StakeGraph};

/// Event notifying that stake data has been received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeDataReceivedEvent {
    /// Data that is required to construct the stake graph.
    pub stake_data: StakeData,
}

/// Event notifying that public nonces were received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstakingNoncesReceivedEvent {
    /// The operator who submitted the nonces.
    pub operator_idx: OperatorIdx,
    /// 1 public nonce per musig transaction input.
    pub pub_nonces: [PubNonce; StakeGraph::N_MUSIG_INPUTS],
}

/// Event notifying that partial signatures were received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstakingPartialsReceivedEvent {
    /// The operator who submitted the partial signatures.
    pub operator_idx: OperatorIdx,
    /// 1 partial signature per musig transaction input.
    pub partial_signatures: [PartialSignature; StakeGraph::N_MUSIG_INPUTS],
}

/// Event notifying that the stake transaction has been confirmed on the bitcoin blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeConfirmedEvent {
    /// The confirmed stake transaction.
    pub tx: Transaction,
}

/// Event notifying that the unstaking preimage has been revealed on the bitcoin blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreimageRevealedEvent {
    /// The observed unstaking intent transaction.
    pub tx: Transaction,
    /// The block height where the transaction was observed.
    pub block_height: BitcoinBlockHeight,
}

/// Event notifying that the unstaking transaction has been confirmed on the bitcoin blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstakingConfirmedEvent {
    /// The confirmed unstaking transaction.
    pub tx: Transaction,
}

/// Event signalling that a new bitcoin block has been observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlockEvent {
    /// The new block height.
    pub block_height: BitcoinBlockHeight,
}

/// Event signalling a nag tick has occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NagTickEvent;

/// Event signalling a retry tick has occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTickEvent;

/// External events that are processed by the Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakeEvent {
    /// Stake data has been received.
    StakeDataReceived(StakeDataReceivedEvent),
    /// Nonces have been received from an operator.
    UnstakingNoncesReceived(UnstakingNoncesReceivedEvent),
    /// Partial signatures have been received from an operator.
    UnstakingPartialsReceived(UnstakingPartialsReceivedEvent),
    /// The stake transaction has been confirmed on-chain.
    StakeConfirmed(StakeConfirmedEvent),
    /// The unstaking preimage has been revealed on-chain.
    PreimageRevealed(PreimageRevealedEvent),
    /// The unstaking transaction has been confirmed on-chain.
    UnstakingConfirmed(UnstakingConfirmedEvent),
    /// A new block has been observed on-chain.
    NewBlock(NewBlockEvent),
    /// Event signalling that nag duties should be emitted for missing operator data.
    NagTick(NagTickEvent),
    /// Event signalling that retriable duties should be emitted for the current state.
    RetryTick(RetryTickEvent),
}

impl std::fmt::Display for StakeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = match self {
            Self::StakeDataReceived(_) => "StakeDataReceived",
            Self::UnstakingNoncesReceived(_) => "UnstakingNoncesReceived",
            Self::UnstakingPartialsReceived(_) => "UnstakingPartialsReceived",
            Self::StakeConfirmed(_) => "StakeConfirmed",
            Self::PreimageRevealed(_) => "PreimageRevealed",
            Self::UnstakingConfirmed(_) => "UnstakingConfirmed",
            Self::NewBlock(_) => "NewBlock",
            Self::NagTick(_) => "NagTick",
            Self::RetryTick(_) => "RetryTick",
        };

        write!(f, "{display}")
    }
}

impl std::fmt::Display for StakeDataReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StakeDataReceived")
    }
}

impl std::fmt::Display for UnstakingNoncesReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnstakingNoncesReceived from operator_idx: {}",
            self.operator_idx
        )
    }
}

impl std::fmt::Display for UnstakingPartialsReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnstakingPartialsReceived from operator_idx: {}",
            self.operator_idx
        )
    }
}

impl std::fmt::Display for StakeConfirmedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StakeConfirmed via {}", self.tx.compute_txid())
    }
}

impl std::fmt::Display for PreimageRevealedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PreimageRevealed via {} at {}",
            self.tx.compute_txid(),
            self.block_height
        )
    }
}

impl std::fmt::Display for UnstakingConfirmedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnstakingConfirmed via {}", self.tx.compute_txid())
    }
}

impl std::fmt::Display for NewBlockEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NewBlock at height {}", self.block_height)
    }
}

impl std::fmt::Display for NagTickEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NagTick")
    }
}

impl std::fmt::Display for RetryTickEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RetryTick")
    }
}

/// Implements `From<T> for StakeEvent` for a leaf event type.
///
/// This allows all stake-related event structs to be ergonomically
/// converted into `StakeEvent` via `.into()` and used uniformly
/// by the Stake State Machine.
macro_rules! impl_into_stake_event {
    ($t:ty, $variant:ident) => {
        impl From<$t> for StakeEvent {
            fn from(event: $t) -> Self {
                StakeEvent::$variant(event)
            }
        }
    };
}

impl_into_stake_event!(StakeDataReceivedEvent, StakeDataReceived);
impl_into_stake_event!(UnstakingNoncesReceivedEvent, UnstakingNoncesReceived);
impl_into_stake_event!(UnstakingPartialsReceivedEvent, UnstakingPartialsReceived);
impl_into_stake_event!(StakeConfirmedEvent, StakeConfirmed);
impl_into_stake_event!(PreimageRevealedEvent, PreimageRevealed);
impl_into_stake_event!(UnstakingConfirmedEvent, UnstakingConfirmed);
impl_into_stake_event!(NewBlockEvent, NewBlock);
impl_into_stake_event!(NagTickEvent, NagTick);
impl_into_stake_event!(RetryTickEvent, RetryTick);
