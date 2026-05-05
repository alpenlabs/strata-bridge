//! Events for the Stake State Machine.

use bitcoin::{OutPoint, Transaction, hashes::sha256};
use bitcoin_bosd::Descriptor;
use musig2::{PartialSignature, PubNonce};
use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph::musig_functor::StakeFunctor;

/// Event notifying that stake data has been received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeDataReceivedEvent {
    /// The funding input for the stake transaction.
    pub stake_funds: OutPoint,

    /// The unstaking hash image for the stake transaction.
    pub unstaking_image: sha256::Hash,

    /// The descriptor where the operator wants to receive the staked funds after unstaking.
    pub unstaking_output_desc: Descriptor,
}

/// Event notifying that public nonces were received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstakingNoncesReceivedEvent {
    /// The operator who submitted the nonces.
    pub operator_idx: OperatorIdx,
    /// 1 public nonce per musig transaction input.
    pub pub_nonces: Box<StakeFunctor<PubNonce>>,
}

/// Event notifying that partial signatures were received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstakingPartialsReceivedEvent {
    /// The operator who submitted the partial signatures.
    pub operator_idx: OperatorIdx,
    /// 1 partial signature per musig transaction input.
    pub partial_signatures: StakeFunctor<PartialSignature>,
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

/// Event notifying that a slash transaction (spending the stake output but
/// distinct from the legitimate unstaking transaction) has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashConfirmedEvent {
    /// The confirmed slash transaction.
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

/// Event that is received when another operator nags for missing graph data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NagReceivedEvent {
    /// The nag payload describing what's being requested.
    pub payload: NagRequestPayload,
    /// The operator index of the sender.
    pub sender_operator_idx: OperatorIdx,
}

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
    /// A slash transaction has been confirmed on-chain.
    SlashConfirmed(SlashConfirmedEvent),
    /// A new block has been observed on-chain.
    NewBlock(NewBlockEvent),
    /// Event signalling that retriable duties should be emitted for the current state.
    RetryTick(RetryTickEvent),
    /// Event signalling that nag duties should be emitted for missing operator data.
    NagTick(NagTickEvent),
    /// Event that is received when another operator nags for missing graph data.
    NagReceived(NagReceivedEvent),
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
            Self::SlashConfirmed(_) => "SlashConfirmed",
            Self::NewBlock(_) => "NewBlock",
            Self::RetryTick(_) => "RetryTick",
            Self::NagTick(_) => "NagTick",
            Self::NagReceived(_) => "NagReceived",
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

impl std::fmt::Display for SlashConfirmedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlashConfirmed via {}", self.tx.compute_txid())
    }
}

impl std::fmt::Display for NewBlockEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NewBlock at height {}", self.block_height)
    }
}

impl std::fmt::Display for RetryTickEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RetryTick")
    }
}

impl std::fmt::Display for NagTickEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NagTick")
    }
}

impl std::fmt::Display for NagReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NagReceived")
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
impl_into_stake_event!(SlashConfirmedEvent, SlashConfirmed);
impl_into_stake_event!(NewBlockEvent, NewBlock);
impl_into_stake_event!(RetryTickEvent, RetryTick);
impl_into_stake_event!(NagTickEvent, NagTick);
impl_into_stake_event!(NagReceivedEvent, NagReceived);
