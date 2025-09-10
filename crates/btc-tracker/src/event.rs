//! Events emitted by the [`BtcNotifyClient`](crate::client::BtcNotifyClient) in its `Connected`
//! state.
use std::fmt;

use bitcoin::{Block, BlockHash, Transaction};

/// TxStatus is the primary output of this API via the subscription.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxStatus {
    /// Indicates that the transaction is not staged for inclusion in the blockchain.
    ///
    /// Concretely this status will only really appear if the transaction is evicted from the
    /// mempool.
    Unknown,
    /// Indicates that the transaction is currently in the mempool.
    ///
    /// This status will be emitted both when a transaction enters the mempool for the first time
    /// as well as if it re-enters the mempool due to a containing block get reorg'ed out of
    /// the main chain and not yet included in the alternative one.
    Mempool,
    /// Indicates that the transaction has been included in a block.
    ///
    /// This status will be received once per transaction per block. If a transaction is included
    /// in a block, and then that block is reorg'ed out and the same transaction is included in
    /// a new block, then the subscription will emit two separate [`TxStatus::Mined`] events
    /// for it.
    Mined {
        /// This is the block hash of the block in which this transaction is included.
        blockhash: BlockHash,

        /// This is the height of the block in which this transaction is included.
        height: u64,
    },
    /// Terminal status. It will be emitted once the transaction's containing block has
    /// been buried under a sufficient number of subsequent blocks.
    ///
    /// After this status is emitted, no further statuses for that transaction will be emitted.
    Buried {
        /// This is the block hash of the block in which this transaction is buried.
        ///
        /// It is the same as the block hash in which it was mined but is included for redundancy.
        blockhash: BlockHash,

        /// This is the height of the block in which this transaction is included.
        ///
        /// It is the same as the height in which it was mined but it is included for redundancy.
        height: u64,
    },
}

impl fmt::Display for TxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxStatus::Unknown => write!(f, "unknown"),
            TxStatus::Mempool => write!(f, "in mempool"),
            TxStatus::Mined { blockhash, height } => {
                write!(f, "mined in block {height} ({blockhash})")
            }
            TxStatus::Buried { blockhash, height } => {
                write!(f, "buried in block {height} ({blockhash})")
            }
        }
    }
}

impl TxStatus {
    /// Returns true if the status is some sort of [`TxStatus::Mined`] status.
    pub const fn is_mined(&self) -> bool {
        matches!(self, TxStatus::Mined { .. })
    }

    /// Returns true if the status is some sort of [`TxStatus::Buried`] status.
    pub const fn is_buried(&self) -> bool {
        matches!(self, TxStatus::Buried { .. })
    }
}

/// Type that is emitted to Subscriptions created with
/// [`crate::client::BtcNotifyClient::subscribe_transactions`].
///
/// It contains the raw transaction data, and the status indicating the Transaction's most up to
/// date status about its inclusion in the canonical history.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxEvent {
    /// The transaction data itself for which the event is describing.
    pub rawtx: Transaction,

    /// The new [`TxStatus`] that this event is reporting for the transaction.
    pub status: TxStatus,
}

/// This is emitted as a pair with block events to denote what is happening to the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStatus {
    /// A block that was once connected to the main chain has been disconnected.
    Uncled,

    /// A block has been connected to the main chain.
    Mined,

    /// A block has been buried under the configured number of blocks in the main chain.
    Buried,
}

/// Event type that is emitted to indicate what is happening with a given block.
#[derive(Debug, Clone)]
pub struct BlockEvent {
    /// The actual block data for the block event in question.
    pub block: Block,

    /// The status of the block as of this event.
    pub status: BlockStatus,
}
