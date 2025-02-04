use bitcoin::{BlockHash, Transaction};

/// TxStatus is the primary output of this API via the subscription.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxStatus {
    /// Unknown indicates that the transaction is not staged for inclusion in the blockchain.
    ///
    /// Concretely this status will only really appear if the transaction is evicted from the
    /// mempool.
    Unknown,
    /// Mempool indicates that the transaction is currently in the mempool.
    ///
    /// This status will be emitted both when a transaction enters the mempool for the first time
    /// as well as if it re-enters the mempool due to a containing block get reorg'ed out of
    /// the main chain and not yet included in the alternative one.
    Mempool,
    /// Mined indicates that the transaction has been included in a block.
    ///
    /// This status will be received once per transaction per block. If a transaction is included
    /// in a block, and then that block is reorg'ed out and the same transaction is included in
    /// a new block, then the subscription will emit two separate [`TxStatus::Mined`] events
    /// for it.
    Mined {
        /// This is the block hash of the block in which this transaction is included.
        blockhash: BlockHash,
    },
    /// Buried is a terminal status. It will be emitted once the transaction's containing block has
    /// been buried under a sufficient number of subsequent blocks.
    ///
    /// After this status is emitted, no further statuses for that transaction will be emitted.
    Buried {
        /// This is the block hash of the block in which this transaction is buried.
        ///
        /// It is the same as the block hash in which it was mined but is included for redundancy.
        blockhash: BlockHash,
    },
}

/// TxEvent is the type that is emitted to Subscriptions created with
/// [`crate::client::BtcZmqClient::subscribe_transactions`].
///
/// It contains the raw transaction data, and the status indicating the Transaction's most up to
/// date status about its inclusion in the canonical history.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxEvent {
    /// rawtx is the transaction data itself for which the event is describing.
    pub rawtx: Transaction,

    /// status is the new [`TxStatus`] that this event is reporting for the transaction.
    pub status: TxStatus,
}
