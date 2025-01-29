//! The stake chain is a series of transactions that move the stake from a previous stake to a new
//! stake.

use bitcoin::{relative, Amount, TxOut};
use serde::{Deserialize, Serialize};

/// A [`StakeChain`] is a series of transactions that move the stake from a previous stake to a new
/// stake.
///
/// It tracks the original stake, the stake index, the funding UTXO, the staking amount, and the
/// maximum number of slashing transactions to be created.
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
///
/// The stake index corresponds to the deposit index i.e., the `n`th stake transaction is used to
/// stake in the transaction graph for the `n`th deposit.
///
/// The funding UTXO is used to fund the stake and should cover not only for the stake transaction
/// itself but also for all the dust amounts in the transaction graph.
///
/// The stake chain can be advanced forward by revealing a pre-image to a locking script that is
/// also relative timelocked to a certain `ΔS` interval.
///
/// The staking amount is the amount that is staked in the transaction graph for a single stake
/// along with its dust amounts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeChain {
    /// The prevout for the first stake transaction.
    pub original_stake: TxOut,

    /// The stake index, i.e., the index of the stake transaction in the chain.
    pub index: u32,

    /// The funding UTXO.
    ///
    /// # Notes
    ///
    /// The funding should cover for all the dust amounts in the transaction graph as well as that
    /// for the stake transaction itself.
    pub funding: TxOut,

    /// The staking amount.
    pub amount: Amount,

    /// The `ΔS` interval relative timelock to advance the stake chain.
    delta: relative::LockTime,

    /// Maximum number of slashing transactions to be created.
    pub max_slashing_transactions: u32,
}
