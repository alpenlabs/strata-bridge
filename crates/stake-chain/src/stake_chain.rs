//! The stake chain is a series of transactions that move the stake from a previous stake to a new
//! stake.

use bitcoin::{hashes::sha256, relative, Amount, TxIn, TxOut};

use crate::{prelude::StakeTx, StakeChainError};

/// A [`StakeChain`] is a series of transactions that move the stake from a previous stake to a new
/// stake.
///
/// It tracks the stake amount and index, the original and current stake prevouts, the current
/// [`StakeTx`] transactions the relative timelock interval to advance the stake chain, and the
/// maximum number of slashing transactions to be created.
///
/// The staking amount is the amount that is staked in the transaction graph for a single stake. It
/// does not need to keep track of the dust output's cost, since it is tracked individually by a
/// dedicated input in each of the [`StakeTx`] transactions.
///
/// The stake index corresponds to the deposit index i.e., the `n`th stake transaction is used to
/// stake in the transaction graph for the `n`th deposit.
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
/// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
///
/// The stake chain can be advanced forward by revealing a preimage to a locking script that is
/// also relative timelocked to a certain `ΔS` interval.
///
/// # Construction
///
/// [`StakeChain`]s can be constructed by first creating a [`StakeInputs`] of length `N` and then
/// calling [`StakeInputs::<M>::to_stake_chain`](StakeInputs::to_stake_chain), where `M < N`
/// (compile-time check).
///
/// The user can also coerce a [`Vec<StakeTx>`] into a `[StakeChain; N]`, but it does not offer the
/// same compile-time guarantees as the previous method.
pub type StakeChain<const N: usize> = [StakeTx; N];

/// An `N`-length [`StakeInputs`] holds all the necessary data to construct an `M < N`-length
/// [`StakeChain`].
///
/// The data that it needs are:
///
/// 1. Stake amount.
/// 2. `ΔS` relative timelock interval.
/// 3. `N`-length array of stake hashes.
/// 4. `N`-length array of operator fund prevouts.
/// 5. Original stake output.
///
/// The staking amount and the `ΔS` relative timelock interval are scalar values and configurable
/// parameters which can be set at compile time to a contracted value.
///
/// The `N`-length stake hashes and operator funds prevouts arrays are needed to construct the
/// transaction graph for the `N` deposits to be claimed while using and advacning the
/// [`StakeChain`].
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
/// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StakeInputs<const N: usize> {
    /// Staking amount.
    // TODO: make this configurable with a fallback const `D_BTC`.
    amount: Amount,

    /// Hashes for the `stake_txs` locking scripts.
    stake_hashes: [sha256::Hash; N],

    /// Operator fund prevouts to cover dust outputs for the entirety of the `N`-length
    /// [`StakeChain`].
    operator_funds: [TxIn; N],

    /// Output for the first stake transaction.
    original_stake: TxOut,

    /// `ΔS` relative timelock interval to advance the stake chain.
    // TODO: make this configurable with a fallback const like FINALITY_DEPTH to something like
    //       `6`.
    delta: relative::LockTime,
}

impl<const N: usize> StakeInputs<N> {
    /// Creates a new N-length [`StakeInputs`].
    ///
    /// # Arguments
    pub fn new(
        amount: Amount,
        stake_hashes: [sha256::Hash; N],
        operator_funds: [TxIn; N],
        original_stake: TxOut,
        delta: relative::LockTime,
    ) -> Self {
        Self {
            amount,
            stake_hashes,
            operator_funds,
            original_stake,
            delta,
        }
    }

    /// Converts a [`StakeInputs`] into a [`StakeChain`].
    ///
    /// # Note
    ///
    /// The [`StakeChain`] can be of length less than or equal to the [`StakeInputs`].
    ///
    /// It is impossible to create a [`StakeChain`] with a length greater than the [`StakeInputs`].
    /// This is done by compile-time checks.
    pub fn to_stake_chain<const M: usize>(&self) -> Result<StakeChain<M>, StakeChainError>
    where
        [(); N - M]:,
    {
        todo!()
    }

    /// Stake amount.
    ///
    /// The staking amount is the amount that is staked in the transaction graph for a single stake.
    pub fn amount(&self) -> Amount {
        self.amount
    }

    /// Stake hashes for all the [`StakeInputs`]s.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you only need the stake hash for a single stake, use
    /// [`StakeInputs::stake_hash_at_index`].
    pub fn stake_hashes(&self) -> [sha256::Hash; N] {
        self.stake_hashes
    }

    /// Stake hash for the [`StakeInputs`] at the given index.
    ///
    /// The stake hashes are used to derive the locking script and must be shared with between
    /// operators so that each operator can compute the transactions deterministically.
    ///
    /// If you need the stake hash for all the stakes, use [`StakeInputs::stake_hashes`].
    pub fn stake_hash_at_index(&self, index: usize) -> sha256::Hash {
        self.stake_hashes[index]
    }

    /// Operator funds for all the [`StakeInputs`]s.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeInputs`]s.
    ///
    /// If you only need the operator funds for a single stake, use
    /// [`StakeInputs::operator_funds_at_index`] since it vastly reduces the allocations.
    pub fn operator_funds(&self) -> [TxIn; N] {
        self.operator_funds.clone()
    }

    /// Operator funds for the [`StakeInputs`] at the given index.
    ///
    /// The operator funds are the inputs to cover the dust outputs for the entirety of the
    /// [`StakeInputs`]s.
    ///
    /// If you need the operator funds for all the stakes, use [`StakeInputs::operator_funds`].
    pub fn operator_funds_at_index(&self, index: usize) -> TxIn {
        self.operator_funds[index].clone()
    }

    /// Original stake.
    ///
    /// The original stake is the first stake transaction in the chain, which is used to stake in
    /// the transaction graph for a single deposit and is moved after a successful deposit, i.e.,
    /// the operator is not succcesfully challenged and has it's stake slashed.
    /// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
    pub fn original_stake(&self) -> TxOut {
        self.original_stake.clone()
    }

    /// Relative timelock interval to advance the stake chain.
    ///
    /// The stake chain can be advanced forward by revealing a preimage to a locking script that is
    /// also relative timelocked to a certain `ΔS` interval.
    pub fn delta(&self) -> relative::LockTime {
        self.delta
    }
}
