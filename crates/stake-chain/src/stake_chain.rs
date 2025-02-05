//! The stake chain is a series of transactions that move the stake from a previous stake to a new
//! stake.

use bitcoin::{hashes::sha256, relative, Amount, Network, OutPoint, TxIn, XOnlyPublicKey};
use strata_bridge_primitives::wots;
use strata_bridge_tx_graph::connectors::prelude::{ConnectorK, ConnectorP, ConnectorStake};

use crate::prelude::{StakeTx, STAKE_VOUT};

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
/// 2. Operator's public key.
/// 3. N-of-N aggregated bridge public key.
/// 4. `N`-length array of WOTS public keys.
/// 5. `N`-length array of stake hashes.
/// 6. `N`-length array of operator fund prevouts.
/// 7. Original stake prevout.
/// 8. `ΔS` relative timelock interval.
/// 9. Network.
///
/// The staking amount and the `ΔS` relative timelock interval are scalar values and configurable
/// parameters which can be set at compile time to a contracted value.
///
/// The `N`-length WOTS public keys, stake hashes, and operator funds prevouts arrays are needed to
/// construct the transaction graph for the `N` deposits to be claimed while using and advancing the
/// [`StakeChain`].
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
/// It is the first output of the [`PreStakeTx`](crate::prelude::PreStakeTx).
///
/// The network is the bitcoin network on which the stake chain operates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeInputs<const N: usize> {
    /// Staking amount.
    // TODO: make this configurable with a fallback const `D_BTC`.
    amount: Amount,

    /// Operator's public key.
    operator_pubkey: XOnlyPublicKey,

    /// N-of-N aggregated bridge public key.
    n_of_n_agg_pubkey: XOnlyPublicKey,

    /// WOTS public keys use for the bitcommitment scripts in [`ConnectorK`]s.
    wots_public_keys: [wots::PublicKeys; N],

    /// Hashes for the `stake_txs` locking scripts.
    stake_hashes: [sha256::Hash; N],

    /// Operator fund prevouts to cover dust outputs for the entirety of the `N`-length
    /// [`StakeChain`].
    operator_funds: [TxIn; N],

    /// Output for the first stake transaction.
    original_stake: TxIn,

    /// `ΔS` relative timelock interval to advance the stake chain.
    // TODO: make this configurable with a fallback const like FINALITY_DEPTH to something like
    //       `6`.
    delta: relative::LockTime,

    /// Network on which the stake chain operates.
    network: Network,
}

impl<const N: usize> StakeInputs<N> {
    /// Creates a new N-length [`StakeInputs`].
    ///
    /// # Arguments
    ///
    /// 1. Stake amount.
    /// 2. Operator's public key.
    /// 3. N-of-N aggregated bridge public key.
    /// 4. `N`-length array of WOTS public keys.
    /// 5. `N`-length array of stake hashes.
    /// 6. `N`-length array of operator fund prevouts.
    /// 7. Original stake prevout.
    /// 8. `ΔS` relative timelock interval.
    /// 9. Network.
    ///
    /// For an explanation of the parameters, see the documentation for [`StakeInputs`].
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        amount: Amount,
        operator_pubkey: XOnlyPublicKey,
        n_of_n_agg_pubkey: XOnlyPublicKey,
        wots_public_keys: [wots::PublicKeys; N],
        stake_hashes: [sha256::Hash; N],
        operator_funds: [TxIn; N],
        original_stake: TxIn,
        delta: relative::LockTime,
        network: Network,
    ) -> Self {
        Self {
            amount,
            operator_pubkey,
            n_of_n_agg_pubkey,
            wots_public_keys,
            stake_hashes,
            operator_funds,
            original_stake,
            delta,
            network,
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
    pub fn to_stake_chain<const M: usize>(&self) -> StakeChain<M>
    where
        [(); N - M]:,
    {
        let connector_k = ConnectorK::new(
            self.n_of_n_agg_pubkey,
            self.network,
            self.wots_public_keys[0],
        );
        let connector_p =
            ConnectorP::new(self.n_of_n_agg_pubkey, self.stake_hashes[0], self.network);
        let connector_s = ConnectorStake::new(
            self.n_of_n_agg_pubkey,
            self.operator_pubkey,
            self.stake_hashes[0],
            self.delta,
            self.network,
        );
        let first_stake_tx = StakeTx::new(
            0,
            self.original_stake.clone(),
            self.amount,
            self.operator_funds[0].clone(),
            self.operator_pubkey,
            connector_k,
            connector_p,
            connector_s,
            self.network,
        );

        // Instantiate a vector with the length `M`.
        let mut stake_chain = Vec::with_capacity(M);
        stake_chain.push(first_stake_tx);

        // for-loop to generate the rest of the `StakeTx`s from the second
        for index in 1..M {
            let previous_stake_tx = stake_chain.get(index -1).expect("always valid since we are starting from 1 (we always have 0) and the length is checked at compile time");
            let new_stake_tx = generate_new_stake_tx(
                previous_stake_tx,
                self.amount,
                self.delta,
                self.operator_funds[index].clone(),
                self.operator_pubkey,
                self.n_of_n_agg_pubkey,
                self.wots_public_keys[index],
                self.stake_hashes[index],
                self.network,
            );
            stake_chain.push(new_stake_tx);
        }
        stake_chain
            .try_into()
            .expect("infallible since we are aware that M < N (compile-time check")
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
    pub fn original_stake(&self) -> TxIn {
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

/// Generates a new [`StakeTx`] transaction for the given current [`StakeTx`] transaction.
#[expect(clippy::too_many_arguments)]
fn generate_new_stake_tx(
    current_stake_tx: &StakeTx,
    stake_amount: Amount,
    delta: relative::LockTime,
    operator_funds: TxIn,
    operator_pubkey: XOnlyPublicKey,
    n_of_n_agg_pubkey: XOnlyPublicKey,
    wots_public_keys: wots::PublicKeys,
    stake_hash: sha256::Hash,
    network: Network,
) -> StakeTx {
    // Get data from current `StakeTx`.
    let current_index = current_stake_tx.index;
    let stake_input = TxIn {
        previous_output: OutPoint {
            txid: current_stake_tx.compute_txid(),
            vout: STAKE_VOUT,
        },
        // Important: set the relative timelock to match the delta from the previous stake tx.
        sequence: delta.into(),
        ..Default::default()
    };

    // Connectors.
    let connector_k = ConnectorK::new(n_of_n_agg_pubkey, network, wots_public_keys);
    let connector_p = ConnectorP::new(n_of_n_agg_pubkey, stake_hash, network);
    let connector_s = ConnectorStake::new(
        n_of_n_agg_pubkey,
        operator_pubkey,
        stake_hash,
        delta,
        network,
    );
    StakeTx::new(
        current_index + 1,
        stake_input,
        stake_amount,
        operator_funds,
        operator_pubkey,
        connector_k,
        connector_p,
        connector_s,
        network,
    )
}
