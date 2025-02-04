//! The stake chain is a series of transactions that move the stake from a previous stake to a new
//! stake.

use bitcoin::{relative, Amount, OutPoint, TxIn, TxOut};
use serde::{Deserialize, Serialize};
use strata_bridge_tx_graph::connectors::prelude::{ConnectorK, ConnectorP, ConnectorStake};

use crate::prelude::StakeTx;

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
/// The current stake with respect to the stake index `k` is the previous stake transaction in index
/// `k-1`. It is the first second output of the [`StakeTx`] with respect to the stake index `k-1`.
///
/// The original stake is the first stake transaction in the chain, which is used to stake in the
/// transaction graph for a single deposit and is moved after a successful deposit, i.e., the
/// operator is not succcesfully challenged and has it's stake slashed.
/// It is the first output of the [`PreStakeTx`](crate::transactions::PreStakeTx).
///
/// The stake chain can be advanced forward by revealing a preimage to a locking script that is
/// also relative timelocked to a certain `ΔS` interval.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeChain {
    /// The staking amount.
    pub amount: Amount,

    /// The stake index, i.e., the index of the stake transaction in the chain.
    pub index: u32,

    /// The current prevout for the last stake transaction.
    pub current_stake: TxIn,

    /// The [`StakeTx`] with respect to the stake [`Self::index`].
    pub stake_tx: StakeTx,

    /// The prevout for the first stake transaction.
    pub original_stake: TxOut,

    /// The `ΔS` relative timelock interval to advance the stake chain.
    pub delta: relative::LockTime,
}

impl StakeChain {
    /// Creates a new stake chain.
    ///
    /// Once a stake chain is created, it can be advanced by revealing a preimage to a locking
    /// script that is also relative timelocked to a certain `ΔS` interval.
    ///
    /// # Arguments
    ///
    /// 1. `original_stake`: The prevout for the first stake transaction, i.e., the first output of
    ///    the [`PreStakeTx`](crate::transactions::PreStakeTx).
    /// 2. `current_stake`: The input for the current stake transaction, this is the same as
    ///    `original_stake` but as a [`TxIn`] instead of [`TxOut`].
    /// 3. `index`: The stake index, i.e., the index of the stake transaction in this stake chain.
    /// 4. `amount`: The staking amount.
    /// 5. `delta`: The `ΔS` interval relative timelock to advance the stake chain.
    /// 6. `max_slashing_transactions`: Maximum number of slashing transactions to be created.
    /// 7. `operator_funds`: The input that needs to be added to cover all the dust outputs of the
    ///    first [`StakeTx`] transaction. It's value should be equal to
    ///    [`OPERATOR_FUNDS`](crate::transactions::constants::OPERATOR_FUNDS).
    /// 8. `connector_k`: The [`ConnectorK`] for the first [`StakeTx`] in the stake chain.
    /// 9. `connector_p`: The [`ConnectorP`] for the first [`StakeTx`] in the stake chain.
    /// 10. `connector_s`: The [`ConnectorStake`] for the first [`StakeTx`] in the stake chain.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        original_stake: TxOut,
        current_stake: TxIn,
        index: u32,
        amount: Amount,
        delta: relative::LockTime,
        operator_funds: TxIn,
        connector_k: ConnectorK,
        connector_p: ConnectorP,
        connector_s: ConnectorStake,
    ) -> Self {
        // The first input is the operator's funds.
        let stake_tx = StakeTx::new(
            index,
            current_stake.clone(),
            operator_funds,
            connector_k,
            connector_p,
            connector_s,
        );
        Self {
            amount,
            index,
            current_stake,
            stake_tx,
            original_stake,
            delta,
        }
    }

    /// Advances the stake chain by revealing a preimage to a locking script that is also
    /// relative timelocked to a certain `ΔS` interval.
    ///
    /// # Arguments
    ///
    /// 1. `operator_funds`: The input that needs to be added to cover all the dust outputs of the
    ///    first [`StakeTx`] transaction. It's value should be equal to
    ///    [`OPERATOR_FUNDS`](crate::transactions::constants::OPERATOR_FUNDS).
    /// 2. `connector_k`: The [`ConnectorK`] for the first [`StakeTx`] in the stake chain.
    /// 3. `connector_p`: The [`ConnectorP`] for the first [`StakeTx`] in the stake chain.
    /// 4. `connector_s`: The [`ConnectorStake`] for the first [`StakeTx`] in the stake chain.
    ///
    /// # Note
    ///
    /// The user should also advance the stake on-chain by signing and adding the preimage to the
    /// [`Self::stake_tx`] transaction.
    pub fn advance(
        &mut self,
        operator_funds: TxIn,
        connector_k: ConnectorK,
        connector_p: ConnectorP,
        connector_s: ConnectorStake,
    ) {
        // The third output of the `StakeTx` is the stake to be moved.
        let current_stake_input = TxIn {
            previous_output: OutPoint {
                // This is valid since this is a SegWit transaction even unsigned the Txid won't
                // change.
                txid: self.stake_tx.psbt.unsigned_tx.compute_txid(),
                vout: 2, // third output
            },
            script_sig: self.stake_tx.outputs()[2].script_pubkey.clone(),
            sequence: self.delta.into(),
            // Witness will be taken care by the PSBT.
            ..Default::default()
        };

        // Mutate in-place the current stake, the index and the stake transaction.
        self.current_stake = current_stake_input.clone();
        self.index += 1;
        self.stake_tx = StakeTx::new(
            self.index,
            current_stake_input,
            operator_funds,
            connector_k,
            connector_p,
            connector_s,
        );
    }
}
