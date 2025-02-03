//! The [`StakeTx`] transaction is used to move stake across transactions.

use bitcoin::{absolute, transaction, Amount, FeeRate, Psbt, Transaction, TxIn, TxOut};
use serde::{Deserialize, Serialize};
use strata_bridge_tx_graph::connectors::prelude::{ConnectorK, ConnectorP, ConnectorStake};

use crate::StakeChainError;

/// The [`StakeTx`] transaction is used to move stake across transactions.
///
/// It includes a PSBT that contains the inputs and outputs for the transaction.
///
/// # Input order
///
/// Inputs must be ordered in the following way:
///
/// 1. The [`OPERATOR_FUNDS`](crate::transactions::constants::OPERATOR_FUNDS) input that will cover
///    all the dust outputs for the current stake transaction.
/// 2. The stake amount from the previous [`StakeTx`] transaction.
///
/// # Output order
///
/// The outputs must be ordered in the following way:
///
/// 1. A dust output, [`ConnectorK`] used as an input to the Claim transaction and it is used to
///    bind the stake to the deposit.
/// 2. A dust output, [`ConnectorP`] used as an input to the Burn Payouts transaction that makes
///    sure that, if an operator publishes their next stake transaction before a previous payout has
///    been received, they will lose the ability to receive the payout. So it is in the operator's
///    best interest to not advance the stake chain before all previous valid payouts have been
///    received.
/// 3. The stake amount, [`ConnectorStake`], which is the first output minus the already taken into
///    account dust outputs. This is used to move the stake from the previous [`StakeTx`]
///    transaction to the current one.
///
/// # Implementation Details
///
/// Users can instantiate a [`StakeTx`] by calling the [`StakeTx::new`] function as in the example:
///
/// ```rust,ignore
/// let stake_1 = StakeTxnew(1, stake_tx_in, connector_k, connector_p, connector_s);
/// # drop(stake_1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeTx {
    /// The index of the stake transaction, denoted by `k` in the docs and specifications.
    pub index: u32,

    /// The PSBT that contains the inputs and outputs for the transaction.
    pub psbt: Psbt,

    /// The stake amount to be moved and locked up.
    pub amount: Amount,
}

impl StakeTx {
    /// Creates a new [`StakeTx`] transaction from the previous stake transaction as input and
    /// connector outputs.
    ///
    /// The inputs should be both the
    /// [`OPERATOR_FUNDS`](crate::transactions::constants::OPERATOR_FUNDS) and the
    /// [`ConnectorStake`] from the previous stake transaction as a [`Transaction`]'s vector of
    /// [`TxIn`].
    pub fn new(
        index: u32,
        inputs: Vec<TxIn>,
        connector_k: ConnectorK,
        connector_p: ConnectorP,
        connector_s: ConnectorStake,
    ) -> Self {
        // The outputs are the `TxOut`s created from the connectors.
        let outputs = vec![
            TxOut {
                value: connector_k
                    .create_taproot_address()
                    .script_pubkey()
                    .minimal_non_dust(),
                script_pubkey: connector_k.create_taproot_address().script_pubkey(),
            },
            TxOut {
                value: connector_p
                    .generate_address()
                    .script_pubkey()
                    .minimal_non_dust(),
                script_pubkey: connector_p.generate_address().script_pubkey(),
            },
            TxOut {
                value: connector_s
                    .generate_address()
                    .script_pubkey()
                    .minimal_non_dust(),
                script_pubkey: connector_s.generate_address().script_pubkey(),
            },
        ];
        let transaction = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // NOTE: The `ConnectorS` is the third output.
        let stake_amount = transaction.output[2].value;

        Self {
            index,
            psbt: Psbt::from_unsigned_tx(transaction)
                .expect("cannot fail since transaction will be always unsigned"),
            amount: stake_amount,
        }
    }

    /// The transaction's inputs.
    pub fn inputs(&self) -> Vec<TxIn> {
        self.psbt.unsigned_tx.input.clone()
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> Vec<TxOut> {
        self.psbt.unsigned_tx.output.clone()
    }

    /// The transaction's fee.
    pub fn fee(&self) -> Result<Amount, StakeChainError> {
        Ok(self.psbt.fee()?)
    }

    /// The transaction's fee rate.
    ///
    /// # Note
    ///
    /// The fee rate calculation relies on an unchecked division using the total fees and the total
    /// transaction virtual size. Internally it calls [`FeeRate::from_sat_per_vb_unchecked`].
    pub fn fee_rate(&self) -> Result<FeeRate, StakeChainError> {
        let vsize = self.psbt.unsigned_tx.vsize();
        let fee = self.fee()?;
        Ok(FeeRate::from_sat_per_vb_unchecked(
            fee.to_sat() / vsize as u64,
        ))
    }
}
