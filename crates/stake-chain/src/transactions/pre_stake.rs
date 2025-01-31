//! The [`PreStakeTx`] transaction is used to lock up a stake in the stake chain.

use bitcoin::{absolute, transaction, Amount, FeeRate, Psbt, Transaction, TxIn, TxOut};
use serde::{Deserialize, Serialize};

use crate::StakeChainError;

/// The [`PreStakeTx`] transaction is used to lock up a stake in the stake chain.
///
/// It includes a PSBT that contains the inputs and outputs for the transaction.
/// Strictly required are one or more inputs that can cover the stake amount along with all the dust
/// amounts that are required to cover the transaction graph.
/// The total stake amount should be the first output for the transaction.
/// This should be the output for the initial stake in the [`StakeChain`](crate::StakeChain).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreStakeTx {
    /// The PSBT that contains the inputs and outputs for the transaction.
    pub psbt: Psbt,

    /// The stake amount to be locked up.
    pub amount: Amount,
}

impl PreStakeTx {
    /// Creates a new [`PreStakeTx`] transaction from inputs and outputs.
    ///
    /// The caller should be responsible for ensuring that the first output should cover for the the
    /// stake amount and all the dust amounts that are required to cover the transaction graph.
    pub fn new(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Self {
        let transaction = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let stake_amount = transaction.output[0].value;

        Self {
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
