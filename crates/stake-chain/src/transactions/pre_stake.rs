//! The [`PreStakeTx`] transaction is used to lock up a stake in the stake chain.

use bitcoin::{absolute, transaction, Amount, FeeRate, Psbt, Transaction, TxIn, TxOut, Txid};
use serde::{Deserialize, Serialize};

use crate::StakeChainError;

/// The [`PreStakeTx`] transaction is used to lock up a stake in the stake chain.
///
/// It includes a PSBT that contains the inputs and outputs for the transaction.
///
/// Strictly required are one or more inputs that can cover the stake amount, this will be the first
/// output to be included as an input for the first [`StakeTx`](super::StakeTx).
///
/// There's no need to include any costs for the dust amounts that are required to cover the
/// transaction graph, since these are included in every `k`th [`StakeTx`](super::StakeTx).
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
    /// stake amount.
    ///
    /// The `previous_utxo` is the [`TxOut`] from the previous transaction that funds the stake
    /// chain.
    ///
    /// NOTE: This is a [V3](`transaction::Version`) transaction.
    pub fn new(inputs: Vec<TxIn>, outputs: Vec<TxOut>, previous_utxo: &TxOut) -> Self {
        let transaction = Transaction {
            version: transaction::Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let stake_amount = transaction.output[0].value;

        let mut psbt = Psbt::from_unsigned_tx(transaction)
            .expect("cannot fail since transaction will be always unsigned");

        psbt.inputs[0].witness_utxo = Some(previous_utxo.clone());

        Self {
            psbt,
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

    /// The transaction's [`Txid`].
    ///
    /// # Note
    ///
    /// Getting the txid from a [`Psbt`]'s `unsigned_tx` is fine IF it's SegWit since the signature
    /// does not change the [`Txid`].
    pub fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
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
