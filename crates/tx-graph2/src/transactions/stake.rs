//! This module contains the stake transaction.

use bitcoin::{absolute, transaction::Version, Amount, OutPoint, Transaction, TxIn, TxOut};
use strata_bridge_connectors2::{
    prelude::{CpfpConnector, NOfNConnector, UnstakingIntentOutput},
    Connector, ParentTx,
};

/// Data that is needed to construct a [`StakeTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct StakeData {
    /// UTXO that funds the stake transaction.
    ///
    /// The value of the UTXO must be equal to
    /// `stake_amount + unstaking_intent_output.value()`.
    /// This ensures that the stake transaction pays 0 fees.
    pub stake_funds: OutPoint,
}

/// The stake transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StakeTx {
    tx: Transaction,
    unstaking_intent_output: UnstakingIntentOutput,
    stake_connector: NOfNConnector,
    cpfp_connector: CpfpConnector,
}

impl StakeTx {
    /// Index of unstaking intent output.
    pub const UNSTAKING_INTENT_VOUT: u32 = 0;
    /// Index of the stake output.
    pub const STAKE_VOUT: u32 = 1;
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 2;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates a stake transaction.
    pub fn new(
        data: StakeData,
        unstaking_intent_output: UnstakingIntentOutput,
        stake_connector: NOfNConnector,
    ) -> Self {
        debug_assert!(unstaking_intent_output.network() == stake_connector.network());
        let cpfp_connector = CpfpConnector::new(unstaking_intent_output.network(), Amount::ZERO);

        let input = vec![TxIn {
            previous_output: data.stake_funds,
            ..Default::default()
        }];
        let output = vec![
            unstaking_intent_output.tx_out(),
            stake_connector.tx_out(),
            cpfp_connector.tx_out(),
        ];
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        Self {
            tx,
            unstaking_intent_output,
            stake_connector,
            cpfp_connector,
        }
    }
}

impl ParentTx for StakeTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }
}

impl AsRef<Transaction> for StakeTx {
    fn as_ref(&self) -> &Transaction {
        &self.tx
    }
}
