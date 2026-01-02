//! This module contains the contest transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::Message;

use crate::{
    connectors::{
        prelude::{
            ContestCounterproofOutput, ContestCounterproofSpend, ContestCounterproofWitness,
            CounterproofConnector, CpfpConnector,
        },
        Connector,
    },
    transactions::{prelude::ContestTx, AsTransaction, ParentTx},
};

/// Data that is needed to construct a [`CounterproofTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofData {
    /// ID of the claim transaction.
    pub contest_txid: Txid,
    /// Index of the watchtower.
    pub watchtower_index: u32,
}

/// The counterproof transaction of a watchtower.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    watchtower_index: u32,
    contest_counterproof_output: ContestCounterproofOutput,
    counterproof_connector: CounterproofConnector,
    cpfp_connector: CpfpConnector,
}

impl CounterproofTx {
    /// Index of the ACK / NACK output.
    pub const ACK_NACK_VOUT: u32 = 0;
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 1;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates a counterproof transaction.
    pub fn new(
        data: CounterproofData,
        contest_counterproof_output: ContestCounterproofOutput,
        counterproof_connector: CounterproofConnector,
    ) -> Self {
        debug_assert!(contest_counterproof_output.network() == counterproof_connector.network());
        debug_assert!(
            contest_counterproof_output.value() == counterproof_connector.value(),
            "tx should have zero fees (value in = {}, value out = {}",
            contest_counterproof_output.value(),
            counterproof_connector.value()
        );
        let cpfp_connector =
            CpfpConnector::new(contest_counterproof_output.network(), Amount::ZERO);

        let prevouts = [contest_counterproof_output.tx_out()];
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: data.contest_txid,
                vout: ContestTx::counterproof_vout(data.watchtower_index),
            },
            sequence: contest_counterproof_output.sequence(ContestCounterproofSpend),
            ..Default::default()
        }];
        let output = vec![counterproof_connector.tx_out(), cpfp_connector.tx_out()];

        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        Self {
            psbt,
            prevouts,
            watchtower_index: data.watchtower_index,
            contest_counterproof_output,
            counterproof_connector,
            cpfp_connector,
        }
    }

    /// Get the sighashes of the single transaction input.
    ///
    /// The first sighash needs to be signed by the N/N key.
    /// The first (again) and all remaining sighashes each need to be signed by the operator key.
    pub fn signing_info(&self) -> Vec<Message> {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        self.contest_counterproof_output
            .get_sighashes_with_code_separator(
                &mut cache,
                Prevouts::All(&self.prevouts),
                ContestCounterproofSpend,
                0,
            )
            .into_iter()
            .collect() // TODO: (@uncomputable) Avoid allocation
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, witness: &ContestCounterproofWitness) -> Transaction {
        let mut psbt = self.psbt;
        self.contest_counterproof_output
            .finalize_input(&mut psbt.inputs[0], witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for CounterproofTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }
}

impl AsTransaction for CounterproofTx {
    fn as_unsigned_tx(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
