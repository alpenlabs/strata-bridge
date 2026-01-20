//! This module contains the counterproof ack transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_connectors2::{
    prelude::{
        ContestPayoutConnector, CounterproofConnector, CpfpConnector, TimelockedSpendPath,
        TimelockedWitness,
    },
    Connector, ParentTx, SigningInfo,
};

use crate::transactions::{
    prelude::{ContestTx, CounterproofTx},
    PresignedTx,
};

/// Data that is needed to construct a [`CounterproofAckTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofAckData {
    /// ID of the counterproof transaction.
    pub counterproof_txid: Txid,
    /// Id of the contest transaction.
    pub contest_txid: Txid,
}

/// The counterproof ack transaction of a watchtower.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterproofAckTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    counterproof_connector: CounterproofConnector,
    contest_payout_connector: ContestPayoutConnector,
    cpfp_connector: CpfpConnector,
}

impl CounterproofAckTx {
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 2;

    /// Creates a counterproof ack transaction.
    pub fn new(
        data: CounterproofAckData,
        counterproof_connector: CounterproofConnector,
        contest_payout_connector: ContestPayoutConnector,
    ) -> Self {
        debug_assert!(counterproof_connector.network() == contest_payout_connector.network());
        let cpfp_connector = CpfpConnector::new(
            counterproof_connector.network(),
            counterproof_connector.value() + contest_payout_connector.value(),
        );

        let prevouts = [
            counterproof_connector.tx_out(),
            contest_payout_connector.tx_out(),
        ];
        let input = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: data.counterproof_txid,
                    vout: CounterproofTx::ACK_NACK_VOUT,
                },
                sequence: counterproof_connector.sequence(TimelockedSpendPath::Timeout),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.contest_txid,
                    vout: ContestTx::PAYOUT_VOUT,
                },
                sequence: contest_payout_connector.sequence(TimelockedSpendPath::Normal),
                ..Default::default()
            },
        ];
        let output = vec![cpfp_connector.tx_out()];

        let value_in: Amount = prevouts.iter().map(|x| x.value).sum();
        let value_out: Amount = output.iter().map(|x| x.value).sum();
        debug_assert!(
            value_in == value_out,
            "tx should pay zero fees (value in = {value_in}, value out = {value_out})"
        );

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
            counterproof_connector,
            contest_payout_connector,
            cpfp_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let counterproof_witness = TimelockedWitness::Timeout {
            timelocked_key_signature: n_of_n_signatures[0],
        };
        let contest_payout_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signatures[1],
        };

        self.counterproof_connector
            .finalize_input(&mut psbt.inputs[0], &counterproof_witness);
        self.contest_payout_connector
            .finalize_input(&mut psbt.inputs[1], &contest_payout_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for CounterproofAckTx {
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

impl PresignedTx<{ Self::N_INPUTS }> for CounterproofAckTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        [
            self.counterproof_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Timeout,
                0,
            ),
            self.contest_payout_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Normal,
                1,
            ),
        ]
    }
}

impl AsRef<Transaction> for CounterproofAckTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
