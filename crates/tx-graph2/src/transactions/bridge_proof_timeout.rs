//! This module contains the bridge proof timeout transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_primitives::scripts::prelude::create_tx_ins;

use crate::{
    connectors::{
        prelude::{
            ContestPayoutConnector, ContestProofConnector, CpfpConnector, TimelockedSpendPath,
            TimelockedWitness,
        },
        Connector, SigningInfo,
    },
    transactions::{prelude::ContestTx, ParentTx, PresignedTx},
};

/// Data that is needed to construct a [`BridgeProofTimeoutTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BridgeProofTimeoutData {
    /// ID of the contest transaction.
    pub contest_txid: Txid,
}

/// The bridge proof timeout transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeProofTimeoutTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    contest_proof_connector: ContestProofConnector,
    contest_payout_connector: ContestPayoutConnector,
    cpfp_connector: CpfpConnector,
}

impl BridgeProofTimeoutTx {
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 2;

    /// Creates a bridge proof timeout transaction.
    pub fn new(
        data: BridgeProofTimeoutData,
        contest_proof_connector: ContestProofConnector,
        contest_payout_connector: ContestPayoutConnector,
    ) -> Self {
        debug_assert!(contest_proof_connector.network() == contest_payout_connector.network());
        let cpfp_connector = CpfpConnector::new(
            contest_proof_connector.network(),
            contest_proof_connector.value() + contest_payout_connector.value(),
        );

        let utxos = [
            OutPoint {
                txid: data.contest_txid,
                vout: ContestTx::PROOF_VOUT,
            },
            OutPoint {
                txid: data.contest_txid,
                vout: ContestTx::PAYOUT_VOUT,
            },
        ];
        let prevouts = [
            contest_proof_connector.tx_out(),
            contest_payout_connector.tx_out(),
        ];
        let mut input = create_tx_ins(utxos);
        input[0].sequence = contest_proof_connector
            .relative_timelock(TimelockedSpendPath::Timeout)
            .expect("contest proof connector should have a relative timelock")
            .to_sequence();

        let output = vec![cpfp_connector.tx_out()];
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
            contest_proof_connector,
            contest_payout_connector,
            cpfp_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let contest_proof_witness = TimelockedWitness::Timeout {
            timelocked_key_signature: n_of_n_signatures[0],
        };
        let contest_payout_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signatures[1],
        };

        self.contest_proof_connector
            .finalize_input(&mut psbt.inputs[0], &contest_proof_witness);
        self.contest_payout_connector
            .finalize_input(&mut psbt.inputs[1], &contest_payout_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for BridgeProofTimeoutTx {
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

impl PresignedTx<{ Self::N_INPUTS }> for BridgeProofTimeoutTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        [
            self.contest_proof_connector.get_signing_info(
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
