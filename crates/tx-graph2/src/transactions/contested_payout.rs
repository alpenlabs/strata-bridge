//! This module contains the contested payout transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_connectors2::{
    prelude::{
        ClaimPayoutConnector, ClaimPayoutSpendPath, ClaimPayoutWitness, ContestPayoutConnector,
        ContestSlashConnector, NOfNConnector, NOfNSpend, TimelockedSpendPath, TimelockedWitness,
    },
    Connector, ParentTx, SigningInfo,
};
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::transactions::{
    prelude::{ClaimTx, ContestTx},
    PresignedTx,
};

/// Data that is needed to construct a [`ContestedPayoutTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ContestedPayoutData {
    /// UTXO that holds the deposit.
    pub deposit_outpoint: OutPoint,
    /// ID of the claim transaction.
    pub claim_txid: Txid,
    /// Id of the contest transaction.
    pub contest_txid: Txid,
}

/// The contested payout transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContestedPayoutTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    deposit_connector: NOfNConnector,
    claim_payout_connector: ClaimPayoutConnector,
    contest_payout_connector: ContestPayoutConnector,
    contest_slash_connector: ContestSlashConnector,
}

impl ContestedPayoutTx {
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 4;

    /// Creates an contested payout transaction.
    pub fn new(
        data: ContestedPayoutData,
        deposit_connector: NOfNConnector,
        claim_payout_connector: ClaimPayoutConnector,
        contest_payout_connector: ContestPayoutConnector,
        contest_slash_connector: ContestSlashConnector,
        operator_descriptor: Descriptor,
    ) -> Self {
        debug_assert!(deposit_connector.network() == claim_payout_connector.network());
        debug_assert!(deposit_connector.network() == contest_payout_connector.network());
        debug_assert!(deposit_connector.network() == contest_slash_connector.network());

        let prevouts = [
            deposit_connector.tx_out(),
            claim_payout_connector.tx_out(),
            contest_payout_connector.tx_out(),
            contest_slash_connector.tx_out(),
        ];
        let input = vec![
            TxIn {
                previous_output: data.deposit_outpoint,
                sequence: deposit_connector.sequence(NOfNSpend),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.claim_txid,
                    vout: ClaimTx::PAYOUT_VOUT,
                },
                sequence: claim_payout_connector.sequence(ClaimPayoutSpendPath::Payout),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.contest_txid,
                    vout: ContestTx::PAYOUT_VOUT,
                },
                sequence: contest_payout_connector.sequence(TimelockedSpendPath::Timeout),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.contest_txid,
                    vout: ContestTx::SLASH_VOUT,
                },
                sequence: contest_slash_connector.sequence(TimelockedSpendPath::Normal),
                ..Default::default()
            },
        ];
        let output = vec![TxOut {
            value: deposit_connector.value()
                + claim_payout_connector.value()
                + contest_payout_connector.value()
                + contest_slash_connector.value(),
            script_pubkey: operator_descriptor.to_script(),
        }];

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
            deposit_connector,
            claim_payout_connector,
            contest_payout_connector,
            contest_slash_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let deposit_witness = n_of_n_signatures[0];
        let claim_payout_witness = ClaimPayoutWitness::Payout {
            output_key_signature: n_of_n_signatures[1],
        };
        let contest_payout_witnes = TimelockedWitness::Timeout {
            timelocked_key_signature: n_of_n_signatures[2],
        };
        let contest_slash_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signatures[3],
        };

        self.deposit_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_witness);
        self.claim_payout_connector
            .finalize_input(&mut psbt.inputs[1], &claim_payout_witness);
        self.contest_payout_connector
            .finalize_input(&mut psbt.inputs[2], &contest_payout_witnes);
        self.contest_slash_connector
            .finalize_input(&mut psbt.inputs[3], &contest_slash_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for ContestedPayoutTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.psbt.unsigned_tx.output[0].clone()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for ContestedPayoutTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [
            self.deposit_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                NOfNSpend,
                0,
            ),
            self.claim_payout_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                ClaimPayoutSpendPath::Payout,
                1,
            ),
            self.contest_payout_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Timeout,
                2,
            ),
            self.contest_slash_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Normal,
                3,
            ),
        ]
    }
}

impl AsRef<Transaction> for ContestedPayoutTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
