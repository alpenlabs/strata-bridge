//! This module contains the uncontested payout transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    connectors::{
        prelude::{
            ClaimContestConnector, ClaimContestSpendPath, ClaimContestWitness,
            ClaimPayoutConnector, ClaimPayoutSpendPath, ClaimPayoutWitness, NOfNConnector,
            NOfNSpend,
        },
        Connector,
    },
    transactions::{prelude::ClaimTx, AsTransaction, ParentTx, PresignedTx, SigningInfo},
};

/// Data that is needed to construct a [`UncontestedPayoutTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct UncontestedPayoutData {
    /// ID of the claim transaction.
    pub claim_txid: Txid,
    /// UTXO that holds the deposit.
    pub deposit_outpoint: OutPoint,
}

/// The uncontested payout transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UncontestedPayoutTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    deposit_connector: NOfNConnector,
    claim_contest_connector: ClaimContestConnector,
    claim_payout_connector: ClaimPayoutConnector,
}

impl UncontestedPayoutTx {
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 3;

    /// Creates an uncontested payout transaction.
    pub fn new(
        data: UncontestedPayoutData,
        deposit_connector: NOfNConnector,
        claim_contest_connector: ClaimContestConnector,
        claim_payout_connector: ClaimPayoutConnector,
        operator_descriptor: Descriptor,
    ) -> Self {
        debug_assert!(deposit_connector.network() == claim_contest_connector.network());
        debug_assert!(deposit_connector.network() == claim_payout_connector.network());

        let prevouts = [
            deposit_connector.tx_out(),
            claim_contest_connector.tx_out(),
            claim_payout_connector.tx_out(),
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
                    vout: ClaimTx::CONTEST_VOUT,
                },
                sequence: claim_contest_connector.sequence(ClaimContestSpendPath::Uncontested),
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
        ];
        let output = vec![TxOut {
            value: deposit_connector.value()
                + claim_contest_connector.value()
                + claim_payout_connector.value(),
            script_pubkey: operator_descriptor.to_script(),
        }];
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
            claim_contest_connector,
            claim_payout_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let deposit_witness = n_of_n_signatures[0];
        let claim_contest_witness = ClaimContestWitness::Uncontested {
            n_of_n_signature: n_of_n_signatures[1],
        };
        let claim_payout_witness = ClaimPayoutWitness::Payout {
            output_key_signature: n_of_n_signatures[2],
        };

        self.deposit_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_witness);
        self.claim_contest_connector
            .finalize_input(&mut psbt.inputs[1], &claim_contest_witness);
        self.claim_payout_connector
            .finalize_input(&mut psbt.inputs[2], &claim_payout_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for UncontestedPayoutTx {
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

impl PresignedTx<{ Self::N_INPUTS }> for UncontestedPayoutTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [
            self.deposit_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                NOfNSpend,
                0,
            ),
            self.claim_contest_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                ClaimContestSpendPath::Uncontested,
                1,
            ),
            self.claim_payout_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                ClaimPayoutSpendPath::Payout,
                2,
            ),
        ]
    }
}

impl AsTransaction for UncontestedPayoutTx {
    fn as_unsigned_tx(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
