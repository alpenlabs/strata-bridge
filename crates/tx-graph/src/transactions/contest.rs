//! This module contains the contest transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_connectors2::{
    prelude::{
        ClaimContestConnector, ClaimContestSpendPath, ClaimContestWitness,
        ContestCounterproofOutput, ContestPayoutConnector, ContestProofConnector,
        ContestSlashConnector, P2AConnector,
    },
    Connector, ParentTx, SigningInfo,
};

use crate::transactions::prelude::ClaimTx;

/// Data that is needed to construct a [`ContestTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ContestData {
    /// ID of the claim transaction.
    pub claim_txid: Txid,
}

/// The contest transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContestTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    claim_contest_connector: ClaimContestConnector,
    proof_connector: ContestProofConnector,
    payout_connector: ContestPayoutConnector,
    slash_connector: ContestSlashConnector,
    counterproof_output: ContestCounterproofOutput,
    cpfp_connector: P2AConnector,
}

impl ContestTx {
    /// Index of the proof output.
    pub const PROOF_VOUT: u32 = 0;
    /// Index of the payout output.
    pub const PAYOUT_VOUT: u32 = 1;
    /// Index of the slash output.
    pub const SLASH_VOUT: u32 = 2;
    /// Index of the counterproof output of watchtower 0.
    pub const WATCHTOWER_0_VOUT: u32 = 3;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates a contest transaction.
    ///
    /// The same counterproof connector is reused across all watchtowers.
    pub fn new(
        data: ContestData,
        claim_contest_connector: ClaimContestConnector,
        proof_connector: ContestProofConnector,
        payout_connector: ContestPayoutConnector,
        slash_connector: ContestSlashConnector,
        counterproof_output: ContestCounterproofOutput,
    ) -> Self {
        debug_assert!(claim_contest_connector.network() == proof_connector.network());
        debug_assert!(claim_contest_connector.network() == payout_connector.network());
        debug_assert!(claim_contest_connector.network() == slash_connector.network());
        debug_assert!(claim_contest_connector.network() == counterproof_output.network());
        let cpfp_connector = P2AConnector::new(claim_contest_connector.network(), Amount::ZERO);

        let prevouts = [claim_contest_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: data.claim_txid,
                vout: ClaimTx::CONTEST_VOUT,
            },
            // NOTE: (@uncomputable) watchtower index does not matter here
            sequence: claim_contest_connector.sequence(ClaimContestSpendPath::Contested {
                watchtower_index: u32::default(),
            }),
            ..Default::default()
        }];
        let mut output = vec![
            proof_connector.tx_out(),
            payout_connector.tx_out(),
            slash_connector.tx_out(),
        ];
        output.extend(std::iter::repeat_n(
            counterproof_output.tx_out(),
            claim_contest_connector.n_watchtowers() as usize,
        ));
        output.push(cpfp_connector.tx_out());

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
            claim_contest_connector,
            proof_connector,
            payout_connector,
            slash_connector,
            counterproof_output,
            cpfp_connector,
        }
    }

    /// Returns the index of the counterproof output of the given watchtower.
    pub const fn counterproof_vout(watchtower_index: u32) -> u32 {
        Self::WATCHTOWER_0_VOUT + watchtower_index
    }

    /// Returns the index of the CPFP output.
    pub const fn cpfp_vout(n_watchtowers: u32) -> u32 {
        Self::WATCHTOWER_0_VOUT + n_watchtowers
    }

    /// Returns the number of Taproot transaction outputs.
    pub const fn n_taproot_outputs(n_watchtowers: u32) -> u32 {
        // The CPFP output is not a Taproot output, so it's not counted.
        Self::WATCHTOWER_0_VOUT + n_watchtowers
    }

    /// Returns the number of watchtowers.
    pub const fn n_watchtowers(&self) -> u32 {
        self.claim_contest_connector.n_watchtowers()
    }

    /// Get the signing info for each transaction input.
    pub fn signing_info(&self, watchtower_index: u32) -> SigningInfo {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        self.claim_contest_connector.get_signing_info(
            &mut cache,
            Prevouts::All(&self.prevouts),
            ClaimContestSpendPath::Contested { watchtower_index },
            0,
        )
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(
        self,
        n_of_n_signature: schnorr::Signature,
        watchtower_index: u32,
        watchtower_signature: schnorr::Signature,
    ) -> Transaction {
        let mut psbt = self.psbt;

        let claim_contest_witness = ClaimContestWitness::Contested {
            n_of_n_signature,
            watchtower_index,
            watchtower_signature,
        };
        self.claim_contest_connector
            .finalize_input(&mut psbt.inputs[0], &claim_contest_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for ContestTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: self.psbt.outputs.len() as u32 - 1,
        }
    }
}

impl AsRef<Transaction> for ContestTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
