//! This module contains the unstaking transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_connectors2::{
    prelude::{NOfNConnector, NOfNSpend, TimelockedSpendPath, TimelockedWitness, UnstakingOutput},
    Connector, ParentTx, SigningInfo,
};
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::transactions::{
    prelude::{StakeTx, UnstakingIntentTx},
    PresignedTx,
};

/// Data that is needed to construct an [`UnstakingTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingData {
    /// ID of the stake transaction.
    pub stake_txid: Txid,
    /// ID of the unstaking intent transaction.
    pub unstaking_intent_txid: Txid,
}

/// The unstaking transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    unstaking_output: UnstakingOutput,
    stake_connector: NOfNConnector,
}

impl UnstakingTx {
    /// Index where the operator receives the stake.
    pub const OPERATOR_VOUT: u32 = 0;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 2;

    /// Creates an unstaking transaction.
    pub fn new(
        data: UnstakingData,
        unstaking_output: UnstakingOutput,
        stake_connector: NOfNConnector,
        operator_descriptor: &Descriptor,
    ) -> Self {
        debug_assert!(unstaking_output.network() == stake_connector.network());

        let prevouts = [unstaking_output.tx_out(), stake_connector.tx_out()];
        let input = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: data.unstaking_intent_txid,
                    vout: UnstakingIntentTx::UNSTAKING_VOUT,
                },
                sequence: unstaking_output.sequence(TimelockedSpendPath::Timeout),
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: data.stake_txid,
                    vout: StakeTx::STAKE_VOUT,
                },
                sequence: stake_connector.sequence(NOfNSpend),
                ..Default::default()
            },
        ];
        let output = vec![TxOut {
            script_pubkey: operator_descriptor.to_script(),
            value: unstaking_output.value() + stake_connector.value(),
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
            unstaking_output,
            stake_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signatures: [schnorr::Signature; Self::N_INPUTS]) -> Transaction {
        let mut psbt = self.psbt;

        let unstaking_witness = TimelockedWitness::Timeout {
            timelocked_key_signature: n_of_n_signatures[0],
        };

        self.unstaking_output
            .finalize_input(&mut psbt.inputs[0], &unstaking_witness);
        self.stake_connector
            .finalize_input(&mut psbt.inputs[1], &n_of_n_signatures[1]);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTx for UnstakingTx {
    fn cpfp_tx_out(&self) -> TxOut {
        self.psbt.unsigned_tx.output[0].clone()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::OPERATOR_VOUT,
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for UnstakingTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);

        [
            self.unstaking_output.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                TimelockedSpendPath::Timeout,
                0,
            ),
            self.stake_connector.get_signing_info(
                &mut cache,
                Prevouts::All(&self.prevouts),
                NOfNSpend,
                1,
            ),
        ]
    }
}

impl AsRef<Transaction> for UnstakingTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
