//! This module contains the cooperative payout transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxIn, TxOut,
};
use secp256k1::schnorr;
use strata_bridge_connectors2::{
    prelude::{CpfpConnector, NOfNConnector, NOfNSpend},
    Connector, ParentTx, SigningInfo,
};
use strata_primitives::bitcoin_bosd::Descriptor;

/// Data that is needed to construct a [`CooperativePayoutTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CooperativePayoutData {
    /// The outpoint of the deposit UTXO being spent.
    pub deposit_outpoint: OutPoint,
}

/// The cooperative payout transaction.
///
/// This transaction spends the deposit UTXO via N-of-N key-path spend
/// and pays out to the assigned operator's descriptor. It includes a
/// CPFP anchor output for fee bumping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CooperativePayoutTx {
    /// The partially signed bitcoin transaction.
    psbt: Psbt,
    /// The prevouts for sighash computation.
    prevouts: [TxOut; Self::N_INPUTS],
    /// The connector for the deposit input.
    deposit_connector: NOfNConnector,
    /// The CPFP connector for fee bumping.
    cpfp_connector: CpfpConnector,
}

impl CooperativePayoutTx {
    /// Index of the operator payout output.
    pub const PAYOUT_VOUT: u32 = 0;
    /// Index of the CPFP anchor output.
    pub const CPFP_VOUT: u32 = 1;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates a cooperative payout transaction.
    ///
    /// # Arguments
    ///
    /// * `data` - The data needed to construct the transaction (deposit outpoint).
    /// * `deposit_connector` - The N-of-N connector for the deposit input (contains amount).
    /// * `operator_descriptor` - The descriptor where the operator wants to receive the payout.
    ///
    /// # Returns
    ///
    /// A new `CooperativePayoutTx` ready for signing.
    pub fn new(
        data: CooperativePayoutData,
        deposit_connector: NOfNConnector,
        operator_descriptor: Descriptor,
    ) -> Self {
        let cpfp_connector = CpfpConnector::new(deposit_connector.network(), bitcoin::Amount::ZERO);

        let prevouts = [deposit_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: data.deposit_outpoint,
            sequence: deposit_connector.sequence(NOfNSpend),
            ..Default::default()
        }];

        let output = vec![
            TxOut {
                value: deposit_connector.value(),
                script_pubkey: operator_descriptor.to_script(),
            },
            cpfp_connector.tx_out(),
        ];

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
            cpfp_connector,
        }
    }

    /// Finalizes the transaction with the given N-of-N aggregated signature.
    ///
    /// # Arguments
    ///
    /// * `n_of_n_signature` - The aggregated Schnorr signature from the N-of-N multisig.
    ///
    /// # Returns
    ///
    /// The finalized Bitcoin transaction ready for broadcast.
    pub fn finalize(self, n_of_n_signature: schnorr::Signature) -> Transaction {
        let mut psbt = self.psbt;

        self.deposit_connector
            .finalize_input(&mut psbt.inputs[0], &n_of_n_signature);

        psbt.extract_tx().expect("should be able to extract tx")
    }

    /// Returns the signing info for the transaction input.
    pub fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [self.deposit_connector.get_signing_info(
            &mut cache,
            Prevouts::All(&self.prevouts),
            NOfNSpend,
            0,
        )]
    }
}

impl ParentTx for CooperativePayoutTx {
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

impl AsRef<Transaction> for CooperativePayoutTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
