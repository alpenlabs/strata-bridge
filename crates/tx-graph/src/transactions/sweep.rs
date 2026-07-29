//! This module contains the safe-harbour sweep transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, FeeRate, OutPoint, Psbt, Transaction, TxIn, TxOut, XOnlyPublicKey,
};
use bitcoin_bosd::Descriptor;
use secp256k1::schnorr;
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::{
    prelude::{MultiAnchor, NOfNConnector, NOfNSpend},
    Connector, ParentTx, SigningInfo,
};

/// Data that is needed to construct a [`SweepTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SweepData {
    /// The outpoint of the deposit UTXO being swept.
    pub deposit_outpoint: OutPoint,
}

/// The safe-harbour sweep transaction.
///
/// This transaction spends the deposit UTXO via N-of-N key-path spend and pays out to the
/// frozen safe-harbour descriptor. Since no operator can spend the safe-harbour output, it
/// carries a dedicated operator-keyed CPFP anchor for fee bumping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SweepTx {
    /// The partially signed bitcoin transaction.
    psbt: Psbt,
    /// The prevouts for sighash computation.
    prevouts: [TxOut; Self::N_INPUTS],
    /// The connector for the deposit input.
    deposit_connector: NOfNConnector,
    /// The operator-keyed CPFP anchor connector.
    cpfp_connector: MultiAnchor,
}

impl SweepTx {
    /// Index of the safe-harbour payout output.
    pub const PAYOUT_VOUT: u32 = 0;
    /// Index of the CPFP output.
    pub const CPFP_VOUT: u32 = 1;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates a sweep transaction.
    ///
    /// # Arguments
    ///
    /// * `data` - The data needed to construct the transaction (deposit outpoint).
    /// * `deposit_connector` - The N-of-N connector for the deposit input (contains amount).
    /// * `safe_harbour_descriptor` - The frozen safe-harbour descriptor to sweep to.
    /// * `operator_pubkeys` - The operator keys for the CPFP anchor (any operator can bump).
    /// * `fee_rate` - The protocol `sweep_fee_rate` shared by all operators.
    ///
    /// # Panics
    ///
    /// Panics if `fee_rate` leaves no payout above dust; validated at params load time.
    pub fn new(
        data: SweepData,
        deposit_connector: NOfNConnector,
        safe_harbour_descriptor: Descriptor,
        operator_pubkeys: Vec<XOnlyPublicKey>,
        fee_rate: FeeRate,
    ) -> Self {
        let fee = crate::fee::sweep_fee(fee_rate).expect("sweep fee must not overflow");
        let payout_value = crate::fee::sweep_payout_value(fee_rate, deposit_connector.value())
            .expect("sweep fee rate must leave a payout above dust");
        let cpfp_connector = MultiAnchor::new(
            deposit_connector.network(),
            operator_pubkeys,
            crate::fee::sweep_anchor_value(fee),
        );

        let prevouts = [deposit_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: data.deposit_outpoint,
            sequence: deposit_connector.sequence(NOfNSpend),
            ..Default::default()
        }];
        let output = vec![
            TxOut {
                value: payout_value,
                script_pubkey: safe_harbour_descriptor.to_script(),
            },
            cpfp_connector.tx_out(),
        ];

        let value_in: Amount = prevouts.iter().map(|x| x.value).sum();
        let value_out: Amount = output.iter().map(|x| x.value).sum();
        debug_assert!(
            value_in == value_out + fee,
            "tx must pay {fee} fees (value in = {value_in}, value out = {value_out})"
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

impl ParentTx for SweepTx {
    type CpfpConnector = MultiAnchor;

    fn cpfp_tx_out(&self) -> TxOut {
        self.cpfp_connector.tx_out()
    }

    fn cpfp_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::CPFP_VOUT,
        }
    }

    fn cpfp_connector(&self) -> &Self::CpfpConnector {
        &self.cpfp_connector
    }
}

impl AsRef<Transaction> for SweepTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Network, OutPoint};
    use strata_bridge_primitives::scripts::prelude::get_aggregated_pubkey;
    use strata_bridge_test_utils::bridge_fixtures::{
        random_p2tr_desc, test_operator_table, TEST_POV_IDX,
    };

    use super::*;
    use crate::fee::{sweep_fee, sweep_payout_value};

    const DEPOSIT_AMOUNT: Amount = Amount::from_sat(10_000_000);
    const FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(2);

    fn test_sweep_tx(fee_rate: FeeRate) -> SweepTx {
        let operator_table = test_operator_table(3, TEST_POV_IDX);
        let n_of_n_pubkey = get_aggregated_pubkey(operator_table.btc_keys());
        let operator_pubkeys = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        SweepTx::new(
            SweepData {
                deposit_outpoint: OutPoint::null(),
            },
            NOfNConnector::new(Network::Regtest, n_of_n_pubkey, DEPOSIT_AMOUNT),
            random_p2tr_desc(),
            operator_pubkeys,
            fee_rate,
        )
    }

    #[test]
    fn sweep_pays_deposit_minus_fee_and_anchor() {
        let tx = test_sweep_tx(FEE_RATE);
        let outputs = &tx.as_ref().output;

        assert_eq!(outputs.len(), 2);
        let payout = &outputs[SweepTx::PAYOUT_VOUT as usize];
        let anchor = &outputs[SweepTx::CPFP_VOUT as usize];
        assert_eq!(
            payout.value,
            sweep_payout_value(FEE_RATE, DEPOSIT_AMOUNT).unwrap()
        );
        assert_eq!(*anchor, tx.cpfp_tx_out());
        assert_eq!(
            payout.value + anchor.value + sweep_fee(FEE_RATE).unwrap(),
            DEPOSIT_AMOUNT
        );
    }

    #[test]
    fn zero_fee_rate_yields_zero_value_anchor() {
        let tx = test_sweep_tx(FeeRate::ZERO);
        let outputs = &tx.as_ref().output;

        assert_eq!(outputs[SweepTx::CPFP_VOUT as usize].value, Amount::ZERO);
        assert_eq!(outputs[SweepTx::PAYOUT_VOUT as usize].value, DEPOSIT_AMOUNT);
    }

    #[test]
    fn sweep_payout_value_rejects_excessive_fee_rate() {
        let absurd = FeeRate::from_sat_per_vb_unchecked(DEPOSIT_AMOUNT.to_sat());
        assert_eq!(sweep_payout_value(absurd, DEPOSIT_AMOUNT), None);

        // A rate whose payout would land below the P2TR dust floor is also rejected.
        let dust_amount = sweep_fee(FEE_RATE).unwrap() + Amount::from_sat(100);
        assert_eq!(sweep_payout_value(FEE_RATE, dust_amount), None);
    }
}
