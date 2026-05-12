//! This module contains the deposit transaction.

use bitcoin::{
    absolute,
    psbt::ExtractTxError,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut,
};
use secp256k1::schnorr;
use serde::{Deserialize, Serialize};
use strata_asm_proto_bridge_v1_txs::deposit::DepositTxHeaderAux;
use strata_bridge_connectors::{
    prelude::{DepositRequestConnector, NOfNConnector, TimelockedSpendPath, TimelockedWitness},
    Connector, SigningInfo,
};
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use tracing::warn;

use crate::transactions::PresignedTx;

/// Data that is needed to construct a [`DepositTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositData {
    /// Deposit index.
    pub deposit_idx: u32,
    /// Outpoint of the deposit request transaction.
    pub deposit_request_outpoint: OutPoint,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
}

impl DepositData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the deposit transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let tag_data = DepositTxHeaderAux::new(self.deposit_idx).build_tag_data();
        ParseConfig::new(self.magic_bytes)
            .encode_script_buf(&tag_data.as_ref())
            .expect("encoding should be valid")
    }
}

// TODO: <https://alpenlabs.atlassian.net/browse/STR-2709>
// Add a unit test proving the deposit transaction can be parsed by ASM code.
// https://github.com/alpenlabs/alpen/blob/b016495114050409e831898436d7d0ac04df8d82/crates/asm/txs/bridge-v1/src/deposit/parse.rs#L85
/// The deposit transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DepositTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    deposit_connector: NOfNConnector,
    deposit_request_connector: DepositRequestConnector,
}

impl DepositTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Index of the deposit connector.
    pub const DEPOSIT_VOUT: u32 = 1;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Returns the minimum value the depositor must put in the deposit-request UTXO so that
    /// the bridge's deposit transaction can pay its own fee.
    pub fn drt_required(deposit_amount: Amount) -> Amount {
        deposit_amount + crate::fee::deposit_fee()
    }

    /// Creates a deposit transaction.
    ///
    /// The depositor's deposit-request UTXO must carry at least
    /// `deposit_connector.value() + crate::fee::deposit_fee()` so the deposit transaction can
    /// pay its own fee. Surplus beyond that is also paid as fee.
    pub fn new(
        data: DepositData,
        deposit_connector: NOfNConnector,
        deposit_request_connector: DepositRequestConnector,
    ) -> Self {
        debug_assert!(deposit_connector.network() == deposit_request_connector.network());
        debug_assert!(deposit_connector.internal_key() == deposit_request_connector.internal_key());
        let fee = crate::fee::deposit_fee();
        debug_assert!(
            deposit_request_connector.value() >= deposit_connector.value() + fee,
            "deposit-request UTXO must include at least {fee} of fee \
             (drt value = {}, deposit value = {})",
            deposit_request_connector.value(),
            deposit_connector.value(),
        );

        let prevouts = [deposit_request_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: data.deposit_request_outpoint,
            sequence: deposit_request_connector.sequence(TimelockedSpendPath::Normal),
            ..Default::default()
        }];
        let output = vec![
            TxOut {
                script_pubkey: data.header_leaf_script(),
                value: Amount::ZERO,
            },
            deposit_connector.tx_out(),
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
            deposit_request_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signature: schnorr::Signature) -> Transaction {
        let mut psbt = self.psbt;
        let deposit_request_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signature,
        };
        self.deposit_request_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_request_witness);

        // `Psbt::extract_tx` rejects fee rates above `DEFAULT_MAX_FEE_RATE` (25 ksat/vb). The
        // depositor controls the DRT amount, so an "absurd" fee rate is external input — not an
        // invariant violation. Log a warning and proceed with the recovered tx; the surplus goes to
        // the miner. The other variants are invariant violations given
        // how `DepositTx::new` is constructed and the upstream DRT validation, so they panic.
        match psbt.extract_tx() {
            Ok(tx) => tx,
            Err(ExtractTxError::AbsurdFeeRate { fee_rate, tx }) => {
                warn!(
                    %fee_rate,
                    txid = %tx.compute_txid(),
                    "DRT overpaid; finalizing deposit tx anyway",
                );
                tx
            }
            // `DepositTx::new` always populates `witness_utxo` on the input.
            Err(err @ ExtractTxError::MissingInputValue { .. }) => {
                panic!("deposit tx PSBT missing input value: {err}")
            }
            // Upstream DRT validation must guarantee `drt_value >= deposit_amount + deposit_fee`.
            Err(err @ ExtractTxError::SendingTooMuch { .. }) => {
                panic!("deposit tx outputs exceed inputs: {err}")
            }
            // `ExtractTxError` is `#[non_exhaustive]`; this catch-all fires only if a future
            // `bitcoin` release adds a new variant, in which case we want to fail loudly until
            // this match is updated.
            Err(err) => panic!("unhandled ExtractTxError variant: {err}"),
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for DepositTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [self.deposit_request_connector.get_signing_info(
            &mut cache,
            Prevouts::All(&self.prevouts),
            TimelockedSpendPath::Normal,
            0,
        )]
    }
}

impl AsRef<Transaction> for DepositTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{relative, Network};
    use secp256k1::Keypair;
    use strata_bridge_test_utils::bitcoin::generate_keypair;

    use super::*;

    const DEPOSIT_AMOUNT: Amount = Amount::from_int_btc(10);
    const RECOVERY_DELAY: u16 = 1_008;

    fn dummy_sig() -> schnorr::Signature {
        schnorr::Signature::from_slice(&[0xAA; 64]).expect("64 bytes is a valid sig length")
    }

    fn make_deposit_tx(drt_value: Amount) -> DepositTx {
        let n_of_n: Keypair = generate_keypair();
        let depositor: Keypair = generate_keypair();
        let deposit_request = DepositRequestConnector::new(
            Network::Regtest,
            n_of_n.x_only_public_key().0,
            depositor.x_only_public_key().0,
            relative::Height::from_height(RECOVERY_DELAY),
            drt_value,
        );
        let deposit_connector = NOfNConnector::new(
            Network::Regtest,
            n_of_n.x_only_public_key().0,
            DEPOSIT_AMOUNT,
        );
        let data = DepositData {
            deposit_idx: 0,
            deposit_request_outpoint: OutPoint::null(),
            magic_bytes: (*b"ALPN").into(),
        };
        DepositTx::new(data, deposit_connector, deposit_request)
    }

    #[test]
    fn finalize_does_not_panic_on_absurd_fee_rate() {
        // 0.034 BTC = 3,400,000 sats => ~25k sat/vbyte fee rate on a 132 vbyte tx
        let drt_value = DEPOSIT_AMOUNT + Amount::from_sat(3_400_000);
        let tx = make_deposit_tx(drt_value).finalize(dummy_sig());

        assert_eq!(
            tx.input.len(),
            DepositTx::N_INPUTS,
            "finalized deposit tx must carry exactly one input",
        );
        assert_eq!(
            tx.output[DepositTx::DEPOSIT_VOUT as usize].value,
            DEPOSIT_AMOUNT,
            "finalized deposit tx's connector output must carry deposit_amount",
        );
    }
}
