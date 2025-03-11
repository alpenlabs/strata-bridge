use alpen_bridge_params::prelude::*;
use bitcoin::{sighash::Prevouts, transaction, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::scripts::prelude::*;
use tracing::trace;

use super::covenant_tx::CovenantTx;

/// Data needed to construct a [`PostAssertTx`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostAssertTxData {
    /// The transaction IDs of the assert data transactions in order.
    pub assert_data_txids: Vec<Txid>,

    /// The transaction ID of the pre-assert transaction used to carry the stake over.
    pub pre_assert_txid: Txid,

    /// The amount of the stake that was carried over after paying transaction fees.
    pub input_amount: Amount,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,
}

/// A transaction in the Assert chain that combines the outputs of the assert data transactions.
///
/// This is used for creating a single transaction that can then be connected to a payout or
/// disprove transaction.
#[derive(Debug, Clone)]
pub struct PostAssertTx {
    psbt: Psbt,

    output_amount: Amount,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl PostAssertTx {
    /// Constructs a new instance of the post-assert transaction.
    pub fn new(
        data: PostAssertTxData,
        connector_a2: ConnectorNOfN,
        connector_a3: ConnectorA3,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        let mut utxos = Vec::with_capacity(NUM_ASSERT_DATA_TX);
        utxos.extend(data.assert_data_txids.iter().map(|txid| OutPoint {
            txid: *txid,
            vout: 0,
        }));

        let tx_ins = create_tx_ins(utxos);

        trace!(event = "created tx ins", count = tx_ins.len());

        let connector_a31_script = connector_a3.generate_locking_script(data.deposit_txid);
        trace!(
            event = "generated a31 locking script",
            size = connector_a31_script.len(),
        );

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amount = cpfp_script.minimal_non_dust();

        let net_amount = data.input_amount - cpfp_amount;
        let scripts_and_amounts = [
            (connector_a31_script.clone(), net_amount),
            (cpfp_script, cpfp_amount),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);
        trace!(event = "created tx outs", count = tx_outs.len());

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        let assert_data_output_script = connector_a2.create_taproot_address().script_pubkey();

        let prevouts = (0..NUM_ASSERT_DATA_TX)
            .map(|_| TxOut {
                script_pubkey: assert_data_output_script.clone(),
                value: assert_data_output_script.minimal_non_dust(),
            })
            .collect::<Vec<TxOut>>();

        trace!(event = "created prevouts", count = prevouts.len());

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        let witnesses = vec![TaprootWitness::Key; NUM_ASSERT_DATA_TX];

        Self {
            psbt,
            output_amount: net_amount,

            prevouts,
            witnesses,
        }
    }

    /// Returns the remaining stake after the post-assert transaction.
    pub fn output_amount(&self) -> Amount {
        self.output_amount
    }

    pub fn cpfp_vout(&self) -> u32 {
        self.psbt.outputs.len() as u32 - 1
    }

    /// Finalizes the transaction by adding the required n-of-n signatures.
    ///
    /// The signatures must be specified in the order of the inputs.
    pub fn finalize(mut self, signatures: &[Signature]) -> Transaction {
        // skip the stake
        for (index, input) in self.psbt.inputs.iter_mut().enumerate() {
            finalize_input(input, [signatures[index].as_ref()]);
        }

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }
}

impl CovenantTx for PostAssertTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness] {
        &self.witnesses
    }

    fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    fn input_amount(&self) -> Amount {
        self.psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .expect("witness utxo must exist")
                    .value
            })
            .sum()
    }
}
