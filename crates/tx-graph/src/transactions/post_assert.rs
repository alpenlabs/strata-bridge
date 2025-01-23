use bitcoin::{sighash::Prevouts, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{params::prelude::*, scripts::prelude::*, types::OperatorIdx};
use tracing::trace;

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::*;

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

    remaining_stake: Amount,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl PostAssertTx {
    /// Constructs a new instance of the post-assert transaction.
    pub fn new(
        data: PostAssertTxData,
        operator_idx: OperatorIdx,
        connector_a2: ConnectorS,
        connector_a30: ConnectorA30,
        connector_a31: ConnectorA31,
    ) -> Self {
        // +1 for stake
        let total_inputs = NUM_ASSERT_DATA_TX + 1;
        let mut utxos = Vec::with_capacity(total_inputs);
        utxos.push(OutPoint {
            txid: data.pre_assert_txid,
            vout: 0,
        });

        utxos.extend(data.assert_data_txids.iter().map(|txid| OutPoint {
            txid: *txid,
            vout: 0,
        }));

        let tx_ins = create_tx_ins(utxos);

        trace!(event = "created tx ins", count = tx_ins.len(), %operator_idx);

        let connector_a31_script = connector_a31.generate_locking_script(data.deposit_txid);
        trace!(
            event = "generated a31 locking script",
            size = connector_a31_script.len(), %operator_idx,
        );

        let mut scripts_and_amounts = [
            (
                connector_a30.generate_locking_script(),
                Amount::from_int_btc(0), // set net amount later
            ),
            (
                connector_a31_script.clone(),
                connector_a31_script.minimal_non_dust(),
            ),
        ];

        let net_stake = data.input_amount
            - scripts_and_amounts.iter().map(|(_, amt)| *amt).sum()
            - MIN_RELAY_FEE;
        trace!(%net_stake, %operator_idx, event = "calculated net stake for post-assert");
        scripts_and_amounts[0].1 = net_stake;

        let tx_outs = create_tx_outs(scripts_and_amounts);
        trace!(event = "created tx outs", count = tx_outs.len(), %operator_idx);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        let assert_data_output_script = connector_a2.create_taproot_address().script_pubkey();

        let mut prevouts = (0..total_inputs)
            .map(|_| TxOut {
                script_pubkey: assert_data_output_script.clone(),
                value: assert_data_output_script.minimal_non_dust(),
            })
            .collect::<Vec<TxOut>>();

        prevouts[0].value = data.input_amount; // from the stake

        trace!(event = "created prevouts", count = prevouts.len(), %operator_idx);

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        let witnesses = vec![TaprootWitness::Key; total_inputs];

        Self {
            psbt,
            remaining_stake: net_stake,

            prevouts,
            witnesses,
        }
    }

    /// Returns the remaining stake after the post-assert transaction.
    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
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
