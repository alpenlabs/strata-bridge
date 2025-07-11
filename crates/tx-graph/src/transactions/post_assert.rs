//! Constructs the post-assert transaction.

use bitcoin::{
    sighash::Prevouts, transaction, Amount, OutPoint, Psbt, TapSighashType, Transaction, TxOut,
    Txid,
};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::{constants::*, scripts::prelude::*};
use tracing::trace;

use super::covenant_tx::CovenantTx;

/// Data needed to construct a [`PostAssertTx`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostAssertTxData {
    /// The transaction IDs of the assert data transactions in order.
    pub assert_data_txids: Vec<Txid>,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,
}

/// The number of inputs that require an $N$-of-$N$ signature in the [`PostAssertTx`].
pub const NUM_POST_ASSERT_INPUTS: usize = NUM_ASSERT_DATA_TX;

/// A transaction in the Assert chain that combines the outputs of the assert data transactions.
///
/// This is used for creating a single transaction that can then be connected to a payout or
/// disprove transaction.
#[derive(Debug, Clone)]
pub struct PostAssertTx {
    psbt: Psbt,

    output_amount: Amount,

    prevouts: [TxOut; NUM_POST_ASSERT_INPUTS],

    witnesses: [TaprootWitness; NUM_POST_ASSERT_INPUTS],
}

impl PostAssertTx {
    /// Constructs a new instance of the post-assert transaction.
    pub fn new(
        data: PostAssertTxData,
        connector_a2: ConnectorNOfN,
        connector_a3: ConnectorA3,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        // all the dust outputs from assert-data transactions
        let input_amount: Amount = SEGWIT_MIN_AMOUNT * NUM_ASSERT_DATA_TX as u64;

        let mut utxos = Vec::with_capacity(NUM_ASSERT_DATA_TX);
        utxos.extend(data.assert_data_txids.iter().map(|txid| OutPoint {
            txid: *txid,
            vout: 0,
        }));

        let tx_ins = create_tx_ins(utxos);

        trace!(event = "created tx ins", count = tx_ins.len());

        let connector_a31_script = connector_a3.generate_locking_script();
        trace!(
            event = "generated a31 locking script",
            size = connector_a31_script.len(),
        );

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amount = cpfp_script.minimal_non_dust();

        let net_amount = input_amount - cpfp_amount;
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

        let prevouts: [TxOut; NUM_ASSERT_DATA_TX] = vec![
            TxOut {
                script_pubkey: assert_data_output_script.clone(),
                value: assert_data_output_script.minimal_non_dust(),
            };
            NUM_ASSERT_DATA_TX
        ]
        .try_into()
        .expect("vec must have exactly NUM_ASSERT_DATA_TX elements");

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
            input.sighash_type = Some(TapSighashType::Default.into());
        }

        let witnesses = vec![TaprootWitness::Key; NUM_ASSERT_DATA_TX]
            .try_into()
            .expect("vec must have exactly NUM_ASSERT_DATA_TX elements");

        Self {
            psbt,
            output_amount: net_amount,

            prevouts,
            witnesses,
        }
    }

    /// Returns the remaining stake after the post-assert transaction.
    pub const fn output_amount(&self) -> Amount {
        self.output_amount
    }

    /// Returns the output index of the CPFP output.
    pub const fn cpfp_vout(&self) -> u32 {
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

impl CovenantTx<NUM_POST_ASSERT_INPUTS> for PostAssertTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness; NUM_ASSERT_DATA_TX] {
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
