use bitcoin::{sighash::Prevouts, transaction, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{params::prelude::*, scripts::prelude::*};
use tracing::trace;

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::*;

/// Data needed to construct a [`PreAssertTx`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAssertData {
    /// The transaction ID of the claim transaction.
    pub claim_txid: Txid,

    /// The stake that remains after paying off the transaction fees in the preceding transactions.
    pub input_stake: Amount,
}

/// A transaction in the Assert chain that contains output scripts used for bitcomitting to the
/// assertion data.
#[derive(Debug, Clone)]
pub struct PreAssertTx {
    psbt: Psbt,

    remaining_stake: Amount,

    prevouts: Vec<TxOut>,

    // The ordering of these is pretty complicated.
    // This field is so that we don't have to recompute this order in other places.
    tx_outs: [TxOut; TOTAL_CONNECTORS + 1 + 1], // +1 for stake, +1 for cpfp

    witnesses: Vec<TaprootWitness>,
}

impl PreAssertTx {
    /// Constructs a new instance of the pre-assert transaction.
    ///
    /// This involves constructing the output scripts for the bitcommitment connectors
    /// ([`ConnectorA256`], [`ConnectorA160`]) and the stake connector [`ConnectorS`] as well as the
    /// input from the connector [`ConnectorC0`].
    ///
    /// The bitcommitment connectors are constructed in such a way that when spending the outputs,
    /// the stack size stays under the bitcoin consensus limit of 1000 elements, and such that when
    /// these UTXOs are sequentially chunked into transactions, the size of these transactions do
    /// not exceed the standard transaction size limit of 100,000 vbytes.
    ///
    /// A CPFP connector is required to pay the transaction fees.
    pub fn new(
        data: PreAssertData,
        connector_c0: ConnectorC0,
        connector_s: ConnectorS,
        connector_cpfp: ConnectorCpfp,
        connector_a256: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
        connector_a160: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,
    ) -> Self {
        let (connector160_batch, connector160_remainder): (
            Vec<ConnectorA160<NUM_PKS_A160_PER_CONNECTOR>>,
            ConnectorA160<NUM_PKS_A160_RESIDUAL>,
        ) = connector_a160.create_connectors();

        let (connector256_batch, _connector256_remainder): (
            Vec<ConnectorA256<NUM_PKS_A256_PER_CONNECTOR>>,
            ConnectorA256<NUM_PKS_A256_RESIDUAL>,
        ) = connector_a256.create_connectors();

        let outpoints = [OutPoint {
            txid: data.claim_txid,
            vout: 0,
        }];
        let tx_ins = create_tx_ins(outpoints);

        /* arrange locking scripts to make it easier to construct minimal number of spending
         * transactions. As of this writing, the following configuration yields the lowest
         * number of transactions:
         *
         * First, `AssertDataTx` take 7 A256<7> connectors.
         * Second, 5 * `AssertDataTx` takes 9 A160<11> connector each.
         * Third, `AssertDataTx` takes  7 A160<11> and 1 A160<2> connector.
         * connector.
         */
        let mut scripts_and_amounts = vec![];

        let connector_s_script = connector_s.create_taproot_address().script_pubkey();
        let connector_s_amt = Amount::from_int_btc(0); // this is set after all the output
                                                       // amounts have been calculated for the assertion

        scripts_and_amounts.push((connector_s_script, connector_s_amt));
        trace!(num_scripts=%scripts_and_amounts.len(), event = "added connnector_s");

        // add connector 6_7x_256
        scripts_and_amounts.extend(
            connector256_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX1_A256_PK7)
                .map(|conn| {
                    let script = conn.create_taproot_address().script_pubkey();
                    let amount = script.minimal_non_dust();

                    (script, amount)
                }),
        );
        trace!(num_scripts=%scripts_and_amounts.len(), event = "added connnector_a256");

        trace!(num_connector_a160_batch=%connector160_batch.len(), event = "a160 batch length");

        // add 5 * connector 9_11x_160 + 1 * 7_11x_160
        // the last iteration accounts for the 7_11x_160
        connector160_batch
            .chunks(NUM_ASSERT_DATA_TX2_A160_PK11)
            .for_each(|conn_batch| {
                conn_batch.iter().for_each(|conn| {
                    scripts_and_amounts.push({
                        let script = conn.create_taproot_address().script_pubkey();
                        let amount = script.minimal_non_dust();

                        (script, amount)
                    });
                });
            });

        // add connector 1_2x_160
        let connector160_remainder_script = connector160_remainder
            .create_taproot_address()
            .script_pubkey();

        let connector160_remainder_amt = connector160_remainder_script.minimal_non_dust();
        scripts_and_amounts.push((connector160_remainder_script, connector160_remainder_amt));

        trace!(num_scripts=%scripts_and_amounts.len(), event = "added connnector_160 residual");

        let cpfp_script = connector_cpfp.generate_taproot_address().script_pubkey();
        let cpfp_amount = cpfp_script.minimal_non_dust();
        scripts_and_amounts.push((cpfp_script, cpfp_amount));
        trace!(event = "added cpfp connector");

        let total_assertion_amount = scripts_and_amounts.iter().map(|(_, amt)| *amt).sum();
        let net_stake = data.input_stake - total_assertion_amount;

        trace!(event = "calculated net remaining stake", %net_stake);

        scripts_and_amounts[0].1 = net_stake;

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs.clone());
        tx.version = transaction::Version(3);

        let mut psbt =
            Psbt::from_unsigned_tx(tx).expect("input should have an empty witness field");

        let prevouts = vec![TxOut {
            value: data.input_stake,
            script_pubkey: connector_c0.generate_locking_script(),
        }];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        let (script_buf, control_block) =
            connector_c0.generate_spend_info(ConnectorC0Leaf::Assert(()));
        let witness = vec![TaprootWitness::Script {
            script_buf,
            control_block,
        }];

        Self {
            psbt,
            remaining_stake: net_stake,

            prevouts,
            tx_outs: tx_outs.try_into().unwrap(),
            witnesses: witness,
        }
    }

    /// Gets for the remaining stake.
    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
    }

    /// Gets the transaction outputs arranged in a specific order.
    pub fn tx_outs(&self) -> [TxOut; NUM_CONNECTOR_A256 + NUM_CONNECTOR_A160 + 1 + 1 + 1] {
        self.tx_outs.clone()
    }

    /// Finalizes the transaction by adding the n-of-n signature to the [`ConnectorC0`] witness.
    pub fn finalize(mut self, n_of_n_sig: Signature, connector_c0: ConnectorC0) -> Transaction {
        connector_c0.finalize_input(
            &mut self.psbt_mut().inputs[0],
            ConnectorC0Leaf::Assert(n_of_n_sig),
        );

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx for PreAssertTx {
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
}
