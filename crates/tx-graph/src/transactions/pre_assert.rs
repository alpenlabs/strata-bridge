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

pub(super) const PRE_ASSERT_OUTS: usize = TOTAL_CONNECTORS + 1 + 1; // +1 for stake, // +1 for cpfp

/// A transaction in the Assert chain that contains output scripts used for bitcomitting to the
/// assertion data.
#[derive(Debug, Clone)]
pub struct PreAssertTx {
    psbt: Psbt,

    remaining_stake: Amount,

    prevouts: Vec<TxOut>,

    // The ordering of these is pretty complicated.
    // This field is so that we don't have to recompute this order in other places.
    tx_outs: [TxOut; PRE_ASSERT_OUTS],

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
    /// not exceed the standard transaction size limit of 10,000 vbytes for v3 transactions.
    ///
    /// Refer to the documentation in [`strata_bridge_primitives::params::connectors`] for more
    /// details.
    ///
    /// A CPFP connector is required to pay the transaction fees.
    pub fn new(
        data: PreAssertData,
        connector_c0: ConnectorC0,
        connector_s: ConnectorS,
        connector_cpfp: ConnectorCpfp,
        connector_a256: ConnectorA256Factory<
            NUM_FIELD_CONNECTORS_BATCH_1,
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1,
            NUM_FIELD_CONNECTORS_BATCH_2,
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2,
        >,
        connector_a160: ConnectorA160Factory<
            NUM_HASH_CONNECTORS_BATCH_1,
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1,
            NUM_HASH_CONNECTORS_BATCH_2,
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2,
        >,
    ) -> Self {
        let outpoints = [OutPoint {
            txid: data.claim_txid,
            vout: 0,
        }];
        let tx_ins = create_tx_ins(outpoints);

        let mut scripts_and_amounts = vec![];

        let connector_s_script = connector_s.create_taproot_address().script_pubkey();
        let connector_s_amt = Amount::from_int_btc(0); // this is set after all the output
                                                       // amounts have been calculated for the assertion

        scripts_and_amounts.push((connector_s_script, connector_s_amt));
        trace!(num_scripts=%scripts_and_amounts.len(), event = "added connnector_s");

        let (connector256_batch1, connector256_batch2): (
            [ConnectorA256<NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1>; NUM_FIELD_CONNECTORS_BATCH_1],
            [ConnectorA256<NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2>; NUM_FIELD_CONNECTORS_BATCH_2],
        ) = connector_a256.create_connectors();

        let (connector160_batch1, connector160_batch2): (
            [ConnectorA160<NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1>; NUM_HASH_CONNECTORS_BATCH_1],
            [ConnectorA160<NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2>; NUM_HASH_CONNECTORS_BATCH_2],
        ) = connector_a160.create_connectors();

        connector256_batch1.iter().for_each(|conn| {
            let script = conn.create_taproot_address().script_pubkey();
            // x2 accounts for the two dust outputs in the assert-data tx one of which will be used
            // for CPFP.
            let amount = script.minimal_non_dust() * 2;

            scripts_and_amounts.push((script, amount));
        });

        connector256_batch2.iter().for_each(|conn| {
            let script = conn.create_taproot_address().script_pubkey();
            // x2 accounts for the two dust outputs in the assert-data tx one of which will be used
            // for CPFP.
            let amount = script.minimal_non_dust() * 2;

            scripts_and_amounts.push((script, amount));
        });

        connector160_batch1.iter().for_each(|conn| {
            let script = conn.create_taproot_address().script_pubkey();
            // x2 accounts for the two dust outputs in the assert-data tx one of which will be used
            // for CPFP.
            let amount = script.minimal_non_dust() * 2;

            scripts_and_amounts.push((script, amount));
        });

        connector160_batch2.iter().for_each(|conn| {
            let script = conn.create_taproot_address().script_pubkey();
            // x2 accounts for the two dust outputs in the assert-data tx one of which will be used
            // for CPFP.
            let amount = script.minimal_non_dust() * 2;

            scripts_and_amounts.push((script, amount));
        });

        trace!(num_scripts=%scripts_and_amounts.len(), event = "added all bitcommitment connectors");

        let cpfp_script = connector_cpfp.generate_taproot_address().script_pubkey();
        let cpfp_amount = cpfp_script.minimal_non_dust();
        scripts_and_amounts.push((cpfp_script, cpfp_amount));
        trace!(event = "added cpfp connector");

        let total_assertion_amount = scripts_and_amounts.iter().map(|(_, amt)| *amt).sum();
        // No additional transaction fees are deducted from the stake.
        // Transaction fees are expected to come via CPFP.
        let net_stake = data.input_stake - total_assertion_amount;

        trace!(event = "calculated net remaining stake", %net_stake);

        scripts_and_amounts[0].1 = net_stake;

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs.clone());
        tx.version = transaction::Version(3); // for 0-fee TRUC transactions

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

        // This cannot be ensured at compile-time due to the need to create the
        // `scripts_and_amounts` vector.
        // Violation of this assertion is a logical error.
        assert_eq!(
            tx_outs.len(),
            PRE_ASSERT_OUTS,
            "BUG: the number of tx_outs in the pre-assert must match"
        );

        Self {
            psbt,
            remaining_stake: net_stake,

            prevouts,
            tx_outs: tx_outs
                .try_into()
                .expect("cannot fail due to the assertion above"),
            witnesses: witness,
        }
    }

    /// Gets for the remaining stake.
    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
    }

    /// Gets the transaction outputs arranged in a specific order.
    pub fn tx_outs(&self) -> [TxOut; PRE_ASSERT_OUTS] {
        self.tx_outs.clone()
    }

    /// Gets the CPFP output index.
    pub fn cpfp_vout(&self) -> u32 {
        self.psbt.outputs.len() as u32 - 1
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
