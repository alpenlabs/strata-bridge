use bitcoin::{OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::signatures::wots::wots256;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    params::{
        connectors::{
            NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160_RESIDUAL, NUM_PKS_A256_PER_CONNECTOR,
        },
        prelude::{NUM_PKS_A160, NUM_PKS_A256, NUM_PKS_A256_RESIDUAL},
    },
    scripts::{prelude::*, wots},
};

use super::constants::{
    NUM_ASSERT_DATA_TX, NUM_ASSERT_DATA_TX1, NUM_ASSERT_DATA_TX1_A160_PK11,
    NUM_ASSERT_DATA_TX1_A256_PK7, NUM_ASSERT_DATA_TX2, NUM_ASSERT_DATA_TX2_A160_PK11,
    NUM_ASSERT_DATA_TX2_A160_PK2, NUM_ASSERT_DATA_TX2_A256_PK7, NUM_INPUTS_PER_ASSERT_DATA_TX,
};
use crate::connectors::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertDataTxInput {
    pub pre_assert_txid: Txid,

    pub pre_assert_txouts: Vec<TxOut>,
}

#[derive(Debug, Clone)]
pub struct AssertDataTxBatch([Psbt; NUM_ASSERT_DATA_TX]);

impl AssertDataTxBatch {
    pub fn new(input: AssertDataTxInput, connector_a2: ConnectorS) -> Self {
        let mut psbts: Vec<Psbt> = Vec::with_capacity(NUM_ASSERT_DATA_TX);

        for i in 0..NUM_ASSERT_DATA_TX {
            let starting_index = i * NUM_INPUTS_PER_ASSERT_DATA_TX + 1; // +1 to account for the stake output from
                                                                        // `pre-assert` tx

            // in the last iteration, there will be less than `N_INPUTS_PER_TX` utxos.
            let mut utxos: Vec<OutPoint> = Vec::with_capacity(NUM_INPUTS_PER_ASSERT_DATA_TX);
            let mut prevouts: Vec<TxOut> = Vec::with_capacity(NUM_INPUTS_PER_ASSERT_DATA_TX);
            for (vout, txout) in input
                .pre_assert_txouts
                .iter()
                .enumerate()
                .skip(starting_index)
                .take(NUM_INPUTS_PER_ASSERT_DATA_TX)
            {
                utxos.push(OutPoint {
                    txid: input.pre_assert_txid,
                    vout: vout as u32,
                });

                prevouts.push(txout.clone());
            }

            let tx_ins = create_tx_ins(utxos);

            let output_script = connector_a2.create_taproot_address().script_pubkey();
            let output_amt = output_script.minimal_non_dust();

            let tx_outs = create_tx_outs([(output_script, output_amt)]);

            let tx = create_tx(tx_ins, tx_outs);

            let mut psbt = Psbt::from_unsigned_tx(tx).expect("must have an empty witness");

            for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts) {
                input.witness_utxo = Some(utxo)
            }

            psbts.push(psbt);
        }

        Self(psbts.try_into().expect("should have exactly N elements"))
    }

    pub fn psbts(&self) -> &[Psbt; NUM_ASSERT_DATA_TX] {
        &self.0
    }

    pub fn psbt_at_index(&self, index: usize) -> Option<&Psbt> {
        self.0.get(index)
    }

    pub fn psbt_at_index_mut(&mut self, index: usize) -> Option<&mut Psbt> {
        self.0.get_mut(index)
    }

    pub const fn num_txs_in_batch(&self) -> usize {
        NUM_ASSERT_DATA_TX
    }

    pub fn compute_txids(&self) -> [Txid; NUM_ASSERT_DATA_TX] {
        self.0
            .iter()
            .map(|psbt| psbt.unsigned_tx.compute_txid())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    pub fn finalize(
        mut self,
        connector_a160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,
        connector_a256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
        msk: &str,
        signatures: wots::Signatures,
    ) -> [Transaction; NUM_ASSERT_DATA_TX] {
        let (connector160_batch, connector160_remainder): (
            Vec<ConnectorA160<NUM_PKS_A160_PER_CONNECTOR>>,
            ConnectorA160<NUM_PKS_A160_RESIDUAL>,
        ) = connector_a160_factory.create_connectors();

        let (connector256_batch, connector256_remainder): (
            Vec<ConnectorA256<NUM_PKS_A256_PER_CONNECTOR>>,
            ConnectorA256<NUM_PKS_A256_RESIDUAL>,
        ) = connector_a256_factory.create_connectors();

        let signatures_256: [wots256::Signature; NUM_PKS_A256] = std::array::from_fn(|i| match i {
            0 => signatures.superblock_hash,
            1 => signatures.groth16.0[0],
            _ => signatures.groth16.1[i - 2],
        });

        let mut value_offset = 0;
        for psbt_index in 0..NUM_ASSERT_DATA_TX1 {
            connector160_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX1_A160_PK11)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index],
                        msk,
                        signatures.groth16.2
                            [value_offset..value_offset + NUM_PKS_A160_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A160_PER_CONNECTOR;
                });

            let input_offset = NUM_ASSERT_DATA_TX1_A160_PK11;
            connector256_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX1_A256_PK7)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index + input_offset],
                        msk,
                        signatures_256[value_offset..value_offset + NUM_PKS_A256_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A256_PER_CONNECTOR;
                });
        }

        for psbt_index in NUM_ASSERT_DATA_TX1..NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2 {
            connector160_batch
                .iter()
                .by_ref()
                .take(NUM_ASSERT_DATA_TX2_A160_PK11)
                .enumerate()
                .for_each(|(input_index, conn)| {
                    conn.create_tx_input(
                        &mut self.0[psbt_index].inputs[input_index],
                        msk,
                        signatures.groth16.2
                            [value_offset..value_offset + NUM_PKS_A160_PER_CONNECTOR]
                            .try_into()
                            .unwrap(),
                    );

                    value_offset += NUM_PKS_A160_PER_CONNECTOR;
                });

            let residual_a160_input = &mut self.0[psbt_index].inputs[NUM_ASSERT_DATA_TX2_A160_PK11];
            connector160_remainder.create_tx_input(
                residual_a160_input,
                msk,
                signatures.groth16.2[value_offset..value_offset + NUM_PKS_A160_RESIDUAL]
                    .try_into()
                    .unwrap(),
            );

            let residual_a256_input = &mut self.0[psbt_index].inputs
                [NUM_ASSERT_DATA_TX2_A160_PK11 + NUM_ASSERT_DATA_TX2_A160_PK2];
            connector256_remainder.create_tx_input(
                residual_a256_input,
                msk,
                signatures_256[value_offset..value_offset + NUM_PKS_A256_RESIDUAL]
                    .try_into()
                    .unwrap(),
            );

            assert_eq!(
                NUM_ASSERT_DATA_TX2_A160_PK11
                    + NUM_ASSERT_DATA_TX2_A160_PK2
                    + NUM_ASSERT_DATA_TX2_A256_PK7,
                self.0[psbt_index].inputs.len(),
                "number of inputs in the second psbt must match"
            );
        }

        self.0
            .into_iter()
            .map(|psbt| {
                psbt.extract_tx()
                    .expect("should be able to extract signed tx")
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
