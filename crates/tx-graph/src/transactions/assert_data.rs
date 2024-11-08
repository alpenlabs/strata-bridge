use bitcoin::{OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::signatures::wots::wots256;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    params::{
        connectors::{
            NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160_RESIDUAL, NUM_PKS_A256_PER_CONNECTOR,
        },
        prelude::{
            NUM_CONNECTOR_A160, NUM_CONNECTOR_A256, NUM_PKS_A160, NUM_PKS_A256,
            NUM_PKS_A256_RESIDUAL,
        },
    },
    scripts::{prelude::*, wots},
};

use super::constants::{
    NUM_ASSERT_DATA_TX, NUM_ASSERT_DATA_TX1, NUM_ASSERT_DATA_TX1_A256_PK7,
    NUM_ASSERT_DATA_TX2_A160_PK11,
};
use crate::{
    connectors::prelude::*,
    transactions::constants::{
        NUM_ASSERT_DATA_TX2, NUM_ASSERT_DATA_TX3_A160_PK11, NUM_ASSERT_DATA_TX3_A160_PK2,
    },
};

#[derive(Debug, Clone)]
pub struct AssertDataTxInput {
    pub pre_assert_txid: Txid,

    pub pre_assert_txouts: [TxOut; NUM_CONNECTOR_A160 + NUM_CONNECTOR_A256 + 1 + 1], /* 1 =>
                                                                                      * residual, 1 => stake */
}

#[derive(Debug, Clone)]
pub struct AssertDataTxBatch([Psbt; NUM_ASSERT_DATA_TX]);

impl AssertDataTxBatch {
    pub fn new(input: AssertDataTxInput, connector_a2: ConnectorS) -> Self {
        Self(std::array::from_fn(|i| {
            let (utxos, prevouts): (Vec<OutPoint>, Vec<TxOut>) = {
                let (skip, take) = match i {
                    0 => (1, NUM_ASSERT_DATA_TX1_A256_PK7),
                    1..=5 => (
                        1 + NUM_ASSERT_DATA_TX1_A256_PK7 + (i - 1) * NUM_ASSERT_DATA_TX2_A160_PK11,
                        NUM_ASSERT_DATA_TX2_A160_PK11,
                    ),
                    _ => (
                        1 + NUM_ASSERT_DATA_TX1_A256_PK7
                            + NUM_ASSERT_DATA_TX2 * NUM_ASSERT_DATA_TX2_A160_PK11,
                        NUM_ASSERT_DATA_TX3_A160_PK11 + NUM_ASSERT_DATA_TX3_A160_PK2,
                    ),
                };
                input
                    .pre_assert_txouts
                    .iter()
                    .enumerate()
                    .skip(skip)
                    .take(take)
                    .map(|(vout, txout)| {
                        (
                            OutPoint {
                                txid: input.pre_assert_txid,
                                vout: vout as u32,
                            },
                            txout.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .unzip()
            };

            let tx_ins = create_tx_ins(utxos);

            let output_script = connector_a2.create_taproot_address().script_pubkey();
            let output_amt = output_script.minimal_non_dust();
            let tx_outs = create_tx_outs([(output_script, output_amt)]);

            let tx = create_tx(tx_ins, tx_outs);
            let mut psbt = Psbt::from_unsigned_tx(tx).expect("must have an empty witness");

            for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts) {
                input.witness_utxo = Some(utxo);
            }

            psbt
        }))
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

        let (connector256_batch, _connector256_remainder): (
            Vec<ConnectorA256<NUM_PKS_A256_PER_CONNECTOR>>,
            ConnectorA256<NUM_PKS_A256_RESIDUAL>,
        ) = connector_a256_factory.create_connectors();

        let signatures_256: [wots256::Signature; NUM_PKS_A256] = std::array::from_fn(|i| match i {
            0 => signatures.superblock_hash,
            1 => signatures.groth16.0[0],
            _ => signatures.groth16.1[i - 2],
        });

        // add connector 6_7x_256
        let psbt_index = 0;
        connector256_batch
            .iter()
            .by_ref()
            .take(NUM_ASSERT_DATA_TX1_A256_PK7)
            .enumerate()
            .for_each(|(input_index, conn)| {
                let range_s = (input_index + psbt_index * NUM_ASSERT_DATA_TX1_A256_PK7)
                    * NUM_PKS_A256_PER_CONNECTOR;
                let range_e = range_s + NUM_PKS_A256_PER_CONNECTOR;
                conn.create_tx_input(
                    &mut self.0[psbt_index].inputs[input_index],
                    msk,
                    signatures_256[range_s..range_e].try_into().unwrap(),
                );
            });

        // add connector 5 9_11x_160
        connector160_batch
            .chunks(NUM_ASSERT_DATA_TX2_A160_PK11)
            .enumerate()
            .for_each(|(psbt_index, conn_batch)| {
                conn_batch
                    .iter()
                    .enumerate()
                    .for_each(|(input_index, conn)| {
                        let range_s = (input_index
                        // last psbt's utxos
                        + psbt_index * NUM_ASSERT_DATA_TX2_A160_PK11)
                        // this input's last utxo
                        * NUM_PKS_A160_PER_CONNECTOR;
                        let range_e = range_s + NUM_PKS_A160_PER_CONNECTOR;

                        conn.create_tx_input(
                            // +1 for earlier psbt
                            &mut self.0[psbt_index + 1].inputs[input_index],
                            msk,
                            signatures.groth16.2[range_s..range_e].try_into().unwrap(),
                        );
                    });
            });

        // add connector 7_11x_160, 1_2x_160
        let psbt_index = NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2;

        let range_s = (NUM_ASSERT_DATA_TX2 * NUM_ASSERT_DATA_TX2_A160_PK11
            + NUM_ASSERT_DATA_TX3_A160_PK11)
            * NUM_PKS_A160_PER_CONNECTOR;
        let range_e = range_s + NUM_PKS_A160_RESIDUAL;
        let residual_a160_input = &mut self.0[psbt_index].inputs[NUM_ASSERT_DATA_TX3_A160_PK11];
        connector160_remainder.create_tx_input(
            residual_a160_input,
            msk,
            signatures.groth16.2[range_s..range_e].try_into().unwrap(),
        );

        assert_eq!(
            NUM_ASSERT_DATA_TX3_A160_PK11 + NUM_ASSERT_DATA_TX3_A160_PK2,
            self.0[psbt_index].inputs.len(),
            "number of inputs in the second psbt must match"
        );

        self.0
            .into_iter()
            .map(|psbt| {
                psbt.extract_tx()
                    .expect("should be able to extract signed tx")
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()

        // FOR TEST
        // self.0
        //     .into_iter()
        //     .map(|psbt| Transaction {
        //         version: bitcoin::transaction::Version::TWO,
        //         lock_time: bitcoin::absolute::LockTime::ZERO,
        //         output: vec![],
        //         input: psbt
        //             .inputs
        //             .iter()
        //             .map(|input| bitcoin::transaction::TxIn {
        //                 witness: input.final_script_witness.clone().unwrap(),
        //                 ..Default::default()
        //             })
        //             .collect(),
        //     })
        //     .collect::<Vec<_>>()
        //     .try_into()
        //     .unwrap()
    }
}
