use bitcoin::{transaction, OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::{groth16::g16, signatures::wots::wots256, treepp::*};
use strata_bridge_primitives::{
    params::{
        connectors::{
            NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160_RESIDUAL, NUM_PKS_A256_PER_CONNECTOR,
        },
        prelude::*,
    },
    scripts::{parse_witness::parse_assertion_witnesses, prelude::*},
    wots,
};

use super::errors::{TxError, TxResult};
use crate::connectors::prelude::*;

/// Data needed to construct a [`AssertDataTxBatch`].
#[derive(Debug, Clone)]
pub struct AssertDataTxInput {
    pub pre_assert_txid: Txid,

    pub pre_assert_txouts: [TxOut; NUM_CONNECTOR_A160 + NUM_CONNECTOR_A256 + 1 + 1 + 1], /* 1 =>
                                                                                          * residual, 1 => stake, 1 => cpfp */
}

/// A batch of transactions in the Assert chain that spend outputs of the pre-assert transaction by
/// bitcommitting to the assertion data.
#[derive(Debug, Clone)]
pub struct AssertDataTxBatch([Psbt; NUM_ASSERT_DATA_TX]);

impl AssertDataTxBatch {
    /// Constructs a new instance of the assert data transaction batch.
    ///
    /// The batch is constructed by taking the pre-assert transaction outputs and spending them in
    /// order.
    pub fn new(
        input: AssertDataTxInput,
        connector_a2: ConnectorS,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
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

            let connector_cpfp_output_script =
                connector_cpfp.generate_taproot_address().script_pubkey();
            let connector_cpfp_output_amt = connector_cpfp_output_script.minimal_non_dust();

            let tx_outs = create_tx_outs([
                (output_script, output_amt),
                (connector_cpfp_output_script, connector_cpfp_output_amt),
            ]);

            let mut tx = create_tx(tx_ins, tx_outs);
            tx.version = transaction::Version(3);

            let mut psbt = Psbt::from_unsigned_tx(tx).expect("must have an empty witness");

            for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts) {
                input.witness_utxo = Some(utxo);
            }

            psbt
        }))
    }

    /// Get the PSBTs in the batch.
    pub fn psbts(&self) -> &[Psbt; NUM_ASSERT_DATA_TX] {
        &self.0
    }

    /// Get a PSBT at a given index.
    pub fn psbt_at_index(&self, index: usize) -> Option<&Psbt> {
        self.0.get(index)
    }

    /// Get a mutable reference to a PSBT at a given index.
    pub fn psbt_at_index_mut(&mut self, index: usize) -> Option<&mut Psbt> {
        self.0.get_mut(index)
    }

    /// Get the number of transactions in the batch.
    pub const fn num_txs_in_batch(&self) -> usize {
        NUM_ASSERT_DATA_TX
    }

    /// Compute the transaction IDs of the PSBTs in the batch.
    pub fn compute_txids(&self) -> [Txid; NUM_ASSERT_DATA_TX] {
        self.0
            .iter()
            .map(|psbt| psbt.unsigned_tx.compute_txid())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Finalize the batch by adding the connector outputs and corresponding WOTS signatures.
    ///
    /// This method adds bitcommitments to the assertions corresponding to the Groth16 proof.
    pub fn finalize(
        mut self,
        connector_a160_factory: ConnectorA160Factory<NUM_PKS_A160_PER_CONNECTOR, NUM_PKS_A160>,
        connector_a256_factory: ConnectorA256Factory<NUM_PKS_A256_PER_CONNECTOR, NUM_PKS_A256>,
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

                        conn.finalize_input(
                            // +1 for earlier psbt
                            &mut self.0[psbt_index + 1].inputs[input_index],
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
        connector160_remainder.finalize_input(
            residual_a160_input,
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
    }

    /// Parse the assertion data from the signed transactions in the batch.
    pub fn parse_witnesses(
        assert_data_txs: &[Transaction; NUM_ASSERT_DATA_TX],
    ) -> TxResult<Option<(wots256::Signature, g16::Signatures)>> {
        let witnesses = assert_data_txs
            .iter()
            .flat_map(|tx| {
                tx.input.iter().map(|txin| {
                    script! {
                        for w in txin.witness.into_iter().take(txin.witness.len() - 2) {
                            if w.len() == 1 { { w[0] } } else { { w.to_vec() } }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        let witness256 = witnesses
            .get(0..NUM_CONNECTOR_A256)
            .ok_or(TxError::Witness("invalid 256-bit witness size".to_string()))?
            .to_vec()
            .try_into()
            .or(Err(TxError::Witness(
                "invalid 256-bit witness size".to_string(),
            )))?;

        let witness160 = witnesses
            .get(NUM_ASSERT_DATA_TX1_A256_PK7..NUM_CONNECTOR_A256 + NUM_CONNECTOR_A160)
            .ok_or(TxError::Witness("invalid 256-bit witness size".to_string()))?
            .to_vec()
            .try_into()
            .or(Err(TxError::Witness(
                "invalid 160-bit witness size".to_string(),
            )))?;

        let witness160_residual = witnesses.last().cloned();

        Ok(Some(
            parse_assertion_witnesses(witness256, witness160, witness160_residual)
                .map_err(|e| TxError::Witness(e.to_string()))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bitcoin::{key::TapTweak, Address, Amount, Network, Witness};
    use rkyv::rancor::Error;
    use strata_bridge_primitives::wots::{
        Assertions as WotsAssertions, PublicKeys as WotsPublicKeys, Signatures as WotsSignatures,
    };
    use strata_bridge_test_utils::prelude::{generate_keypair, generate_txid};
    use wots::Groth16PublicKeys;

    use super::*;

    #[test]
    fn test_parse_witnesses() {
        let network = Network::Regtest;
        let pre_assert_txout = TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: Address::p2tr_tweaked(
                generate_keypair()
                    .x_only_public_key()
                    .0
                    .dangerous_assume_tweaked(),
                network,
            )
            .script_pubkey(),
        };

        let input = AssertDataTxInput {
            pre_assert_txid: generate_txid(),
            pre_assert_txouts: std::array::from_fn(|_| pre_assert_txout.clone()),
        };

        let connector_a2 = ConnectorS::new(generate_keypair().x_only_public_key().0, network);
        let connector_cpfp = ConnectorCpfp::new(generate_keypair().x_only_public_key().0, network);

        let assert_data_tx_batch = AssertDataTxBatch::new(input, connector_a2, connector_cpfp);

        let msk = "test-assert-data-parse-witnesses";
        let wots_public_keys = WotsPublicKeys::new(msk, generate_txid());

        let wots::PublicKeys {
            bridge_out_txid: _,
            superblock_hash: superblock_hash_public_key,
            superblock_period_start_ts: _,
            groth16:
                Groth16PublicKeys(([public_inputs_hash_public_key], public_keys_256, public_keys_160)),
        } = wots_public_keys;

        let public_keys_256 = std::array::from_fn(|i| match i {
            0 => superblock_hash_public_key.0,
            1 => public_inputs_hash_public_key,
            _ => public_keys_256[i - 2],
        });

        let connector_a160_factory = ConnectorA160Factory {
            network,
            public_keys: public_keys_160,
        };
        let connector_a256_factory = ConnectorA256Factory {
            network,
            public_keys: public_keys_256,
        };

        let assertions =
            fs::read("../../test-data/assertions.bin").expect("test data must be readable");
        let assertions = rkyv::from_bytes::<WotsAssertions, Error>(&assertions)
            .expect("assertion data must be valid");
        let deposit_txid = generate_txid();
        let signatures = WotsSignatures::new(msk, deposit_txid, assertions);

        let mut signed_assert_data_txs = assert_data_tx_batch.finalize(
            connector_a160_factory,
            connector_a256_factory,
            signatures,
        );

        AssertDataTxBatch::parse_witnesses(&signed_assert_data_txs)
            .expect("must parse witnesses")
            .expect("must have witnesses");

        signed_assert_data_txs[0].input[0].witness =
            Witness::from_slice(&[[0u8; 32]; NUM_CONNECTOR_A256 - 1]);

        assert!(
            AssertDataTxBatch::parse_witnesses(&signed_assert_data_txs).is_err_and(|e| {
                dbg!(e.to_string());
                e.to_string().contains("invalid witness")
            })
        );
    }
}
