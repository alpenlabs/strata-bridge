use std::array;

use bitcoin::{transaction, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::{groth16::g16, signatures::wots::wots256, treepp::*};
use strata_bridge_primitives::{
    params::prelude::*,
    scripts::{parse_witness::parse_assertion_witnesses, prelude::*},
    wots,
};

use super::{
    errors::{TxError, TxResult},
    pre_assert::PRE_ASSERT_OUTS,
};
use crate::connectors::prelude::*;

/// Data needed to construct a [`AssertDataTxBatch`].
#[derive(Debug, Clone)]
pub struct AssertDataTxInput {
    pub pre_assert_txid: Txid,

    pub pre_assert_txouts: [TxOut; PRE_ASSERT_OUTS],
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
        const STAKE_VOUT_OFFSET: usize = 1;

        Self(array::from_fn(|i| {
            let (outpoint, prevout) = input
                .pre_assert_txouts
                .get(STAKE_VOUT_OFFSET + i)
                .map(|txout| {
                    (
                        OutPoint {
                            txid: input.pre_assert_txid,
                            vout: (STAKE_VOUT_OFFSET + i) as u32,
                        },
                        txout.clone(),
                    )
                })
                .expect("must have enough prevouts");

            let tx_ins = create_tx_ins([outpoint]);

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
            psbt.inputs[0].witness_utxo = Some(prevout);

            psbt
        }))
    }

    /// Gets the PSBTs in the batch.
    pub fn psbts(&self) -> &[Psbt; NUM_ASSERT_DATA_TX] {
        &self.0
    }

    /// Gets a PSBT at a given index.
    pub fn psbt_at_index(&self, index: usize) -> Option<&Psbt> {
        self.0.get(index)
    }

    /// Gets a mutable reference to a PSBT at a given index.
    pub fn psbt_at_index_mut(&mut self, index: usize) -> Option<&mut Psbt> {
        self.0.get_mut(index)
    }

    /// Gets the number of transactions in the batch.
    pub const fn num_txs_in_batch(&self) -> usize {
        NUM_ASSERT_DATA_TX
    }

    /// Gets the vout for CPFP in each PSBT in the batch.
    pub fn cpfp_vout(&self) -> u32 {
        self.0[0].outputs.len() as u32 - 1
    }

    /// Gets the total input amount of the psbt at the given index if present.
    pub fn total_input_amount(&self, index: usize) -> Option<Amount> {
        self.0.get(index).map(|psbt| {
            psbt.inputs
                .iter()
                .map(|input| input.witness_utxo.as_ref().unwrap().value)
                .sum()
        })
    }

    /// Computes the transaction IDs of the PSBTs in the batch.
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
        connector_a160_factory: ConnectorA160Factory<
            NUM_HASH_CONNECTORS_BATCH_1,
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1,
            NUM_HASH_CONNECTORS_BATCH_2,
            NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2,
        >,
        connector_a256_factory: ConnectorA256Factory<
            NUM_FIELD_CONNECTORS_BATCH_1,
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1,
            NUM_FIELD_CONNECTORS_BATCH_2,
            NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2,
        >,
        signatures: wots::Signatures,
    ) -> [Transaction; NUM_ASSERT_DATA_TX] {
        let (connector160_batch1, connector160_batch2): (
            [ConnectorA160<NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1>; NUM_HASH_CONNECTORS_BATCH_1],
            [ConnectorA160<NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2>; NUM_HASH_CONNECTORS_BATCH_2],
        ) = connector_a160_factory.create_connectors();

        let (connector256_batch1, connector256_batch2): (
            [ConnectorA256<NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1>; NUM_FIELD_CONNECTORS_BATCH_1],
            [ConnectorA256<NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2>; NUM_FIELD_CONNECTORS_BATCH_2],
        ) = connector_a256_factory.create_connectors();

        let signatures_256: [wots256::Signature; NUM_PKS_A256] = array::from_fn(|i| match i {
            0 => signatures.groth16.0[0],
            _ => signatures.groth16.1[i - 1],
        });

        connector256_batch1
            .iter()
            .enumerate()
            .for_each(|(psbt_index, conn)| {
                let input = &mut self.0[psbt_index].inputs[0];

                let start_index = psbt_index * NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1;
                let end_index = start_index + NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1;

                conn.finalize_input(
                    input,
                    signatures_256[start_index..end_index]
                        .try_into()
                        .expect("must have NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1 signatures"),
                );
            });

        let mut psbt_offset = NUM_FIELD_CONNECTORS_BATCH_1;
        let sigs_offset = NUM_FIELD_CONNECTORS_BATCH_1 * NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1;
        connector256_batch2
            .iter()
            .enumerate()
            .for_each(|(psbt_index, conn)| {
                let input = &mut self.0[psbt_offset + psbt_index].inputs[0];

                let start_index = sigs_offset + psbt_index * NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2;
                let end_index = start_index + NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2;

                conn.finalize_input(
                    input,
                    signatures_256[start_index..end_index]
                        .try_into()
                        .expect("must have NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_2 signatures"),
                );
            });

        psbt_offset += NUM_FIELD_CONNECTORS_BATCH_2;
        connector160_batch1
            .iter()
            .enumerate()
            .for_each(|(psbt_index, conn)| {
                let input = &mut self.0[psbt_offset + psbt_index].inputs[0];

                let start_index = psbt_index * NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1;
                let end_index = start_index + NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1;

                conn.finalize_input(
                    input,
                    signatures.groth16.2[start_index..end_index]
                        .try_into()
                        .expect("must have NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1 signatures"),
                );
            });

        psbt_offset += NUM_HASH_CONNECTORS_BATCH_1;
        let sigs_offset = NUM_HASH_CONNECTORS_BATCH_1 * NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_1;
        connector160_batch2
            .iter()
            .enumerate()
            .for_each(|(psbt_index, conn)| {
                let input = &mut self.0[psbt_offset + psbt_index].inputs[0];

                let start_index = sigs_offset + psbt_index * NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2;
                let end_index = start_index + NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2;

                conn.finalize_input(
                    input,
                    signatures.groth16.2[start_index..end_index]
                        .try_into()
                        .expect("must have NUM_HASH_ELEMS_PER_CONNECTOR_BATCH_2 signatures"),
                );
            });

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
    ) -> TxResult<Option<g16::Signatures>> {
        let witnesses: [_; TOTAL_CONNECTORS] = assert_data_txs
            .iter()
            .flat_map(|tx| {
                tx.input.iter().map(|txin| {
                    script! {
                        // skip the last two elements which are the script and control block
                        for w in txin.witness.into_iter().take(txin.witness.len() - 2) {
                            if w.len() == 1 { { w[0] } } else { { w.to_vec() } }
                        }
                    }
                })
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| {
                TxError::Witness(format!("number of witnesses must be {TOTAL_CONNECTORS}"))
            })?;

        let witness256_batch1 = witnesses[..NUM_FIELD_CONNECTORS_BATCH_1]
            .to_vec()
            .try_into()
            .or(Err(TxError::Witness(
                "invalid 256-bit witness size in batch 1".to_string(),
            )))?;

        let mut offset = NUM_FIELD_CONNECTORS_BATCH_1;
        let witness256_batch2 = witnesses[offset..offset + NUM_FIELD_CONNECTORS_BATCH_2]
            .to_vec()
            .try_into()
            .or(Err(TxError::Witness(
                "invalid 256-bit witness size in batch 2".to_string(),
            )))?;

        offset += NUM_FIELD_CONNECTORS_BATCH_2;
        let witness160_batch1 = witnesses[offset..offset + NUM_HASH_CONNECTORS_BATCH_1]
            .to_vec()
            .try_into()
            .or(Err(TxError::Witness(
                "invalid 160-bit witness size in batch 1".to_string(),
            )))?;

        let witness160_batch2 = witnesses[witnesses.len() - NUM_HASH_CONNECTORS_BATCH_2..]
            .to_vec()
            .try_into()
            .or(Err(TxError::Witness(
                "invalid 160-bit witness size in batch 2".to_string(),
            )))?;

        Ok(Some(
            parse_assertion_witnesses(
                witness256_batch1,
                witness256_batch2,
                witness160_batch1,
                witness160_batch2,
            )
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
            withdrawal_fulfillment_pk: _,
            groth16:
                Groth16PublicKeys(([public_inputs_hash_public_key], public_keys_256, public_keys_160)),
        } = wots_public_keys;

        let public_keys_256 = std::array::from_fn(|i| match i {
            0 => public_inputs_hash_public_key,
            _ => public_keys_256[i - 1],
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
            Witness::from_slice(&[[0u8; 32]; NUM_FIELD_ELEMS_PER_CONNECTOR_BATCH_1]);

        assert!(AssertDataTxBatch::parse_witnesses(&signed_assert_data_txs)
            .is_err_and(|e| e.to_string().contains("invalid witness")));
    }
}
