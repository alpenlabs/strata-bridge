use std::sync::Arc;

use bitcoin::{hashes::Hash, Transaction, TxOut};
use bitvm::{
    groth16::g16,
    signatures::wots::{wots256, wots32, SignatureImpl},
    treepp::*,
};
use sha2::{Digest, Sha256};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    duties::VerifierDuty,
    params::{
        prelude::*,
        tx::{BTC_CONFIRM_PERIOD, DISPROVER_REWARD},
    },
    scripts::parse_witness::parse_assertion_witnesses,
    wots::Signatures,
};
use strata_bridge_proof_protocol::BridgeProofPublicParams;
use strata_bridge_proof_snark::bridge_vk;
use strata_bridge_tx_graph::{
    connectors::prelude::{ConnectorA30, ConnectorA30Leaf, ConnectorA31, ConnectorA31Leaf},
    partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS,
    transactions::prelude::{CovenantTx, DisproveData, DisproveTx},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tracing::{error, info, trace, warn};

use crate::base::Agent;

pub type VerifierIdx = u32;

#[derive(Debug)]
pub struct Verifier<P: PublicDb> {
    pub agent: Agent, // required for broadcasting tx

    build_context: TxBuildContext,

    public_db: Arc<P>,
}

impl<P> Verifier<P>
where
    P: PublicDb + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(public_db: Arc<P>, build_context: TxBuildContext, agent: Agent) -> Self {
        Self {
            public_db,
            build_context,
            agent,
        }
    }

    pub async fn start(&mut self, duty_receiver: &mut broadcast::Receiver<VerifierDuty>) {
        info!(action = "starting verifier");

        loop {
            match duty_receiver.recv().await {
                Ok(verifier_duty) => {
                    trace!(event = "received duty", ?verifier_duty); // NOTE: this is a very big data structure beware before logging
                    self.process_duty(verifier_duty).await;
                }
                Err(RecvError::Lagged(skipped_messages)) => {
                    warn!(action = "processing last available duty", event = "duty executor lagging behind, please adjust '--duty-interval' arg", %skipped_messages);
                }
                Err(err) => {
                    error!(msg = "error receiving duties", ?err);

                    panic!("verifier duty sender closed unexpectedly");
                }
            }
        }
    }

    pub async fn process_duty(&mut self, duty: VerifierDuty) {
        match duty {
            VerifierDuty::VerifyClaim {
                operator_id: _,
                deposit_txid: _,
                claim_tx,
            } => {
                warn!("No challenging yet!");
                let (_superblock_period_start_ts, _bridge_out_txid) =
                    self.parse_claim_tx(&claim_tx);

                // get bridge_out_tx from bitcoin canonical chain
                // verify that the latest checkpoint state in the rollup has a withdrawal request
                // that
                // 1. matches the operator_id inscribed in the first OP_RETURN UTXO.
                // 2. matches the recipient address in second P2TR UTXO.
                // If these checks fail, the settle the challenge transaction (anyone can pay)
            }
            VerifierDuty::VerifyAssertions {
                operator_id,
                deposit_txid,

                post_assert_tx,
                claim_tx,
                assert_data_txs,
            } => {
                info!(event = "verifying assertion", by_operator=%operator_id, for_deposit=%deposit_txid);

                let (superblock_period_start_ts, bridge_out_txid) = self.parse_claim_tx(&claim_tx);
                info!(event = "parsed claim transaction", superblock_start_ts_size = superblock_period_start_ts.len(), bridge_out_txid_size = %bridge_out_txid.len());

                let (superblock_hash, groth16) = self.parse_assert_data_txs(&assert_data_txs);
                info!(event = "parsed assert data", wots256_signature_size=%groth16.0.len(), groth16_signature_size=%groth16.1.len());

                let signatures = Signatures {
                    bridge_out_txid,
                    superblock_hash,
                    superblock_period_start_ts,
                    groth16,
                };
                info!(event = "constructed signatures");

                let public_keys = self
                    .public_db
                    .get_wots_public_keys(operator_id, deposit_txid)
                    .await
                    .unwrap()
                    .unwrap(); // FIXME: Handle me

                let connector_leaf = {
                    // 1. public input hash validation
                    info!(action = "validating public input hash");

                    let public_inputs = BridgeProofPublicParams {
                        deposit_txid: deposit_txid.to_byte_array(),
                        superblock_hash: superblock_hash.parse(),
                        bridge_out_txid: bridge_out_txid.parse(),
                        superblock_period_start_ts: u32::from_le_bytes(
                            superblock_period_start_ts.parse(),
                        ),
                    };
                    let serialized_public_inputs = bincode::serialize(&public_inputs).unwrap();
                    let public_inputs_hash = {
                        let data: &[u8] = &serialized_public_inputs;
                        let mut hasher = Sha256::new();
                        hasher.update(data);
                        let mut hash: [u8; 32] = hasher.finalize().into();
                        hash[0] &= 0b00011111; // mask 3 most significant bits
                        hash
                    };
                    let committed_public_inputs_hash = groth16.0[0].parse();

                    // TODO: remove this: fix nibble flipping
                    let committed_public_inputs_hash =
                        committed_public_inputs_hash.map(|b| ((b & 0xf0) >> 4) | ((b & 0x0f) << 4));

                    if public_inputs_hash != committed_public_inputs_hash {
                        warn!(msg = "public inputs hash mismatch");
                        Some(ConnectorA31Leaf::DisprovePublicInputsCommitment(
                            deposit_txid,
                            Some((
                                superblock_hash,
                                bridge_out_txid,
                                superblock_period_start_ts,
                                groth16.0[0],
                            )),
                        ))
                    } else {
                        // 2. do superblock validation
                        let is_superblock_invalid = false;
                        if is_superblock_invalid {
                            unreachable!("always false for now");
                        } else {
                            info!(action = "verifying groth16 assertions");
                            // 3. groth16 proof validation
                            if let Some((tapleaf_index, witness_script)) =
                                g16::verify_signed_assertions(
                                    bridge_vk::GROTH16_VERIFICATION_KEY.clone(),
                                    *public_keys.groth16,
                                    signatures.groth16,
                                )
                            {
                                let disprove_script = g16::generate_disprove_scripts(
                                    *public_keys.groth16,
                                    &PARTIAL_VERIFIER_SCRIPTS,
                                )[tapleaf_index]
                                    .clone();
                                Some(ConnectorA31Leaf::DisproveProof((
                                    disprove_script,
                                    Some(witness_script),
                                )))
                            } else {
                                None
                            }
                        }
                    }
                };

                const STAKE_OUTPUT_INDEX: usize = 0;
                if let Some(disprove_leaf) = connector_leaf {
                    info!(action = "constructing disprove tx", for_operator_id=%operator_id, %deposit_txid);
                    let disprove_tx_data = DisproveData {
                        post_assert_txid: post_assert_tx.compute_txid(),
                        deposit_txid,
                        input_stake: post_assert_tx
                            .tx_out(STAKE_OUTPUT_INDEX)
                            .expect("stake output must exist in post-assert tx")
                            .value,
                        network: self.build_context.network(),
                    };

                    let connector_a30 = ConnectorA30::new(
                        self.build_context.aggregated_pubkey(),
                        self.build_context.network(),
                    );
                    let connector_a31 =
                        ConnectorA31::new(self.build_context.network(), public_keys);

                    let disprove_tx =
                        DisproveTx::new(disprove_tx_data, connector_a30, connector_a31);

                    let reward_out = TxOut {
                        value: DISPROVER_REWARD,
                        script_pubkey: self
                            .agent
                            .taproot_address(self.build_context.network())
                            .script_pubkey(),
                    };
                    let disprove_n_of_n_sig = self
                        .public_db
                        .get_signature(
                            operator_id,
                            disprove_tx.compute_txid(),
                            ConnectorA30Leaf::Disprove.get_input_index(),
                        )
                        .await
                        .unwrap()
                        .unwrap(); // FIXME: Handle me

                    let signed_disprove_tx = disprove_tx.finalize(
                        connector_a30,
                        connector_a31,
                        reward_out,
                        deposit_txid,
                        disprove_leaf,
                        disprove_n_of_n_sig,
                    );

                    {
                        let vsize = signed_disprove_tx.vsize();
                        let total_size = signed_disprove_tx.total_size();
                        let weight = signed_disprove_tx.weight();
                        info!(event = "finalized disprove tx", txid = %signed_disprove_tx.compute_txid(), %vsize, %total_size, %weight);
                    }

                    let disprove_txid = self
                        .agent
                        .wait_and_broadcast(&signed_disprove_tx, BTC_CONFIRM_PERIOD)
                        .await
                        .expect("should settle disprove tx correctly");

                    info!(event = "broadcasted disprove tx successfully", %disprove_txid, %deposit_txid, %operator_id);
                } else {
                    info!(event = "assertion is valid!", %operator_id, %deposit_txid);
                }
            }
        }
    }

    // parse claim tx
    pub fn parse_claim_tx(
        &self,
        claim_tx: &Transaction,
    ) -> (wots32::Signature, wots256::Signature) {
        let witness = claim_tx.input.first().unwrap().witness.to_vec();
        let (witness_txid, witness_ts) = witness.split_at(2 * wots256::N_DIGITS as usize);
        (
            std::array::from_fn(|i| {
                let (i, j) = (2 * i, 2 * i + 1);
                let preimage = witness_ts[i].clone().try_into().unwrap();
                let digit = if witness_ts[j].is_empty() {
                    0
                } else {
                    witness_ts[j][0]
                };
                (preimage, digit)
            }),
            std::array::from_fn(|i| {
                let (i, j) = (2 * i, 2 * i + 1);
                let preimage = witness_txid[i].clone().try_into().unwrap();
                let digit = if witness_txid[j].is_empty() {
                    0
                } else {
                    witness_txid[j][0]
                };
                (preimage, digit)
            }),
        )
    }

    // parse assert data txs
    pub fn parse_assert_data_txs(
        &self,
        assert_data_txs: &[Transaction; NUM_ASSERT_DATA_TX],
    ) -> (wots256::Signature, g16::Signatures) {
        let witnesses = assert_data_txs
            .iter()
            .flat_map(|tx| {
                tx.input
                    .iter()
                    .map(|txin| {
                        script! {
                            for w in &txin.witness.to_vec()[..txin.witness.len()-2] {
                                if w.len() == 1 { { w[0] } } else { { w.clone() } }
                            }
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        parse_assertion_witnesses(
            witnesses[..NUM_CONNECTOR_A256].to_vec().try_into().unwrap(),
            witnesses[NUM_ASSERT_DATA_TX1_A256_PK7..NUM_CONNECTOR_A256 + NUM_CONNECTOR_A160]
                .to_vec()
                .try_into()
                .unwrap(),
            witnesses.last().cloned(),
        )
    }
}

/*
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use bitcoin::{
        absolute::LockTime, hashes::Hash, transaction::Version, Amount, Network, OutPoint,
        ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
    };
    use bitvm::{
        groth16::g16,
        signatures::wots::{wots256, wots32, SignatureImpl},
        treepp::*,
    };
    use secp256k1::{Keypair, Secp256k1, SECP256K1};
    use strata_bridge_db::{inmemory::prelude::PublicDbInMemory, public::PublicDb};
    use strata_bridge_primitives::{
        build_context::TxBuildContext,
        params::prelude::*,
        scripts::wots::{
            generate_wots_public_keys, generate_wots_signatures, Assertions, Signatures,
        },
        types::PublickeyTable,
    };
    use strata_bridge_tx_graph::{
        connectors::{
            connector_s::ConnectorS,
            connectors_a::{ConnectorA160Factory, ConnectorA256Factory},
        },
        mock_txid,
        transactions::assert_data::{AssertDataTxBatch, AssertDataTxInput},
    };

    use super::Verifier;
    use crate::{base::Agent, verifier::VerifierDuty};

    fn mock_x_only_public_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        XOnlyPublicKey::from_keypair(&keypair).0
    }

    fn build_claim_tx(ts: wots32::Signature, txid: wots256::Signature) -> bitcoin::Transaction {
        let mut witness = Witness::new();
        let res = execute_script(script! {
            { txid.to_script() }
            { ts.to_script() }
        });
        for i in 0..res.final_stack.len() {
            witness.push(res.final_stack.get(i));
        }
        bitcoin::Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: mock_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![],
        }
    }

    async fn build_assert_data_txs(
        db: PublicDbInMemory,
        msk: &str,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: Signatures,
    ) -> [bitcoin::Transaction; NUM_ASSERT_DATA_TX] {
        let network = bitcoin::Network::Regtest;

        let input = AssertDataTxInput {
            pre_assert_txid: mock_txid(),
            pre_assert_txouts: std::array::from_fn(|i| TxOut {
                value: Amount::from_sat(i as u64),
                script_pubkey: ScriptBuf::new(),
            }),
        };

        let connector_a2 = ConnectorS::new(mock_x_only_public_key(), network);

        let assert_data = AssertDataTxBatch::new(input, connector_a2);

        let public_keys = db.get_wots_public_keys(operator_id, deposit_txid).await;

        let c160 = ConnectorA160Factory {
            network,
            public_keys: public_keys.groth16.2,
        };
        let c256 = ConnectorA256Factory {
            network,
            public_keys: std::array::from_fn(|i| match i {
                0 => public_keys.superblock_hash.0,
                1 => (*public_keys.groth16).0[0],
                _ => public_keys.groth16.1[i - 2],
            }),
        };

        assert_data.finalize(c160, c256, msk, signatures)
    }

    #[tokio::test]
    async fn test_verify_assertions() {
            let msk = "secret";
            let operator_id = 0;
            let deposit_txid = Txid::from_byte_array(mock::PUBLIC_INPUTS.0);

            println!("initializing the db");
            let db = PublicDbInMemory::default();

            db.set_wots_public_keys(
                operator_id,
                deposit_txid,
                &generate_wots_public_keys(msk, deposit_txid),
            )
            .await;

            let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
            let agent = Agent::new(
                keypair,
                "abc",
                "abc",
                "abc",
                "abc",
                Duration::from_millis(10),
            )
            .await;
            let context = TxBuildContext::new(
                Network::Regtest,
                PublickeyTable::from(BTreeMap::from([(0, keypair.public_key())])),
                0,
            );

            let mut verifier = Verifier::new(db.clone().into(), context, agent);

            println!("generating assertions");
            // let assertions = {
            //     let (proof, public_inputs) = mock::get_proof_and_public_inputs();

            //     println!("verifying_key: {:?}", mock::get_verifying_key());
            //     println!("proof: {:?}", proof);
            //     println!("public_inputs: {:?}", public_inputs);

            //     let assertions = Assertions {
            //         bridge_out_txid: mock::PUBLIC_INPUTS.2,
            //         superblock_hash: mock::PUBLIC_INPUTS.1,
            //         superblock_period_start_ts: mock::PUBLIC_INPUTS.3.to_le_bytes(),
            //         groth16: g16::generate_proof_assertions(
            //             mock::get_verifying_key(),
            //             proof,
            //             public_inputs,
            //         ),
            //     };
            //     println!("assertions: {:?}", assertions);
            //     assertions
            // };
            // return;
            let mut assertions = mock_assertions();
            // disprove public inputs hash disprove proof
            assertions.superblock_period_start_ts = [1u8; 4]; // assertions.groth16.0[0] = [0u8; 32];
                                                              // assertions.groth16.1[0] = [0u8; 32]; // disprove proof

            let signatures = generate_wots_signatures(msk, deposit_txid, assertions);

            println!("building claim tx");
            let claim_tx = build_claim_tx(
                signatures.superblock_period_start_ts,
                signatures.bridge_out_txid,
            );
            let (superblock_period_start_ts, bridge_out_txid) = verifier.parse_claim_tx(&claim_tx);

            println!("building assert data txs");
            let assert_data_txs =
                build_assert_data_txs(db.clone(), msk, operator_id, deposit_txid, signatures).await;

            println!("parse assert data txs");
            let (superblock_hash, groth16) = verifier.parse_assert_data_txs(&assert_data_txs);
            assert_eq!(
                signatures,
                Signatures {
                    superblock_hash,
                    superblock_period_start_ts,
                    bridge_out_txid,
                    groth16,
                }
            );

            let duty = VerifierDuty::VerifyAssertions {
                operator_id,
                deposit_txid,

                post_assert_tx: claim_tx.clone(), /* FIXME: this should be post-assert tx (this is
                                                   * okay for
                                                   * test for now) */
                claim_tx,
                assert_data_txs,
            };

            println!("verifier.process_duty");
            verifier.process_duty(duty).await;
        }

    #[tokio::test]
    async fn test_verify_assertions_exhaustive() {
        let msk = "secret";
        let operator_id = 0;
        let deposit_txid = Txid::from_byte_array(mock::PUBLIC_INPUTS.0);

        println!("initializing the db");
        let db = PublicDbInMemory::default();

        db.set_wots_public_keys(
            operator_id,
            deposit_txid,
            &generate_wots_public_keys(msk, deposit_txid),
        )
        .await;

        let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let agent = Agent::new(keypair, "", "", "", "", Duration::from_millis(10)).await;
        let context =
            TxBuildContext::new(Network::Regtest, PublickeyTable::from(BTreeMap::new()), 0);

        let mut verifier = Verifier::new(db.clone().into(), context, agent);

        fn invalidate_groth16_assertions(assertions: &mut Assertions, i: usize, j: u8) {
            match i {
                0 => assertions.groth16.0[i] = [j; 32],
                1..=g16::N_VERIFIER_FQS => assertions.groth16.1[i - 1] = [j; 32],
                _ => assertions.groth16.2[i - g16::N_VERIFIER_FQS - 1] = [j; 20],
            };
        }

        for i in 0..615 * 2 {
            println!("ITERATION: {i}");
            // disprove public inputs hash disprove proof
            let mut assertions = mock_assertions();
            let j = (i % 2) as u8;
            match i {
                0 => assertions.superblock_hash = [j; 32],
                1 => assertions.bridge_out_txid = [j; 32],
                2 => assertions.superblock_period_start_ts = [j; 4],
                3.. => invalidate_groth16_assertions(&mut assertions, i - 3, j),
            };

            let signatures = generate_wots_signatures(msk, deposit_txid, assertions);

            println!("building claim tx");
            let claim_tx = build_claim_tx(
                signatures.superblock_period_start_ts,
                signatures.bridge_out_txid,
            );
            let (superblock_period_start_ts, bridge_out_txid) = verifier.parse_claim_tx(&claim_tx);

            println!("building assert data txs");
            let assert_data_txs =
                build_assert_data_txs(db.clone(), msk, operator_id, deposit_txid, signatures).await;

            let (superblock_hash, groth16) = verifier.parse_assert_data_txs(&assert_data_txs);
            assert_eq!(
                signatures,
                Signatures {
                    superblock_hash,
                    superblock_period_start_ts,
                    bridge_out_txid,
                    groth16,
                }
            );

            let duty = VerifierDuty::VerifyAssertions {
                operator_id,
                deposit_txid,
                post_assert_tx: claim_tx.clone(),
                claim_tx,
                assert_data_txs,
            };

            verifier.process_duty(duty).await;
        }
    }
}
*/
