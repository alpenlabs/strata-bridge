use std::sync::Arc;

use bitcoin::{hashes::Hash, TxOut};
use bitvm::{groth16::g16, signatures::wots::SignatureImpl};
use sha2::{Digest, Sha256};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    duties::VerifierDuty,
    params::tx::{BTC_CONFIRM_PERIOD, DISPROVER_REWARD},
    wots::Signatures,
};
use strata_bridge_proof_protocol::BridgeProofPublicParams;
use strata_bridge_proof_snark::bridge_vk;
use strata_bridge_tx_graph::{
    connectors::prelude::{
        ConnectorA30, ConnectorA30Leaf, ConnectorA31, ConnectorA31Leaf,
        DisprovePublicInputsCommitmentWitness,
    },
    partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS,
    transactions::{
        claim::ClaimTx,
        prelude::{AssertDataTxBatch, CovenantTx, DisproveData, DisproveTx},
    },
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
                if let Ok(Some((_superblock_period_start_ts, _bridge_out_txid))) =
                    ClaimTx::parse_witness(&claim_tx)
                {
                    info!(event = "parsed claim transaction");
                }

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

                let (superblock_period_start_ts, bridge_out_txid) =
                    ClaimTx::parse_witness(&claim_tx).unwrap().unwrap(); // FIXME: Handle me
                info!(event = "parsed claim transaction", superblock_start_ts_size = superblock_period_start_ts.len(), bridge_out_txid_size = %bridge_out_txid.len());

                let (superblock_hash, groth16) =
                    AssertDataTxBatch::parse_witnesses(&assert_data_txs)
                        .unwrap()
                        .unwrap(); // FIXME:
                                   // Handle me
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
                        Some(ConnectorA31Leaf::DisprovePublicInputsCommitment {
                            deposit_txid,
                            witness: Some(DisprovePublicInputsCommitmentWitness {
                                sig_superblock_hash: superblock_hash,
                                sig_bridge_out_txid: bridge_out_txid,
                                sig_superblock_period_start_ts: superblock_period_start_ts,
                                sig_public_inputs_hash: groth16.0[0],
                            }),
                        })
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
                                Some(ConnectorA31Leaf::DisproveProof {
                                    disprove_script,
                                    witness_script: Some(witness_script),
                                })
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
                            ConnectorA30Leaf::Disprove(()).get_input_index(),
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
}
