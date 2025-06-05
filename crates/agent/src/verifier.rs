//! Verifier for the agent.

use std::{ops::Deref, sync::Arc};

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{relative, taproot, OutPoint, TxOut};
use bitvm::chunk::api::{api_generate_full_tapscripts, validate_assertions};
use sp1_verifier::{blake3_hash, hash_public_inputs_with_fn};
use strata_bridge_connectors::{
    partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS,
    prelude::{
        ConnectorA3, ConnectorA3Leaf, ConnectorStake, DisprovePublicInputsCommitmentWitness,
        StakeSpendPath,
    },
};
use strata_bridge_db::public::PublicDb;
#[expect(deprecated)]
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    duties::VerifierDuty,
    scripts::prelude::wots_to_byte_array,
    wots::{self, Groth16Sigs, Wots256Sig},
};
use strata_bridge_proof_protocol::BridgeProofPublicOutput;
use strata_bridge_proof_snark::bridge_vk;
use strata_bridge_stake_chain::prelude::STAKE_VOUT;
use strata_bridge_tx_graph::transactions::{
    claim::ClaimTx,
    prelude::{AssertDataTxBatch, CovenantTx, DisproveData, DisproveTx},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tracing::{error, info, trace, warn};

use crate::base::{Agent, BTC_CONFIRM_PERIOD, CONNECTOR_PARAMS, DISPROVER_REWARD};

/// The verifier index.
pub type VerifierIdx = u32;

/// The verifier.
#[derive(Debug)]
pub struct Verifier<P: PublicDb> {
    /// The agent.
    pub agent: Agent, // required for broadcasting tx

    /// The build context.
    build_context: TxBuildContext,

    /// The public database.
    public_db: Arc<P>,
}

/// The verifier implementation.
impl<P> Verifier<P>
where
    P: PublicDb + Clone,
{
    /// Creates a new verifier.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(public_db: Arc<P>, build_context: TxBuildContext, agent: Agent) -> Self {
        Self {
            public_db,
            build_context,
            agent,
        }
    }

    /// Starts the verifier.
    #[expect(deprecated)]
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

    /// Processes a duty.
    #[expect(deprecated)]
    pub async fn process_duty(&mut self, duty: VerifierDuty) {
        match duty {
            VerifierDuty::VerifyClaim {
                operator_id: _,
                deposit_txid: _,
                claim_tx,
            } => {
                warn!("No challenging yet!");
                if let Ok(_bridge_out_txid) = ClaimTx::parse_witness(&claim_tx) {
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

                let withdrawal_fulfillment_txid = ClaimTx::parse_witness(&claim_tx).unwrap(); // FIXME: Handle me
                info!(event = "parsed claim transaction", bridge_out_txid_size = %withdrawal_fulfillment_txid.len());

                let groth16 = AssertDataTxBatch::parse_witnesses(&assert_data_txs).unwrap(); // FIXME:
                                                                                             // Handle me
                info!(event = "parsed assert data", wots256_signature_size=%groth16.0.len(), groth16_signature_size=%groth16.1.len());

                let signatures = wots::Signatures {
                    withdrawal_fulfillment: Wots256Sig(withdrawal_fulfillment_txid),
                    groth16: Groth16Sigs(groth16.clone()),
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

                    let withdrawal_txid: [u8; 32] =
                        wots_to_byte_array(withdrawal_fulfillment_txid).into();
                    let public_inputs = BridgeProofPublicOutput {
                        deposit_txid: deposit_txid.into(),
                        withdrawal_fulfillment_txid: withdrawal_txid.into(),
                    };

                    // NOTE: This is zkvm-specific logic
                    let serialized_public_inputs = borsh::to_vec(&public_inputs).unwrap();
                    let public_inputs_hash =
                        hash_public_inputs_with_fn(&serialized_public_inputs, blake3_hash);

                    let committed_public_inputs_hash = wots_to_byte_array(groth16.0[0]);

                    // FIXME: fix nibble flipping and remove this
                    let committed_public_inputs_hash =
                        committed_public_inputs_hash.map(|b| ((b & 0xf0) >> 4) | ((b & 0x0f) << 4));

                    if public_inputs_hash != committed_public_inputs_hash {
                        warn!(
                            expected = ?public_inputs_hash,
                            committed = ?committed_public_inputs_hash,
                            msg = "public inputs hash mismatch"
                        );

                        Some(ConnectorA3Leaf::DisprovePublicInputsCommitment {
                            deposit_txid,
                            witness: Some(DisprovePublicInputsCommitmentWitness {
                                sig_withdrawal_fulfillment_txid: withdrawal_fulfillment_txid,
                                sig_public_inputs_hash: groth16.0[0],
                            }),
                        })
                    } else {
                        // 2. groth16 proof validation
                        info!(action = "verifying groth16 assertions");
                        let complete_disprove_scripts = api_generate_full_tapscripts(
                            *public_keys.groth16,
                            &PARTIAL_VERIFIER_SCRIPTS,
                        );

                        if let Some((tapleaf_index, witness_script)) = validate_assertions(
                            &bridge_vk::GROTH16_VERIFICATION_KEY,
                            signatures.groth16.deref().clone(),
                            *public_keys.groth16,
                            &complete_disprove_scripts,
                        ) {
                            let disprove_script = complete_disprove_scripts[tapleaf_index].clone();
                            Some(ConnectorA3Leaf::DisproveProof {
                                disprove_script,
                                witness_script: Some(witness_script),
                            })
                        } else {
                            None
                        }
                    }
                };

                if let Some(disprove_leaf) = connector_leaf {
                    info!(action = "constructing disprove tx", for_operator_id=%operator_id, %deposit_txid);
                    let deposit_id = self
                        .public_db
                        .get_deposit_id(deposit_txid)
                        .await
                        .unwrap()
                        .unwrap(); // FIXME:
                                   // Handle me
                    let stake_txid = self
                        .public_db
                        .get_stake_txid(operator_id, deposit_id)
                        .await
                        .unwrap()
                        .unwrap(); // FIXME:
                                   // Handle me

                    let stake_data = self
                        .public_db
                        .get_stake_data(operator_id, deposit_id)
                        .await
                        .unwrap()
                        .unwrap(); // FIXME: Handle me

                    let disprove_tx_data = DisproveData {
                        post_assert_txid: post_assert_tx.compute_txid(),
                        deposit_txid,
                        stake_outpoint: OutPoint {
                            txid: stake_txid,
                            vout: STAKE_VOUT,
                        },
                        input_amount: post_assert_tx
                            .tx_out(0)
                            .expect("first output must exist in post-assert tx")
                            .value,
                        network: self.build_context.network(),
                    };

                    let connector_a3 = ConnectorA3::new(
                        self.build_context.network(),
                        deposit_txid,
                        self.build_context.aggregated_pubkey(),
                        public_keys.clone(),
                        CONNECTOR_PARAMS.payout_timelock,
                    );

                    let delta = relative::LockTime::from_height(6);
                    let stake_hash = stake_data.hash;
                    let connector_stake = ConnectorStake::new(
                        self.build_context.aggregated_pubkey(),
                        self.agent.public_key().x_only_public_key().0,
                        stake_hash,
                        delta,
                        self.build_context.network(),
                    );

                    let stake_chain_params = StakeChainParams::default();
                    let disprove_tx = DisproveTx::new(
                        disprove_tx_data,
                        stake_chain_params,
                        connector_a3,
                        connector_stake,
                    );

                    let reward_out = TxOut {
                        value: DISPROVER_REWARD,
                        script_pubkey: self
                            .agent
                            .taproot_address(self.build_context.network())
                            .script_pubkey(),
                    };

                    let disprove_sig = self
                        .public_db
                        .get_signature(operator_id, disprove_tx.compute_txid(), 0)
                        .await
                        .unwrap()
                        .unwrap(); // FIXME: Handle me
                    let disprove_sig = taproot::Signature {
                        signature: disprove_sig,
                        sighash_type: disprove_tx.psbt().inputs[0]
                            .sighash_type
                            .map(|sig| sig.taproot_hash_ty().unwrap())
                            .unwrap(),
                    };
                    let stake_spend_path = StakeSpendPath::Disprove(disprove_sig);
                    let connector_a3 = ConnectorA3::new(
                        self.build_context.network(),
                        deposit_txid,
                        self.build_context.aggregated_pubkey(),
                        public_keys,
                        CONNECTOR_PARAMS.payout_timelock,
                    );
                    let signed_disprove_tx = disprove_tx.finalize(
                        reward_out,
                        stake_spend_path,
                        disprove_leaf,
                        connector_stake,
                        connector_a3,
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
