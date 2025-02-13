use core::fmt;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    sync::Arc,
    time::Duration,
};

use anyhow::bail;
use ark_serialize::CanonicalSerialize;
use bitcoin::{
    block::Header,
    consensus,
    hex::DisplayHex,
    sighash::{Prevouts, SighashCache},
    Block, TapSighashType, Transaction, TxOut, Txid,
};
use bitcoin_bosd::Descriptor;
use bitvm::groth16::g16;
use musig2::{
    aggregate_partial_signatures, sign_partial, AggNonce, KeyAggContext, PartialSignature, PubNonce,
};
use rand::Rng;
use secp256k1::schnorr::Signature;
use strata_bridge_db::{
    errors::DbError,
    operator::{KickoffInfo, OperatorDb},
    public::PublicDb,
    tracker::DutyTrackerDb,
};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress,
    build_context::{BuildContext, TxBuildContext, TxKind},
    deposit::DepositInfo,
    duties::{BridgeDuty, BridgeDutyStatus, DepositStatus, WithdrawalStatus},
    params::{connectors::PAYOUT_TIMELOCK, prelude::*},
    scripts::taproot::{create_message_hash, finalize_input, TaprootWitness},
    types::{OperatorIdx, TxSigningData},
    withdrawal::WithdrawalInfo,
    wots::{Assertions, PublicKeys as WotsPublicKeys, Signatures as WotsSignatures},
};
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_bridge_proof_protocol::BridgeProofInput;
use strata_bridge_proof_snark::{bridge_vk, prover};
use strata_bridge_tx_graph::{
    connectors::prelude::ConnectorA30Leaf,
    partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS,
    peg_out_graph::{PegOutGraph, PegOutGraphConnectors, PegOutGraphInput},
    transactions::prelude::*,
};
use strata_btcio::rpc::traits::{BroadcasterRpc, ReaderRpc, SignerRpc};
use strata_primitives::{
    buf::{Buf32, Buf64},
    params::RollupParams,
};
use strata_rpc_api::StrataApiClient;
use strata_state::{block::L2Block, chain_state::Chainstate, id::L2BlockId, l1::get_btc_params};
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    base::Agent,
    proof_interop::{checkpoint_last_verified_l1_height, get_verification_state},
    signal::{
        AggNonces, CovenantNonceRequest, CovenantNonceRequestFulfilled, CovenantNonceSignal,
        CovenantSigRequest, CovenantSigRequestFulfilled, CovenantSignatureSignal, DepositSignal,
    },
};

const ENV_DUMP_TEST_DATA: &str = "DUMP_TEST_DATA";
const ENV_SKIP_VALIDATION: &str = "SKIP_VALIDATION";

#[derive(Debug)]
pub struct Operator<O: OperatorDb, P: PublicDb, D: DutyTrackerDb> {
    pub agent: Agent,
    pub msk: String,
    pub build_context: TxBuildContext,
    pub db: Arc<O>,
    pub public_db: Arc<P>,
    pub duty_db: Arc<D>,
    pub is_faulty: bool,
    pub btc_poll_interval: Duration,
    pub rollup_params: RollupParams,

    pub duty_status_sender: mpsc::Sender<(Txid, BridgeDutyStatus)>,
    pub deposit_signal_sender: broadcast::Sender<DepositSignal>,
    pub deposit_signal_receiver: broadcast::Receiver<DepositSignal>,
    pub covenant_nonce_sender: broadcast::Sender<CovenantNonceSignal>,
    pub covenant_nonce_receiver: broadcast::Receiver<CovenantNonceSignal>,
    pub covenant_sig_sender: broadcast::Sender<CovenantSignatureSignal>,
    pub covenant_sig_receiver: broadcast::Receiver<CovenantSignatureSignal>,
}

impl<O, P, D> Operator<O, P, D>
where
    O: OperatorDb,
    P: PublicDb + Clone,
    D: DutyTrackerDb,
{
    pub fn am_i_faulty(&self) -> bool {
        self.is_faulty
    }

    pub async fn start(&mut self, duty_receiver: &mut broadcast::Receiver<BridgeDuty>) {
        let own_index = self.build_context.own_index();
        info!(action = "starting operator", %own_index);

        loop {
            match duty_receiver.recv().await {
                Ok(bridge_duty) => {
                    debug!(event = "received duty", ?bridge_duty, %own_index);
                    self.process_duty(bridge_duty).await;
                }
                Err(RecvError::Lagged(skipped_messages)) => {
                    warn!(action = "processing last available duty", event = "duty executor lagging behind, please adjust '--duty-interval' arg", %skipped_messages);
                }
                Err(err) => {
                    error!(msg = "error receiving duties", ?err);

                    panic!("duty sender closed unexpectedly");
                }
            }
        }
    }

    pub async fn process_duty(&mut self, duty: BridgeDuty) {
        let own_index = self.build_context.own_index();
        let duty_id = duty.get_id();

        let latest_status = if let Some(status) =
            self.duty_db.fetch_duty_status(duty_id).await.unwrap()
        // FIXME: Handle me
        {
            status
        } else {
            let status: BridgeDutyStatus = match &duty {
                BridgeDuty::SignDeposit(_info) => DepositStatus::Received.into(),
                BridgeDuty::FulfillWithdrawal(_info) => WithdrawalStatus::Received.into(),
            };

            self.duty_status_sender
                .send((duty_id, status.clone()))
                .await
                .expect("should be able to send duty status");

            status
        };

        if latest_status.is_done() {
            debug!(action = "skipping already executed duty", %duty_id, %own_index);
            return;
        }

        match duty {
            BridgeDuty::SignDeposit(deposit_info) => {
                let txid = deposit_info.deposit_request_outpoint().txid;
                info!(event = "received deposit", %own_index, drt_txid = %txid);

                self.handle_deposit(deposit_info).await;
            }
            BridgeDuty::FulfillWithdrawal(withdrawal_info) => {
                let txid = withdrawal_info.deposit_outpoint().txid;
                let assignee_id = withdrawal_info.assigned_operator_idx();

                debug!(event = "received withdrawal", dt_txid = %txid, assignee = %assignee_id, %own_index);

                if assignee_id != own_index {
                    trace!(action = "ignoring withdrawal duty unassigned to this operator", %assignee_id, %own_index);
                    return;
                }

                let deposit_txid = withdrawal_info.deposit_outpoint().txid;

                info!(action = "getting the latest checkpoint index");
                let latest_checkpoint_idx = if let Some(checkpoint_idx) =
                    self.db.get_checkpoint_index(deposit_txid).await.unwrap()
                // FIXME: Handle me
                {
                    info!(event = "found strata checkpoint index in db", %checkpoint_idx, %deposit_txid, %own_index);

                    checkpoint_idx
                } else {
                    info!(event = "querying strata for latest checkpoint", %deposit_txid, %own_index);
                    self.agent
                        .strata_client
                        .get_latest_checkpoint_index(Some(true))
                        .await
                        .expect("should be able to get latest checkpoint index")
                        .expect("checkpoint index must exist")
                };

                info!(event = "received latest checkpoint index", %latest_checkpoint_idx);

                self.db
                    .set_checkpoint_index(deposit_txid, latest_checkpoint_idx)
                    .await
                    .unwrap(); // FIXME: Handle me

                let withdrawal_status = match latest_status {
                    BridgeDutyStatus::Withdrawal(withdrawal_status) => withdrawal_status,
                    _ => unreachable!("withdrawal duty must be associated with withdrawal status"),
                };

                self.handle_withdrawal(withdrawal_info, withdrawal_status)
                    .await;
            }
        }
    }

    pub async fn handle_deposit(&mut self, deposit_info: DepositInfo) {
        let own_index = self.build_context.own_index();

        // 1. aggregate_tx_graph
        let deposit_tx = deposit_info.construct_signing_data(&self.build_context);

        if let Err(cause) = deposit_tx {
            let deposit_txid = deposit_info.deposit_request_outpoint().txid;
            warn!(msg = "could not process deposit", %cause, %deposit_txid, %own_index);

            return;
        }

        let mut deposit_tx = deposit_tx.unwrap();

        let deposit_txid = deposit_tx.psbt.unsigned_tx.compute_txid();

        info!(action = "generating wots public keys", %deposit_txid, %own_index);
        let public_keys = WotsPublicKeys::new(&self.msk, deposit_txid);
        self.public_db
            .set_wots_public_keys(self.build_context.own_index(), deposit_txid, &public_keys)
            .await
            .unwrap(); // FIXME: Handle me

        info!(action = "generating kickoff", %deposit_txid, %own_index);

        let reserved_outpoints = self.db.selected_outpoints().await.unwrap(); // FIXME: Handle me
        info!(event = "got reserved outpoints", ?reserved_outpoints);

        let (change_address, funding_input, total_amount, funding_utxo) = self
            .agent
            .select_utxo(OPERATOR_STAKE, reserved_outpoints)
            .await
            .expect("should be able to get outpoints");

        self.db.add_outpoint(funding_input).await.unwrap(); // FIXME: Handle me

        let funding_inputs = vec![funding_input];
        let funding_utxos = vec![funding_utxo];
        let change_amt = total_amount - OPERATOR_STAKE - MIN_RELAY_FEE;

        let change_address =
            BitcoinAddress::parse(&change_address.to_string(), self.build_context.network())
                .expect("address and network must match");

        info!(action = "composing pegout graph input", %deposit_txid, %own_index);
        let peg_out_graph_input = PegOutGraphInput {
            deposit_amount: BRIDGE_DENOMINATION,
            operator_pubkey: self.agent.public_key().x_only_public_key().0,
            kickoff_data: KickoffTxData {
                funding_inputs: funding_inputs.clone(),
                funding_utxos: funding_utxos.clone(),
                change_address: change_address.clone(),
                change_amt,
                deposit_txid,
            },
        };

        info!(action = "adding kickoff info to db", %deposit_txid, %own_index, ?funding_inputs, ?funding_utxos);
        self.db
            .add_kickoff_info(
                deposit_txid,
                KickoffInfo {
                    funding_inputs,
                    funding_utxos,
                    change_address,
                    change_amt,
                },
            )
            .await
            .unwrap(); // FIXME: Handle me

        info!(action = "generating pegout graph and connectors", %deposit_txid, %own_index);
        let wots_public_keys = self
            .public_db
            .get_wots_public_keys(own_index, deposit_txid)
            .await
            .expect("should be able to get wots public keys")
            .unwrap(); // FIXME: Handle me
        let (peg_out_graph, _connectors) = PegOutGraph::generate(
            peg_out_graph_input.clone(),
            &self.build_context,
            deposit_txid,
            own_index,
            wots_public_keys,
        )
        .await
        .expect("must be able to generate tx graph");

        info!(action = "registering txids on the watcher", %deposit_txid, %own_index);
        self.register_graph(&peg_out_graph, own_index, deposit_txid)
            .await
            .expect("must be able to register graph");

        // 2. Aggregate nonces for peg out graph txs that require covenant.
        info!(action = "aggregating nonces for emulated covenant", %deposit_txid, %own_index);
        self.aggregate_covenant_nonces(
            deposit_txid,
            peg_out_graph_input.clone(),
            peg_out_graph.clone(),
        )
        .await;

        // 3. Aggregate signatures for peg out graph txs that require covenant.
        info!(action = "aggregating signatures for emulated covenant", %deposit_txid, %own_index);
        self.aggregate_covenant_signatures(deposit_txid, peg_out_graph_input, peg_out_graph)
            .await;

        // 4. Collect nonces and signatures for deposit tx.
        info!(action = "aggregating nonces for deposit sweeping", %deposit_txid, %own_index);
        let agg_nonce = self
            .aggregate_nonces(deposit_tx.clone())
            .await
            .expect("nonce aggregation must complete");

        info!(action = "aggregating signatures for deposit sweeping", %deposit_txid, %own_index);
        let signed_deposit_tx = self
            .aggregate_signatures(agg_nonce, &mut deposit_tx)
            .await
            .expect("should be able to construct fully signed deposit tx");

        // 5. Broadcast deposit tx.
        info!(action = "broadcasting deposit tx", operator_id=%own_index, %deposit_txid);
        match self
            .agent
            .btc_client
            .send_raw_transaction(&signed_deposit_tx)
            .await
        {
            Ok(txid) => {
                info!(event = "deposit tx successfully broadcasted", %txid);

                let duty_status = DepositStatus::Executed;
                info!(action = "reporting deposit duty status", duty_id = %txid, ?duty_status);

                let duty_id = deposit_info.deposit_request_outpoint().txid;
                if let Err(cause) = self
                    .duty_status_sender
                    .send((duty_id, duty_status.into()))
                    .await
                {
                    error!(msg = "could not report deposit duty status", %cause);
                }
            }
            Err(e) => {
                error!(?e, "could not broadcast deposit tx");
            }
        }
    }

    pub async fn aggregate_covenant_nonces(
        &mut self,
        deposit_txid: Txid,
        self_peg_out_graph_input: PegOutGraphInput,
        self_peg_out_graph: PegOutGraph,
    ) {
        let own_index = self.build_context.own_index();

        // 1. Prepare txs
        let PegOutGraph {
            assert_chain,
            payout_tx,
            disprove_tx,
            ..
        } = self_peg_out_graph;
        let AssertChain {
            pre_assert,
            assert_data: _,
            post_assert,
        } = assert_chain;

        // 2. Generate own nonces
        info!(action = "generating nonce for this operator", %deposit_txid, %own_index);
        self.generate_covenant_nonces(
            pre_assert.clone(),
            post_assert.clone(),
            payout_tx.clone(),
            disprove_tx.clone(),
            self.build_context.own_index(),
        )
        .await;

        // 3. Broadcast nonce request
        info!(action = "broadcasting this operator's nonce", %deposit_txid, %own_index);
        let details = CovenantNonceRequest {
            peg_out_graph_input: self_peg_out_graph_input,
        };

        self.covenant_nonce_sender
            .send(CovenantNonceSignal::Request {
                details,
                sender_id: self.build_context.own_index(),
            })
            .expect("should be able to send covenant signal");

        // 4. Listen for requests and fulfillment data from others.
        self.gather_and_fulfill_nonces(
            deposit_txid,
            pre_assert.compute_txid(),
            post_assert.compute_txid(),
            payout_tx.compute_txid(),
            disprove_tx.compute_txid(),
        )
        .await;
    }

    async fn generate_covenant_nonces(
        &self,
        pre_assert: PreAssertTx,
        post_assert: PostAssertTx,
        payout_tx: PayoutTx,
        disprove_tx: DisproveTx,
        operator_index: OperatorIdx,
    ) -> CovenantNonceRequestFulfilled {
        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");
        let key_agg_ctx_keypath = key_agg_ctx
            .clone()
            .with_unspendable_taproot_tweak()
            .expect("should be able to create key agg ctx with unspendable key");

        // As all these calls lock on the same `HashMap`, there is no point in making these
        // concurrent.
        trace!(action = "creating secnonce and pubnonce for pre-assert tx", %operator_index);
        let pre_assert_pubnonce = self
            .generate_nonces(operator_index, &key_agg_ctx, 0, &pre_assert)
            .await;

        trace!(action = "creating secnonce and pubnonce for post-assert tx", %operator_index);
        let post_assert_pubnonce = self
            .generate_nonces(operator_index, &key_agg_ctx_keypath, 0, &post_assert)
            .await;

        trace!(action = "creating secnonce and pubnonce for payout tx input 0", %operator_index);
        let payout_pubnonce_0 = self
            .generate_nonces(operator_index, &key_agg_ctx_keypath, 0, &payout_tx)
            .await;

        trace!(action = "creating secnonce and pubnonce for payout tx input 1", %operator_index);
        let payout_pubnonce_1 = self
            .generate_nonces(operator_index, &key_agg_ctx, 1, &payout_tx)
            .await;

        trace!(action = "creating secnonce and pubnonce for disprove tx", %operator_index);
        let disprove_pubnonce = self
            .generate_nonces(operator_index, &key_agg_ctx, 0, &disprove_tx)
            .await;

        CovenantNonceRequestFulfilled {
            pre_assert: pre_assert_pubnonce,
            post_assert: post_assert_pubnonce,
            disprove: disprove_pubnonce,
            payout_0: payout_pubnonce_0,
            payout_1: payout_pubnonce_1,
        }
    }

    async fn gather_and_fulfill_nonces(
        &mut self,
        deposit_txid: Txid,
        pre_assert_txid: Txid,
        post_assert_txid: Txid,
        payout_txid: Txid,
        disprove_txid: Txid,
    ) {
        let own_index = self.build_context.own_index();

        let mut requests_served = HashSet::new();
        requests_served.insert(own_index);

        let mut self_requests_fulfilled = false;

        let num_signers = self.build_context.pubkey_table().0.len();

        // FIXME: beware of `continue`-ing in this while loop. Since we don't close the sender
        // ever (as it is shared), continue-ing may cause the loop to wait for a message that will
        // never be received.
        while let Ok(msg) = self.covenant_nonce_receiver.recv().await {
            match msg {
                CovenantNonceSignal::Request { details, sender_id } => {
                    if sender_id == self.build_context.own_index() {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        info!(event = "self request ignored", %deposit_txid, %sender_id, %own_index);

                        // ignore own request
                        continue;
                    }

                    // fulfill request
                    let CovenantNonceRequest {
                        peg_out_graph_input,
                    } = details;
                    info!(event = "received covenant request for nonce", %deposit_txid, %sender_id, %own_index);

                    let wots_public_keys = self
                        .public_db
                        .get_wots_public_keys(sender_id, deposit_txid)
                        .await
                        .expect("should be able to get wots public keys")
                        .unwrap(); // FIXME: Handle me
                    let (
                        PegOutGraph {
                            assert_chain,
                            disprove_tx,
                            payout_tx,
                            ..
                        },
                        _connectors,
                    ) = PegOutGraph::generate(
                        peg_out_graph_input,
                        &self.build_context,
                        deposit_txid,
                        sender_id,
                        wots_public_keys,
                    )
                    .await
                    .expect("should be able to generate tx graph");

                    let AssertChain {
                        pre_assert,
                        assert_data: _,
                        post_assert,
                    } = assert_chain;

                    info!(action = "fulfilling covenant request for nonce", %deposit_txid, %sender_id, %own_index);
                    let request_fulfilled = self
                        .generate_covenant_nonces(
                            pre_assert,
                            post_assert,
                            payout_tx,
                            disprove_tx,
                            sender_id,
                        )
                        .await;

                    info!(action = "sending covenant request fulfillment signal for nonce", %deposit_txid, %sender_id, %own_index);
                    self.covenant_nonce_sender
                        .send(CovenantNonceSignal::RequestFulfilled {
                            details: request_fulfilled,
                            sender_id: self.build_context.own_index(),
                            destination_id: sender_id,
                        })
                        .expect("should be able to send through the covenant signal sender");

                    requests_served.insert(sender_id);
                    let count = requests_served.len();
                    trace!(event = "requests served", %deposit_txid, %count, %own_index);

                    if count == num_signers && self_requests_fulfilled {
                        info!(event = "all nonce requests served and fulfilled", %deposit_txid, %count, %own_index);

                        return;
                    }
                }
                CovenantNonceSignal::RequestFulfilled {
                    details,
                    sender_id,
                    destination_id,
                } => {
                    info!(event = "received covenant fulfillment data for nonce", %deposit_txid, %sender_id, %destination_id, %own_index);

                    if destination_id != own_index {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        // ignore messages meant for others
                        continue;
                    }

                    let CovenantNonceRequestFulfilled {
                        pre_assert,
                        post_assert,
                        disprove,
                        payout_0,
                        payout_1,
                    } = details;
                    info!(event = "received covenant fulfillment data for nonce", %deposit_txid, %sender_id, %own_index);

                    let txid_input_index_and_nonce = [
                        (pre_assert_txid, 0, pre_assert),
                        (post_assert_txid, 0, post_assert),
                        (disprove_txid, 0, disprove),
                        (payout_txid, 0, payout_0),
                        (payout_txid, 1, payout_1),
                    ];

                    let mut all_done = true;
                    for (txid, input_index, nonce) in txid_input_index_and_nonce {
                        self.db
                            .add_pubnonce(txid, input_index, sender_id, nonce)
                            .await
                            .unwrap(); // FIXME: Handle me

                        all_done = self
                            .db
                            .collected_pubnonces(txid, input_index)
                            .await
                            .is_ok_and(|v| v.len() == num_signers);
                    }

                    self_requests_fulfilled = all_done;
                    if self_requests_fulfilled && requests_served.len() == num_signers {
                        info!(event = "nonce requests fulfilled and served", %own_index);

                        return;
                    }
                }
            }
        }
    }

    pub async fn aggregate_covenant_signatures(
        &mut self,
        deposit_txid: Txid,
        self_peg_out_graph_input: PegOutGraphInput,
        self_peg_out_graph: PegOutGraph,
    ) {
        let own_index = self.build_context.own_index();

        // 1. Prepare txs
        let PegOutGraph {
            assert_chain,
            payout_tx,
            disprove_tx,
            ..
        } = self_peg_out_graph;
        let AssertChain {
            pre_assert,
            assert_data: _,
            post_assert,
        } = assert_chain;

        // 2. Generate agg nonces
        info!(action = "getting aggregated nonces", %deposit_txid, %own_index);
        let pre_assert_agg_nonce = self
            .get_aggregated_nonce(pre_assert.compute_txid(), 0)
            .await
            .expect("pre-assert nonce must exist");
        let post_assert_agg_nonce = self
            .get_aggregated_nonce(post_assert.compute_txid(), 0)
            .await
            .expect("post-assert nonce must exist");
        let disprove_agg_nonce = self
            .get_aggregated_nonce(disprove_tx.compute_txid(), 0)
            .await
            .expect("disprove nonce must exist");
        let payout_agg_nonce_0 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 0)
            .await
            .expect("payout 0 nonce must exist");
        let payout_agg_nonce_1 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 1)
            .await
            .expect("payout nonce 1 must exist");

        let agg_nonces = AggNonces {
            pre_assert: pre_assert_agg_nonce,
            post_assert: post_assert_agg_nonce,
            disprove: disprove_agg_nonce,
            payout_0: payout_agg_nonce_0,
            payout_1: payout_agg_nonce_1,
        };

        // 3. Generate own signatures
        info!(action = "generating signature for this operator",  deposit_txid = %deposit_txid, %own_index);
        self.generate_covenant_signatures(
            agg_nonces.clone(),
            own_index,
            pre_assert.clone(),
            post_assert.clone(),
            payout_tx.clone(),
            disprove_tx.clone(),
        )
        .await;

        // 3. Broadcast signature request
        info!(action = "broadcasting this operator's signature", %deposit_txid, %own_index);
        let details = CovenantSigRequest {
            peg_out_graph_input: self_peg_out_graph_input,
            agg_nonces: agg_nonces.clone(),
        };
        self.covenant_sig_sender
            .send(CovenantSignatureSignal::Request {
                details,
                sender_id: own_index,
            })
            .expect("should be able to send covenant signal");

        // 4. Listen for requests and fulfillment data from others.
        info!(action = "listening for signature requests and fulfillments",  deposit_txid = %deposit_txid, %own_index );
        self.gather_and_fulfill_signatures(
            deposit_txid,
            pre_assert.compute_txid(),
            post_assert.compute_txid(),
            payout_tx.compute_txid(),
            disprove_tx.compute_txid(),
        )
        .await;

        // 5. Update public db with aggregated signatures
        info!(action = "computing aggregate signatures",  deposit_txid = %deposit_txid, %own_index );
        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");

        let all_inputs = pre_assert.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            pre_assert,
            vec![agg_nonces.pre_assert; all_inputs].as_ref(),
        )
        .await;
        debug!(event = "computed aggregate signature for pre-assert", deposit_txid = %deposit_txid, %own_index);

        let all_inputs = post_assert.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            post_assert,
            vec![agg_nonces.post_assert; all_inputs].as_ref(),
        )
        .await;
        debug!(event = "computed aggregate signature for post-assert", deposit_txid = %deposit_txid, %own_index);

        self.compute_agg_sig(
            &key_agg_ctx,
            all_inputs,
            payout_tx,
            &[agg_nonces.payout_0, agg_nonces.payout_1],
        )
        .await;
        debug!(event = "computed aggregate signature for payout", deposit_txid = %deposit_txid, %own_index);

        let all_inputs = disprove_tx.witnesses().len();
        self.compute_agg_sig(
            &key_agg_ctx,
            1,
            disprove_tx,
            vec![agg_nonces.disprove; all_inputs].as_ref(),
        )
        .await;
        debug!(event = "computed aggregate signature for disprove", deposit_txid = %deposit_txid, %own_index);
    }

    pub async fn generate_covenant_signatures(
        &self,
        agg_nonces: AggNonces,
        operator_index: OperatorIdx,
        pre_assert: PreAssertTx,
        post_assert: PostAssertTx,
        payout_tx: PayoutTx,
        disprove_tx: DisproveTx,
    ) -> CovenantSigRequestFulfilled {
        let own_index = self.build_context.own_index();

        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg ctx");

        let all_inputs = pre_assert.witnesses().len();
        trace!(action = "signing pre-assert tx partially", %operator_index);
        let pre_assert_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Default,
                all_inputs,
                own_index,
                operator_index,
                pre_assert,
                vec![agg_nonces.pre_assert; all_inputs].as_ref(),
            )
            .await;

        trace!(action = "signing post-assert tx partially", %operator_index);
        let all_inputs = post_assert.witnesses().len();
        let post_assert_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Default,
                all_inputs,
                own_index,
                operator_index,
                post_assert,
                vec![agg_nonces.post_assert; all_inputs].as_ref(),
            )
            .await;

        trace!(action = "signing payout tx partially", %operator_index);
        let all_inputs = payout_tx.witnesses().len();
        let payout_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Default,
                all_inputs,
                own_index,
                operator_index,
                payout_tx,
                &[agg_nonces.payout_0, agg_nonces.payout_1],
            )
            .await;

        trace!(action = "signing disprove tx partially", %operator_index);
        let inputs_to_sign = disprove_tx.witnesses().len();
        let disprove_partial_sigs = self
            .sign_partial(
                &key_agg_ctx,
                TapSighashType::Single,
                inputs_to_sign,
                own_index,
                operator_index,
                disprove_tx,
                vec![agg_nonces.disprove; inputs_to_sign].as_ref(),
            )
            .await;

        CovenantSigRequestFulfilled {
            pre_assert: pre_assert_partial_sigs,
            post_assert: post_assert_partial_sigs,
            disprove: disprove_partial_sigs,
            payout: payout_partial_sigs,
        }
    }

    pub async fn gather_and_fulfill_signatures(
        &mut self,
        deposit_txid: Txid,
        pre_assert_txid: Txid,
        post_assert_txid: Txid,
        payout_txid: Txid,
        disprove_txid: Txid,
    ) {
        let own_index = self.build_context.own_index();

        let mut requests_served = HashSet::new();
        requests_served.insert(own_index);

        let mut self_requests_fulfilled = false;

        let num_signers = self.build_context.pubkey_table().0.len();

        // FIXME: beware of `continue`-ing in this while loop. Since we don't close the sender
        // ever (as it is shared), continue-ing may cause the loop to wait for a message that will
        // never be received.
        while let Ok(msg) = self.covenant_sig_receiver.recv().await {
            match msg {
                CovenantSignatureSignal::Request { details, sender_id } => {
                    if sender_id == own_index {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        info!(event = "ignored self request for signatures", %deposit_txid, %own_index);
                        continue;
                    }

                    // fulfill request
                    let CovenantSigRequest {
                        agg_nonces,
                        peg_out_graph_input,
                    } = details;
                    info!(event = "received covenant request for signatures", %deposit_txid, %sender_id, %own_index);
                    let wots_public_keys = self
                        .public_db
                        .get_wots_public_keys(sender_id, deposit_txid)
                        .await
                        .expect("should be able to get wots public keys")
                        .unwrap(); // FIXME: Handle me
                    let (peg_out_graph, _connectors) = PegOutGraph::generate(
                        peg_out_graph_input,
                        &self.build_context,
                        deposit_txid,
                        sender_id,
                        wots_public_keys,
                    )
                    .await
                    .expect("should be able to generate tx graph");

                    self.register_graph(&peg_out_graph, sender_id, deposit_txid)
                        .await
                        .expect("should be able to register graph");

                    let PegOutGraph {
                        assert_chain,
                        disprove_tx,
                        payout_tx,
                        ..
                    } = peg_out_graph;

                    let AssertChain {
                        pre_assert,
                        assert_data: _,
                        post_assert,
                    } = assert_chain;

                    info!(action = "fulfilling covenant request for signatures", %deposit_txid, %sender_id, %own_index);
                    let request_fulfilled = self
                        .generate_covenant_signatures(
                            agg_nonces,
                            sender_id,
                            pre_assert,
                            post_assert,
                            payout_tx,
                            disprove_tx,
                        )
                        .await;

                    info!(action = "sending covenant request fulfillment signal for signatures", %deposit_txid, destination_id = %sender_id, %own_index);
                    self.covenant_sig_sender
                        .send(CovenantSignatureSignal::RequestFulfilled {
                            details: request_fulfilled,
                            sender_id: own_index,
                            destination_id: sender_id,
                        })
                        .expect("should be able to send through the covenant signal sender");

                    requests_served.insert(sender_id);
                    let count = requests_served.len();
                    trace!(event = "requests served", %deposit_txid, %count, %own_index);

                    if count == num_signers && self_requests_fulfilled {
                        info!(event = "all signature requests served and fulfilled", %deposit_txid, %own_index);

                        return;
                    }
                }
                CovenantSignatureSignal::RequestFulfilled {
                    details,
                    sender_id,
                    destination_id,
                } => {
                    if destination_id != own_index {
                        if self_requests_fulfilled && requests_served.len() == num_signers {
                            info!(event = "all nonce requests fulfilled and served", %deposit_txid, %own_index);

                            return;
                        }

                        // ignore messages meant for others
                        continue;
                    }

                    let CovenantSigRequestFulfilled {
                        pre_assert,
                        post_assert,
                        disprove,
                        payout,
                    } = details;
                    info!(event = "received covenant fulfillment data for signature", %deposit_txid, %sender_id, %own_index);

                    let txid_and_signatures = [
                        (pre_assert_txid, pre_assert),
                        (post_assert_txid, post_assert),
                        (disprove_txid, disprove),
                        (payout_txid, payout),
                    ];

                    let mut all_done = true;
                    for (txid, signatures) in txid_and_signatures {
                        for (input_index, partial_sig) in signatures.into_iter().enumerate() {
                            self.db
                                .add_partial_signature(
                                    txid,
                                    input_index as u32,
                                    sender_id,
                                    partial_sig,
                                )
                                .await
                                .unwrap(); // FIXME: Handle me

                            all_done = all_done
                                && self
                                    .db
                                    .collected_signatures_per_msg(txid, input_index as u32)
                                    .await
                                    .unwrap() // FIXME:  Handle me
                                    .is_some_and(|v| {
                                        let sig_count = v.1.len();
                                        debug!(event = "got sig count", %sig_count, %txid, %input_index, %own_index);

                                        sig_count == num_signers
                                    });
                        }
                    }

                    self_requests_fulfilled = all_done;
                    if self_requests_fulfilled && requests_served.len() == num_signers {
                        info!(event = "all signature requests fulfilled and served", %deposit_txid, %own_index);

                        return;
                    }
                }
            }
        }
    }

    pub async fn aggregate_nonces(&mut self, tx_signing_data: TxSigningData) -> Option<AggNonce> {
        let tx = tx_signing_data.psbt.unsigned_tx.clone();
        let txid = tx.compute_txid();

        let own_index = self.build_context.own_index();

        info!(action = "generating one's own nonce for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);
        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to create key agg context");

        let secnonce = self.agent.generate_sec_nonce(&txid, &key_agg_ctx);
        self.db
            .add_secnonce(txid, 0, secnonce.clone())
            .await
            .unwrap(); // FIXME: Handle me

        let pubnonce = secnonce.public_nonce();

        self.db
            .add_pubnonce(txid, 0, own_index, pubnonce.clone())
            .await
            .unwrap(); // FIXME: Handle me

        info!(action = "broadcasting one's own nonce for deposit sweeping", deposit_txid=%txid, %own_index);
        self.deposit_signal_sender
            .send(DepositSignal::Nonce {
                txid,
                pubnonce,
                sender_id: own_index,
            })
            .expect("should be able to send deposit pubnonce");

        info!(action = "listening for nonces for deposit sweeping", deposit_txid=%txid, %own_index);

        let expected_nonce_count = self.build_context.pubkey_table().0.len();
        while let Ok(deposit_signal) = self.deposit_signal_receiver.recv().await {
            if let DepositSignal::Nonce {
                txid,
                pubnonce,
                sender_id,
            } = deposit_signal
            {
                info!(event = "received nonce for deposit sweeping", deposit_txid=%txid, %own_index, %sender_id);
                self.db
                    .add_pubnonce(txid, 0, sender_id, pubnonce)
                    .await
                    .unwrap(); // FIXME: Handle me

                if let Ok(collected_nonces) = self.db.collected_pubnonces(txid, 0).await {
                    // FIXME: Handle me
                    let nonce_count = collected_nonces.len();
                    if nonce_count != expected_nonce_count {
                        // NOTE: there is still some nonce to be received, so continuing to listen
                        // on the channel is fine.
                        debug!(event = "collected nonces but not sufficient yet", %nonce_count, %expected_nonce_count);

                        continue;
                    }

                    info!(event = "received all required nonces for deposit sweeping", deposit_txid=%txid, %own_index, %sender_id);
                    return Some(collected_nonces.values().sum());
                }
            } else {
                // ignore signatures in this function
                warn!(
                    ?deposit_signal,
                    %own_index,
                    "should not receive signatures in this function"
                );
            }
        }

        error!(event = "deposit signal sender closed before completion", deposit_txid=%txid, %own_index);
        None
    }

    pub async fn aggregate_signatures(
        &mut self,
        agg_nonce: AggNonce,
        tx_signing_data: &mut TxSigningData,
    ) -> Option<Transaction> {
        let own_index = self.build_context.own_index();

        let tx = &tx_signing_data.psbt.unsigned_tx;
        let txid = tx.compute_txid();

        let prevouts = tx_signing_data
            .psbt
            .inputs
            .iter()
            .map(|i| {
                i.witness_utxo
                    .clone()
                    .expect("witness UTXO must be present")
            })
            .collect::<Vec<TxOut>>();
        let prevouts = Prevouts::All(&prevouts);

        let key_agg_ctx = KeyAggContext::new(self.build_context.pubkey_table().0.values().copied())
            .expect("should be able to generate agg key context");
        let seckey = self.agent.secret_key();
        let secnonce = self
            .db
            .get_secnonce(txid, 0)
            .await
            .unwrap() // FIXME: Handle me
            .expect("secnonce should exist before adding signatures");

        info!(action = "generating one's own signature for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

        let mut sighash_cache = SighashCache::new(tx);
        let message = create_message_hash(
            &mut sighash_cache,
            prevouts,
            &tx_signing_data.spend_path,
            TapSighashType::Default,
            0,
        )
        .expect("should be able to create message hash");
        let message = message.as_ref();

        let partial_signature = sign_partial(&key_agg_ctx, seckey, secnonce, &agg_nonce, message)
            .expect("should be able to sign deposit");
        self.db
            .add_message_hash_and_signature(txid, 0, message.to_vec(), own_index, partial_signature)
            .await
            .unwrap(); // FIXME: Handle me

        info!(action = "broadcasting one's own signature for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);
        self.deposit_signal_sender
            .send(DepositSignal::Signature {
                txid,
                signature: partial_signature,
                sender_id: own_index,
            })
            .expect("should be able to send signature");

        info!(action = "listening for signatures for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

        let expected_signature_count = self.build_context.pubkey_table().0.len();
        while let Ok(deposit_signal) = self.deposit_signal_receiver.recv().await {
            if let DepositSignal::Signature {
                txid,
                signature,
                sender_id,
            } = deposit_signal
            {
                // TODO: add signature verification logic in prod
                // for now, this is fine because musig2 validates every signature during generation.
                self.db
                    .add_partial_signature(txid, 0, sender_id, signature)
                    .await
                    .unwrap(); // FIXME: Handle me

                if let Some((_, collected_signatures)) =
                    self.db.collected_signatures_per_msg(txid, 0).await.unwrap()
                // FIXME: Handle me
                {
                    let sig_count = collected_signatures.len();
                    if collected_signatures.len() != expected_signature_count {
                        // NOTE: there is still some signature to be received, so continuing to
                        // listen on the channel is fine.
                        debug!(event = "collected signatures but not sufficient yet", %sig_count, %expected_signature_count);

                        continue;
                    }

                    info!(event = "received all required signatures for deposit sweeping");

                    let agg_signature: Signature = aggregate_partial_signatures(
                        &key_agg_ctx,
                        &agg_nonce,
                        collected_signatures.values().copied(),
                        message,
                    )
                    .expect("should be able to aggregate signatures");

                    info!(event = "signature aggregation complete for deposit sweeping", deposit_txid=%txid, operator_idx=%own_index);

                    if let TaprootWitness::Script {
                        script_buf,
                        control_block,
                    } = tx_signing_data.spend_path.clone()
                    {
                        let witnesses = [
                            agg_signature.as_ref().to_vec(),
                            script_buf.to_bytes(),
                            control_block.serialize(),
                        ];
                        finalize_input(
                            tx_signing_data
                                .psbt
                                .inputs
                                .first_mut()
                                .expect("the first input must exist"),
                            witnesses,
                        );

                        let signed_tx = tx_signing_data
                            .psbt
                            .clone()
                            .extract_tx()
                            .expect("should be able to extract fully signed tx");
                        debug!(event = "created signed tx", ?signed_tx);
                        info!(event = "deposit transaction fully signed and ready for broadcasting", deposit_txid=%txid, operator_idx=%own_index);

                        return Some(signed_tx);
                    } else {
                        unreachable!("deposit request should have a script spend path");
                    };
                }
            } else {
                // ignore nonces in this function
                warn!(?deposit_signal, %own_index, "should not receive nonces in this function");
            }
        }

        error!(event = "deposit signal sender closed before completion", deposit_txid=%txid, %own_index);
        None
    }

    pub async fn generate_nonces(
        &self,
        operator_idx: OperatorIdx,
        key_agg_ctx: &KeyAggContext,
        input_index: u32,
        tx: &impl CovenantTx,
    ) -> PubNonce {
        let txid = tx.compute_txid();

        let secnonce = self.agent.generate_sec_nonce(&txid, key_agg_ctx);
        let pubnonce = secnonce.public_nonce();

        // add the secnonce and pubnonce to db even for txid from others as it is required for
        // partial signing later.
        self.db
            .add_secnonce(txid, input_index, secnonce)
            .await
            .unwrap(); // FIXME: Handle me
        self.db
            .add_pubnonce(txid, input_index, operator_idx, pubnonce.clone())
            .await
            .unwrap(); // FIXME: Handle me

        pubnonce
    }

    /// Get the aggregated nonce from the list of collected nonces for the transaction
    /// corresponding to the given [`Txid`].
    ///
    /// Please refer to MuSig2 nonce aggregation section in
    /// [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
    /// # Errors
    ///
    /// If not all nonces have been colllected yet.
    pub async fn get_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> anyhow::Result<AggNonce> {
        if let Ok(collected_nonces) = self.db.collected_pubnonces(txid, input_index).await {
            let expected_nonce_count = self.build_context.pubkey_table().0.len();
            if collected_nonces.len() != expected_nonce_count {
                let collected: Vec<u32> = collected_nonces.keys().copied().collect();
                error!(?collected, %expected_nonce_count, "nonce collection incomplete");

                bail!("nonce collection incomplete");
            }

            Ok(collected_nonces.values().sum())
        } else {
            error!(%txid, %input_index, "nonces not found");

            bail!("nonce not found");
        }
    }

    /// Create partial signature for the tx.
    ///
    /// Make sure that `prevouts`, `agg_nonces` and `witnesses` have the same length.
    #[expect(clippy::too_many_arguments)]
    async fn sign_partial<Tx: CovenantTx + fmt::Debug>(
        &self,
        key_agg_ctx: &KeyAggContext,
        sighash_type: TapSighashType,
        inputs_to_sign: usize,
        own_index: OperatorIdx,
        operator_index: OperatorIdx,
        covenant_tx: Tx,
        agg_nonces: &[AggNonce],
    ) -> Vec<PartialSignature> {
        let tx = &covenant_tx.psbt().unsigned_tx;
        let txid = tx.compute_txid();

        let prevouts = covenant_tx.prevouts();
        let witnesses = covenant_tx.witnesses();

        let mut sighash_cache = SighashCache::new(tx);

        let mut partial_sigs: Vec<PartialSignature> = Vec::with_capacity(witnesses.len());
        for (input_index, (agg_nonce, witness)) in agg_nonces
            .iter()
            .zip(witnesses)
            .enumerate()
            .take(inputs_to_sign)
        {
            trace!(action = "creating message hash", ?covenant_tx, %input_index);

            let message = create_message_hash(
                &mut sighash_cache,
                prevouts.clone(),
                witness,
                sighash_type,
                input_index,
            )
            .expect("should be able to create a message hash");
            let message = message.as_ref();

            let secnonce = if let Some(secnonce) = self
                .db
                .get_secnonce(txid, input_index as u32)
                .await
                // FIXME: Handle me
                .unwrap()
            {
                secnonce
            } else {
                // use the first secnonce if the given input_index does not exist
                // this is the case for post_assert inputs (but not for payout)
                self.db
                    .get_secnonce(txid, 0)
                    .await
                    .unwrap() // FIXME: Handle me
                    .expect("first secnonce should exist")
            };

            let seckey = self.agent.secret_key();

            let agg_ctx = if matches!(witness, TaprootWitness::Key) {
                &key_agg_ctx
                    .clone()
                    .with_unspendable_taproot_tweak()
                    .expect("should be able to add unspendable key tweak")
            } else {
                key_agg_ctx
            };

            let partial_sig: PartialSignature =
                sign_partial(agg_ctx, seckey, secnonce, agg_nonce, message)
                    .expect("should be able to sign pre-assert");

            partial_sigs.push(partial_sig);

            if own_index == operator_index {
                self.db
                    .add_message_hash_and_signature(
                        txid,
                        input_index as u32,
                        message.to_vec(),
                        own_index,
                        partial_sig,
                    )
                    .await
                    .unwrap(); // FIXME: Handle me
            }
        }

        partial_sigs
    }

    async fn compute_agg_sig(
        &self,
        key_agg_ctx: &KeyAggContext,
        inputs_to_sign: usize,
        covenant_tx: impl CovenantTx,
        agg_nonces: &[AggNonce],
    ) {
        let txid = covenant_tx.compute_txid();

        let witnesses = covenant_tx.witnesses();

        for (input_index, (agg_nonce, witness)) in agg_nonces
            .iter()
            .zip(witnesses)
            .enumerate()
            .take(inputs_to_sign)
        {
            let agg_ctx = if matches!(witness, TaprootWitness::Key) {
                &key_agg_ctx
                    .clone()
                    .with_unspendable_taproot_tweak()
                    .expect("should be able to add unspendable key tweak")
            } else {
                key_agg_ctx
            };

            let collected_msgs_and_sigs = self
                .db
                .collected_signatures_per_msg(txid, input_index as u32)
                .await
                .unwrap() // FIXME: Handle me
                .expect("partial signatures must be present");
            let message = collected_msgs_and_sigs.0;
            let partial_sigs: Vec<PartialSignature> =
                collected_msgs_and_sigs.1.values().copied().collect();

            let agg_sig: Signature =
                aggregate_partial_signatures(agg_ctx, agg_nonce, partial_sigs, message)
                    .expect("signature aggregation must succeed");

            self.public_db
                .set_signature(
                    self.build_context.own_index(),
                    txid,
                    input_index as u32,
                    agg_sig,
                )
                .await
                .unwrap(); // FIXME: Handle me
        }
    }

    pub async fn handle_withdrawal(
        &self,
        withdrawal_info: WithdrawalInfo,
        status: WithdrawalStatus,
    ) {
        let mut status = status;

        // 0. get context
        let network = self.build_context.network();
        let own_index = self.build_context.own_index();

        let deposit_txid = withdrawal_info.deposit_outpoint().txid;
        let deposit_idx = 0; // FIXME: this must be extracted from the state

        let own_pubkey = self.agent.public_key().x_only_public_key().0;

        // 1. pay the user
        if status.should_pay() {
            let user_destination = withdrawal_info.user_destination();

            info!(action = "paying out the user", %user_destination, %own_index);

            let withdrawal_fulfillment_txid = self
                .pay_user(user_destination, network, own_index, deposit_idx)
                .await
                .expect("must be able to pay user");

            let duty_status = WithdrawalStatus::PaidUser(withdrawal_fulfillment_txid).into();
            info!(
                action = "sending out duty update status for withdrawal fulfillment",
                ?duty_status
            );

            self.duty_status_sender
                .send((deposit_txid, duty_status))
                .await
                .expect("should be able to send duty status");

            status.next(withdrawal_fulfillment_txid);
        } else {
            info!(action = "already paid user, so skipping");
        }

        // 2. create tx graph from public data
        info!(action = "reconstructing pegout graph", %deposit_txid, %own_index);
        let KickoffInfo {
            funding_inputs,
            funding_utxos,
            change_address,
            change_amt,
        } = self
            .db
            .get_kickoff_info(deposit_txid)
            .await
            .unwrap() // FIXME: Handle me
            .expect("kickoff data for the deposit must be present");

        let peg_out_graph_input = PegOutGraphInput {
            deposit_amount: BRIDGE_DENOMINATION,
            operator_pubkey: own_pubkey,
            kickoff_data: KickoffTxData {
                funding_inputs,
                funding_utxos,
                change_address,
                change_amt,
                deposit_txid,
            },
        };

        let wots_public_keys = self
            .public_db
            .get_wots_public_keys(own_index, deposit_txid)
            .await
            .expect("should be able to get wots public keys")
            .unwrap(); // FIXME: Handle me
        let (peg_out_graph, connectors) = PegOutGraph::generate(
            peg_out_graph_input,
            &self.build_context,
            deposit_txid,
            own_index,
            wots_public_keys,
        )
        .await
        .expect("should be able to generate tx graph");

        self.register_graph(&peg_out_graph, own_index, deposit_txid)
            .await
            .expect("should be able to register graph");

        let PegOutGraph {
            kickoff_tx,
            claim_tx,
            assert_chain,
            payout_tx,
            ..
        } = peg_out_graph;
        // 3. publish kickoff -> claim
        self.broadcast_kickoff_and_claim(
            &connectors,
            own_index,
            deposit_txid,
            kickoff_tx,
            claim_tx,
            &mut status,
        )
        .await;

        let AssertChain {
            pre_assert,
            assert_data,
            post_assert,
        } = assert_chain;

        if let Some(withdrawal_fulfillment_txid) = status.should_pre_assert() {
            // 5. Publish pre-assert tx
            info!(event = "challenge received, broadcasting pre-assert tx");
            let pre_assert_txid = pre_assert.compute_txid();
            let n_of_n_sig = self
                .public_db
                .get_signature(own_index, pre_assert_txid, 0)
                .await
                .unwrap()
                .unwrap(); // FIXME: Handle me
            let signed_pre_assert = pre_assert.finalize(connectors.claim_out_0, n_of_n_sig);
            let vsize = signed_pre_assert.vsize();
            let total_size = signed_pre_assert.total_size();
            let weight = signed_pre_assert.weight();
            info!(event = "finalized pre-assert tx", %pre_assert_txid, %vsize, %total_size, %weight, %own_index);

            let n_blocks = PRE_ASSERT_TIMELOCK + 10;
            info!(%n_blocks, "waiting before settling pre-assert");
            let pre_assert_txid = self
                .agent
                .wait_and_broadcast(&signed_pre_assert, Duration::from_secs(n_blocks as u64))
                .await
                .expect("should settle pre-assert");
            info!(event = "broadcasted pre-assert", %pre_assert_txid, %own_index);

            self.duty_status_sender
                .send((
                    deposit_txid,
                    WithdrawalStatus::PreAssert {
                        withdrawal_fulfillment_txid,
                        pre_assert_txid,
                    }
                    .into(),
                ))
                .await
                .expect("should be able to send duty status");

            status.next(withdrawal_fulfillment_txid);
        } else {
            info!(action = "already broadcasted pre-assert, so skipping");
        }

        // 6. compute proof
        // check that at least one assert data is still left to broadcast i.e, the last one has not
        // been broadcasted yet.
        let should_assert = status.should_assert_data(NUM_ASSERT_DATA_TX - 1);
        if let Some(bridge_out_txid) = should_assert {
            info!(action = "creating assertion signatures", %bridge_out_txid, %own_index);

            let mut assertions = self
                .prove_and_generate_assertions(deposit_txid, bridge_out_txid)
                .await;

            let mut assert_data_signatures =
                WotsSignatures::new(&self.msk, deposit_txid, assertions);

            if std::env::var(ENV_DUMP_TEST_DATA).is_ok() {
                fs::write(
                    "assertions.bin",
                    rkyv::to_bytes::<rkyv::rancor::Error>(&assertions).unwrap(),
                )
                .unwrap();
            }

            if std::env::var(ENV_SKIP_VALIDATION).is_err() {
                let public_keys = self
                    .public_db
                    .get_wots_public_keys(own_index, deposit_txid)
                    .await
                    .unwrap()
                    .unwrap(); // FIXME: Handle me

                let complete_disprove_scripts =
                    g16::generate_disprove_scripts(*public_keys.groth16, &PARTIAL_VERIFIER_SCRIPTS);

                if let Some((tapleaf_index, _witness_script)) = g16::verify_signed_assertions(
                    bridge_vk::GROTH16_VERIFICATION_KEY.clone(),
                    *public_keys.groth16,
                    assert_data_signatures.groth16,
                    &complete_disprove_scripts,
                ) {
                    error!(event = "assertions verification failed", %tapleaf_index, %own_index);
                } else {
                    info!(event = "assertions verification succeeded", %own_index);
                }
            }

            if self.am_i_faulty() {
                warn!(action = "making a faulty assertion");
                for _ in 0..assertions.groth16.2.len() {
                    let proof_index_to_tweak =
                        rand::thread_rng().gen_range(0..assertions.groth16.2.len());
                    warn!(action = "introducing faulty assertion", index=%proof_index_to_tweak);
                    if assertions.groth16.2[proof_index_to_tweak] != [0u8; 20] {
                        assertions.groth16.2[proof_index_to_tweak] = [0u8; 20];
                        break;
                    }
                }

                assert_data_signatures = WotsSignatures::new(&self.msk, deposit_txid, assertions);
            }

            let signed_assert_data_txs = assert_data.finalize(
                connectors.assert_data160_factory,
                connectors.assert_data256_factory,
                assert_data_signatures,
            );

            let num_assert_data_txs = signed_assert_data_txs.len();
            info!(
                event = "finalized signed assert data txs",
                num_assert_data_txs
            );

            info!(action = "estimating finalized assert data tx sizes", %own_index);
            let mut total_assertion_size = 0;
            for (index, signed_assert_data_tx) in signed_assert_data_txs.iter().enumerate() {
                let txid = signed_assert_data_tx.compute_txid();
                let vsize = signed_assert_data_tx.vsize();
                let total_size = signed_assert_data_tx.total_size();
                let weight = signed_assert_data_tx.weight();
                info!(event = "assert-data tx", %index, %txid, %vsize, %total_size, %weight, %own_index);

                total_assertion_size += vsize;
            }

            info!(action = "broadcasting finalized assert data txs", %own_index, %total_assertion_size);
            let mut broadcasted_assert_data_txids = Vec::with_capacity(TOTAL_CONNECTORS);

            for (index, signed_assert_data_tx) in signed_assert_data_txs.iter().enumerate() {
                if let Some(withdrawal_fulfillment_txid) = status.should_assert_data(index) {
                    info!(event = "broadcasting signed assert data tx", %index, %num_assert_data_txs);
                    let txid = self
                        .agent
                        .wait_and_broadcast(signed_assert_data_tx, Duration::from_secs(1))
                        .await
                        .expect("should settle assert-data");

                    broadcasted_assert_data_txids.push(txid);

                    self.duty_status_sender
                        .send((
                            deposit_txid,
                            BridgeDutyStatus::Withdrawal(WithdrawalStatus::AssertData {
                                withdrawal_fulfillment_txid,
                                assert_data_txids: broadcasted_assert_data_txids.clone(),
                            }),
                        ))
                        .await
                        .expect("should be able to send duty status");

                    info!(event = "broadcasted signed assert data tx", %index, %num_assert_data_txs);

                    status.next(txid);
                } else {
                    info!(action = "already broadcasted this assert data tx; so skipping", %index);
                }
            }
        } else {
            info!(action = "already broadcated all assert data txs, so skipping");
        }

        // 7. Broadcast post assert tx
        if status.should_post_assert() {
            let post_assert_txid = post_assert.compute_txid();
            let mut signatures = Vec::new();
            // num_assert_data_tx + 1 for stake
            for input_index in 0..=NUM_ASSERT_DATA_TX {
                let n_of_n_sig = self
                    .public_db
                    .get_signature(own_index, post_assert_txid, input_index as u32)
                    .await
                    .unwrap()
                    .unwrap(); // FIXME: Handle me

                signatures.push(n_of_n_sig);
            }

            let signed_post_assert = post_assert.finalize(&signatures);
            let vsize = signed_post_assert.vsize();
            let total_size = signed_post_assert.total_size();
            let weight = signed_post_assert.weight();
            info!(event = "finalized post-assert tx", %post_assert_txid, %vsize, %total_size, %weight, %own_index);

            let txid = self
                .agent
                .wait_and_broadcast(&signed_post_assert, BTC_CONFIRM_PERIOD)
                .await
                .expect("should be able to finalize post-assert tx");

            self.duty_status_sender
                .send((
                    deposit_txid,
                    BridgeDutyStatus::Withdrawal(WithdrawalStatus::PostAssert),
                ))
                .await
                .expect("should be able to send duty status");

            info!(event = "broadcasted post-assert tx", %post_assert_txid, %own_index);

            status.next(txid);
        } else {
            info!(action = "already broadcasted post assert tx, so skipping");
        }

        // 8. settle reimbursement tx after wait time
        if status.should_get_payout() {
            let wait_time = Duration::from_secs(PAYOUT_TIMELOCK as u64);
            info!(action = "waiting for timeout period before seeking reimbursement", wait_time_secs=%wait_time.as_secs());
            tokio::time::sleep(wait_time).await;

            let deposit_signature = self
                .public_db
                .get_signature(own_index, payout_tx.compute_txid(), 0)
                .await
                .unwrap()
                .unwrap(); // FIXME: Handle me
            let n_of_n_sig = self
                .public_db
                .get_signature(
                    own_index,
                    payout_tx.compute_txid(),
                    ConnectorA30Leaf::Payout(()).get_input_index(),
                )
                .await
                .unwrap()
                .unwrap(); // FIXME:  Handle me
            let signed_payout_tx =
                payout_tx.finalize(connectors.post_assert_out_0, deposit_signature, n_of_n_sig);

            info!(action = "trying to get reimbursement", payout_txid=%signed_payout_tx.compute_txid(), %own_index);

            match self
                .agent
                .wait_and_broadcast(&signed_payout_tx, BTC_CONFIRM_PERIOD)
                .await
            {
                Ok(txid) => {
                    self.duty_status_sender
                        .send((
                            deposit_txid,
                            BridgeDutyStatus::Withdrawal(WithdrawalStatus::Executed),
                        ))
                        .await
                        .expect("should be able to send duty status");

                    info!(event = "successfully received reimbursement", %txid, %own_index);

                    // NOTE: no need to call next because it is not used later outside this if
                    // clause
                }
                Err(err) => {
                    if !err.is_missing_or_invalid_input() {
                        warn!(msg = "unable to get reimbursement", %err, %deposit_txid, %own_index);
                        return; // try again later
                    }

                    error!(msg = "unable to get reimbursement due to disprove :(", %err, %deposit_txid, %own_index);
                }
            }
        } else {
            info!(action = "already attempted to get reimbursement; so skipping");
        }

        let duty_id = deposit_txid;
        let duty_status = BridgeDutyStatus::Withdrawal(WithdrawalStatus::Executed);
        info!(action = "reporting withdrawal duty status", %duty_id, ?duty_status);

        if let Err(cause) = self.duty_status_sender.send((duty_id, duty_status)).await {
            error!(msg = "could not report withdrawal duty status", %cause);
        }
    }

    async fn broadcast_kickoff_and_claim(
        &self,
        connectors: &PegOutGraphConnectors,
        own_index: u32,
        deposit_txid: Txid,
        kickoff_tx: KickOffTx,
        claim_tx: ClaimTx,
        status: &mut WithdrawalStatus,
    ) {
        if let Some(withdrawal_fulfillment_txid) = status.should_kickoff() {
            let unsigned_kickoff = &kickoff_tx.psbt().unsigned_tx;
            info!(action = "funding kickoff tx with wallet", ?unsigned_kickoff);
            let funded_kickoff = self
                .agent
                .btc_client
                .sign_raw_transaction_with_wallet(unsigned_kickoff, None)
                .await
                .expect("should be able to sign kickoff tx with wallet");
            let funded_kickoff_tx: Transaction =
                consensus::encode::deserialize_hex(&funded_kickoff.hex)
                    .expect("must be able to decode kickoff tx");
            info!(event = "funded kickoff tx with wallet", ?funded_kickoff_tx);

            let kickoff_txid = funded_kickoff_tx.compute_txid();
            info!(action = "broadcasting kickoff tx", %deposit_txid, %kickoff_txid, %own_index);
            let kickoff_txid = self
                .agent
                .btc_client
                .send_raw_transaction(&funded_kickoff_tx)
                .await
                .expect("should be able to broadcast signed kickoff tx");

            let duty_status = BridgeDutyStatus::Withdrawal(WithdrawalStatus::Kickoff {
                withdrawal_fulfillment_txid,
                kickoff_txid,
            });
            info!(action = "sending out duty status", ?duty_status);
            self.duty_status_sender
                .send((deposit_txid, duty_status))
                .await
                .expect("should be able to send duty status");

            info!(event = "broadcasted kickoff tx", %deposit_txid, %kickoff_txid, %own_index);

            status.next(withdrawal_fulfillment_txid);
        } else {
            info!(action = "already broadcasted kickoff, so skipping");
        }

        if let Some(withdrawal_fulfillment_txid) = status.should_claim() {
            let claim_tx_with_commitment = claim_tx.finalize(
                deposit_txid,
                &connectors.kickoff,
                &self.msk,
                withdrawal_fulfillment_txid,
            );

            let raw_claim_tx: String = consensus::encode::serialize_hex(&claim_tx_with_commitment);
            trace!(event = "finalized claim tx", %deposit_txid, ?claim_tx_with_commitment, %raw_claim_tx, %own_index);

            let claim_txid = self
                .agent
                .wait_and_broadcast(&claim_tx_with_commitment, BTC_CONFIRM_PERIOD)
                .await
                .expect("should be able to publish claim tx with commitment to bridge_out_txid");

            let duty_status = BridgeDutyStatus::Withdrawal(WithdrawalStatus::Claim {
                withdrawal_fulfillment_txid,
                claim_txid,
            });
            info!(
                action = "sending out duty update status for claim",
                ?duty_status
            );
            self.duty_status_sender
                .send((deposit_txid, duty_status))
                .await
                .expect("should be able to send duty status");

            info!(event = "broadcasted claim tx", %deposit_txid, %claim_txid, %own_index);

            status.next(withdrawal_fulfillment_txid);
        } else {
            info!(action = "already broadcasted claim tx, so skipping");
        }
    }

    async fn pay_user(
        &self,
        user_destination: &Descriptor,
        network: bitcoin::Network,
        own_index: OperatorIdx,
        deposit_idx: u32,
    ) -> anyhow::Result<Txid> {
        let net_payment = BRIDGE_DENOMINATION - OPERATOR_FEE;

        // don't use kickoff utxo for payment
        let reserved_utxos = self.db.selected_outpoints().await.unwrap(); // FIXME: Handle me

        let (change_address, outpoint, total_amount, prevout) = self
            .agent
            .select_utxo(net_payment, reserved_utxos)
            .await
            .expect("at least one funding utxo must be present in wallet");

        let change_amount = total_amount - net_payment - MIN_RELAY_FEE;
        debug!(%change_address, %change_amount, %outpoint, %total_amount, %net_payment, ?prevout, "found funding utxo for withdrawal fulfillment");

        let withdrawal_metadata = WithdrawalMetadata {
            deposit_idx,
            operator_idx: own_index,
        };
        let change = TxOut {
            script_pubkey: change_address.script_pubkey(),
            value: change_amount,
        };
        let recipient_addr = user_destination.to_address(network)?;
        let withdrawal_fulfillment = WithdrawalFulfillment::new(
            withdrawal_metadata,
            vec![outpoint],
            net_payment,
            Some(change),
            recipient_addr.into(),
        );

        let signed_tx_result = self
            .agent
            .btc_client
            .sign_raw_transaction_with_wallet(&withdrawal_fulfillment.tx(), None)
            .await
            .expect("must be able to sign withdrawal fulfillment transaction");

        assert!(
            signed_tx_result.complete,
            "withdrawal fulfillment tx must be completely signed"
        );

        let signed_tx: Transaction = consensus::encode::deserialize_hex(&signed_tx_result.hex)
            .expect("should be able to deserialize signed tx");

        match self.agent.btc_client.send_raw_transaction(&signed_tx).await {
            Ok(txid) => {
                info!(event = "paid the user successfully", %txid, %own_index);

                Ok(txid)
            }
            Err(e) => {
                error!(?e, "could not broadcast withdrawal fulfillment tx");

                bail!(e.to_string());
            }
        }
    }

    async fn prove_and_generate_assertions(
        &self,
        deposit_txid: Txid,
        withdrawal_fulfillment_txid: Txid,
    ) -> Assertions {
        info!(action = "getting latest checkpoint at the time of withdrawal duty reception");
        let latest_checkpoint_at_payout = self
            .db
            .get_checkpoint_index(deposit_txid)
            .await
            .unwrap() // FIXME: Handle me
            .expect("checkpoint index must exist");

        info!(action = "getting the checkpoint info for the index", %latest_checkpoint_at_payout);
        let checkpoint_info = self
            .agent
            .strata_client
            .get_checkpoint_info(latest_checkpoint_at_payout)
            .await
            .expect("should be able to get checkpoint info")
            .expect("checkpoint info must exist");
        let l1_range = checkpoint_info.l1_range;
        let l2_range = checkpoint_info.l2_range;

        info!(event = "got checkpoint info", %latest_checkpoint_at_payout, ?l1_range, ?l2_range);

        let next_l2_block = l2_range.1.slot() + 1;
        info!(action = "getting block id for the next L2 Block", %next_l2_block);
        let l2_block_id = self
            .agent
            .strata_client
            .get_headers_at_idx(next_l2_block)
            .await
            .expect("should be able to get L2 block headers")
            .expect("L2 block headers must be present")
            .first()
            .expect("L2 block headers must not be empty")
            .block_id;

        info!(
            action = "getting chain state",
            l2_block_id = l2_block_id.to_lower_hex_string()
        );
        let cl_block_witness = self
            .agent
            .strata_client
            .get_cl_block_witness_raw(L2BlockId::from(Buf32(l2_block_id)))
            .await
            .expect("should be able to query for CL block witness");

        let chain_state = borsh::from_slice::<(Chainstate, L2Block)>(&cl_block_witness)
            .expect("should be able to deserialize CL block witness")
            .0;

        let l1_start_height = (checkpoint_info.l1_range.1.height() + 1) as u32;
        let mut block_count = 0;

        let btc_params = get_btc_params();

        // FIXME: bring `get_verification_state` impl into the loop below
        let header_vs = get_verification_state(
            self.agent.btc_client.as_ref(),
            l1_start_height as u64,
            &btc_params,
        )
        .await
        .expect("should be able to initial header state");
        info!(event = "got initial header state", %l1_start_height, ?header_vs);

        let mut height = l1_start_height as u32;
        let mut headers: Vec<Header> = vec![];
        let mut blocks: Vec<Block> = vec![];
        let mut withdrawal_fulfillment = None;
        let mut checkpoint = None;

        info!(action = "scanning blocks...", %deposit_txid, %withdrawal_fulfillment_txid, start_height=%height);
        let poll_interval = Duration::from_secs(self.btc_poll_interval.as_secs() / 2);
        loop {
            let block = self.agent.btc_client.get_block_at(height.into()).await;

            if block.is_err() {
                tokio::time::sleep(poll_interval).await;
                continue;
            }

            let block = block.unwrap();

            // Only set `checkpoint` if it's currently `None` and we find a matching tx
            checkpoint = checkpoint.or_else(|| {
                block
                    .txdata
                    .iter()
                    .enumerate()
                    .find(|(_, tx)| {
                        checkpoint_last_verified_l1_height(tx, &self.rollup_params)
                            .is_some_and(|h| h == header_vs.last_verified_block_num)
                    })
                    .map(|(idx, tx)| {
                        let height = block.bip34_block_height().unwrap() as u32;
                        info!(
                            event = "found checkpoint",
                            %height,
                            checkpoint_txid = %tx.compute_txid()
                        );
                        (
                            L1TxWithProofBundle::generate(&block.txdata, idx as u32),
                            (height - l1_start_height) as usize,
                        )
                    })
            });

            // Only set `withdrawal_fulfillment` if it's currently `None` and we find a matching tx
            withdrawal_fulfillment = withdrawal_fulfillment.or_else(|| {
                block
                    .txdata
                    .iter()
                    .enumerate()
                    .find(|(_, tx)| tx.compute_txid() == withdrawal_fulfillment_txid)
                    .map(|(idx, _)| {
                        let height = block.bip34_block_height().unwrap() as u32;
                        info!(
                            event = "found withdrawal fulfillment",
                            %height,
                            %withdrawal_fulfillment_txid
                        );
                        (
                            L1TxWithProofBundle::generate(&block.txdata, idx as u32),
                            (height - l1_start_height) as usize,
                        )
                    })
            });

            let header = block.header;
            headers.push(header);
            blocks.push(block);
            height += 1;

            block_count += 1;

            if block_count >= EXPECTED_BLOCK_COUNT {
                info!(event = "blocks period complete", total_blocks = %headers.len());
                break;
            }

            tokio::time::sleep(poll_interval).await;
        }

        let deposit_idx = chain_state
            .deposits_table()
            .deposits()
            .find(|deposit| deposit.output().outpoint().txid == deposit_txid)
            .expect("expected a deposit idx")
            .idx();

        let pk = self.agent.public_key();
        info!(action = "signing txid", ?withdrawal_fulfillment_txid, %pk);
        let op_signature: Buf64 = self.agent.sign_txid(&withdrawal_fulfillment_txid).into();

        if std::env::var(ENV_DUMP_TEST_DATA)
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            dump_proof_input_data(&chain_state, blocks, op_signature);
        }

        let input = BridgeProofInput {
            rollup_params: self.rollup_params.clone(),
            headers,
            chain_state,
            header_vs,
            deposit_idx,
            strata_checkpoint_tx: checkpoint.expect("must be able to find checkpoint"),
            withdrawal_fulfillment_tx: withdrawal_fulfillment
                .expect("must be able to find withdrawal fulfillment tx"),
            op_signature,
        };

        let (proof, public_inputs, public_output) = prover::sp1_prove(&input).unwrap();

        if std::env::var(ENV_DUMP_TEST_DATA).is_ok() {
            let proof_file = File::create("proof.bin").unwrap();
            let public_inputs_file = File::create("public_inputs.bin").unwrap();
            proof.serialize_uncompressed(proof_file).unwrap();
            public_inputs[0]
                .serialize_uncompressed(public_inputs_file)
                .unwrap();
        }

        Assertions {
            bridge_out_txid: public_output.withdrawal_fulfillment_txid.0,
            groth16: g16::generate_proof_assertions(
                bridge_vk::GROTH16_VERIFICATION_KEY.clone(),
                proof,
                public_inputs,
            ),
        }
    }

    async fn register_graph(
        &self,
        peg_out_graph: &PegOutGraph,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> Result<(), DbError> {
        let claim_txid = peg_out_graph.claim_tx.compute_txid();
        info!(action = "registering claim", %claim_txid, %deposit_txid, %operator_idx);
        self.public_db
            .register_claim_txid(claim_txid, operator_idx, deposit_txid)
            .await?;

        let pre_assert_txid = peg_out_graph.assert_chain.pre_assert.compute_txid();
        info!(action = "registering pre-assert", %pre_assert_txid, %deposit_txid, %operator_idx);
        self.public_db
            .register_pre_assert_txid(pre_assert_txid, operator_idx, deposit_txid)
            .await?;

        let assert_data_txids = peg_out_graph.assert_chain.assert_data.compute_txids();
        info!(action = "registering assert data txids", ?assert_data_txids, %deposit_txid, %operator_idx);
        self.public_db
            .register_assert_data_txids(assert_data_txids, operator_idx, deposit_txid)
            .await?;

        let post_assert_txid = peg_out_graph.assert_chain.post_assert.compute_txid();
        info!(action = "registering post-assert txid", %post_assert_txid, %deposit_txid, %operator_idx);
        self.public_db
            .register_post_assert_txid(post_assert_txid, operator_idx, deposit_txid)
            .await?;

        Ok(())
    }
}

fn dump_proof_input_data(chain_state: &Chainstate, blocks: Vec<Block>, op_signature: Buf64) {
    // Dump the proof to file if flag is enabled
    // Save chainstate
    let chainstate_file = "chainstate.borsh";
    let mut file = File::create("chainstate.borsh").unwrap();
    let data = borsh::to_vec(chain_state).expect("chainstate borsh serialization failed");
    file.write_all(&data)
        .expect("must be able to write chainstate to file");
    info!(event = "dumped chainstate to file", filename = %chainstate_file);

    // Save blocks
    let blocks_file = "blocks.bin";
    bincode::serialize_into(File::create("blocks.bin").unwrap(), &blocks).unwrap();
    info!(event = "dumped blocks to file", filename = %blocks_file);

    let op_signature_file = "op_signature.borsh";
    let mut file = File::create("op_signature.borsh").unwrap();
    let data = op_signature.as_slice();
    file.write_all(data)
        .expect("must be able to write op_signature to file");
    info!(event = "dumped op_signature to file", filename = %op_signature_file);

    panic!("done dumping proof input data");
}
