//! Operator module.

#![allow(deprecated)]

use core::fmt;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::Write,
    ops::Deref,
    sync::Arc,
    time::Duration,
};

use alpen_bridge_params::prelude::*;
use anyhow::bail;
use ark_serialize::CanonicalSerialize;
use bitcoin::{
    block::Header,
    consensus,
    hashes::{self, Hash},
    hex::DisplayHex,
    key::TapTweak,
    secp256k1::XOnlyPublicKey,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Address, Block, Network, OutPoint, TapNodeHash, TapSighashType, Transaction, TxOut, Txid,
};
use bitcoin_bosd::Descriptor;
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader, Signer},
};
use bitvm::{
    chunk::api::{api_generate_full_tapscripts, generate_assertions, validate_assertions},
    signatures::wots_api::HASH_LEN,
};
use musig2::{
    aggregate_partial_signatures, sign_partial, AggNonce, KeyAggContext, PartialSignature, PubNonce,
};
use rand::Rng;
use secp256k1::schnorr::Signature;
use strata_bridge_connectors::{
    partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS,
    prelude::{ConnectorA3Leaf, ConnectorCpfp, ConnectorP, ConnectorStake},
};
use strata_bridge_db::{
    errors::DbError,
    operator::{LegacyOperatorDb, OperatorDb},
    public::PublicDb,
    tracker::DutyTrackerDb,
};
use strata_bridge_primitives::scripts::prelude::drt_take_back;
#[expect(deprecated)]
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    constants::*,
    deposit::DepositInfo,
    duties::{BridgeDuty, BridgeDutyStatus, DepositStatus, WithdrawalStatus},
    scripts::{
        prelude::{create_tx, create_tx_ins, create_tx_outs},
        taproot::{create_message_hash, finalize_input, TaprootWitness},
    },
    types::OperatorIdx,
    withdrawal::WithdrawalInfo,
    wots::{Assertions, PublicKeys as WotsPublicKeys, Signatures as WotsSignatures},
};
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_bridge_proof_protocol::{
    BridgeProofInput, REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX,
};
use strata_bridge_proof_snark::{bridge_vk, prover};
use strata_bridge_stake_chain::{
    prelude::{PreStakeTx, OPERATOR_FUNDS, STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::StakeTxData,
    StakeChain,
};
use strata_bridge_tx_graph::{
    peg_out_graph::{PegOutGraph, PegOutGraphInput},
    transactions::prelude::*,
};
use strata_primitives::{
    buf::{Buf32, Buf64},
    params::RollupParams,
};
use strata_rpc_api::StrataApiClient;
use strata_state::{block::L2Block, chain_state::Chainstate, id::L2BlockId};
use tokio::sync::{
    broadcast::{self, error::RecvError},
    mpsc,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    base::{
        Agent, BRIDGE_DENOMINATION, BTC_CONFIRM_PERIOD, CONNECTOR_PARAMS, MIN_RELAY_FEE,
        OPERATOR_FEE, OPERATOR_STAKE,
    },
    proof_interop::checkpoint_last_verified_l1_height,
    signal::{
        AggNonces, CovenantNonceRequest, CovenantNonceRequestFulfilled, CovenantNonceSignal,
        CovenantSigRequest, CovenantSigRequestFulfilled, CovenantSignatureSignal, DepositSignal,
    },
};

const ENV_DUMP_TEST_DATA: &str = "DUMP_TEST_DATA";
const ENV_SKIP_VALIDATION: &str = "SKIP_VALIDATION";
const STAKE_CHAIN_LENGTH: u32 = 10;

/// The operator is responsible for signing and broadcasting transactions.
#[derive(Debug)]
pub struct Operator<O: OperatorDb, P: PublicDb, D: DutyTrackerDb> {
    /// The agent.
    pub agent: Agent,

    /// The master secret key.
    pub msk: String,

    /// The build context.
    pub build_context: TxBuildContext,

    /// The database.
    pub db: Arc<O>,

    /// The public database.
    pub public_db: Arc<P>,

    /// The duty database.
    pub duty_db: Arc<D>,

    /// Whether the operator is faulty.
    pub is_faulty: bool,

    /// The interval at which to poll the Bitcoin blockchain.
    pub btc_poll_interval: Duration,

    /// The rollup parameters.
    pub rollup_params: RollupParams,

    /// The sender for duty status.
    pub duty_status_sender: mpsc::Sender<(Txid, BridgeDutyStatus)>,

    /// The sender for deposit signal.
    pub deposit_signal_sender: broadcast::Sender<DepositSignal>,

    /// The receiver for deposit signal.
    pub deposit_signal_receiver: broadcast::Receiver<DepositSignal>,

    /// The sender for covenant nonce signal.
    pub covenant_nonce_sender: broadcast::Sender<CovenantNonceSignal>,

    /// The receiver for covenant nonce signal.
    pub covenant_nonce_receiver: broadcast::Receiver<CovenantNonceSignal>,

    /// The sender for covenant signature signal.
    pub covenant_sig_sender: broadcast::Sender<CovenantSignatureSignal>,

    /// The receiver for covenant signature signal.
    pub covenant_sig_receiver: broadcast::Receiver<CovenantSignatureSignal>,
}

impl<O, P, D> Operator<LegacyOperatorDb<O>, P, D>
where
    O: OperatorDb + Send + Sync + Clone,
    P: PublicDb + Clone,
    D: DutyTrackerDb,
{
    /// Returns whether the operator is faulty.
    pub const fn am_i_faulty(&self) -> bool {
        self.is_faulty
    }

    /// Starts the operator.
    pub async fn start(&mut self, duty_receiver: &mut broadcast::Receiver<BridgeDuty>) {
        let own_index = self.build_context.own_index();
        info!(action = "starting operator", %own_index);

        info!(action = "creating stake chain", %STAKE_CHAIN_LENGTH);
        self.create_stake_chain(STAKE_CHAIN_LENGTH).await;

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

    /// Processes a duty.
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

        let pegout_graph_params = PegOutGraphParams::default();
        match duty {
            BridgeDuty::SignDeposit(deposit_info) => {
                let txid = deposit_info.deposit_request_outpoint().txid;
                info!(event = "received deposit duty", %own_index, drt_txid = %txid);

                let psbt = deposit_info
                    .construct_psbt(
                        &self.build_context,
                        &pegout_graph_params,
                        &self.rollup_params,
                    )
                    .unwrap(); // FIXME: Handle
                let deposit_txid = psbt.unsigned_tx.compute_txid();

                info!(action = "updating deposit table", %deposit_txid);
                self.public_db.add_deposit_txid(deposit_txid).await.unwrap(); // FIXME: Handle me

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

    /// Handles a deposit.
    #[expect(deprecated)]
    pub async fn handle_deposit(&mut self, deposit_info: DepositInfo) {
        let own_index = self.build_context.own_index();
        let pegout_graph_params = PegOutGraphParams::default();
        let take_back_key = deposit_info.x_only_public_key();

        // 1. aggregate_tx_graph
        let mut deposit_psbt = match deposit_info.construct_psbt(
            &self.build_context,
            &pegout_graph_params,
            &self.rollup_params,
        ) {
            Ok(deposit_psbt) => deposit_psbt,
            Err(cause) => {
                let deposit_txid = deposit_info.deposit_request_outpoint().txid;
                warn!(msg = "could not process deposit", %cause, %deposit_txid, %own_index);

                return;
            }
        };

        let deposit_txid = deposit_psbt.unsigned_tx.compute_txid();

        info!(action = "retrieving stake chain information", %deposit_txid, %own_index);
        let deposit_id = self
            .public_db
            .get_deposit_id(deposit_txid)
            .await
            .unwrap()
            .unwrap(); // FIXME:
                       // Handle me
        let stake_txid = self
            .public_db
            .get_stake_txid(own_index, deposit_id)
            .await
            .unwrap()
            .unwrap(); // FIXME:
                       // Handle me
        let stake_data = self
            .public_db
            .get_stake_data(own_index, deposit_id)
            .await
            .unwrap()
            .unwrap(); // FIXME:
                       // Handle me

        info!(action = "generating wots public keys", %deposit_txid, %own_index);
        let mut public_keys = WotsPublicKeys::new(&self.msk, deposit_txid);
        public_keys.withdrawal_fulfillment = stake_data.withdrawal_fulfillment_pk;

        self.public_db
            .set_wots_public_keys(own_index, deposit_txid, &public_keys)
            .await
            .unwrap(); // FIXME: Handle me

        info!(action = "composing peg out graph input", %deposit_txid, %own_index);
        let wots_public_keys = self
            .public_db
            .get_wots_public_keys(own_index, deposit_txid)
            .await
            .expect("should be able to get wots public keys")
            .unwrap(); // FIXME: Handle me

        let peg_out_graph_input = PegOutGraphInput {
            stake_outpoint: OutPoint {
                txid: stake_txid,
                vout: STAKE_VOUT,
            },
            withdrawal_fulfillment_outpoint: OutPoint {
                txid: stake_txid,
                vout: WITHDRAWAL_FULFILLMENT_VOUT,
            },
            stake_hash: stake_data.hash,
            wots_public_keys,
            operator_pubkey: self.agent.public_key().x_only_public_key().0,
        };
        let graph_params = PegOutGraphParams::default();

        info!(action = "generating pegout graph and connectors", %deposit_txid, %own_index);
        let (peg_out_graph, _connectors) = PegOutGraph::generate(
            &peg_out_graph_input,
            &self.build_context,
            deposit_txid,
            graph_params,
            CONNECTOR_PARAMS,
            StakeChainParams::default(),
            vec![],
        );

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
            .aggregate_nonces(&deposit_psbt)
            .await
            .expect("nonce aggregation must complete");

        info!(action = "aggregating signatures for deposit sweeping", %deposit_txid, %own_index);
        let signed_deposit_tx = self
            .aggregate_signatures(agg_nonce, &mut deposit_psbt, *take_back_key)
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

    /// Aggregates covenant nonces.
    pub async fn aggregate_covenant_nonces(
        &mut self,
        deposit_txid: Txid,
        self_peg_out_graph_input: PegOutGraphInput,
        self_peg_out_graph: PegOutGraph,
    ) {
        let own_index = self.build_context.own_index();
        let payout_tweak = ConnectorP::new(
            self.build_context.aggregated_pubkey(),
            self_peg_out_graph_input.stake_hash,
            self.build_context.network(),
        )
        .generate_merkle_root();

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
            payout_tweak,
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
        payout_tweak: TapNodeHash,
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

        trace!(action = "creating secnonce and pubnonce for payout tx input 2", %operator_index);
        let payout_pubnonce_2 = self
            .generate_nonces(operator_index, &key_agg_ctx_keypath, 2, &payout_tx)
            .await;

        trace!(action = "creating secnonce and pubnonce for payout tx input 3", %operator_index);
        let payout_key_agg_ctx = key_agg_ctx
            .clone()
            .with_taproot_tweak(payout_tweak.as_ref())
            .expect("should be able to create key agg ctx with tweak");
        let payout_pubnonce_3 = self
            .generate_nonces(operator_index, &payout_key_agg_ctx, 3, &payout_tx)
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
            payout_2: payout_pubnonce_2,
            payout_3: payout_pubnonce_3,
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

                    let graph_params = PegOutGraphParams::default();

                    let (
                        PegOutGraph {
                            assert_chain,
                            disprove_tx,
                            payout_tx,
                            ..
                        },
                        _connectors,
                    ) = PegOutGraph::generate(
                        &peg_out_graph_input,
                        &self.build_context,
                        deposit_txid,
                        graph_params,
                        CONNECTOR_PARAMS,
                        StakeChainParams::default(),
                        vec![],
                    );

                    let AssertChain {
                        pre_assert,
                        assert_data: _,
                        post_assert,
                    } = assert_chain;

                    info!(action = "fulfilling covenant request for nonce", %deposit_txid, %sender_id, %own_index);
                    let payout_tweak = ConnectorP::new(
                        self.build_context.aggregated_pubkey(),
                        peg_out_graph_input.stake_hash,
                        self.build_context.network(),
                    )
                    .generate_merkle_root();
                    let request_fulfilled = self
                        .generate_covenant_nonces(
                            pre_assert,
                            post_assert,
                            payout_tx,
                            disprove_tx,
                            sender_id,
                            payout_tweak,
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
                        payout_2,
                        payout_3,
                    } = details;
                    info!(event = "received covenant fulfillment data for nonce", %deposit_txid, %sender_id, %own_index);

                    let txid_input_index_and_nonce = [
                        (pre_assert_txid, 0, pre_assert),
                        (post_assert_txid, 0, post_assert),
                        (disprove_txid, 0, disprove),
                        (payout_txid, 0, payout_0),
                        (payout_txid, 1, payout_1),
                        (payout_txid, 2, payout_2),
                        (payout_txid, 3, payout_3),
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

    /// Aggregates covenant signatures.
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
            .expect("payout nonce 0 must exist");
        let payout_agg_nonce_1 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 1)
            .await
            .expect("payout nonce 1 must exist");
        let payout_agg_nonce_2 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 2)
            .await
            .expect("payout nonce 2 must exist");
        let payout_agg_nonce_3 = self
            .get_aggregated_nonce(payout_tx.compute_txid(), 3)
            .await
            .expect("payout nonce 3 must exist");

        let agg_nonces = AggNonces {
            pre_assert: pre_assert_agg_nonce,
            post_assert: post_assert_agg_nonce,
            disprove: disprove_agg_nonce,
            payout_0: payout_agg_nonce_0,
            payout_1: payout_agg_nonce_1,
            payout_2: payout_agg_nonce_2,
            payout_3: payout_agg_nonce_3,
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
            &[
                agg_nonces.payout_0,
                agg_nonces.payout_1,
                agg_nonces.payout_2,
                agg_nonces.payout_3,
            ],
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

    /// Generates covenant signatures.
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
                &[
                    agg_nonces.payout_0,
                    agg_nonces.payout_1,
                    agg_nonces.payout_2,
                    agg_nonces.payout_3,
                ],
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

    /// Gathers and fulfills covenant signatures.
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
                    let graph_params = PegOutGraphParams::default();
                    let (peg_out_graph, _connectors) = PegOutGraph::generate(
                        &peg_out_graph_input,
                        &self.build_context,
                        deposit_txid,
                        graph_params,
                        CONNECTOR_PARAMS,
                        StakeChainParams::default(),
                        vec![],
                    );

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

    /// Aggregates covenant nonces.
    pub async fn aggregate_nonces(&mut self, deposit_psbt: &bitcoin::Psbt) -> Option<AggNonce> {
        let tx = deposit_psbt.unsigned_tx.clone();
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

    /// Aggregates covenant signatures.
    pub async fn aggregate_signatures(
        &mut self,
        agg_nonce: AggNonce,
        deposit_psbt: &mut bitcoin::Psbt,
        take_back_key: XOnlyPublicKey,
    ) -> Option<Transaction> {
        let own_index = self.build_context.own_index();

        let tx = &deposit_psbt.unsigned_tx;
        let txid = tx.compute_txid();
        let refund_delay = 1008;
        let take_back_script = drt_take_back(take_back_key, refund_delay);
        let tweak = TapNodeHash::from_script(&take_back_script, LeafVersion::TapScript);

        let prevouts = deposit_psbt
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
            .expect("should be able to generate agg key context")
            .with_taproot_tweak(&tweak.to_byte_array())
            .unwrap();

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
            &TaprootWitness::Tweaked { tweak },
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

                    let witnesses = [agg_signature.as_ref().to_vec()];
                    finalize_input(
                        deposit_psbt
                            .inputs
                            .first_mut()
                            .expect("the first input must exist"),
                        witnesses,
                    );

                    let signed_tx = deposit_psbt
                        .clone()
                        .extract_tx()
                        .expect("should be able to extract fully signed tx");
                    debug!(event = "created signed tx", ?signed_tx);
                    info!(event = "deposit transaction fully signed and ready for broadcasting", deposit_txid=%txid, operator_idx=%own_index);

                    return Some(signed_tx);
                }
            } else {
                // ignore nonces in this function
                warn!(?deposit_signal, %own_index, "should not receive nonces in this function");
            }
        }

        error!(event = "deposit signal sender closed before completion", deposit_txid=%txid, %own_index);
        None
    }

    /// Generates covenant nonces.
    pub async fn generate_nonces<const NUM_COVENANT_INPUTS: usize>(
        &self,
        operator_idx: OperatorIdx,
        key_agg_ctx: &KeyAggContext,
        input_index: u32,
        tx: &impl CovenantTx<NUM_COVENANT_INPUTS>,
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
    async fn sign_partial<
        const NUM_COVENANT_INPUTS: usize,
        Tx: CovenantTx<NUM_COVENANT_INPUTS> + fmt::Debug,
    >(
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

            let agg_ctx = match witness {
                TaprootWitness::Key => &key_agg_ctx
                    .clone()
                    .with_unspendable_taproot_tweak()
                    .expect("should be able to add unspendable key tweak"),
                TaprootWitness::Script { .. } => key_agg_ctx,
                TaprootWitness::Tweaked { tweak } => &key_agg_ctx
                    .clone()
                    .with_taproot_tweak(&tweak.to_byte_array())
                    .expect("should be able to add tweak"),
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

    /// Computes an aggregated signature.
    async fn compute_agg_sig<const NUM_COVENANT_INPUTS: usize>(
        &self,
        key_agg_ctx: &KeyAggContext,
        inputs_to_sign: usize,
        covenant_tx: impl CovenantTx<NUM_COVENANT_INPUTS>,
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
            let agg_ctx = match witness {
                TaprootWitness::Key => &key_agg_ctx
                    .clone()
                    .with_unspendable_taproot_tweak()
                    .expect("should be able to add unspendable key tweak"),
                TaprootWitness::Script { .. } => key_agg_ctx,
                TaprootWitness::Tweaked { tweak } => &key_agg_ctx
                    .clone()
                    .with_taproot_tweak(&tweak.to_byte_array())
                    .expect("should be able to add tweak"),
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

    /// Handles a withdrawal.
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

        let own_pubkey = self.agent.public_key().x_only_public_key().0;

        // 1. pay the user
        if status.should_pay() {
            let user_destination = withdrawal_info.user_destination();

            info!(action = "paying out the user", %user_destination, %own_index);

            let deposit_idx = self
                .public_db
                .get_deposit_id(deposit_txid)
                .await
                .expect("should be able to get deposit id")
                .unwrap(); // FIXME: Handle me

            let withdrawal_fulfillment_txid = self
                .pay_user(
                    user_destination,
                    network,
                    own_index,
                    deposit_idx,
                    deposit_txid,
                )
                .await
                .expect("must be able to pay user");

            let duty_status = WithdrawalStatus::PaidUser {
                withdrawal_fulfillment_txid,
            }
            .into();
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
        info!(action = "retrieving stake chain information", %deposit_txid, %own_index);
        let deposit_id = self
            .public_db
            .get_deposit_id(deposit_txid)
            .await
            .unwrap()
            .unwrap(); // FIXME:
                       // Handle me
        let stake_txid = self
            .public_db
            .get_stake_txid(own_index, deposit_id)
            .await
            .unwrap()
            .unwrap(); // FIXME:
                       // Handle me
        let stake_data = self
            .public_db
            .get_stake_data(own_index, deposit_id)
            .await
            .unwrap()
            .unwrap(); // FIXME:
                       // Handle me
        let wots_public_keys = self
            .public_db
            .get_wots_public_keys(own_index, deposit_txid)
            .await
            .unwrap()
            .unwrap();

        info!(action = "reconstructing pegout graph", %deposit_txid, %own_index);
        let graph_params = PegOutGraphParams::default();
        let peg_out_graph_input = PegOutGraphInput {
            operator_pubkey: own_pubkey,
            stake_outpoint: OutPoint {
                txid: stake_txid,
                vout: STAKE_VOUT,
            },
            withdrawal_fulfillment_outpoint: OutPoint {
                txid: stake_txid,
                vout: WITHDRAWAL_FULFILLMENT_VOUT,
            },
            stake_hash: stake_data.hash,
            wots_public_keys,
        };

        let (peg_out_graph, connectors) = PegOutGraph::generate(
            &peg_out_graph_input,
            &self.build_context,
            deposit_txid,
            graph_params,
            CONNECTOR_PARAMS,
            StakeChainParams::default(),
            vec![],
        );

        // self.register_graph(&peg_out_graph, own_index, deposit_txid)
        //     .await
        //     .expect("should be able to register graph");

        let PegOutGraph {
            claim_tx,
            assert_chain,
            payout_tx,
            ..
        } = peg_out_graph;
        // 3. publish stake -> claim
        self.broadcast_claim(own_index, deposit_txid, claim_tx, deposit_id, &mut status)
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

            let n_blocks = CONNECTOR_PARAMS.pre_assert_timelock + 10;
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
                info!(action = "dumping assertions for testing", %own_index);
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
                    api_generate_full_tapscripts(*public_keys.groth16, &PARTIAL_VERIFIER_SCRIPTS);

                if let Some((tapleaf_index, _witness_script)) = validate_assertions(
                    &bridge_vk::GROTH16_VERIFICATION_KEY,
                    assert_data_signatures.groth16.deref().clone(),
                    *public_keys.groth16,
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
                    if assertions.groth16.2[proof_index_to_tweak] != [0u8; HASH_LEN as usize] {
                        assertions.groth16.2[proof_index_to_tweak] = [0u8; HASH_LEN as usize];
                        break;
                    }
                }

                assert_data_signatures = WotsSignatures::new(&self.msk, deposit_txid, assertions);
            }

            let signed_assert_data_txs = assert_data.finalize(
                connectors.assert_data_hash_factory,
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
            for input_index in 0..NUM_ASSERT_DATA_TX {
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
            let wait_time = Duration::from_secs(CONNECTOR_PARAMS.payout_timelock as u64);
            info!(action = "waiting for timeout period before seeking reimbursement", wait_time_secs=%wait_time.as_secs());
            tokio::time::sleep(wait_time).await;

            let deposit_signature = self
                .public_db
                .get_signature(own_index, payout_tx.compute_txid(), 0)
                .await
                .unwrap()
                .unwrap(); // FIXME: Handle me
            let n_of_n_sig_a3 = self
                .public_db
                .get_signature(
                    own_index,
                    payout_tx.compute_txid(),
                    ConnectorA3Leaf::Payout(None).get_input_index(),
                )
                .await
                .unwrap()
                .unwrap(); // FIXME:  Handle me

            let n_of_n_sig_c2 = self
                .public_db
                .get_signature(own_index, payout_tx.compute_txid(), 2)
                .await
                .unwrap()
                .unwrap(); // FIXME:
                           // Handle me

            let n_of_n_sig_p = self
                .public_db
                .get_signature(own_index, payout_tx.compute_txid(), 3)
                .await
                .unwrap()
                .unwrap(); // FIXME:
                           // Handle me

            let signed_payout_tx = payout_tx.finalize(
                deposit_signature,
                n_of_n_sig_a3,
                n_of_n_sig_c2,
                n_of_n_sig_p,
                connectors.post_assert_out_0,
                connectors.n_of_n,
                connectors.hashlock_payout,
            );

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
                    if matches!(err, ClientError::Server(-26, _)) {
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

    async fn broadcast_claim(
        &self,
        own_index: u32,
        deposit_txid: Txid,
        claim_tx: ClaimTx,
        stake_id: u32,
        status: &mut WithdrawalStatus,
    ) {
        if let Some(withdrawal_fulfillment_txid) = status.should_claim() {
            info!(action = "broadcasting required stake txs", %deposit_txid, %own_index);
            let _stake_tx = self
                .broadcast_stake_chain(self.build_context.network(), deposit_txid)
                .await;

            let claim_commitment = self.agent.generate_withdrawal_fulfillment_signature(
                &self.msk,
                stake_id,
                withdrawal_fulfillment_txid,
            );
            let claim_tx_with_commitment = claim_tx.finalize(*claim_commitment);

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
        deposit_txid: Txid,
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
            tag: PegOutGraphParams::default().tag.as_bytes().to_vec(),
            operator_idx: own_index,
            deposit_idx,
            deposit_txid,
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

        let mut height = l1_start_height as u32;
        let mut headers: Vec<Header> = vec![];
        let mut blocks: Vec<Block> = vec![];
        let mut withdrawal_fulfillment = None;
        let mut checkpoint = None;

        info!(action = "scanning blocks...", %deposit_txid, %withdrawal_fulfillment_txid, start_height=%height);
        let mut num_blocks_after_fulfillment = 0;
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
                            .is_some_and(|index| index == latest_checkpoint_at_payout)
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

            if withdrawal_fulfillment.is_some() {
                num_blocks_after_fulfillment += 1;
            }

            if num_blocks_after_fulfillment
                > REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX
            {
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
            info!(action = "dumping proof input data for testing", %deposit_txid, %withdrawal_fulfillment_txid);
            dump_proof_input_data(&chain_state, blocks, op_signature);
        }

        let pegout_graph_params = PegOutGraphParams::default();

        let input = BridgeProofInput {
            pegout_graph_params,
            rollup_params: self.rollup_params.clone(),
            headers,
            deposit_idx,
            strata_checkpoint_tx: checkpoint.expect("must be able to find checkpoint"),
            withdrawal_fulfillment_tx: withdrawal_fulfillment
                .expect("must be able to find withdrawal fulfillment tx"),
            op_signature,
        };

        let (proof, public_inputs, public_output) = prover::sp1_prove(&input).unwrap();

        if std::env::var(ENV_DUMP_TEST_DATA).is_ok() {
            info!(action = "dumping proof data for testing", %deposit_txid, %withdrawal_fulfillment_txid);

            let proof_file = File::create("proof.bin").unwrap();
            let public_inputs_file = File::create("public_inputs.bin").unwrap();
            proof.serialize_uncompressed(proof_file).unwrap();
            public_inputs[0]
                .serialize_uncompressed(public_inputs_file)
                .unwrap();
        }

        Assertions {
            withdrawal_fulfillment: public_output.withdrawal_fulfillment_txid.0,
            groth16: generate_assertions(
                proof,
                public_inputs.to_vec(),
                &bridge_vk::GROTH16_VERIFICATION_KEY,
            )
            .expect("must feed correct input proof"),
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

    async fn create_stake_chain(&self, stake_chain_length: u32) {
        let own_index = self.build_context.own_index();

        info!(action = "checking if stake chain data exists", %own_index);
        let pre_stake = self.public_db.get_pre_stake(own_index).await.unwrap();
        if pre_stake.is_some() {
            // FIXME: needs logic for the case where some intermediate values are missing.
            // for now, this just checks if the last one is present.
            info!(action = "pre-stake data present, checking for stake chain", %own_index);
            if self
                .public_db
                .get_stake_txid(own_index, stake_chain_length - 1)
                .await
                .unwrap()
                .is_some()
            {
                info!(action = "stake chain present, skipping rebuild", %own_index);

                return;
            }
        }

        let connector_cpfp = ConnectorCpfp::new(
            self.agent.public_key().x_only_public_key().0,
            self.build_context.network(),
        );
        let operator_pubkey = self.agent.public_key().x_only_public_key().0;
        let operator_address = self.agent.taproot_address(self.build_context.network());

        info!(action = "constructing pre-stake transaction", %own_index);
        let reserved_utxos = self.db.selected_outpoints().await.unwrap(); // FIXME: Handle me
        let (change_address, funding_input, total_amount, prev_utxo) = self
            .agent
            .select_utxo(OPERATOR_STAKE, reserved_utxos.clone())
            .await
            .unwrap();

        let utxos = vec![funding_input];
        let inputs = create_tx_ins(utxos);
        let scripts_and_amounts = vec![
            (operator_address.script_pubkey(), OPERATOR_STAKE),
            (
                change_address.script_pubkey(),
                total_amount - OPERATOR_STAKE - MIN_RELAY_FEE,
            ),
        ];
        let outputs = create_tx_outs(scripts_and_amounts);

        let pre_stake_tx = PreStakeTx::new(inputs, outputs, &prev_utxo);

        let signed_pre_stake = self
            .agent
            .btc_client
            .sign_raw_transaction_with_wallet(&pre_stake_tx.psbt.unsigned_tx, None)
            .await
            .unwrap();
        let signed_pre_stake =
            consensus::encode::deserialize_hex::<Transaction>(&signed_pre_stake.hex).unwrap();
        self.agent
            .btc_client
            .send_raw_transaction(&signed_pre_stake)
            .await
            .unwrap();
        info!(event = "broadcasted pre-stake tx", %own_index, txid=%signed_pre_stake.compute_txid());

        info!(action = "creating funding transaction", %own_index);
        let (change_address, funding_input, total_amount, ..) = self
            .agent
            .select_utxo(
                OPERATOR_FUNDS
                    .checked_mul(stake_chain_length as u64)
                    .unwrap(),
                reserved_utxos,
            )
            .await
            .unwrap();
        let utxos = [funding_input];
        let tx_ins = create_tx_ins(utxos);
        let scripts_and_amounts =
            (0..stake_chain_length).map(|_| (operator_address.script_pubkey(), OPERATOR_FUNDS));
        let mut tx_outs = create_tx_outs(scripts_and_amounts);
        tx_outs.push(TxOut {
            script_pubkey: change_address.script_pubkey(),
            value: total_amount - OPERATOR_FUNDS * stake_chain_length as u64 - MIN_RELAY_FEE,
        });

        let funding_tx = create_tx(tx_ins, tx_outs);
        let signed_funding_tx = self
            .agent
            .btc_client
            .sign_raw_transaction_with_wallet(&funding_tx, None)
            .await
            .unwrap();
        let signed_funding_tx =
            consensus::encode::deserialize_hex::<Transaction>(&signed_funding_tx.hex).unwrap();
        self.agent
            .btc_client
            .send_raw_transaction(&signed_funding_tx)
            .await
            .unwrap();

        info!(event = "broadcasted funding transaction", %own_index, txid=%signed_funding_tx.compute_txid());

        let funding_txid = signed_funding_tx.compute_txid();
        let pre_stake_txid = pre_stake_tx.compute_txid();

        let pre_stake_outpoint = OutPoint {
            txid: pre_stake_txid,
            vout: 0,
        };
        self.public_db
            .set_pre_stake(own_index, pre_stake_outpoint)
            .await
            .unwrap();

        if self
            .public_db
            .get_stake_txid(own_index, stake_chain_length - 1)
            .await
            .unwrap()
            .is_some()
        {
            info!(action = "stake chain present, skipping rebuild", %own_index);
            return;
        }

        info!(action = "creating stake chain", length = %stake_chain_length, %own_index);

        let mut stake_inputs: BTreeMap<u32, StakeTxData> = BTreeMap::new();
        for i in 0..stake_chain_length {
            let preimage = self.agent.generate_preimage(&self.msk, i);
            let hash = hashes::sha256::Hash::hash(&preimage);

            let withdrawal_fulfillment_pk =
                self.agent.generate_withdrawal_fulfillment_pk(&self.msk, i);

            let stake_tx_data = StakeTxData {
                operator_funds: OutPoint {
                    txid: funding_txid,
                    vout: i,
                },
                hash,
                withdrawal_fulfillment_pk,
            };

            info!(action = "adding stake data to db", %own_index, index = %i);
            self.public_db
                .add_stake_data(own_index, i, stake_tx_data.clone())
                .await
                .unwrap();

            stake_inputs.insert(i, stake_tx_data);
        }

        let stake_chain_params = StakeChainParams::default();
        let stake_chain_inputs = StakeChainInputs {
            operator_pubkey,
            stake_inputs,
            pre_stake_outpoint,
        };

        let stake_chain = StakeChain::new(
            &self.build_context,
            &stake_chain_inputs,
            &stake_chain_params,
            connector_cpfp,
        );

        let stake_chain_head = stake_chain.head();
        self.public_db
            .add_stake_txid(own_index, stake_chain_head.unwrap().compute_txid())
            .await
            .unwrap();

        for (index, stake_txid) in stake_chain
            .tail()
            .iter()
            .map(|stake_tx| stake_tx.compute_txid())
            .enumerate()
        {
            info!(event = "adding stake txid to db", %own_index, %stake_txid, %index);
            self.public_db
                .add_stake_txid(own_index, stake_txid)
                .await
                .unwrap()
        }
    }

    /// Broadcasts the required stake transactions and returns the stake transaction
    /// corresponding to the deposit txid that can be spent by the claim transaction.
    async fn broadcast_stake_chain(&self, network: Network, deposit_txid: Txid) -> Transaction {
        let own_index = self.build_context.own_index();
        info!(action = "retrieving stake id from db", %own_index, %deposit_txid);
        let stake_id = self
            .public_db
            .get_deposit_id(deposit_txid)
            .await
            .unwrap()
            .unwrap(); // FIXME: Handle
                       // me

        info!(action = "retrieving pre-stake from db", %own_index, %deposit_txid, %stake_id);
        let pre_stake = self
            .public_db
            .get_pre_stake(own_index)
            .await
            .unwrap()
            .unwrap(); // FIXME: Handle
                       // me

        let n_of_n_agg_pubkey = self.build_context.aggregated_pubkey();
        let operator_pubkey = self.agent.public_key().x_only_public_key().0;

        let num_stake_txs = stake_id as usize + 1;
        let mut stake_inputs = BTreeMap::new();
        for i in 0..num_stake_txs {
            let stake_data = self
                .public_db
                .get_stake_data(own_index, i as u32)
                .await
                .unwrap()
                .unwrap(); // FIXME:
                           // Handle me

            stake_inputs.insert(i as u32, stake_data);
        }

        let params = StakeChainParams::default();
        let operator_untweaked_address =
            Address::p2tr_tweaked(operator_pubkey.dangerous_assume_tweaked(), network);
        let pre_stake_address = operator_untweaked_address.clone();
        let stake_chain_inputs = StakeChainInputs {
            operator_pubkey,
            pre_stake_outpoint: pre_stake,
            stake_inputs: stake_inputs.clone(),
        };

        let connector_cpfp = ConnectorCpfp::new(operator_pubkey, self.build_context.network());
        let funding_address = operator_untweaked_address.clone();
        let stake_chain = StakeChain::new(
            &self.build_context,
            &stake_chain_inputs,
            &params,
            connector_cpfp,
        );

        // Broadcast all stake transactions.
        // This is a dumb approach in that it does not check if a stake transaction was previously
        // broadcasted.
        // FIXME: use `getrawtransaction` to check if a transaction is broadcasted and also how long
        // to wait before broadcasting the next one.

        // first, broadcast the first stake transaction.
        let first_stake_tx = stake_chain.head().unwrap().clone();
        let prevouts = vec![
            TxOut {
                script_pubkey: funding_address.script_pubkey(),
                value: OPERATOR_FUNDS,
            },
            TxOut {
                script_pubkey: pre_stake_address.script_pubkey(),
                value: OPERATOR_STAKE,
            },
        ];
        let first_stake_raw_tx = first_stake_tx.psbt.unsigned_tx.clone();
        let first_funds_sig = self
            .agent
            .sign(&first_stake_raw_tx, &prevouts, 0, None, None);
        let first_stake_sig = self
            .agent
            .sign(&first_stake_raw_tx, &prevouts, 1, None, None);

        let mut signed_stake_tx =
            first_stake_tx.finalize_unchecked(first_funds_sig, first_stake_sig);

        let mut stake_txid = signed_stake_tx.compute_txid();
        let vsize = signed_stake_tx.vsize();
        let weight = signed_stake_tx.weight();
        match self
            .agent
            .btc_client
            .send_raw_transaction(&signed_stake_tx)
            .await
        {
            Ok(txid) => {
                info!(event = "broadcasted first stake tx", %txid, %own_index);
            }
            Err(e) if matches!(e, ClientError::Server(-25, _)) => {
                warn!(event = "stake tx already broadcasted", stake_index = 0, %e, %vsize, %weight, %stake_txid, %own_index);
            }
            Err(e) => {
                unreachable!(
                    "operator {own_index} must be able to broadcast first stake tx but encountered: {}",
                    e
                );
            }
        };

        for (stake_index, stake_tx) in stake_chain.tail().iter().cloned().enumerate() {
            let prevouts = stake_tx
                .psbt
                .inputs
                .iter()
                .filter_map(|input| input.witness_utxo.clone())
                .collect::<Vec<_>>();

            let raw_tx = &stake_tx.psbt.unsigned_tx;
            let funds_sig =
                self.agent
                    .sign(raw_tx, &prevouts, 0, Some(&stake_tx.witnesses()[0]), None);
            let stake_sig =
                self.agent
                    .sign(raw_tx, &prevouts, 1, Some(&stake_tx.witnesses()[1]), None);
            let prev_preimage = self.agent.generate_preimage(&self.msk, stake_index as u32);
            let computed_hash = hashes::sha256::Hash::hash(&prev_preimage);
            let prev_stake_hash = stake_inputs
                .get(&(stake_index as u32))
                .map(|stake_input| stake_input.hash)
                .unwrap();
            assert!(
                computed_hash == prev_stake_hash,
                "stake hash in db must match hash of computed preimage"
            );

            let prev_connector_s = ConnectorStake::new(
                n_of_n_agg_pubkey,
                operator_pubkey,
                prev_stake_hash,
                params.delta,
                self.build_context.network(),
            );

            signed_stake_tx =
                stake_tx.finalize_unchecked(&prev_preimage, funds_sig, stake_sig, prev_connector_s);
            stake_txid = signed_stake_tx.compute_txid();

            let vsize = signed_stake_tx.vsize();
            let weight = signed_stake_tx.weight();

            let slack = 2;
            let timelock = Duration::from_secs(params.delta.to_consensus_u32() as u64 + slack);
            match self
                .agent
                .wait_and_broadcast(&signed_stake_tx, timelock)
                .await
            {
                Ok(txid) => {
                    info!(event = "broadcasted stake tx", %txid, %stake_index, %vsize, %weight, %own_index);
                }
                Err(e) if matches!(e, ClientError::Server(-25, _)) => {
                    warn!(event = "stake tx already broadcasted", %stake_index, %e, %vsize, %weight, %stake_txid, %own_index);
                }
                Err(e) => {
                    unreachable!(
                        "operator {own_index} must be able to broadcast stake tx {stake_index} but encountered {}",
                        e,
                    );
                }
            }
        }

        signed_stake_tx
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

    let op_signature_file = "op_signature.bin";
    let mut file = File::create(op_signature_file).unwrap();
    let data = op_signature.as_slice();
    file.write_all(data)
        .expect("must be able to write op_signature to file");
    info!(event = "dumped op_signature to file", filename = %op_signature_file);
}
