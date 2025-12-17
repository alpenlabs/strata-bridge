//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    future, mem,
    sync::Arc,
    time::{Duration, Instant},
    vec,
};

use algebra::retry::{retry_with, Strategy};
use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{hashes::Hash, Address, Block, Network, OutPoint, ScriptBuf, Transaction, Txid};
use bitcoind_async_client::{client::Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::{
    client::{BlockFetcher, BtcNotifyClient},
    event::BlockStatus,
    tx_driver::TxDriver,
};
use futures::{future::join_all, SinkExt, StreamExt};
use libp2p_identity::secp256k1::Keypair;
use operator_wallet::OperatorWallet;
use p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use p2p_wire::p2p::v1::{
    ArchivedGetMessageRequest, ArchivedGossipsubMsg, GetMessageRequest, GossipsubMsg,
    UnsignedGossipsubMsg,
};
use secret_service_client::SecretServiceClient;
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_tx_graph::transactions::{
    deposit::DepositTx,
    prelude::{AssertDataTxInput, CovenantTx},
};
use strata_bridge_types::DepositState;
use strata_ol_chainstate_types::Chainstate;
use strata_p2p::{
    self,
    commands::{GossipCommand, RequestResponseCommand},
    events::{GossipEvent, ReqRespEvent},
    swarm::handle::{GossipHandle, ReqRespHandle},
};
use strata_params::RollupParams;
use tokio::{
    select,
    sync::{mpsc, oneshot, RwLock},
    task::{self, JoinHandle},
    time,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    contract_persister::ContractPersister,
    contract_state_machine::{
        ContractCfg, ContractEvent, ContractSM, ContractState, DepositSetup, FulfillerDuty,
        OperatorDuty, TransitionErr,
    },
    errors::{ContractManagerErr, StakeChainErr},
    executors::{config::StakeTxRetryConfig, prelude::*},
    predicates::{deposit_request_info, parse_strata_checkpoint},
    shutdown::ExecutionState,
    stake_chain_persister::StakeChainPersister,
    stake_chain_state_machine::StakeChainSM,
};

/// System that handles all of the chain and p2p events and forwards them to their respective
/// [`ContractSM`]s.
#[derive(Debug)]
pub struct ContractManager {
    /// Handle to the task that runs the contract manager event loop.
    ///
    /// NOTE: it holds a [`ContractManagerErr`] since the event loop exiting is an error.
    pub thread_handle: JoinHandle<ContractManagerErr>,

    /// Channel sender for initiating shutdown and extracting the execution state.
    shutdown_sender: Option<oneshot::Sender<oneshot::Sender<ExecutionState>>>,
}

impl ContractManager {
    /// Initializes the ContractManager with the appropriate external event feeds and data stores.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        // Static Config Parameters
        network: Network,
        keypair: Keypair,
        nag_interval: Duration,
        connector_params: ConnectorParams,
        pegout_graph_params: PegOutGraphParams,
        stake_chain_params: StakeChainParams,
        sidesystem_params: RollupParams,
        operator_table: OperatorTable,
        is_faulty: bool,
        min_withdrawal_fulfillment_window: u64,
        stake_funding_pool_size: usize,
        stake_tx_retry_config: StakeTxRetryConfig,
        // Genesis information
        pre_stake_pubkey: ScriptBuf,
        // Subsystem Handles
        zmq_client: BtcNotifyClient,
        rpc_client: BitcoinClient,
        mut gossip_handle: GossipHandle,
        mut req_resp_handle: ReqRespHandle,
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
        s2_client: SecretServiceClient,
        wallet: OperatorWallet,
        db: SqliteDb,
    ) -> ContractManager {
        let (shutdown_sender, shutdown_receiver) =
            oneshot::channel::<oneshot::Sender<ExecutionState>>();

        let thread_handle = task::spawn(async move {
            let mut shutdown_receiver = Some(shutdown_receiver);

            info!("loading all active contracts");

            let active_contracts = match contract_persister
                .load_all(
                    network,
                    connector_params,
                    pegout_graph_params,
                    sidesystem_params.clone(),
                    stake_chain_params,
                )
                .await
            {
                Ok(contract_data) => contract_data
                    .into_iter()
                    .map(|(cfg, state)| {
                        (
                            cfg.deposit_tx.compute_txid(),
                            ContractSM::restore(cfg, state),
                        )
                    })
                    .collect::<BTreeMap<Txid, ContractSM>>(),
                Err(e) => {
                    error!(?e, "failed to load active contracts, crashing");
                    return e.into();
                }
            };
            debug!(num_contracts=%active_contracts.len(), "loaded all active contracts");

            let funding_address =
                Address::from_script(wallet.stakechain_script_buf(), network.params())
                    .expect("funding locking script must be valid for supplied network");

            let stake_chains = match stake_chain_persister.load(&operator_table).await {
                Ok(stake_chains) => {
                    match StakeChainSM::restore(
                        network,
                        operator_table.clone(),
                        stake_chain_params,
                        stake_chains,
                    ) {
                        Ok(stake_chains) => stake_chains,
                        Err(e) => {
                            error!(?e, "failed to load stake chains, crashing");
                            return ContractManagerErr::StakeChainErr(e);
                        }
                    }
                }
                Err(e) => {
                    error!(?e, "failed to load stake chain persister, crashing");
                    return e.into();
                }
            };
            debug!("restored stake chain data");

            let current = match rpc_client.get_block_count().await {
                Ok(a) => a - (zmq_client.bury_depth() as u64),
                Err(e) => {
                    error!(?e, "failed to get block count, crashing");
                    return e.into();
                }
            };

            // It's extremely unlikely that these will ever differ at all but it's possible for
            // them to differ by at most 1 in the scenario where we crash mid-batch when committing
            // contract state to disk.
            //
            // We take the minimum height that any state machine has observed since we want to
            // re-feed chain events that they might have missed. We then start processing from the
            // next block.
            let cursor = active_contracts
                .values()
                .min_by(|sm1, sm2| sm1.state().block_height.cmp(&sm2.state().block_height))
                .map(|sm| sm.state().block_height + 1) // start from the next block
                .unwrap_or(current);

            let fetcher = BtcFetcher(rpc_client.clone());
            info!(%cursor, %current, "establishing zmq client connection");
            let zmq_client = zmq_client
                .connect(cursor, fetcher)
                .await
                .expect("must be able to connect to bitcoind's zmq interface");

            let mut block_sub = zmq_client.subscribe_blocks().await;
            let tx_driver = TxDriver::new(zmq_client, rpc_client.clone()).await;

            let cfg = Arc::new(ExecutionConfig {
                network,
                connector_params,
                pegout_graph_params,
                stake_chain_params,
                sidesystem_params,
                operator_table,
                stake_tx_retry_config,
                pre_stake_pubkey: pre_stake_pubkey.clone(),
                funding_address: funding_address.clone(),
                is_faulty,
                min_withdrawal_fulfillment_window,
                stake_funding_pool_size,
            });

            // TODO: (@Rajil1213) at this point, it may or may not be necessary to make this
            // configurable. When this capacity is reached, messages will be dropped (although the
            // documentation on broadcast::channel says that the actual capacity may be higher).
            // This will only happen if this node as well as other event sources generate far too
            // many events.
            let (ouroboros_msg_sender, mut ouroboros_msg_receiver) = mpsc::unbounded_channel();
            let (ouroboros_req_sender, mut ouroboros_req_receiver) = mpsc::unbounded_channel();

            let msg_handler = MessageHandler::new(ouroboros_msg_sender, ouroboros_req_sender);

            let output_handles = Arc::new(OutputHandles {
                wallet: RwLock::new(wallet),
                msg_handler,
                bitcoind_rpc_client: rpc_client.clone(),
                s2_client,
                tx_driver,
                db,
            });

            let state_handles = StateHandles {
                contract_persister,
                stake_chain_persister,
            };

            let claim_txids = active_contracts
                .iter()
                .flat_map(|(deposit_txid, csm)| {
                    csm.claim_txids()
                        .into_iter()
                        .map(|claim_txid| (claim_txid, *deposit_txid))
                })
                .collect();

            let state = ExecutionState {
                active_contracts,
                claim_txids,
                stake_chains,
                operator_table: cfg.operator_table.clone(),
            };
            let mut ctx = ContractManagerCtx {
                cfg: cfg.clone(),
                state,
                state_handles,
            };

            let mut interval = time::interval(nag_interval);
            // skip any missed ticks to avoid flooding the network with duplicate nag messages
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                let mut duties = vec![];
                select! {
                    biased; // follow the same order as specified below

                    // First, we prioritize the ouroboros channel since processing our own message is
                    // necessary for having consistent state.
                    ouroboros_msg = ouroboros_msg_receiver.recv() => match ouroboros_msg {
                        Some(msg) => {
                            match ctx.process_unsigned_gossip_msg(
                                msg.publish.clone().into(),
                                cfg.operator_table.pov_p2p_key().clone(),
                                cfg.operator_table.pov_idx()
                            ).await {
                                Ok(ouroboros_duties) => {
                                    if !ouroboros_duties.is_empty() {
                                        info!(num_duties=ouroboros_duties.len(), "queueing duties generated via ouroboros");
                                        for duty in ouroboros_duties.iter() {
                                            trace!(?duty, "received ouroboros message duty");
                                        }

                                        duties.extend(ouroboros_duties);
                                    }

                                    // If peer is specified, then send only to that peer. Otherwise
                                    // broadcast the message.
                                    if let Some(peer) = msg.peer {
                                        let msg = UnsignedGossipsubMsg::from(msg.publish);
                                        let data = msg.content();
                                        if peer.send(data).is_err() {
                                            error!("failed to send ouroboros message to peer");
                                        }
                                        continue;
                                    }

                                    // If we successfully handle the processing of our message, we
                                    // can forward it to the rest of the p2p network.
                                    let signed = msg.publish.sign_secp256k1(&keypair);
                                    let msg = GossipsubMsg::from(signed);
                                    let mut data = Vec::new();
                                    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
                                        .expect("must be able to serialize message");
                                    if let Err(e) = gossip_handle.send(GossipCommand { data }).await {
                                        error!(%e, "failed to forward ouroboros message to gossip handler");
                                    }
                                }
                                Err(e) => {
                                    error!(%e, "CRITICAL: failed to process ouroboros message");
                                    // NOTE: (@Rajil1213) Generally speaking, not being able to
                                    // process self-published messages is indicative of deeper
                                    // issues in the system as a node should always publish valid
                                    // messages. However, there is a case where this is not strictly
                                    // true. Consider the following:
                                    //
                                    // A node processes and persists a new contract (say, index 10) and then crashes
                                    // without having created the `DepositSetup` message (aka the
                                    // `StakeTxData`). While it is down, another deposit request comes
                                    // in (index 11). When processing the lagged blocks, the node
                                    // will first create the duty to publish the `DepositSetup`
                                    // for index 11. This means that the node will create and
                                    // publish the `DepositSetup` message which gets sent via
                                    // ouroboros. At this point, we fail to process the
                                    // `DepositSetup` message because the stake chain is broken
                                    // (i.e., the stake data for index 10 does not exist but it does
                                    // for index 11).
                                    //
                                    // If we were to panic here, the node would never be able to
                                    // progress beyond this point. But if we let things run their
                                    // course, the node will eventually create the `DepositSetup`
                                    // message (via the self-nagging mechanism) and things should
                                    // eventually stabilize. Therefore, we do not return the error when we
                                    // fail to process an ouroboros message.
                                }
                            }
                        },
                        None => {
                            error!("ouroboros stream closed");
                            return ContractManagerErr::FatalErr("ouroboros stream closed".to_string());
                        },
                    },

                    // And similarly, prioritize nags next
                    ouroboros_req = ouroboros_req_receiver.recv() => match ouroboros_req {
                        Some(req) => {
                            if req.operator_pubkey() == cfg.operator_table.pov_p2p_key() {
                                // Peel off requests that were directed at ourselves.
                                match ctx.process_p2p_request(req.clone(), None).await {
                                    Ok(p2p_req_duties) => {
                                        duties.extend(p2p_req_duties);
                                    },
                                    Err(e) => {
                                        error!(?req, %e, "failed to process p2p request");
                                        // in case an error occurs, we will just nag again
                                        // so no need to break out of the event loop
                                    }
                                }
                            } else {
                                // If it wasn't meant for us we can forward the request to the p2p
                                // network
                                let mut data = Vec::new();
                                rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&req, &mut data)
                                    .expect("must be able to serialize request message");
                                if let Err(e) = req_resp_handle.send(RequestResponseCommand {
                                    target_transport_id: req.peer_id(),
                                    data,
                                }).await {
                                    error!(%e, "failed to forward ouroboros p2p request to req/resp handler");
                                }
                            }
                        },
                        None => {
                            error!("ouroboros request stream closed");
                            return ContractManagerErr::FatalErr("ouroboros request stream closed".to_string());
                        }
                    },

                    // Next, we handle shutdown signal.
                    state_sender = async {
                        match shutdown_receiver.as_mut() {
                            Some(receiver) => receiver.await,
                            None => future::pending().await, // Never resolves if already consumed
                        }
                    } => {
                        shutdown_receiver = None; // Consume the receiver
                        if let Ok(state_sender) = state_sender {
                            info!("shutdown signal received, extracting execution state");

                            // Move the state out since we're shutting down
                            let shutdown_state = ExecutionState {
                                active_contracts: mem::take(&mut ctx.state.active_contracts),
                                claim_txids: mem::take(&mut ctx.state.claim_txids),
                                stake_chains: mem::replace(&mut ctx.state.stake_chains, {
                                    // Create a minimal replacement since we're shutting down
                                    StakeChainSM::new(cfg.network, cfg.operator_table.clone(), cfg.stake_chain_params)
                                }),
                                operator_table: cfg.operator_table.clone(),
                            };

                            if state_sender.send(shutdown_state).is_err() {
                                error!("failed to send execution state during shutdown");
                            }
                            info!("contract manager event loop exited due to shutdown");
                            return ContractManagerErr::FatalErr("contract manager event loop exited due to shutdown".to_string());
                        }
                    },

                    // Then prioritize processing the backlog of chain state.
                    Some(block_event) = block_sub.next() => {
                        if block_event.status != BlockStatus::Buried {
                            continue;
                        }

                        let blockhash = block_event.block.block_hash();
                        let block_height = block_event.block.bip34_block_height().expect("block header version will always be >= 2");
                        info!(%block_height, %blockhash, "processing block");

                        let num_blocks_remaining = block_sub.backlog();
                        debug!(%num_blocks_remaining);

                        match ctx.process_block(block_event.block).await {
                            Ok(block_duties) if !block_duties.is_empty() => {
                                let num_duties = block_duties.len();
                                info!(%blockhash, %block_height, %num_duties, "queueing duties generated by the block event for execution");
                                duties.extend(block_duties);
                            },
                            Ok(_) => {},
                            Err(e) => {
                                error!(%blockhash, %block_height, ?e, "failed to process block");
                                return e;
                            }
                        }
                    },

                    // Finally, we process peer messages. We do this last so we have the best chance of
                    // servicing peer requests and can sidestep the processing of unnecessary peer
                    // messages.
                    Ok(GossipEvent::ReceivedMessage(raw_msg)) = gossip_handle.next_event() => {
                        let archived_msg  = match rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg) {
                            Ok(msg) => msg,
                            Err(e) => {
                                error!(%e, "failed to access archived p2p msg");
                                continue;
                            }
                        };
                        match rkyv::deserialize::<_, rkyv::rancor::Error>(archived_msg) {
                            Ok(msg) => {
                                match ctx.process_p2p_message(msg.clone()).await {
                                    Ok(msg_duties) if !msg_duties.is_empty() => {
                                        duties.extend(msg_duties);
                                    },
                                    Ok(_) => {},
                                    Err(e) => {
                                        error!(?msg, %e, "failed to process p2p msg");
                                        // in case an error occurs, we will just nag again
                                        // so no need to break out of the event loop
                                    }
                                }
                            }
                            Err(e) => {
                                error!(%e, "failed to decode p2p msg");
                            }
                        }
                    },

                    Some(ReqRespEvent::ReceivedRequest(raw_req, peer)) = req_resp_handle.next_event() => {
                        let archived = match rkyv::access::<ArchivedGetMessageRequest, rkyv::rancor::Error>(&raw_req) {
                            Ok(req) => req,
                            Err(e) => {
                                error!(%e, "failed to access archived p2p request");
                                continue;
                            }
                        };
                        match rkyv::deserialize::<_, rkyv::rancor::Error>(archived) {
                            Ok(req) => {
                                match ctx.process_p2p_request(req.clone(), Some(peer)).await {
                                    Ok(p2p_duties) => duties.extend(p2p_duties),
                                    Err(e) => {
                                        error!(?req, %e, "failed to process p2p request");
                                        // in case an error occurs, the requester will just nag again
                                        // so no need to break out of the event loop
                                    },
                                }
                            }
                            Err(e) => {
                                error!(%e, "failed to decode p2p request");
                            }
                        }
                    },

                    _instant = interval.tick() => {
                        debug!("nagging peers for necessary p2p messages");

                        let nags = ctx.nag().into_iter().map(|nag| {
                            let output_handles = output_handles.clone();
                            async move {
                                let msg_handler = &output_handles.msg_handler;

                                match nag {
                                    GetMessageRequest::StakeChainExchange { stake_chain_id, operator_pk } => msg_handler.request_stake_chain_exchange(stake_chain_id, operator_pk).await,
                                    GetMessageRequest::DepositSetup { scope, operator_pk } => msg_handler.request_deposit_setup(scope, operator_pk).await,
                                    GetMessageRequest::Musig2NoncesExchange { session_id, operator_pk } => msg_handler.request_musig2_nonces(session_id, operator_pk).await,
                                    GetMessageRequest::Musig2SignaturesExchange { session_id, operator_pk } => msg_handler.request_musig2_signatures(session_id, operator_pk).await,
                                }
                            }
                        });

                        join_all(nags).await;
                    }
                }

                for duty in duties {
                    debug!(%duty, "starting duty execution from new events");

                    let cfg = ctx.cfg.clone();
                    let output_handles = output_handles.clone();
                    let duty_str = duty.to_string();
                    if let Err(e) = execute_duty(cfg, output_handles, duty).await {
                        error!(%e, duty=duty_str, "failed to execute duty");
                    }
                }
            }

            #[allow(
                unreachable_code,
                reason = "Failsafe mechanism so that the event loop never exits without an error!"
            )]
            ContractManagerErr::FatalErr(
                "contract manager event loop exited unexpectedly".to_string(),
            )
        });

        ContractManager {
            thread_handle,
            shutdown_sender: Some(shutdown_sender),
        }
    }

    /// Initiates graceful shutdown and extracts the [`ExecutionState`].
    pub async fn shutdown_and_extract_state(
        mut self,
    ) -> Result<ExecutionState, ContractManagerErr> {
        let (state_sender, state_receiver) = oneshot::channel();

        let shutdown_sender = self.shutdown_sender.take().ok_or_else(|| {
            ContractManagerErr::FatalErr("ContractManager shutdown already initiated".to_string())
        })?;

        if shutdown_sender.send(state_sender).is_err() {
            return Err(ContractManagerErr::FatalErr(
                "Failed to send shutdown signal to contract manager".to_string(),
            ));
        }

        match state_receiver.await {
            Ok(execution_state) => Ok(execution_state),
            Err(_) => Err(ContractManagerErr::FatalErr(
                "Failed to receive execution state from contract manager".to_string(),
            )),
        }
    }
}

impl Drop for ContractManager {
    fn drop(&mut self) {
        self.thread_handle.abort();
    }
}

#[derive(Debug)]
struct BtcFetcher(BitcoinClient);

#[async_trait::async_trait]
impl BlockFetcher for BtcFetcher {
    type Error = ClientError;

    async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
        // TODO: (@Rajil1213) make these configurable
        const MAX_RETRIES: usize = 10;
        const INITIAL_DELAY: Duration = Duration::from_secs(1);
        const MAX_DELAY: Duration = Duration::from_secs(60);
        const MULTIPLIER: f64 = 2.0;

        let retry_strategy = Strategy::exponential_backoff(INITIAL_DELAY, MAX_DELAY, MULTIPLIER)
            .with_max_retries(MAX_RETRIES);

        let client = self.0.clone();
        retry_with(retry_strategy, move || {
            let client = client.clone();
            async move { client.get_block_at(height).await }
        })
        .await
    }
}

/// The handles required by the duty tracker to execute duties.
pub(super) struct OutputHandles {
    /// [`OperatorWallet`] handle.
    pub(super) wallet: RwLock<OperatorWallet>,

    /// [`MessageHandler`] handle.
    pub(super) msg_handler: MessageHandler,

    /// [`BitcoinClient`] handle.
    pub(super) bitcoind_rpc_client: BitcoinClient,

    pub(super) s2_client: SecretServiceClient,

    pub(super) tx_driver: TxDriver,

    /// Database [`SqliteDb`] handle.
    pub(super) db: SqliteDb,
}

/// The proxy for the state being tracked by the [`ContractManager`].
#[derive(Debug)]
pub(super) struct StateHandles {
    /// [`ContractPersister`] handle.
    pub(super) contract_persister: ContractPersister,

    /// [`StakeChainPersister`] handle.
    pub(super) stake_chain_persister: StakeChainPersister,
}

/// The parameters that all duty executions depend upon.
#[derive(Debug, Clone)]
pub(super) struct ExecutionConfig {
    pub(super) network: Network,
    pub(super) connector_params: ConnectorParams,
    pub(super) pegout_graph_params: PegOutGraphParams,
    pub(super) stake_chain_params: StakeChainParams,
    pub(super) sidesystem_params: RollupParams,
    pub(super) operator_table: OperatorTable,
    pub(super) stake_tx_retry_config: StakeTxRetryConfig,
    pub(super) pre_stake_pubkey: ScriptBuf,
    pub(super) funding_address: Address,
    pub(super) is_faulty: bool,
    pub(super) min_withdrawal_fulfillment_window: u64,
    pub(super) stake_funding_pool_size: usize,
}

/// The contract manager context.
struct ContractManagerCtx {
    /// The parameters that all duty executions depend upon.
    cfg: Arc<ExecutionConfig>,

    /// The proxy for the state being tracked by the [`ContractManager`].
    state_handles: StateHandles,

    /// The actual state that is being tracked by the [`ContractManager`].
    state: ExecutionState,
}

impl ContractManagerCtx {
    async fn process_block(
        &mut self,
        block: Block,
    ) -> Result<Vec<OperatorDuty>, ContractManagerErr> {
        let block_process_start_time = Instant::now();
        let height = block.bip34_block_height().unwrap_or(0);
        // TODO(proofofkeags): persist entire block worth of states at once. Ensure all the state
        // transitions succeed before committing them to disk.
        let mut duties = Vec::new();

        // this is to aggregate and commit new contracts separately so that the block event that
        // advances the cursor does not advance the cursor on the newly created contracts.
        let mut new_contracts = Vec::new();

        let pov_key = self.cfg.operator_table.pov_p2p_key().clone();
        // The next contract will have its index at a value that is 1 more than the max deposit
        // index that has already been processed.
        let deposit_idx_offset = self
            .state
            .active_contracts
            .values()
            .map(|contract| contract.deposit_idx())
            .max()
            .map(|max_index| max_index + 1)
            .unwrap_or(0);

        for tx in block.txdata {
            let txid = tx.compute_txid();

            let tx_process_start_time = Instant::now();
            // could be an assignment
            let assignment_duties = self.process_assignments(&tx).await?;
            if !assignment_duties.is_empty() {
                info!(num_duties=%assignment_duties.len(), "queueing assignment duties");
                duties.extend(assignment_duties);
                trace!(time_taken=?tx_process_start_time.elapsed(), "processed assignments for {txid}");

                // It's impossible for a transaction to contain assignments and otherwise have any
                // effect on existing or new contracts, so we move on.
                continue;
            }

            let deposit_idx = deposit_idx_offset + new_contracts.len() as u32;

            // or a deposit request
            if let Some(deposit_request_data) = deposit_request_info(
                &tx,
                &self.cfg.sidesystem_params,
                &self.cfg.pegout_graph_params,
                &self.cfg.operator_table.tx_build_context(self.cfg.network),
                deposit_idx,
            ) {
                let deposit_request_txid = txid;
                let deposit_tx = match DepositTx::new(
                    &deposit_request_data,
                    &self.cfg.operator_table.tx_build_context(self.cfg.network),
                    &self.cfg.pegout_graph_params,
                    &self.cfg.sidesystem_params,
                ) {
                    Ok(tx) => tx,
                    Err(err) => {
                        error!(
                            ?deposit_request_data,
                            %err,
                            "invalid metadata supplied in deposit request"
                        );
                        continue;
                    }
                };

                let deposit_txid = deposit_tx.compute_txid();
                if self.state.active_contracts.contains_key(&deposit_txid) {
                    // We already processed this. Do not create another contract attached to this
                    // deposit txid.
                    continue;
                }

                let stake_chain_inputs = self
                    .state
                    .stake_chains
                    .state()
                    .get(&pov_key)
                    .expect("this operator's p2p key must exist in the operator table")
                    .clone();

                debug!(%deposit_idx, %deposit_request_txid, "creating new contract");
                let cfg = ContractCfg {
                    network: self.cfg.network,
                    operator_table: self.cfg.operator_table.clone(),
                    connector_params: self.cfg.connector_params,
                    peg_out_graph_params: self.cfg.pegout_graph_params,
                    sidesystem_params: self.cfg.sidesystem_params.clone(),
                    stake_chain_params: self.cfg.stake_chain_params,
                    deposit_idx,
                    deposit_tx,
                };

                let duty = OperatorDuty::PublishDepositSetup {
                    deposit_txid: cfg.deposit_tx.compute_txid(),
                    deposit_idx: cfg.deposit_idx,
                    stake_chain_inputs,
                    peer: None,
                };

                let sm = ContractSM::new(
                    cfg,
                    height,
                    height + self.cfg.pegout_graph_params.refund_delay as u64,
                );

                new_contracts.push(sm);
                duties.push(duty);
                trace!(time_taken=?tx_process_start_time.elapsed(), "processed {txid} as DRT");

                // It's impossible for this transaction to be routable to another CSM so we move on
                continue;
            }

            // or a deposit
            if let Some(contract) = self.state.active_contracts.get_mut(&txid) {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                match contract.process_contract_event(ContractEvent::DepositConfirmation(tx)) {
                    Ok(new_duties) => duties.extend(new_duties),
                    Err(e) => error!(%e, "failed to process deposit confirmation"),
                }
                trace!(time_taken=?tx_process_start_time.elapsed(), "processed {txid} as DT");

                continue;
            }

            // or one of the pegout graph confirmations
            for (_deposit_txid, contract) in self.state.active_contracts.iter_mut() {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                if contract.transaction_filter(&tx) {
                    match contract.process_contract_event(ContractEvent::PegOutGraphConfirmation(
                        tx.clone(),
                        height,
                    )) {
                        Ok(new_duties) => duties.extend(new_duties),
                        Err(e) => {
                            error!(%e, "failed to process pegout graph confirmation");
                            return Err(e)?;
                        }
                    }
                    trace!(time_taken=?tx_process_start_time.elapsed(), "processed {txid} as POG tx confirmation");
                }
            }
        }
        trace!(%height, time_taken=?block_process_start_time.elapsed(), "processed all transaction-level contract events for block");

        // Now that we've handled all the transaction level events, we should inform all the
        // CSMs that a new block has arrived
        for (_, contract) in self.state.active_contracts.iter_mut() {
            duties.extend(contract.process_contract_event(ContractEvent::Block(height))?)
        }

        let num_active_contracts = self.state.active_contracts.len();
        let num_new_contracts = new_contracts.len();

        // Now that we've processed all the events related to the old contracts and dispatched the
        // corresponding events to them, we can add the new contracts which will receive relevant
        // events from subsequent blocks.
        for sm in new_contracts {
            self.state.active_contracts.insert(sm.deposit_txid(), sm);
        }

        debug!(%num_active_contracts, %num_new_contracts, %height, "finished processing block, committing all contract states to disk");
        self.state_handles
            .contract_persister
            .commit_all(self.state.active_contracts.iter())
            .await?;

        Ok(duties)
    }

    /// This function validates whether a transaction is a valid Strata checkpoint transaction,
    /// extracts any valid assigned deposit entries and produces the `Assignment` [`ContractEvent`]
    /// so that it can be processed further.
    async fn process_assignments(
        &mut self,
        tx: &Transaction,
    ) -> Result<Vec<OperatorDuty>, ContractManagerErr> {
        let mut duties = Vec::new();

        if let Some(checkpoint) = parse_strata_checkpoint(tx, &self.cfg.sidesystem_params) {
            debug!(
                epoch = %checkpoint.batch_info().epoch(),
                "found valid strata checkpoint"
            );

            let chain_state = checkpoint.sidecar().chainstate();

            match borsh::from_slice::<Chainstate>(chain_state) {
                Ok(chain_state) => {
                    let deposits_table =
                        chain_state.deposits_table().deposits().collect::<Vec<_>>();
                    debug!(?deposits_table, "extracted deposits table from chain state");

                    let assigned_deposit_entries = deposits_table.into_iter().filter(|entry| {
                        matches!(entry.deposit_state(), DepositState::Dispatched(_))
                    });

                    for entry in assigned_deposit_entries {
                        let deposit_txid = entry.output().outpoint().txid;

                        let sm = self
                            .state
                            .active_contracts
                            .get_mut(&deposit_txid)
                            .expect("withdrawal info must be for an active contract");

                        let pov_op_p2p_key = self.cfg.operator_table.pov_p2p_key();
                        let stake_index = entry.idx();
                        let Ok(Some(stake_tx)) = self
                            .state
                            .stake_chains
                            .stake_tx(pov_op_p2p_key, stake_index)
                        else {
                            warn!(%stake_index, %pov_op_p2p_key, "deposit assigned but stake chain data missing");
                            continue;
                        };

                        let l1_start_height = checkpoint
                            .batch_info()
                            .l1_range
                            .1
                            .height()
                            .to_consensus_u32()
                            + 1;
                        match sm.process_contract_event(ContractEvent::Assignment {
                            deposit_entry: entry.clone(),
                            stake_tx,
                            l1_start_height: l1_start_height.into(),
                        }) {
                            Ok(new_duties) if !new_duties.is_empty() => {
                                duties.extend(new_duties);
                            }
                            Ok(_) => {
                                debug!(?entry, "no duty generated for assignment");
                            }
                            Err(e) => {
                                error!(%e, "could not generate duty for assignment event");
                                return Err(e)?;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(%e, "failed to deserialize chainstate inscribed in checkpoint tx");
                }
            }
        };

        Ok(duties)
    }

    async fn process_p2p_message(
        &mut self,
        msg: GossipsubMsg,
    ) -> Result<Vec<OperatorDuty>, ContractManagerErr> {
        let mut duties = vec![];
        let sender_id = self
            .cfg
            .operator_table
            .p2p_key_to_idx(&msg.key)
            .expect("sender must be in the operator table");
        let msg_kind = match msg.unsigned {
            UnsignedGossipsubMsg::StakeChainExchange { .. } => "StakeChainExchange".to_string(),
            UnsignedGossipsubMsg::DepositSetup { scope, index, .. } => {
                format!("DepositSetup({scope}/{index})")
            }
            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, .. } => {
                format!("Musig2NoncesExchange({session_id})")
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange { session_id, .. } => {
                format!("Musig2SignaturesExchange({session_id})")
            }
        };
        info!(sender=%msg.key, %msg_kind, "processing p2p message");

        match self
            .process_unsigned_gossip_msg(msg.unsigned, msg.key, sender_id)
            .await
        {
            Ok(p2p_duties) => duties.extend(p2p_duties),
            Err(e) => {
                error!(%e, "failed to process p2p message");
                return Err(e)?;
            }
        }

        Ok(duties)
    }

    async fn process_unsigned_gossip_msg(
        &mut self,
        msg: UnsignedGossipsubMsg,
        key: P2POperatorPubKey,
        sender_id: u32,
    ) -> Result<Vec<OperatorDuty>, ContractManagerErr> {
        let mut duties = Vec::new();

        match msg {
            UnsignedGossipsubMsg::StakeChainExchange {
                operator_pk: _,
                pre_stake_txid,
                pre_stake_vout,
                stake_chain_id: _,
            } => {
                self.state
                    .stake_chains
                    .process_exchange(key, OutPoint::new(pre_stake_txid.into(), pre_stake_vout))?;

                self.state_handles
                    .stake_chain_persister
                    .commit_prestake(
                        sender_id,
                        OutPoint::new(pre_stake_txid.into(), pre_stake_vout),
                    )
                    .await?;

                Ok(vec![])
            }
            UnsignedGossipsubMsg::DepositSetup {
                scope,
                index,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => {
                let deposit_txid = Txid::from_byte_array(*scope.as_ref());
                info!(%sender_id, %index, %deposit_txid, operator_pk=operator_pk.to_lower_hex_string(), "received deposit setup message");

                if let Some(contract) = self.state.active_contracts.get_mut(&deposit_txid) {
                    let setup = DepositSetup {
                        index,
                        hash: hash.into(),
                        funding_outpoint: OutPoint::new(funding_txid.into(), funding_vout),
                        operator_pk: operator_pk
                            .try_into()
                            .map_err(|_| ContractManagerErr::InvalidOperatorPubkey)?,
                        wots_pks: wots_pks.clone(),
                    };

                    let Some(_stake_txid) =
                        self.state.stake_chains.process_setup(key.clone(), &setup)?
                    else {
                        // if the stake txid cannot be generated it means that the chain is broken,
                        // this can happen if the deposit setup messages are received out of order,
                        // when there are multiple deposits being processed concurrently.
                        return Ok(vec![]);
                    };

                    debug!(%deposit_txid, %sender_id, %index, "committing stake data to disk");
                    self.state_handles
                        .stake_chain_persister
                        .commit_stake_data(
                            &self.cfg.operator_table,
                            self.state.stake_chains.state().clone(),
                        )
                        .await
                        .inspect_err(|e| {
                            error!(%e, "could not persist stake chain data to disk");
                        })?;

                    let deposit_idx = contract.cfg().deposit_idx;
                    let stake_tx = self
                        .state
                        .stake_chains
                        .stake_tx(&key, deposit_idx)?
                        .ok_or(StakeChainErr::StakeTxNotFound(key.clone(), deposit_idx))?;

                    let wots_keys =
                        Box::new(wots_pks.try_into().map_err(|e: (String, WotsPublicKeys)| {
                            ContractManagerErr::InvalidP2PMessage(Box::new(
                                UnsignedGossipsubMsg::DepositSetup {
                                    scope,
                                    index,
                                    hash,
                                    funding_txid,
                                    funding_vout,
                                    operator_pk,
                                    wots_pks: e.1,
                                },
                            ))
                        })?);

                    let deposit_setup_duties =
                        contract.process_contract_event(ContractEvent::DepositSetup {
                            operator_p2p_key: key.clone(),
                            operator_btc_key: operator_pk
                                .try_into()
                                .map_err(|_| ContractManagerErr::InvalidOperatorPubkey)?,
                            stake_hash: hash.into(),
                            stake_txid: stake_tx.compute_txid(),
                            wots_keys,
                        })?;

                    for duty in deposit_setup_duties.iter() {
                        // we need a way to feed the claim txids back into the manager's index so we
                        // skim it off of the publish graph nonces duty.
                        if let OperatorDuty::PublishGraphNonces { claim_txid, .. } = duty {
                            self.state.claim_txids.insert(*claim_txid, deposit_txid);
                        }
                    }

                    // immediately commit the state to disk as this is a critical state transition.
                    if !deposit_setup_duties.is_empty() {
                        debug!(%deposit_txid, %index, "committing deposit setup to disk");
                        let deposit_idx = contract.cfg().deposit_idx;
                        let deposit_tx = &contract.cfg().deposit_tx;
                        let operator_table = &contract.cfg().operator_table;

                        self.state_handles
                            .contract_persister
                            .commit(&deposit_txid, deposit_idx, deposit_tx, operator_table, contract.state())
                            .await.inspect_err(|e| {
                                error!(%e, %deposit_txid, %deposit_idx, "could not persist contract data to disk");
                            })?;
                    }

                    duties.extend(deposit_setup_duties);
                } else {
                    // One of the other operators may have seen a DRT that we have not yet
                    // seen
                    warn!("Received a P2P message about an unknown contract: {deposit_txid}");
                }
                Ok(duties)
            }
            UnsignedGossipsubMsg::Musig2NoncesExchange {
                session_id,
                mut nonces,
            } => {
                let txid = Txid::from_byte_array(*session_id.as_ref());

                if let Some(contract) = self
                    .state
                    .claim_txids
                    .get(&txid)
                    .and_then(|deposit_txid| self.state.active_contracts.get_mut(deposit_txid))
                {
                    let claim_txid = txid;
                    duties.extend(
                        contract.process_contract_event(ContractEvent::GraphNonces {
                            signer: key,
                            claim_txid,
                            pubnonces: nonces
                                .into_iter()
                                .map(|nonce| {
                                    nonce
                                        .try_into()
                                        .map_err(|_| ContractManagerErr::InvalidPubNonces)
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        })?,
                    );
                } else if let Some((_, contract)) = self
                    .state
                    .active_contracts
                    .iter_mut()
                    .find(|(_, contract)| contract.deposit_request_txid() == txid)
                {
                    let Some(nonce) = nonces.pop() else {
                        return Err(ContractManagerErr::InvalidP2PMessage(Box::new(
                            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, nonces },
                        )));
                    };
                    if !nonces.is_empty() {
                        return Err(ContractManagerErr::InvalidP2PMessage(Box::new(
                            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, nonces },
                        )));
                    }
                    duties.extend(
                        contract.process_contract_event(ContractEvent::RootNonce(
                            key,
                            nonce
                                .try_into()
                                .map_err(|_| ContractManagerErr::InvalidPubNonces)?,
                        ))?,
                    );
                }

                Ok(duties)
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id,
                ref signatures,
            } => {
                let txid = Txid::from_byte_array(*session_id.as_ref());

                if let Some(contract) = self
                    .state
                    .claim_txids
                    .get(&txid)
                    .and_then(|txid| self.state.active_contracts.get_mut(txid))
                {
                    let publish_graph_sigs_duty =
                        contract.process_contract_event(ContractEvent::GraphSigs {
                            signer: key,
                            claim_txid: txid,
                            signatures: signatures
                                .iter()
                                .cloned()
                                .map(|s| {
                                    s.try_into()
                                        .map_err(|_| ContractManagerErr::InvalidPartialSignature)
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        })?;

                    // this is a critical state transition as signatures are aggregated here, so
                    // commit the state to disk immediately.
                    if !publish_graph_sigs_duty.is_empty() {
                        debug!(%txid, "committing graph sigs to disk");
                        let deposit_idx = contract.cfg().deposit_idx;
                        let deposit_tx = &contract.cfg().deposit_tx;
                        let operator_table = &contract.cfg().operator_table;

                        self.state_handles
                            .contract_persister
                            .commit(&txid, deposit_idx, deposit_tx, operator_table, contract.state())
                            .await.inspect_err(|e| {
                                error!(%e, %txid, %deposit_idx, "could not persist contract data to disk");
                            })?;
                    }

                    duties.extend(publish_graph_sigs_duty);
                } else if let Some((_, contract)) = self
                    .state
                    .active_contracts
                    .iter_mut()
                    .find(|(_, contract)| contract.deposit_request_txid() == txid)
                {
                    if signatures.len() != 1 {
                        // TODO(proofofkeags): is this an error? For now we just ignore the message
                        // entirely.
                        return Err(ContractManagerErr::InvalidP2PMessage(Box::new(msg)));
                    }

                    let sig = signatures
                        .first()
                        .expect("must exist due to the length check above");

                    duties.extend(
                        contract.process_contract_event(ContractEvent::RootSig(
                            key,
                            (*sig)
                                .try_into()
                                .map_err(|_| ContractManagerErr::InvalidPartialSignature)?,
                        ))?,
                    );
                }

                Ok(duties)
            }
        }
    }

    /// Processes incoming P2P requests from other operators and generates appropriate duty
    /// responses.
    ///
    /// This method handles different types of P2P requests and generates the corresponding operator
    /// duties that need to be executed in response. The method supports the following request
    /// types:
    ///
    /// # Request Types
    ///
    /// - [`GetMessageRequest::StakeChainExchange`]: Requests for stake chain exchange data
    ///   - Returns an [`OperatorDuty::PublishStakeChainExchange`] duty
    ///
    /// - [`GetMessageRequest::DepositSetup`]: Requests for deposit setup information for a specific
    ///   contract
    ///   - Validates that the requested contract exists in active contracts
    ///   - Returns an [`OperatorDuty::PublishDepositSetup`] duty with deposit and stake chain
    ///     information
    ///
    /// - [`GetMessageRequest::Musig2NoncesExchange`]: Requests for MuSig2 nonces for either graph
    ///   or root transactions
    ///   - For claim transactions: Returns an [`OperatorDuty::PublishGraphNonces`] duty with pegout
    ///     graph data
    ///   - For deposit request transactions: Returns an [`OperatorDuty::PublishRootNonce`] duty
    ///     with deposit transaction data
    ///
    /// - [`GetMessageRequest::Musig2SignaturesExchange`]: Requests for MuSig2 partial signatures
    ///   - For claim transactions: Returns an [`OperatorDuty::PublishGraphSignatures`] duty with
    ///     graph signature data
    ///   - For deposit request transactions: Returns an [`OperatorDuty::PublishRootSignature`] duty
    ///     with root signature data
    ///
    /// # Arguments
    ///
    /// * `req` - The P2P request from another operator
    ///
    /// # Returns
    ///
    /// Returns a vector of [`OperatorDuty`] instances that should be executed in response to the
    /// request. An empty vector indicates no duties are needed (e.g., when contract is not
    /// found or not ready).
    ///
    /// # Errors
    ///
    /// Returns [`ContractManagerErr::InvalidP2PRequest`] if:
    ///
    /// - A deposit setup request is made for a non-existent contract
    /// - The request format is invalid or malformed
    async fn process_p2p_request(
        &mut self,
        req: GetMessageRequest,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        match req {
            GetMessageRequest::StakeChainExchange { .. } => {
                Ok(self.process_stake_chain_exchange_request(peer))
            }
            GetMessageRequest::DepositSetup { scope, .. } => {
                self.process_deposit_setup_request(scope, peer)
            }
            GetMessageRequest::Musig2NoncesExchange { session_id, .. } => {
                self.process_musig2_nonces_exchange_request(session_id, peer)
            }
            GetMessageRequest::Musig2SignaturesExchange { session_id, .. } => {
                self.process_musig2_signatures_exchange_request(session_id, peer)
            }
        }
    }

    fn process_stake_chain_exchange_request(
        &self,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Option<OperatorDuty> {
        info!("received request for stake chain exchange");
        // TODO(proofofkeags): actually choose the correct stake chain
        // inputs based off the stake chain id we receive.
        Some(OperatorDuty::PublishStakeChainExchange(peer))
    }

    fn process_deposit_setup_request(
        &self,
        scope: Scope,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        let deposit_txid = Txid::from_byte_array(*scope.as_ref());

        info!(%deposit_txid, "received request for deposit setup");
        let stake_chain_inputs = self
            .state
            .stake_chains
            .state()
            .get(self.cfg.operator_table.pov_p2p_key())
            .expect("our p2p key must exist in the operator table")
            .clone();

        if let Some(deposit_idx) = self
            .state
            .active_contracts
            .get(&deposit_txid)
            .map(|sm| sm.cfg().deposit_idx)
        {
            Ok(Some(OperatorDuty::PublishDepositSetup {
                deposit_txid,
                deposit_idx,
                stake_chain_inputs,
                peer,
            }))
        } else {
            warn!(%deposit_txid, "received deposit setup request for unknown contract");
            Err(ContractManagerErr::InvalidP2PRequest(Box::new(
                GetMessageRequest::DepositSetup {
                    scope,
                    operator_pk: self.cfg.operator_table.pov_p2p_key().clone(),
                },
            )))
        }
    }

    fn process_musig2_nonces_exchange_request(
        &mut self,
        session_id: SessionId,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        let session_id_as_txid = Txid::from_byte_array(*session_id.as_ref());

        trace!(claims = ?self.state.claim_txids, "get nonces exchange");

        // First try to find by claim_txid
        if let Some(deposit_txid) = self.state.claim_txids.get(&session_id_as_txid) {
            if let Some(csm) = self.state.active_contracts.get(deposit_txid) {
                return Self::process_graph_nonces_request(session_id_as_txid, csm, peer);
            }
        }

        // Try to find by deposit request txid
        if let Some(csm) = self
            .state
            .active_contracts
            .values()
            .find(|sm| sm.deposit_request_txid() == session_id_as_txid)
        {
            Ok(Self::process_root_nonces_request(
                session_id_as_txid,
                csm,
                peer,
            ))
        } else {
            // otherwise ignore this message.
            warn!(txid=%session_id_as_txid, "received a musig2 nonces exchange for an unknown session");
            Ok(None)
        }
    }

    fn process_graph_nonces_request(
        claim_txid: Txid,
        csm: &ContractSM,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        info!(%claim_txid, "received request for graph nonces");

        if let ContractState::Requested {
            peg_out_graph_inputs,
            graph_nonces,
            ..
        } = &csm.state().state
        {
            info!(%claim_txid, "received nag for graph nonces");

            let Some(graph_owner) = csm.state().state.claim_to_operator(&claim_txid) else {
                return Ok(None);
            };

            let input = peg_out_graph_inputs
                .get(&graph_owner)
                .expect("graph input must exist if claim_txid exists");

            let (pog_prevouts, pog_witnesses) = csm
                .pog()
                .get(&input.stake_outpoint.txid)
                .map(|pog| Ok((pog.musig_inpoints(), pog.musig_witnesses())))
                .unwrap_or_else(|| {
                    csm.cfg()
                        .build_graph(input)
                        .map(|pog| (pog.musig_inpoints(), pog.musig_witnesses()))
                })?;

            // Get nonces from state if they exist for this claim txid
            let existing_nonces = graph_nonces
                .get(&claim_txid)
                .and_then(|session_nonces| {
                    session_nonces.get(csm.cfg().operator_table.pov_p2p_key())
                })
                .cloned();

            Ok(Some(OperatorDuty::PublishGraphNonces {
                claim_txid,
                pog_prevouts,
                pog_witnesses,
                nonces: existing_nonces,
                peer,
            }))
        } else {
            warn!(deposit_idx=%csm.cfg().deposit_idx, "nagged for nonces on a ContractSM that is not in a Requested state");
            Ok(None)
        }
    }

    fn process_root_nonces_request(
        deposit_request_txid: Txid,
        csm: &ContractSM,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Option<OperatorDuty> {
        info!(%deposit_request_txid, "received nag for root nonces");

        if let ContractState::Requested {
            graph_sigs,
            root_nonces,
            ..
        } = &csm.state().state
        {
            if graph_sigs.len() != csm.cfg().operator_table.cardinality() {
                warn!(%deposit_request_txid, "aggregated graphs sigs incomplete, cannot publish root nonces");
                return None;
            }

            let witness = csm.cfg().deposit_tx.witnesses()[0].clone();

            // Get nonce from state if it exists for this operator
            let existing_nonce = root_nonces
                .get(csm.cfg().operator_table.pov_p2p_key())
                .cloned();

            Some(OperatorDuty::PublishRootNonce {
                deposit_request_txid,
                witness,
                nonce: existing_nonce,
                peer,
            })
        } else {
            warn!(deposit_idx=%csm.cfg().deposit_idx, "nagged for nonces on a ContractSM that is not in a Requested state");
            None
        }
    }

    fn process_musig2_signatures_exchange_request(
        &mut self,
        session_id: SessionId,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        let session_id_as_txid = Txid::from_byte_array(*session_id.as_ref());

        trace!(claims = ?self.state.claim_txids, "get signatures exchange");

        // First try to find by claim_txid
        if let Some(deposit_txid) = self.state.claim_txids.get(&session_id_as_txid) {
            if let Some(csm) = self.state.active_contracts.get(deposit_txid) {
                return Self::process_graph_signatures_request(
                    &self.cfg,
                    session_id_as_txid,
                    csm,
                    peer,
                );
            }
        }

        // Try to find by deposit request txid
        if let Some(csm) = self
            .state
            .active_contracts
            .values()
            .find(|sm| sm.deposit_request_txid() == session_id_as_txid)
        {
            Ok(Self::process_root_signatures_request(
                session_id_as_txid,
                csm,
                peer,
            ))
        } else {
            // otherwise ignore this message.
            warn!(txid=%session_id_as_txid, "received a musig2 signatures exchange for an unknown session");
            Ok(None)
        }
    }

    fn process_graph_signatures_request(
        cfg: &ExecutionConfig,
        claim_txid: Txid,
        csm: &ContractSM,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        if let ContractState::Requested {
            peg_out_graph_inputs,
            graph_partials,
            agg_nonces,
            ..
        } = &csm.state().state
        {
            info!(%claim_txid, "received nag for graph signatures");

            // Check if we already have our own partial signatures for this graph
            let our_p2p_key = cfg.operator_table.pov_p2p_key();
            let existing_partials = graph_partials
                .get(&claim_txid)
                .and_then(|session_partials| session_partials.get(our_p2p_key))
                .cloned();

            let Some(graph_owner) = csm.state().state.claim_to_operator(&claim_txid) else {
                return Ok(None);
            };

            let input = &peg_out_graph_inputs
                .get(&graph_owner)
                .expect("graph input must exist if claim_txid exists");

            let (pog_prevouts, pog_sighashes, pog_witnesses) = csm
                .pog()
                .get(&input.stake_outpoint.txid)
                .map(|cached_graph| {
                    Ok((
                        cached_graph.musig_inpoints(),
                        cached_graph.musig_sighashes(),
                        cached_graph.musig_witnesses(),
                    ))
                })
                .unwrap_or_else(|| {
                    csm.cfg().build_graph(input).map(|pog| {
                        (
                            pog.musig_inpoints(),
                            pog.musig_sighashes(),
                            pog.musig_witnesses(),
                        )
                    })
                })?;

            let Some(aggnonces) = agg_nonces.get(&claim_txid).cloned() else {
                return Ok(None);
            };

            Ok(Some(OperatorDuty::PublishGraphSignatures {
                claim_txid,
                aggnonces,
                pog_prevouts,
                pog_sighashes,
                witnesses: pog_witnesses,
                partial_signatures: existing_partials,
                peer,
            }))
        } else {
            warn!("nagged for nonces on a ContractSM that is not in a Requested state");
            Ok(None)
        }
    }

    fn process_root_signatures_request(
        deposit_request_txid: Txid,
        csm: &ContractSM,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) -> Option<OperatorDuty> {
        info!(%deposit_request_txid, "received nag for root signatures");

        if let ContractState::Requested {
            root_nonces,
            root_partials,
            ..
        } = &csm.state().state
        {
            info!(%deposit_request_txid, "received nag for root signatures");

            // Check if we already have our own root partial signature for this contract
            let our_p2p_key = csm.cfg().operator_table.pov_p2p_key();
            let existing_partial = root_partials.get(our_p2p_key).copied();

            let deposit_tx = &csm.cfg().deposit_tx;
            let sighash = deposit_tx.sighashes()[0];
            let witness = deposit_tx.witnesses()[0].clone();
            let aggnonce = csm
                .cfg()
                .operator_table
                .convert_map_p2p_to_btc(root_nonces.clone())
                .expect("valid operator table")
                .into_values()
                .sum();

            Some(OperatorDuty::PublishRootSignature {
                deposit_request_txid,
                aggnonce,
                sighash,
                witness,
                partial_signature: existing_partial,
                peer,
            })
        } else {
            warn!("nagged for nonces on a ContractSM that is not in a Requested state");
            None
        }
    }

    /// Generates a list of all of the commands needed to acquire P2P messages needed to move a
    /// deposit from the requested to deposited states.
    ///
    /// Note that the node does not nag itself as it will add to much noise to the p2p messages. The
    /// ouroboros mechanism should ensure that any message sent to the network by the current node
    /// will always be received by it as well. If the message is not sent to the network, the
    /// other peers will nag the current node and so the message will be produced and consumed
    /// in response to these nags.
    fn nag(&self) -> Vec<GetMessageRequest> {
        // Get the operator set as a whole.
        let want = self.cfg.operator_table.p2p_keys();

        let mut all_requests = Vec::new();
        all_requests.extend(
            want.difference(
                &self
                    .state
                    .stake_chains
                    .state()
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>(),
            )
            .cloned()
            .map(|operator_pk| {
                let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);

                debug!(peer=%operator_pk, "nagging peer for stake chain exchange");
                GetMessageRequest::StakeChainExchange {
                    stake_chain_id,
                    operator_pk,
                }
            }),
        );

        debug!(num_contracts=%self.state.active_contracts.len(), "constructing nag commands for active contracts in Requested state");

        let stake_chains = &self.state.stake_chains;
        for (txid, contract) in self.state.active_contracts.iter() {
            let state = &contract.state().state;
            let stake_index = contract.cfg().deposit_idx;
            let mut requests = Vec::new();

            // Check if we have the stake data from everybody for this contract.
            // Since this data lives in a separate SM and is persisted separately,
            // chances are that this data may not be available in the event of a crash.
            //
            // For example, this can happen in extreme cases where the node crashes before
            // persisting the deposit setup data and remains down past
            // the `refund_delay`.
            //
            // NOTE: (@Rajil1213) This only applies to a contract in the `Aborted` state but we
            // take the conservative approach and sanity check this for contracts in any
            // state.
            let have = self
                .cfg
                .operator_table
                .p2p_keys()
                .into_iter()
                .filter_map(|p2p_key| {
                    if stake_chains.stake_txid(&p2p_key, stake_index).is_some() {
                        Some(p2p_key)
                    } else {
                        None
                    }
                })
                .collect::<BTreeSet<_>>();

            // Take the difference and add it to the list of things to nag.
            requests.extend(want.difference(&have).map(|key| {
                let operator_id = self.cfg.operator_table.p2p_key_to_idx(key);
                let scope = Scope::from_bytes(*txid.as_ref());

                debug!(?operator_id, %txid, %stake_index, "queueing nag for deposit setup since stake data is missing");
                GetMessageRequest::DepositSetup {
                    scope,
                    operator_pk: key.clone(),
                }
            }));

            // if the stake data is missing, don't proceed further with this contract
            if !requests.is_empty() {
                all_requests.extend(requests.into_iter());
                continue;
            }

            if let ContractState::Requested {
                deposit_request_txid,
                peg_out_graph_inputs,
                claim_txids,
                graph_nonces,
                graph_partials,
                root_nonces,
                root_partials,
                ..
            } = state
            {
                let have = peg_out_graph_inputs
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();

                requests.extend(want.difference(&have).map(|key| {
                    let operator_id = self.cfg.operator_table.p2p_key_to_idx(key);
                    let scope = Scope::from_bytes(*txid.as_ref());

                    debug!(?operator_id, %txid, "queueing nag for deposit setup since peg out graph input is missing");
                    GetMessageRequest::DepositSetup {
                        scope,
                        operator_pk: key.clone(),
                    }
                }));

                // If this is not empty then we can't yet nag for the graph nonces.
                if !requests.is_empty() {
                    all_requests.extend(requests.into_iter());
                    continue;
                }

                // If all the deposit setup data are present, we continue nagging for graph nonces.
                // We can also do this simultaneously with the nags for deposit setup messages.
                // However, this can be a bit wasteful during race conditions where we query for
                // both deposit setup and nonces even though one or both of them may be en-route
                // or being processed.
                for claim_txid in claim_txids.values() {
                    let have = graph_nonces
                        .get(claim_txid)
                        .map(|nonces| {
                            nonces
                                .keys()
                                .cloned()
                                .collect::<BTreeSet<P2POperatorPubKey>>()
                        })
                        .unwrap_or_default();

                    requests.extend(want.difference(&have).map(|key| {
                        let operator_id = self.cfg.operator_table.p2p_key_to_idx(key);
                        let session_id = SessionId::from_bytes(*claim_txid.as_ref());

                        debug!(?operator_id, %claim_txid, deposit_idx=%stake_index, "queueing nag for graph nonces");
                        GetMessageRequest::Musig2NoncesExchange {
                            session_id,
                            operator_pk: key.clone(),
                        }
                    }));
                }

                // If this is not empty then we can't yet nag for the graph sigs.
                if !requests.is_empty() {
                    all_requests.extend(requests.into_iter());
                    continue;
                }

                // Otherwise we can move onto the graph signatures.
                for claim_txid in claim_txids.values() {
                    let have = graph_partials
                        .get(claim_txid)
                        .map(|partials| {
                            partials
                                .keys()
                                .cloned()
                                .collect::<BTreeSet<P2POperatorPubKey>>()
                        })
                        .unwrap_or_default();

                    requests.extend(want.difference(&have).map(|key| {
                        let operator_id = self.cfg.operator_table.p2p_key_to_idx(key);
                        let session_id = SessionId::from_bytes(claim_txid.to_byte_array());

                        debug!(?operator_id, %txid, deposit_idx=%stake_index, "queueing nag for graph sigs");
                        GetMessageRequest::Musig2SignaturesExchange {
                            session_id,
                            operator_pk: key.clone(),
                        }
                    }));
                }

                // If this is not empty then we can't yet nag for the root nonces.
                if !requests.is_empty() {
                    all_requests.extend(requests.into_iter());
                    continue;
                }

                // Otherwise we can.
                let have = root_nonces
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();
                requests.extend(want.difference(&have).map(|key| {
                    let operator_id = self.cfg.operator_table.p2p_key_to_idx(key);
                    let session_id = SessionId::from_bytes(*deposit_request_txid.as_ref());

                    debug!(?operator_id, %txid, deposit_idx=%stake_index, "queueing nag for root nonces");
                    GetMessageRequest::Musig2NoncesExchange {
                        session_id,
                        operator_pk: key.clone(),
                    }
                }));

                // If this is not empty then we can't yet nag for the root sigs.
                if !requests.is_empty() {
                    all_requests.extend(requests.into_iter());
                    continue;
                }

                // Finally we can nag for the root sigs.
                let have = root_partials
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();

                all_requests.extend(want.difference(&have).map(|key| {
                    let operator_id = self.cfg.operator_table.p2p_key_to_idx(key);
                    let session_id = SessionId::from_bytes(*deposit_request_txid.as_ref());

                    debug!(?operator_id, %txid, deposit_idx=%stake_index, "queueing nag for root sigs");
                    GetMessageRequest::Musig2SignaturesExchange {
                        session_id,
                        operator_pk: key.clone(),
                    }
                }));
            }
        }

        all_requests
    }
}

async fn execute_duty(
    cfg: Arc<ExecutionConfig>,
    outs: Arc<OutputHandles>,
    duty: OperatorDuty,
) -> Result<(), ContractManagerErr> {
    let duty_description = format!("{duty}");
    let log_error = move |error: &ContractManagerErr| {
        error!(%error, "failed to execute {duty_description}");
    };
    match duty {
        OperatorDuty::PublishStakeChainExchange(peer) => handle_publish_stake_chain_exchange(
            &cfg,
            &outs.s2_client,
            &outs.db,
            &outs.msg_handler,
            peer,
        )
        .await
        .inspect_err(log_error),

        OperatorDuty::PublishDepositSetup {
            deposit_idx,
            deposit_txid,
            stake_chain_inputs,
            peer,
        } => handle_publish_deposit_setup(
            &cfg,
            outs,
            deposit_txid,
            deposit_idx,
            stake_chain_inputs,
            peer,
        )
        .await
        .inspect_err(log_error),
        OperatorDuty::PublishRootNonce {
            deposit_request_txid,
            witness,
            nonce,
            peer,
        } => handle_publish_root_nonce(
            &outs.s2_client,
            cfg.operator_table
                .btc_keys()
                .into_iter()
                .map(|pk| pk.x_only_public_key().0)
                .collect(),
            &outs.msg_handler,
            OutPoint::new(deposit_request_txid, 0),
            witness,
            nonce,
            peer,
        )
        .await
        .inspect_err(log_error),

        OperatorDuty::PublishGraphNonces {
            claim_txid,
            pog_prevouts: pog_inputs,
            pog_witnesses,
            nonces,
            peer,
        } => handle_publish_graph_nonces(
            &outs.s2_client,
            cfg.operator_table
                .btc_keys()
                .into_iter()
                .map(|pk| pk.x_only_public_key().0)
                .collect(),
            &outs.msg_handler,
            claim_txid,
            pog_inputs,
            pog_witnesses,
            nonces,
            peer,
        )
        .await
        .inspect_err(log_error),

        OperatorDuty::PublishGraphSignatures {
            claim_txid,
            aggnonces,
            pog_prevouts: pog_outpoints,
            pog_sighashes,
            witnesses,
            partial_signatures,
            peer,
        } => {
            let input = aggnonces
                .zip(pog_outpoints)
                .zip(pog_sighashes)
                .zip(witnesses)
                .map(
                    |(((aggnonce, pog_outpoint), pog_sighash), witness)| GenPartialsInput {
                        aggnonce,
                        outpoint: pog_outpoint,
                        sighash: pog_sighash,
                        witness,
                    },
                );

            handle_publish_graph_sigs(
                &outs.s2_client,
                cfg.operator_table
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect(),
                &outs.msg_handler,
                claim_txid,
                input,
                partial_signatures,
                peer,
            )
            .await
            .inspect_err(log_error)
        }

        OperatorDuty::PublishRootSignature {
            aggnonce,
            deposit_request_txid,
            sighash,
            witness,
            partial_signature,
            peer,
        } => handle_publish_root_signature(
            &outs.s2_client,
            cfg.operator_table
                .btc_keys()
                .into_iter()
                .map(|pk| pk.x_only_public_key().0)
                .collect(),
            &outs.msg_handler,
            aggnonce,
            OutPoint::new(deposit_request_txid, 0),
            sighash,
            witness,
            partial_signature,
            peer,
        )
        .await
        .inspect_err(log_error),

        OperatorDuty::PublishDeposit {
            deposit_tx,
            partial_sigs,
            aggnonce,
        } => {
            tokio::spawn(async move {
                handle_publish_deposit(
                    &outs.tx_driver,
                    cfg.operator_table.btc_keys().into_iter().collect(),
                    deposit_tx,
                    partial_sigs,
                    aggnonce,
                )
                .await
                .inspect_err(log_error)
            });

            Ok(())
        }

        OperatorDuty::FulfillerDuty(fulfiller_duty) => match fulfiller_duty {
            FulfillerDuty::HandleFulfillment {
                withdrawal_metadata,
                user_descriptor,
                deadline,
                stake_tx,
                ..
            } => {
                tokio::spawn(async move {
                    handle_withdrawal_fulfillment(
                        &cfg,
                        outs.clone(),
                        stake_tx,
                        withdrawal_metadata,
                        user_descriptor,
                        deadline,
                    )
                    .await
                    .inspect_err(log_error)
                });

                Ok(())
            }
            FulfillerDuty::PublishClaim {
                withdrawal_fulfillment_txid,
                stake_txid,
                deposit_txid,
            } => {
                tokio::spawn(async move {
                    handle_publish_claim(
                        &cfg,
                        &outs,
                        stake_txid,
                        deposit_txid,
                        withdrawal_fulfillment_txid,
                    )
                    .await
                    .inspect_err(log_error)
                });

                Ok(())
            }
            FulfillerDuty::PublishPayoutOptimistic {
                deposit_txid,
                claim_txid,
                stake_txid,
                stake_index,
                agg_sigs,
            } => {
                tokio::spawn(async move {
                    handle_publish_payout_optimistic(
                        &cfg,
                        &outs,
                        deposit_txid,
                        claim_txid,
                        stake_txid,
                        stake_index,
                        *agg_sigs,
                    )
                    .await
                    .inspect_err(log_error)
                });

                Ok(())
            }
            FulfillerDuty::PublishPreAssert {
                deposit_idx,
                deposit_txid,
                claim_txid,
                agg_sig,
            } => {
                tokio::spawn(async move {
                    handle_publish_pre_assert(
                        &cfg,
                        &outs,
                        deposit_idx,
                        deposit_txid,
                        claim_txid,
                        agg_sig,
                    )
                    .await
                    .inspect_err(log_error)
                });

                Ok(())
            }
            FulfillerDuty::PublishAssertData {
                start_height,
                withdrawal_fulfillment_txid,
                deposit_idx,
                deposit_txid,
                pre_assert_txid,
                pre_assert_locking_scripts,
            } => {
                tokio::spawn(async move {
                    handle_publish_assert_data(
                        &cfg,
                        &outs,
                        deposit_idx,
                        deposit_txid,
                        AssertDataTxInput {
                            pre_assert_txid,
                            pre_assert_locking_scripts: *pre_assert_locking_scripts,
                        },
                        withdrawal_fulfillment_txid,
                        start_height,
                    )
                    .await
                });

                Ok(())
            }
            FulfillerDuty::PublishPostAssertData {
                deposit_txid,
                assert_data_txids,
                agg_sigs,
            } => {
                tokio::spawn(async move {
                    handle_publish_post_assert(
                        &cfg,
                        &outs,
                        deposit_txid,
                        *assert_data_txids,
                        *agg_sigs,
                    )
                    .await
                    .inspect_err(log_error)
                });

                Ok(())
            }
            FulfillerDuty::PublishPayout {
                deposit_idx,
                deposit_txid,
                stake_txid,
                claim_txid,
                post_assert_txid,
                agg_sigs,
            } => {
                tokio::spawn(async move {
                    handle_publish_payout(
                        &cfg,
                        &outs,
                        deposit_idx,
                        deposit_txid,
                        stake_txid,
                        claim_txid,
                        post_assert_txid,
                        *agg_sigs,
                    )
                    .await
                    .inspect_err(log_error)
                });

                Ok(())
            }
            FulfillerDuty::InitStakeChain => Err(TransitionErr(
                "received an InitStakeChain duty but it should only be invoked once at genesis"
                    .to_string(),
            )
            .into()),
        },
        OperatorDuty::Abort => {
            warn!("received an Abort duty, this should not happen in normal operation");

            // TODO(proofofkeags): right now we don't actively attempt to prune Aborted contracts.
            // We need to hold onto them in our active state for now because of its implications on
            // advancing the stake chain. In the future we need to prune them after their stake
            // transaction is published since their state is no longer relevant.
            Ok(())
        }
        OperatorDuty::VerifierDuty(verifier_duty) => {
            warn!(%verifier_duty, "ignoring verifier duty");

            Ok(())
        }
    }
}
