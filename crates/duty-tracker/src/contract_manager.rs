//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    sync::Arc,
    time::Duration,
    vec,
};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{
    hashes::Hash, hex::DisplayHex, Address, Block, Network, OutPoint, ScriptBuf, Transaction, Txid,
};
use bitcoind_async_client::{client::Client as BitcoinClient, traits::Reader};
use btc_notify::client::{BlockStatus, BtcZmqClient};
use futures::{future, StreamExt};
use operator_wallet::OperatorWallet;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::*;
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::transactions::stake::StakeTxKind;
use strata_bridge_tx_graph::transactions::{
    deposit::DepositTx,
    prelude::{AssertDataTxInput, CovenantTx},
};
use strata_p2p::{self, commands::Command, events::Event, swarm::handle::P2PHandle};
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use strata_p2p_wire::p2p::v1::{GetMessageRequest, GossipsubMsg, UnsignedGossipsubMsg};
use strata_primitives::params::RollupParams;
use strata_state::{bridge_state::DepositState, chain_state::Chainstate};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    task::{self, JoinHandle},
    time,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    contract_persister::ContractPersister,
    contract_state_machine::{
        ContractCfg, ContractEvent, ContractSM, ContractState, DepositSetup, FulfillerDuty,
        OperatorDuty, SyntheticEvent, TransitionErr,
    },
    errors::{ContractManagerErr, StakeChainErr},
    executors::prelude::*,
    predicates::{deposit_request_info, parse_strata_checkpoint},
    s2_session_manager::MusigSessionManager,
    stake_chain_persister::StakeChainPersister,
    stake_chain_state_machine::StakeChainSM,
    tx_driver::TxDriver,
};

/// System that handles all of the chain and p2p events and forwards them to their respective
/// [`ContractSM`]s.
#[derive(Debug)]
pub struct ContractManager {
    thread_handle: JoinHandle<()>,
}

impl ContractManager {
    /// Initializes the ContractManager with the appropriate external event feeds and data stores.
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::new_ret_no_self)]
    pub fn new(
        // Static Config Parameters
        network: Network,
        nag_interval: Duration,
        connector_params: ConnectorParams,
        pegout_graph_params: PegOutGraphParams,
        stake_chain_params: StakeChainParams,
        sidesystem_params: RollupParams,
        operator_table: OperatorTable,
        is_faulty: bool,
        min_withdrawal_fulfillment_window: u64,
        // Genesis information
        pre_stake_pubkey: ScriptBuf,
        // Subsystem Handles
        zmq_client: BtcZmqClient,
        rpc_client: BitcoinClient,
        tx_driver: TxDriver,
        mut p2p_handle: P2PHandle,
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
        s2_client: SecretServiceClient,
        wallet: OperatorWallet,
        db: SqliteDb,
    ) -> JoinHandle<()> {
        task::spawn(async move {
            let crash = |e: ContractManagerErr| {
                error!(?e, "crashing");
                panic!("{e}");
            };

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
                Err(e) => crash(e.into()),
            };
            info!(num_contracts=%active_contracts.len(), "loaded all active contracts");

            let operator_pubkey = s2_client
                .general_wallet_signer()
                .pubkey()
                .await
                .expect("must be able to get stake chain wallet key");

            let funding_address =
                Address::from_script(wallet.stakechain_script_buf(), network.params())
                    .expect("funding locking script must be valid for supplied network");

            let stake_chains = match stake_chain_persister
                .load(&operator_table, operator_pubkey)
                .await
            {
                Ok(stake_chains) => {
                    info!("restoring stake chain data");

                    match StakeChainSM::restore(
                        network,
                        operator_table.clone(),
                        stake_chain_params,
                        stake_chains,
                    ) {
                        Ok(stake_chains) => stake_chains,
                        Err(e) => {
                            crash(ContractManagerErr::StakeChainErr(e));
                            return;
                        }
                    }
                }
                Err(e) => {
                    crash(e.into());
                    return;
                }
            };

            let current = match rpc_client.get_block_count().await {
                Ok(a) => a - (zmq_client.bury_depth() as u64),
                Err(e) => {
                    crash(e.into());
                    return;
                }
            };
            let mut block_sub = zmq_client
                .subscribe_blocks()
                .await
                .filter(|evt| future::ready(evt.status == BlockStatus::Buried));

            // It's extremely unlikely that these will ever differ at all but it's possible for
            // them to differ by at most 1 in the scenario where we crash mid-batch when committing
            // contract state to disk.
            //
            // We take the minimum height that any state machine has observed since we want to
            // re-feed chain events that they might have missed.
            let mut cursor = active_contracts
                .values()
                .min_by(|sm1, sm2| sm1.state().block_height.cmp(&sm2.state().block_height))
                .map(|sm| sm.state().block_height)
                .unwrap_or(current);

            let cfg = Arc::new(ExecutionConfig {
                network,
                connector_params,
                pegout_graph_params,
                stake_chain_params,
                sidesystem_params,
                operator_table,
                pre_stake_pubkey: pre_stake_pubkey.clone(),
                funding_address: funding_address.clone(),
                is_faulty,
                min_withdrawal_fulfillment_window,
            });

            // TODO: (@Rajil1213) at this point, it may or may not be necessary to make this
            // configurable. When this capacity is reached, messages will be dropped (although the
            // documentation on broadcast::channel says that the actual capacity may be higher).
            // This will only happen if this node as well as other event sources generate far too
            // many events.
            const OUROBOROS_CAP: usize = 100;
            let (ouroboros_sender, mut ouroboros_receiver) = broadcast::channel(OUROBOROS_CAP);
            let msg_handler = MessageHandler::new(p2p_handle.clone(), ouroboros_sender);

            let (synthetic_event_sender, mut synthetic_event_receiver) =
                mpsc::unbounded_channel::<SyntheticEvent>();

            let output_handles = Arc::new(OutputHandles {
                wallet: RwLock::new(wallet),
                msg_handler,
                bitcoind_rpc_client: rpc_client.clone(),
                synthetic_event_sender,
                s2_session_manager: MusigSessionManager::new(cfg.operator_table.clone(), s2_client),
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
            };
            let mut ctx = ContractManagerCtx {
                cfg,
                state,
                state_handles,
            };

            info!(cursor = %cursor, current = %current, "performing bitcoin rpc sync");
            while cursor < current {
                let next = cursor + 1;
                let block = match rpc_client.get_block_at(next).await {
                    Ok(a) => a,
                    Err(e) => {
                        crash(e.into());
                        return;
                    }
                };
                let blockhash = block.block_hash();
                let res = ctx.process_block(block).await;
                match res {
                    Ok(duties) => {
                        info!(%next, "successfully rpc sync'ed block");
                        let cfg = Arc::new(ctx.cfg.clone());
                        duties.into_iter().for_each(|duty| {
                            info!(%duty, "starting duty execution from lagging blocks");
                            let cfg = cfg.clone();
                            let output_handles = output_handles.clone();
                            tokio::task::spawn(async move {
                                if let Err(e) =
                                    execute_duty(&cfg, output_handles, duty.clone()).await
                                {
                                    error!(%e, %duty, "failed to execute duty");
                                }
                            });
                        });
                    }
                    Err(e) => {
                        error!(%blockhash, %cursor, %e, "failed to process block");
                        panic!("{e:?}");
                    }
                }

                cursor = next;
            }

            let mut interval = time::interval(nag_interval);
            // skip any missed ticks to avoid flooding the network with duplicate nag messages
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                let mut duties = vec![];
                tokio::select! {
                    biased; // follow the same order as specified below

                    synthetic_event = synthetic_event_receiver.recv() => {
                        if let Some(SyntheticEvent::AggregatedSigs{ deposit_txid, agg_sigs }) = synthetic_event {
                            let contract = ctx.state.active_contracts.get_mut(&deposit_txid).expect("contract must exist in the state");

                            info!(%deposit_txid, "committing aggregate signatures");
                            match contract.process_contract_event(ContractEvent::AggregatedSigs { agg_sigs }) {
                                Ok(synthetic_event_duties) if !synthetic_event_duties.is_empty() => duties.extend(synthetic_event_duties),
                                Ok(synthetic_event_duties) => { trace!(?synthetic_event_duties, "got no duties when processing contract event from synthetic event"); },
                                Err(e) => {
                                    error!(%deposit_txid, %e, "failed to process ouroboros event");
                                    // We only receive an event from this channel once (no retries).
                                    // Not having aggregate signatures is catastrophic because we
                                    // don't have a reliable fallback mechanism to get them in the
                                    // future. So it's better to break the event loop and panic if this ever happens.
                                    break;
                                },

                            }
                        }
                    },

                    Some(block) = block_sub.next() => {
                        let blockhash = block.block.block_hash();
                        let block_height = block.block.bip34_block_height().expect("must have valid height");
                        info!(%blockhash, %block_height, "processing block");
                        match ctx.process_block(block.block).await {
                            Ok(block_duties) if !block_duties.is_empty() => {
                                let num_duties = block_duties.len();
                                info!(%blockhash, %block_height, %num_duties, "queueing duties generated by the block event for execution");
                                duties.extend(block_duties);
                            },
                            Ok(_) => {},
                            Err(e) => {
                                error!(%blockhash, %block_height, ?e, "failed to process block");
                                break;
                            }
                        }
                    },
                    ouroboros_msg = ouroboros_receiver.recv() => match ouroboros_msg {
                        Ok(msg) => {
                            match ctx.process_p2p_message(msg).await {
                                Ok(ouroboros_duties) if !ouroboros_duties.is_empty() => {
                                    info!(num_duties=ouroboros_duties.len(), "queueing duties generated via ouroboros");
                                    debug!(?ouroboros_duties, "queueing duties generated via ouroboros");

                                    duties.extend(ouroboros_duties);
                                },
                                Ok(_) => {},
                                Err(e) => {
                                    error!(%e, "failed to process ouroboros message");
                                    break;
                                }
                            }
                        },
                        Err(e) => {
                            error!(%e, "failed to receive ouroboros message");
                            break;
                        },
                    },
                    Some(event) = p2p_handle.next() => match event {
                        Ok(Event::ReceivedMessage(msg)) => {
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
                        },
                        Ok(Event::ReceivedRequest(req)) => {
                            match ctx.process_p2p_request(req.clone()).await {
                                Ok(p2p_requests) => duties.extend(p2p_requests),
                                Err(e) => {
                                    error!(?req, %e, "failed to process p2p request");
                                    // in case an error occurs, the requester will just nag again
                                    // so no need to break out of the event loop
                                },
                            }
                        },
                        Err(e) => {
                            error!(%e, "error while polling for p2p messages");
                            // this could be a transient issue, so no need to break immediately
                        }
                    },
                    instant = interval.tick() => {
                        debug!(?instant, "constructing nags");

                        let nags = ctx.nag();
                        for nag in nags {
                            p2p_handle.send_command(nag).await;
                        }
                    }
                }

                duties.into_iter().for_each(|duty| {
                    debug!(%duty, "starting duty execution from new events");

                    let cfg = ctx.cfg.clone();
                    let output_handles = output_handles.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = execute_duty(&cfg, output_handles, duty.clone()).await {
                            error!(%e, %duty, "failed to execute duty");
                        }
                    });
                });
            }

            unreachable!("event loop must never end");
        })
    }
}
impl Drop for ContractManager {
    fn drop(&mut self) {
        self.thread_handle.abort();
    }
}

/// The handles required by the duty tracker to execute duties.
pub(super) struct OutputHandles {
    pub(super) wallet: RwLock<OperatorWallet>,
    pub(super) msg_handler: MessageHandler,
    pub(super) bitcoind_rpc_client: BitcoinClient,
    pub(super) synthetic_event_sender: mpsc::UnboundedSender<SyntheticEvent>,
    pub(super) s2_session_manager: MusigSessionManager,
    pub(super) tx_driver: TxDriver,
    pub(super) db: SqliteDb,
}

/// The actual state that is being tracked by the [`ContractManager`].
#[derive(Debug)]
pub(super) struct ExecutionState {
    pub(super) active_contracts: BTreeMap<Txid, ContractSM>,
    pub(super) claim_txids: BTreeMap<Txid, Txid>,
    pub(super) stake_chains: StakeChainSM,
}

/// pub(super) The proxy for the state being tracked by the [`ContractManager`].
#[derive(Debug)]
pub(super) struct StateHandles {
    pub(super) contract_persister: ContractPersister,
    pub(super) stake_chain_persister: StakeChainPersister,
}

/// pub(super) The parameters that all duty executions depend upon.
#[derive(Debug, Clone)]
pub(super) struct ExecutionConfig {
    pub(super) network: Network,
    pub(super) connector_params: ConnectorParams,
    pub(super) pegout_graph_params: PegOutGraphParams,
    pub(super) stake_chain_params: StakeChainParams,
    pub(super) sidesystem_params: RollupParams,
    pub(super) operator_table: OperatorTable,
    pub(super) pre_stake_pubkey: ScriptBuf,
    pub(super) funding_address: Address,
    pub(super) is_faulty: bool,
    pub(super) min_withdrawal_fulfillment_window: u64,
}

struct ContractManagerCtx {
    cfg: Arc<ExecutionConfig>,
    state_handles: StateHandles,
    state: ExecutionState,
}

impl ContractManagerCtx {
    async fn process_block(
        &mut self,
        block: Block,
    ) -> Result<Vec<OperatorDuty>, ContractManagerErr> {
        let height = block.bip34_block_height().unwrap_or(0);
        // TODO(proofofkeags): persist entire block worth of states at once. Ensure all the state
        // transitions succeed before committing them to disk.
        let mut duties = Vec::new();
        // this is to aggregate and commit new contracts separately so that the block event that
        // advances the cursor does not advance the cursor on the newly created contracts.
        let mut new_contracts = Vec::new();

        let pov_key = self.cfg.operator_table.pov_op_key().clone();
        // TODO(proofofkeags): prune the active contract set and still preserve the ability
        // to recover this value.
        //
        // Since new contracts are added after all the transactions are processed, we can
        // assume that the stake/deposit index is the same as the number of active contracts
        // throughout the processing of this block.
        let stake_index = self.state.active_contracts.len() as u32;

        for tx in block.txdata {
            // could be an assignment
            let assignment_duties = self.process_assignments(&tx).await?;
            if !assignment_duties.is_empty() {
                info!(num_duties=%assignment_duties.len(), "queueing assignment duties");
                duties.extend(assignment_duties);
            }

            let txid = tx.compute_txid();
            // or a deposit request
            if let Some(deposit_request_data) = deposit_request_info(
                &tx,
                &self.cfg.sidesystem_params,
                &self.cfg.pegout_graph_params,
                &self.cfg.operator_table.tx_build_context(self.cfg.network),
                stake_index,
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

                if self
                    .state
                    .active_contracts
                    .contains_key(&deposit_tx.compute_txid())
                {
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

                debug!(%stake_index, %deposit_request_txid, "creating a new contract");
                let cfg = ContractCfg {
                    network: self.cfg.network,
                    operator_table: self.cfg.operator_table.clone(),
                    connector_params: self.cfg.connector_params,
                    peg_out_graph_params: self.cfg.pegout_graph_params,
                    sidesystem_params: self.cfg.sidesystem_params.clone(),
                    stake_chain_params: self.cfg.stake_chain_params,
                    deposit_idx: stake_index + new_contracts.len() as u32,
                    deposit_tx,
                };

                let duty = OperatorDuty::PublishDepositSetup {
                    deposit_txid: cfg.deposit_tx.compute_txid(),
                    deposit_idx: cfg.deposit_idx,
                    stake_chain_inputs,
                };

                let sm = ContractSM::new(
                    cfg,
                    height,
                    height + self.cfg.pegout_graph_params.refund_delay as u64,
                );

                new_contracts.push(sm);
                duties.push(duty);

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
                }
            }
        }

        // Now that we've handled all the transaction level events, we should inform all the
        // CSMs that a new block has arrived
        for (_, contract) in self.state.active_contracts.iter_mut() {
            duties.extend(contract.process_contract_event(ContractEvent::Block(height))?)
        }

        self.state_handles
            .contract_persister
            .commit_all(self.state.active_contracts.iter())
            .await?;

        // Now that we've processed all the events related to the old contracts and dispatched the
        // corresponding events to them, we can add the new contracts which will receive relevant
        // events from subsequent blocks.
        for sm in new_contracts {
            self.state_handles
                .contract_persister
                .init(sm.cfg(), sm.state())
                .await?;

            self.state.active_contracts.insert(sm.deposit_txid(), sm);
        }

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

                        let pov_op_p2p_key = self.cfg.operator_table.pov_op_key();
                        let stake_index = entry.idx();
                        let Ok(Some(stake_tx)) = self
                            .state
                            .stake_chains
                            .stake_tx(pov_op_p2p_key, stake_index)
                        else {
                            warn!(%stake_index, %pov_op_p2p_key, "deposit assigned but stake chain data missing");
                            continue;
                        };

                        let l1_start_height = checkpoint.batch_info().l1_range.1.height() + 1;
                        match sm.process_contract_event(ContractEvent::Assignment {
                            deposit_entry: entry.clone(),
                            stake_tx,
                            l1_start_height,
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
            .op_key_to_idx(&msg.key)
            .expect("sender must be in the operator table");
        let message_signature = msg.signature.to_lower_hex_string();
        let msg_kind = match msg.unsigned {
            UnsignedGossipsubMsg::StakeChainExchange { .. } => "stake_chain_exchange",
            UnsignedGossipsubMsg::DepositSetup { .. } => "deposit_setup",
            UnsignedGossipsubMsg::Musig2NoncesExchange { .. } => "musig2_nonces_exchange",
            UnsignedGossipsubMsg::Musig2SignaturesExchange { .. } => "musig2_signatures_exchange",
        };
        info!(sender=%sender_id, %message_signature, %msg_kind, "received p2p message");

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
                    .process_exchange(key, OutPoint::new(pre_stake_txid, pre_stake_vout))?;

                self.state_handles
                    .stake_chain_persister
                    .commit_prestake(sender_id, OutPoint::new(pre_stake_txid, pre_stake_vout))
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

                info!(%sender_id, %index, %deposit_txid, %operator_pk, "received deposit setup message");

                if let Some(contract) = self.state.active_contracts.get_mut(&deposit_txid) {
                    let setup = DepositSetup {
                        index,
                        hash,
                        funding_outpoint: OutPoint::new(funding_txid, funding_vout),
                        operator_pk,
                        wots_pks: wots_pks.clone(),
                    };

                    info!(%deposit_txid, %sender_id, %index, "processing stake tx setup");
                    let Some(_stake_txid) =
                        self.state.stake_chains.process_setup(key.clone(), &setup)?
                    else {
                        // if the stake txid cannot be generated it means that the chain is broken,
                        // this can happen if the deposit setup messages are received out of order,
                        // when there are multiple deposits being processed concurrently.
                        return Ok(vec![]);
                    };

                    info!(%deposit_txid, %sender_id, %index, "committing stake data to disk");
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

                    let deposit_setup_duties = contract
                        .process_contract_event(ContractEvent::DepositSetup {
                            operator_p2p_key: key.clone(),
                            operator_btc_key: operator_pk,
                            stake_hash: hash,
                            stake_txid: stake_tx.compute_txid(),
                            wots_keys,
                        })?
                        .into_iter()
                        .map(|duty| {
                            // we need a way to feed the claim txids back into the manager's index
                            // so we skim it off of the publish graph
                            // nonces duty.
                            if let OperatorDuty::PublishGraphNonces { claim_txid, .. } = duty {
                                self.state.claim_txids.insert(claim_txid, deposit_txid);
                            }

                            duty
                        });

                    duties.extend(deposit_setup_duties);
                } else {
                    // One of the other operators may have seen a DRT that we have not yet
                    // seen
                    warn!(
                        "Received a P2P message about an unknown contract: {}",
                        deposit_txid
                    );
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
                    duties.extend(contract.process_contract_event(ContractEvent::GraphNonces {
                        signer: key,
                        claim_txid,
                        pubnonces: nonces,
                    })?);
                } else if let Some((_, contract)) = self
                    .state
                    .active_contracts
                    .iter_mut()
                    .find(|(_, contract)| contract.deposit_request_txid() == txid)
                {
                    if nonces.len() != 1 {
                        return Err(ContractManagerErr::InvalidP2PMessage(Box::new(
                            UnsignedGossipsubMsg::Musig2NoncesExchange { session_id, nonces },
                        )));
                    }
                    let nonce = nonces.pop().unwrap();
                    duties.extend(
                        contract.process_contract_event(ContractEvent::RootNonce(key, nonce))?,
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
                    duties.extend(contract.process_contract_event(ContractEvent::GraphSigs {
                        signer: key,
                        claim_txid: txid,
                        signatures: signatures.clone(),
                    })?);
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
                        contract.process_contract_event(ContractEvent::RootSig(key, *sig))?,
                    );
                }

                Ok(duties)
            }
        }
    }

    async fn process_p2p_request(
        &mut self,
        req: GetMessageRequest,
    ) -> Result<Option<OperatorDuty>, ContractManagerErr> {
        Ok(match req {
            GetMessageRequest::StakeChainExchange { .. } => {
                info!("received request for stake chain exchange");
                // TODO(proofofkeags): actually choose the correct stake chain
                // inputs based off the stake chain id we receive.
                Some(OperatorDuty::PublishStakeChainExchange)
            }
            GetMessageRequest::DepositSetup { scope, .. } => {
                let deposit_txid = Txid::from_byte_array(*scope.as_ref());

                info!(%deposit_txid, "received request for deposit setup");
                let stake_chain_inputs = self
                    .state
                    .stake_chains
                    .state()
                    .get(self.cfg.operator_table.pov_op_key())
                    .expect("our p2p key must exist in the operator table")
                    .clone();

                if let Some(deposit_idx) = self
                    .state
                    .active_contracts
                    .get(&deposit_txid)
                    .map(|sm| sm.cfg().deposit_idx)
                {
                    Some(OperatorDuty::PublishDepositSetup {
                        deposit_txid,
                        deposit_idx,
                        stake_chain_inputs,
                    })
                } else {
                    warn!(%deposit_txid, "received deposit setup request for unknown contract");
                    return Err(ContractManagerErr::InvalidP2PRequest(Box::new(req)));
                }
            }
            GetMessageRequest::Musig2NoncesExchange { session_id, .. } => {
                let session_id_as_txid = Txid::from_byte_array(*session_id.as_ref());

                debug!(claims = ?self.state.claim_txids, "get nonces exchange");
                if let Some(csm) = self
                    .state
                    .claim_txids
                    .get(&session_id_as_txid)
                    .and_then(|deposit_txid| self.state.active_contracts.get_mut(deposit_txid))
                {
                    let claim_txid = session_id_as_txid;
                    info!(%claim_txid, "received request for graph nonces");

                    if let ContractState::Requested {
                        peg_out_graph_inputs,
                        graph_nonces,
                        ..
                    } = &csm.state().state
                    {
                        info!(%claim_txid, "received nag for graph nonces");

                        let graph_owner = csm
                            .state()
                            .state
                            .claim_to_operator(&claim_txid)
                            .expect("claim_txid must exist as it is part of the claim_txids");

                        let input = peg_out_graph_inputs
                            .get(&graph_owner)
                            .expect("graph input must exist if claim_txid exists");

                        let (pog_prevouts, pog_witnesses) = csm
                            .pog()
                            .get(&input.stake_outpoint.txid)
                            .map(|pog| (pog.musig_inpoints(), pog.musig_witnesses()))
                            .unwrap_or_else(|| {
                                let pog = csm.cfg().build_graph(input);

                                (pog.musig_inpoints(), pog.musig_witnesses())
                            });

                        // Get nonces from state if they exist for this claim txid
                        let existing_nonces = graph_nonces
                            .get(&claim_txid)
                            .and_then(|session_nonces| {
                                session_nonces.get(csm.cfg().operator_table.pov_op_key())
                            })
                            .cloned();

                        Some(OperatorDuty::PublishGraphNonces {
                            claim_txid,
                            pog_prevouts,
                            pog_witnesses,
                            nonces: existing_nonces,
                        })
                    } else {
                        warn!("nagged for nonces on a ContractSM that is not in a Requested state");
                        None
                    }
                } else if let Some(csm) = self
                    .state
                    .active_contracts
                    .values()
                    .find(|sm| sm.deposit_request_txid() == session_id_as_txid)
                {
                    let deposit_request_txid = session_id_as_txid;
                    info!(%deposit_request_txid, "received nag for root nonces");

                    if let ContractState::Requested { root_nonces, .. } = &csm.state().state {
                        let witness = csm.cfg().deposit_tx.witnesses()[0].clone();

                        // Get nonce from state if it exists for this operator
                        let existing_nonce = root_nonces
                            .get(csm.cfg().operator_table.pov_op_key())
                            .cloned();

                        Some(OperatorDuty::PublishRootNonce {
                            deposit_request_txid,
                            witness,
                            nonce: existing_nonce,
                        })
                    } else {
                        warn!("nagged for nonces on a ContractSM that is not in a Requested state");
                        None
                    }
                } else {
                    // otherwise ignore this message.
                    warn!(txid=%session_id_as_txid, "received a musig2 nonces exchange for an unknown session");
                    None
                }
            }
            GetMessageRequest::Musig2SignaturesExchange { session_id, .. } => {
                let session_id_as_txid = Txid::from_byte_array(*session_id.as_ref());

                debug!(claims = ?self.state.claim_txids, "get signatures exchange");
                if let Some(csm) = self
                    .state
                    .claim_txids
                    .get(&session_id_as_txid)
                    .and_then(|deposit_txid| self.state.active_contracts.get_mut(deposit_txid))
                {
                    if let ContractState::Requested {
                        peg_out_graph_inputs,
                        graph_nonces,
                        graph_partials,
                        ..
                    } = &csm.state().state
                    {
                        let claim_txid = session_id_as_txid;
                        info!(%claim_txid, "received nag for graph signatures");

                        // Check if we already have our own partial signatures for this graph
                        let our_p2p_key = self.cfg.operator_table.pov_op_key();
                        let existing_partials = graph_partials
                            .get(&claim_txid)
                            .and_then(|session_partials| session_partials.get(our_p2p_key))
                            .cloned();

                        let graph_nonces = graph_nonces.get(&claim_txid).unwrap().clone();
                        let graph_owner = csm
                            .state()
                            .state
                            .claim_to_operator(&claim_txid)
                            .expect("claim_txid must exist as it is part of the claim_txids");

                        let input = &peg_out_graph_inputs
                            .get(&graph_owner)
                            .expect("graph input must exist if claim_txid exists");

                        let (pog_prevouts, pog_sighashes) = csm
                            .pog()
                            .get(&input.stake_outpoint.txid)
                            .map(|pog| (pog.musig_inpoints(), pog.musig_sighashes()))
                            .unwrap_or_else(|| {
                                let pog = csm.cfg().build_graph(input);

                                (pog.musig_inpoints(), pog.musig_sighashes())
                            });

                        Some(OperatorDuty::PublishGraphSignatures {
                            claim_txid,
                            pubnonces: csm
                                .cfg()
                                .operator_table
                                .convert_map_op_to_btc(graph_nonces)
                                .unwrap(),
                            pog_prevouts,
                            pog_sighashes,
                            partial_signatures: existing_partials,
                        })
                    } else {
                        warn!("nagged for nonces on a ContractSM that is not in a Requested state");
                        None
                    }
                } else if let Some(csm) = self
                    .state
                    .active_contracts
                    .values()
                    .find(|sm| sm.deposit_request_txid() == session_id_as_txid)
                {
                    let deposit_request_txid = session_id_as_txid;
                    info!(%deposit_request_txid, "received nag for root signatures");

                    if let ContractState::Requested {
                        root_nonces,
                        root_partials,
                        ..
                    } = &csm.state().state
                    {
                        let deposit_request_txid = session_id_as_txid;
                        info!(%deposit_request_txid, "received nag for root signatures");

                        // Check if we already have our own root partial signature for this contract
                        let our_p2p_key = self.cfg.operator_table.pov_op_key();
                        let existing_partial = root_partials.get(our_p2p_key).copied();

                        let deposit_tx = &csm.cfg().deposit_tx;
                        let sighash = deposit_tx.sighashes()[0];

                        Some(OperatorDuty::PublishRootSignature {
                            deposit_request_txid: session_id_as_txid,
                            nonces: csm
                                .cfg()
                                .operator_table
                                .convert_map_op_to_btc(root_nonces.clone())
                                .expect("received nonces from non-existent operator"),
                            sighash,
                            partial_signature: existing_partial,
                        })
                    } else {
                        warn!("nagged for nonces on a ContractSM that is not in a Requested state");

                        None
                    }
                } else {
                    // otherwise ignore this message.
                    warn!(txid=%session_id_as_txid, "received a musig2 signatures exchange for an unknown session");
                    None
                }
            }
        })
    }

    /// Generates a list of all of the commands needed to acquire P2P messages needed to move a
    /// deposit from the requested to deposited states.
    ///
    /// Note that the node does not nag itself as it will add to much noise to the p2p messages. The
    /// ouroboros mechanism should ensure that any message sent to the network by the current node
    /// will always be received by it as well. If the message is not sent to the network, the
    /// other peers will nag the current node and so the message will be produced and consumed
    /// in response to these nags.
    fn nag(&self) -> Vec<Command> {
        let pov_idx = self.cfg.operator_table.pov_idx();

        // Get the operator set as a whole.
        let want = self.cfg.operator_table.p2p_keys();

        let mut all_commands = Vec::new();
        all_commands.extend(
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
            .filter_map(|operator_pk| {
                let operator_id = self.cfg.operator_table.op_key_to_idx(&operator_pk);
                if operator_id.is_some_and(|idx| idx == pov_idx) {
                    return None;
                }

                let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);

                info!(?operator_id, "queueing nag for stake chain exchange");
                Some(Command::RequestMessage(
                    GetMessageRequest::StakeChainExchange {
                        stake_chain_id,
                        operator_pk,
                    },
                ))
            }),
        );

        debug!(num_contracts=%self.state.active_contracts.len(), "constructing nag commands for active contracts in Requested state");

        for (txid, contract) in self.state.active_contracts.iter() {
            let state = &contract.state().state;
            if let ContractState::Requested {
                deposit_request_txid,
                peg_out_graph_inputs,
                graph_nonces,
                graph_partials,
                root_nonces,
                root_partials,
                ..
            } = state
            {
                let mut commands = Vec::new();

                // Get all of the operator keys who have already given us their wots keys.
                let have = peg_out_graph_inputs
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();

                // Take the difference and add it to the list of things to nag.
                commands.extend(want.difference(&have).filter_map(|key| {
                    let operator_id = self.cfg.operator_table.op_key_to_idx(key);
                    if operator_id.is_some_and(|idx| idx == pov_idx) {
                        return None;
                    }

                    let scope = Scope::from_bytes(*txid.as_ref());

                    info!(?operator_id, %txid, "queueing nag for deposit setup");
                    Some(Command::RequestMessage(GetMessageRequest::DepositSetup {
                        scope,
                        operator_pk: key.clone(),
                    }))
                }));

                if !commands.is_empty() {
                    all_commands.extend(commands.into_iter());
                    continue;
                }

                // If all the deposit setup data are present, we continue nagging for graph nonces.
                // We can also do this simultaneously with the nags for deposit setup messages.
                // However, this can be a bit wasteful during race conditions where we query for
                // both deposit setup and nonces even though one or both of them may be en-route
                // or being processed.
                for (claim_txid, nonces) in graph_nonces {
                    let have = nonces
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<P2POperatorPubKey>>();

                    commands.extend(want.difference(&have).filter_map(|key| {
                        let operator_id = self.cfg.operator_table.op_key_to_idx(key);
                        if operator_id.is_some_and(|idx| idx == pov_idx) {
                            return None;
                        }

                        let session_id = SessionId::from_bytes(*claim_txid.as_ref());

                        info!(?operator_id, %claim_txid, "queueing nag for graph nonces");
                        Some(Command::RequestMessage(
                            GetMessageRequest::Musig2NoncesExchange {
                                session_id,
                                operator_pk: key.clone(),
                            },
                        ))
                    }));
                }

                if !commands.is_empty() {
                    all_commands.extend(commands.into_iter());
                    continue;
                }

                // Otherwise we can move onto the graph signatures.
                for (claim_txid, partials) in graph_partials {
                    let have = partials
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<P2POperatorPubKey>>();
                    commands.extend(want.difference(&have).filter_map(|key| {
                        let operator_id = self.cfg.operator_table.op_key_to_idx(key);
                        if operator_id.is_some_and(|idx| idx == pov_idx) {
                            return None;
                        }

                        let session_id = SessionId::from_bytes(claim_txid.to_byte_array());

                        info!(?operator_id, %claim_txid, "queueing nag for graph signatures");
                        Some(Command::RequestMessage(
                            GetMessageRequest::Musig2SignaturesExchange {
                                session_id,
                                operator_pk: key.clone(),
                            },
                        ))
                    }));
                }

                // If this is not empty then we can't yet nag for the root nonces.
                if !commands.is_empty() {
                    all_commands.extend(commands.into_iter());
                    continue;
                }

                // Otherwise we can.
                let have = root_nonces
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();
                commands.extend(want.difference(&have).filter_map(|key| {
                    let operator_id = self.cfg.operator_table.op_key_to_idx(key);
                    if operator_id.is_some_and(|id| id == pov_idx) {
                        return None;
                    }

                    let session_id = SessionId::from_bytes(*deposit_request_txid.as_ref());

                    info!(?operator_id, %txid, "queueing nag for root nonces");
                    Some(Command::RequestMessage(
                        GetMessageRequest::Musig2NoncesExchange {
                            session_id,
                            operator_pk: key.clone(),
                        },
                    ))
                }));

                if !commands.is_empty() {
                    all_commands.extend(commands.into_iter());
                    continue;
                }

                // Finally we can nag for the root sigs.
                let have = root_partials
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();
                commands.extend(want.difference(&have).filter_map(|key| {
                    let operator_id = self.cfg.operator_table.op_key_to_idx(key);
                    if operator_id.is_some_and(|idx| idx == pov_idx) {
                        return None;
                    }

                    let session_id = SessionId::from_bytes(*deposit_request_txid.as_ref());

                    info!(?operator_id, %txid, "queueing nag for root signatures");
                    Some(Command::RequestMessage(
                        GetMessageRequest::Musig2SignaturesExchange {
                            session_id,
                            operator_pk: key.clone(),
                        },
                    ))
                }));
            }
        }

        all_commands
    }
}

async fn execute_duty(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    duty: OperatorDuty,
) -> Result<(), ContractManagerErr> {
    let OutputHandles {
        msg_handler,
        synthetic_event_sender,
        s2_session_manager,
        db,
        tx_driver,
        ..
    } = &*output_handles;

    match duty {
        OperatorDuty::PublishStakeChainExchange => {
            handle_publish_stake_chain_exchange(cfg, &s2_session_manager.s2_client, db, msg_handler)
                .await
        }
        OperatorDuty::PublishDepositSetup {
            deposit_idx,
            deposit_txid,
            stake_chain_inputs,
        } => {
            handle_publish_deposit_setup(
                cfg,
                output_handles.clone(),
                deposit_txid,
                deposit_idx,
                stake_chain_inputs,
            )
            .await
        }
        OperatorDuty::PublishRootNonce {
            deposit_request_txid,
            witness,
            nonce,
        } => {
            handle_publish_root_nonce(
                &output_handles.s2_session_manager,
                &output_handles.msg_handler,
                OutPoint::new(deposit_request_txid, 0),
                witness,
                nonce,
            )
            .await
        }
        OperatorDuty::PublishGraphNonces {
            claim_txid,
            pog_prevouts: pog_inputs,
            pog_witnesses,
            nonces,
        } => {
            handle_publish_graph_nonces(
                s2_session_manager,
                msg_handler,
                claim_txid,
                pog_inputs,
                pog_witnesses,
                nonces,
            )
            .await
        }
        OperatorDuty::PublishGraphSignatures {
            claim_txid,
            pubnonces,
            pog_prevouts: pog_outpoints,
            pog_sighashes,
            partial_signatures,
        } => {
            handle_publish_graph_sigs(
                s2_session_manager,
                msg_handler,
                claim_txid,
                pubnonces,
                pog_outpoints,
                pog_sighashes,
                partial_signatures,
            )
            .await
        }
        OperatorDuty::CommitSig {
            deposit_txid,
            graph_partials,
            pog_inpoints,
            pog_sighash_types,
        } => {
            handle_commit_sig(
                cfg,
                deposit_txid,
                s2_session_manager,
                synthetic_event_sender,
                pog_inpoints,
                pog_sighash_types,
                graph_partials,
            )
            .await
        }
        OperatorDuty::PublishRootSignature {
            nonces,
            deposit_request_txid,
            sighash,
            partial_signature,
        } => {
            handle_publish_root_signature(
                cfg,
                s2_session_manager,
                msg_handler,
                nonces,
                OutPoint::new(deposit_request_txid, 0),
                sighash,
                partial_signature,
            )
            .await
        }
        OperatorDuty::PublishDeposit {
            deposit_tx,

            partial_sigs,
        } => {
            handle_publish_deposit(
                s2_session_manager,
                tx_driver,
                deposit_tx,
                partial_sigs
                    .into_iter()
                    .map(|(k, v)| (cfg.operator_table.op_key_to_btc_key(&k).unwrap(), v))
                    .collect(),
            )
            .await
        }
        OperatorDuty::FulfillerDuty(fulfiller_duty) => match fulfiller_duty {
            FulfillerDuty::AdvanceStakeChain {
                stake_index,
                stake_tx,
            } => match stake_tx {
                StakeTxKind::Head(stake_tx) => {
                    handle_publish_first_stake(cfg, output_handles, stake_tx).await
                }
                StakeTxKind::Tail(stake_tx) => {
                    handle_advance_stake_chain(cfg, output_handles, stake_index, stake_tx).await
                }
            },
            FulfillerDuty::PublishFulfillment {
                withdrawal_metadata,
                user_descriptor,
                deadline,
            } => {
                handle_withdrawal_fulfillment(
                    cfg,
                    output_handles,
                    withdrawal_metadata,
                    user_descriptor,
                    deadline,
                )
                .await
            }
            FulfillerDuty::PublishClaim {
                withdrawal_fulfillment_txid,
                stake_txid,
                deposit_txid,
            } => {
                handle_publish_claim(
                    cfg,
                    output_handles.clone(),
                    stake_txid,
                    deposit_txid,
                    withdrawal_fulfillment_txid,
                )
                .await
            }
            FulfillerDuty::PublishPayoutOptimistic {
                deposit_txid,
                claim_txid,
                stake_txid,
                stake_index,
                agg_sigs,
            } => {
                handle_publish_payout_optimistic(
                    cfg,
                    output_handles.clone(),
                    deposit_txid,
                    claim_txid,
                    stake_txid,
                    stake_index,
                    *agg_sigs,
                )
                .await
            }
            FulfillerDuty::PublishPreAssert {
                deposit_idx,
                deposit_txid,
                claim_txid,
                agg_sig,
            } => {
                handle_publish_pre_assert(
                    cfg,
                    output_handles.clone(),
                    deposit_idx,
                    deposit_txid,
                    claim_txid,
                    agg_sig,
                )
                .await
            }
            FulfillerDuty::PublishAssertData {
                start_height,
                withdrawal_fulfillment_txid,
                deposit_idx,
                deposit_txid,
                pre_assert_txid,
                pre_assert_locking_scripts,
            } => {
                handle_publish_assert_data(
                    cfg,
                    output_handles.clone(),
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
            }
            FulfillerDuty::PublishPostAssertData {
                deposit_txid,
                assert_data_txids,
                agg_sigs,
            } => {
                handle_publish_post_assert(
                    cfg,
                    output_handles.clone(),
                    deposit_txid,
                    *assert_data_txids,
                    *agg_sigs,
                )
                .await
            }
            FulfillerDuty::PublishPayout {
                deposit_idx,
                deposit_txid,
                stake_txid,
                claim_txid,
                post_assert_txid,
                agg_sigs,
            } => {
                handle_publish_payout(
                    cfg,
                    output_handles.clone(),
                    deposit_idx,
                    deposit_txid,
                    stake_txid,
                    claim_txid,
                    post_assert_txid,
                    *agg_sigs,
                )
                .await
            }
            FulfillerDuty::InitStakeChain => Err(TransitionErr(
                "received an InitStakeChain duty but it should only be invoked once at genesis"
                    .to_string(),
            )
            .into()),
        },
        OperatorDuty::Abort => {
            warn!("received an Abort duty, this should not happen in normal operation");

            unimplemented!("abort duty is not implemented yet");
        }
        OperatorDuty::VerifierDuty(verifier_duty) => {
            warn!(%verifier_duty, "ignoring verifier duty");

            Ok(())
        }
    }
}
