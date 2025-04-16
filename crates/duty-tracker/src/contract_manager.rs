//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bdk_wallet::miniscript::ToPublicKey;
use bitcoin::{hashes::sha256d, Block, Network, OutPoint, Transaction, Txid};
use btc_notify::client::BtcZmqClient;
use futures::StreamExt;
use operator_wallet::OperatorWallet;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::*;
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_btcio::rpc::{traits::ReaderRpc, BitcoinClient};
use strata_p2p::{
    self,
    commands::{Command, UnsignedPublishMessage},
    events::Event,
    swarm::handle::P2PHandle,
};
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId};
use strata_p2p_wire::p2p::v1::{GetMessageRequest, GossipsubMsg, UnsignedGossipsubMsg};
use strata_primitives::params::RollupParams;
use strata_state::{bridge_state::DepositState, chain_state::Chainstate};
use tokio::{
    sync::RwLock,
    task::{self, JoinHandle},
    time,
};
use tracing::{error, info, trace, warn};

use crate::{
    contract_persister::ContractPersister,
    contract_state_machine::{
        ContractEvent, ContractSM, DepositSetup, FulfillerDuty, OperatorDuty,
    },
    errors::{ContractManagerErr, StakeChainErr},
    executors::{
        handle_advance_stake_chain, handle_publish_deposit_setup, handle_withdrawal_fulfillment,
    },
    predicates::{deposit_request_info, parse_strata_checkpoint},
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
                    pegout_graph_params.clone(),
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

            let operator_pubkey = s2_client
                .general_wallet_signer()
                .pubkey()
                .await
                .expect("must be able to get stake chain wallet key")
                .to_x_only_pubkey();

            let stake_chains = match stake_chain_persister
                .load(&operator_table, operator_pubkey)
                .await
            {
                Ok(stake_chains) => {
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
                Ok(a) => a,
                Err(e) => {
                    crash(e.into());
                    return;
                }
            };

            // It's extremely unlikely that these will ever differ at all but it's possible for
            // them to differ by at most 1 in the scenario where we crash mid-batch when committing
            // contract state to disk.
            let mut cursor = active_contracts
                .iter()
                .min_by(|(_, sm1), (_, sm2)| {
                    sm1.state().block_height.cmp(&sm2.state().block_height)
                })
                .map(|(_, sm)| sm.state().block_height)
                .unwrap_or(current);

            let msg_handler = MessageHandler::new(p2p_handle.clone());
            let output_handles = Arc::new(OutputHandles {
                wallet: RwLock::new(wallet),
                msg_handler,
                s2_client,
                tx_driver,
                db,
            });
            let cfg = ExecutionConfig {
                network,
                connector_params,
                pegout_graph_params,
                stake_chain_params,
                sidesystem_params,
                operator_table,
            };
            let state_handles = StateHandles {
                contract_persister,
                stake_chain_persister,
            };
            let state = ExecutionState {
                active_contracts,
                stake_chains,
            };
            let mut ctx = ContractManagerCtx {
                cfg: cfg.clone(),
                state,
                state_handles,
            };

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
                match ctx.process_block(block).await {
                    Ok(duties) => {
                        duties.into_iter().for_each(|duty| {
                            info!(?duty, "starting duty execution from lagging blocks");
                            let cfg = cfg.clone();
                            let output_handles = output_handles.clone();
                            tokio::task::spawn(async move {
                                if let Err(e) = execute_duty(cfg, output_handles, duty).await {
                                    error!(%e, "failed to execute duty");
                                }
                            });
                        });
                    }
                    Err(e) => {
                        error!(%blockhash, %cursor, %e, "failed to process block");
                        break;
                    }
                }

                cursor = next;
            }

            let mut block_sub = zmq_client.subscribe_blocks().await;
            let mut interval = time::interval(nag_interval);
            let pov_key = ctx.cfg.operator_table.pov_op_key().clone();
            loop {
                let mut duties = vec![];
                tokio::select! {
                    Some(block) = block_sub.next() => {
                        let blockhash = block.block_hash();
                        let block_height = block.bip34_block_height().expect("must have valid height");
                        info!(%blockhash, %block_height, "processing block");
                        match ctx.process_block(block).await {
                            Ok(block_duties) => {
                                let num_duties = block_duties.len();
                                info!(%blockhash, %block_height, %num_duties, "queueing duties generated by the block event for execution");
                                duties.extend(block_duties.into_iter());
                            },
                            Err(e) => {
                                error!(%blockhash, %block_height, ?e, "failed to process block");
                                break;
                            }
                        }
                    },
                    Some(event) = p2p_handle.next() => match event {
                        Ok(Event::ReceivedMessage(msg)) => {
                            if let Err(e) = ctx.process_p2p_message(msg.clone()).await {
                                error!(%e, "failed to process p2p msg");
                                break;
                            }
                        },
                        Ok(Event::ReceivedRequest(req)) => match req {
                            GetMessageRequest::StakeChainExchange { stake_chain_id, .. } => {
                                // TODO(proofofkeags): actually choose the correct stake chain
                                // inputs based off the stake chain id we receive.
                                if let Some(inputs) = ctx.state.stake_chains
                                    .state()
                                    .get(ctx.cfg.operator_table.pov_op_key()) {

                                    let exchange = UnsignedPublishMessage::StakeChainExchange {
                                        stake_chain_id,
                                        pre_stake_txid: inputs.pre_stake_outpoint.txid,
                                        pre_stake_vout: inputs.pre_stake_outpoint.vout
                                    };

                                    p2p_handle.send_command(
                                        Command::PublishMessage(
                                            p2p_handle.sign_message(exchange)
                                        )
                                    ).await;
                                }
                            },
                            GetMessageRequest::DepositSetup { scope, .. } => {
                                let deposit_txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(scope.as_ref()));
                                let stake_chain_inputs = ctx.state.stake_chains.state().get(&pov_key).expect("our p2p key must exist in the operator table").clone();

                                if let Some(deposit_idx) = ctx.state.active_contracts.get(&deposit_txid).map(|sm| sm.cfg().deposit_idx) {
                                    let duty = OperatorDuty::PublishDepositSetup {
                                        deposit_txid,
                                        deposit_idx,
                                        stake_chain_inputs,
                                    };

                                    duties.push(duty);
                                } else {
                                    warn!(%deposit_txid, "received deposit setup message for unknown contract");
                                }
                            },
                            GetMessageRequest::Musig2NoncesExchange { session_id, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(
                                    *sha256d::Hash::from_bytes_ref(session_id.as_ref())
                                );

                                if ctx.state.active_contracts.contains_key(&session_id_as_txid) {
                                    duties.push(OperatorDuty::PublishGraphNonces);
                                } else if ctx.state.active_contracts
                                    .values()
                                    .map(|sm| sm.deposit_request_txid())
                                    .any(|txid| txid == session_id_as_txid) {

                                    duties.push(OperatorDuty::PublishRootNonce);
                                } else {
                                    // otherwise ignore this message.
                                    warn!(txid=%session_id_as_txid, "received a musig2 nonces exchange for an unknown session");
                                }
                            }
                            GetMessageRequest::Musig2SignaturesExchange { session_id, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));

                                if ctx.state.active_contracts.contains_key(&session_id_as_txid) {
                                    duties.push(OperatorDuty::PublishGraphSignatures);
                                } else if ctx.state.active_contracts
                                    .values()
                                    .map(|sm| sm.deposit_request_txid())
                                    .any(|txid| txid == session_id_as_txid) {

                                    duties.push(OperatorDuty::PublishRootSignature);
                                } else {
                                    // otherwise ignore this message.
                                    warn!(txid=%session_id_as_txid, "received a musig2 signatures exchange for an unknown session");
                                }
                            }
                        }
                        Err(e) => {
                            error!("{}", e);
                        }
                    },
                    _ = interval.tick() => {
                        let nags = ctx.nag();
                        for nag in nags {
                            p2p_handle.send_command(nag).await;
                        }
                    }
                }

                duties.into_iter().for_each(|duty| {
                    info!(?duty, "starting duty execution from new blocks");

                    let cfg = cfg.clone();
                    let output_handles = output_handles.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = execute_duty(cfg, output_handles, duty).await {
                            error!(%e, "failed to execute duty");
                        }
                    });
                });
            }
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
    pub(super) s2_client: SecretServiceClient,
    pub(super) tx_driver: TxDriver,
    pub(super) db: SqliteDb,
}

/// The actual state that is being tracked by the [`ContractManager`].
#[derive(Debug)]
pub(super) struct ExecutionState {
    pub(super) active_contracts: BTreeMap<Txid, ContractSM>,
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
}

pub(super) struct ContractManagerCtx {
    pub(super) cfg: ExecutionConfig,
    pub(super) state_handles: StateHandles,
    pub(super) state: ExecutionState,
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
            let assignment_duties = self.process_assignments(&tx).await?;
            duties.extend(assignment_duties.into_iter());

            let txid = tx.compute_txid();
            if let Some(deposit_info) = deposit_request_info(
                &tx,
                &self.cfg.sidesystem_params,
                &self.cfg.pegout_graph_params,
                stake_index,
            ) {
                let deposit_request_txid = txid;
                let deposit_tx = match deposit_info.construct_signing_data(
                    &self.cfg.operator_table.tx_build_context(self.cfg.network),
                    &self.cfg.pegout_graph_params,
                    &self.cfg.sidesystem_params,
                ) {
                    Ok(data) => data.psbt.unsigned_tx,
                    Err(err) => {
                        error!(
                            ?deposit_info,
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
                let (sm, duty) = ContractSM::new(
                    self.cfg.network,
                    self.cfg.operator_table.clone(),
                    self.cfg.connector_params,
                    self.cfg.pegout_graph_params.clone(),
                    self.cfg.stake_chain_params,
                    height,
                    height + self.cfg.pegout_graph_params.refund_delay as u64,
                    stake_index,
                    deposit_request_txid,
                    deposit_tx,
                    stake_chain_inputs,
                );

                new_contracts.push(sm);
                duties.push(duty);

                // It's impossible for this transaction to be routable to another CSM so we move on
                continue;
            }

            if let Some(contract) = self.state.active_contracts.get_mut(&txid) {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                match contract.process_contract_event(ContractEvent::DepositConfirmation(tx)) {
                    Ok(Some(duty)) => duties.push(duty),
                    Ok(None) => trace!("this is fine"),
                    Err(e) => error!(%e, "failed to process deposit confirmation"),
                }

                continue;
            }

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
                        Ok(Some(duty)) => duties.push(duty),
                        Ok(None) => {
                            trace!(txid=%tx.compute_txid(), "no duty emitted when processing this transaction...this is fine 🔥")
                        }
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
            if let Some(duty) = contract.process_contract_event(ContractEvent::Block(height))? {
                duties.push(duty);
            }
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
            let chain_state = checkpoint.sidecar().chainstate();

            if let Ok(chain_state) = borsh::from_slice::<Chainstate>(chain_state) {
                let deposits_table = chain_state.deposits_table().deposits();

                let assigned_deposit_entries = deposits_table
                    .filter(|entry| matches!(entry.deposit_state(), DepositState::Dispatched(_)));

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
                        .stake_tx(pov_op_p2p_key, stake_index as usize)
                    else {
                        warn!(%stake_index, %pov_op_p2p_key, "deposit assigned but stake chain data missing");
                        continue;
                    };

                    match sm
                        .process_contract_event(ContractEvent::Assignment(entry.clone(), stake_tx))
                    {
                        Ok(Some(duty)) => {
                            info!("committing stake chain state");
                            self.state_handles
                                .stake_chain_persister
                                .commit_stake_data(
                                    &self.cfg.operator_table,
                                    self.state.stake_chains.state().clone(),
                                )
                                .await?;

                            duties.push(duty);
                        }
                        Ok(None) => {
                            info!(?entry, "no duty generated for assignment");
                        }
                        Err(e) => {
                            error!(%e, "could not generate duty for assignment event");
                            return Err(e)?;
                        }
                    }
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
        match msg.unsigned.clone() {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id,
                pre_stake_txid,
                pre_stake_vout,
            } => {
                let operator_id = self
                    .cfg
                    .operator_table
                    .op_key_to_idx(&msg.key)
                    .expect("sender must be in the operator table");

                self.state.stake_chains.process_exchange(
                    msg.key,
                    stake_chain_id,
                    OutPoint::new(pre_stake_txid, pre_stake_vout),
                )?;

                self.state_handles
                    .stake_chain_persister
                    .commit_prestake(operator_id, OutPoint::new(pre_stake_txid, pre_stake_vout))
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
                let deposit_txid =
                    Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(scope.as_ref()));
                let sender_id = self
                    .cfg
                    .operator_table
                    .op_key_to_idx(&msg.key)
                    .expect("sender must be in the operator table");

                info!(%sender_id, %index, %deposit_txid, %operator_pk, "received deposit setup message");

                if let Some(contract) = self.state.active_contracts.get_mut(&deposit_txid) {
                    let setup = DepositSetup {
                        index,
                        hash,
                        funding_outpoint: OutPoint::new(funding_txid, funding_vout),
                        operator_pk,
                        wots_pks: wots_pks.clone(),
                    };

                    info!(%deposit_txid, %sender_id, %index, "processing stake chain setup");
                    self.state
                        .stake_chains
                        .process_setup(msg.key.clone(), &setup)?;

                    info!(%deposit_txid, %sender_id, %index, "committing stake chain setup to disk");
                    self.state_handles
                        .stake_chain_persister
                        .commit_stake_data(
                            &self.cfg.operator_table,
                            self.state.stake_chains.state().clone(),
                        )
                        .await?;

                    let deposit_idx = contract.cfg().deposit_idx;
                    let stake_tx = self
                        .state
                        .stake_chains
                        .stake_tx(&msg.key, deposit_idx as usize)?
                        .ok_or(StakeChainErr::StakeTxNotFound(msg.key.clone(), deposit_idx))?;

                    if let Some(duty) =
                        contract.process_contract_event(ContractEvent::DepositSetup {
                            operator_p2p_key: msg.key.clone(),
                            operator_btc_key: self
                                .cfg
                                .operator_table
                                .op_key_to_btc_key(&msg.key)
                                .unwrap()
                                .x_only_public_key()
                                .0,
                            stake_hash: hash,
                            stake_tx,
                            wots_keys: Box::new(wots_pks),
                        })?
                    {
                        duties.push(duty);
                    }
                } else {
                    // One of the other operators has may have seen a DRT that we have not yet
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
                let txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));
                if let Some(contract) = self.state.active_contracts.get_mut(&txid) {
                    if let Some(duty) = contract
                        .process_contract_event(ContractEvent::GraphNonces(msg.key, nonces))?
                    {
                        duties.push(duty);
                    }
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
                    if let Some(duty) =
                        contract.process_contract_event(ContractEvent::RootNonce(msg.key, nonce))?
                    {
                        duties.push(duty);
                    }
                }

                Ok(duties)
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id,
                mut signatures,
            } => {
                let txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));
                if let Some(contract) = self.state.active_contracts.get_mut(&txid) {
                    if let Some(duty) = contract
                        .process_contract_event(ContractEvent::GraphSigs(msg.key, signatures))?
                    {
                        duties.push(duty);
                    }
                } else if let Some((_, contract)) = self
                    .state
                    .active_contracts
                    .iter_mut()
                    .find(|(_, contract)| contract.deposit_request_txid() == txid)
                {
                    if signatures.len() != 1 {
                        // TODO(proofofkeags): is this an error? For now we just ignore the message
                        // entirely.
                        return Err(ContractManagerErr::InvalidP2PMessage(Box::new(
                            msg.unsigned,
                        )));
                    }
                    let sig = signatures.pop().unwrap();
                    if let Some(duty) =
                        contract.process_contract_event(ContractEvent::RootSig(msg.key, sig))?
                    {
                        duties.push(duty);
                    }
                }

                Ok(duties)
            }
        }
    }

    /// Generates a list of all of the commands needed to acquire P2P messages needed to move a
    /// deposit from the requested to deposited states.
    fn nag(&self) -> Vec<Command> {
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
            .map(|operator_pk| {
                let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);
                Command::RequestMessage(GetMessageRequest::StakeChainExchange {
                    stake_chain_id,
                    operator_pk,
                })
            }),
        );

        for (txid, contract) in self.state.active_contracts.iter() {
            let state = &contract.state().state;
            if let crate::contract_state_machine::ContractState::Requested {
                deposit_request_txid,
                wots_keys,
                graph_nonces,
                graph_sigs,
                root_nonces,
                root_sigs,
                ..
            } = state
            {
                let mut commands = Vec::new();

                // Get all of the operator keys who have already given us their wots keys.
                let have = wots_keys
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();

                // Take the difference and add it to the list of things to nag.
                commands.extend(want.difference(&have).map(|key| {
                    let scope = Scope::from_bytes(*txid.as_ref());
                    Command::RequestMessage(GetMessageRequest::DepositSetup {
                        scope,
                        operator_pk: key.clone(),
                    })
                }));

                // We can simultaneously nag for the nonces as well.
                let have = graph_nonces
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();
                commands.extend(want.difference(&have).map(|key| {
                    let session_id = SessionId::from_bytes(*txid.as_ref());
                    Command::RequestMessage(GetMessageRequest::Musig2NoncesExchange {
                        session_id,
                        operator_pk: key.clone(),
                    })
                }));

                // If this is not empty then we can't nag for the next steps in the process.
                if !commands.is_empty() {
                    all_commands.extend(commands.into_iter());
                    continue;
                }

                // Otherwise we can move onto the graph signatures.
                let have = graph_sigs
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();
                commands.extend(want.difference(&have).map(|key| {
                    let session_id = SessionId::from_bytes(*txid.as_ref());
                    Command::RequestMessage(GetMessageRequest::Musig2SignaturesExchange {
                        session_id,
                        operator_pk: key.clone(),
                    })
                }));

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
                commands.extend(want.difference(&have).map(|key| {
                    let session_id = SessionId::from_bytes(*deposit_request_txid.as_ref());
                    Command::RequestMessage(GetMessageRequest::Musig2NoncesExchange {
                        session_id,
                        operator_pk: key.clone(),
                    })
                }));

                if !commands.is_empty() {
                    all_commands.extend(commands.into_iter());
                    continue;
                }

                // Finally we can nag for the root sigs.
                let have = root_sigs
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<P2POperatorPubKey>>();
                commands.extend(want.difference(&have).map(|key| {
                    let session_id = SessionId::from_bytes(*deposit_request_txid.as_ref());
                    Command::RequestMessage(GetMessageRequest::Musig2SignaturesExchange {
                        session_id,
                        operator_pk: key.clone(),
                    })
                }));
            }
        }

        all_commands
    }
}

async fn execute_duty(
    cfg: ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    duty: OperatorDuty,
) -> Result<(), ContractManagerErr> {
    match duty {
        OperatorDuty::PublishDepositSetup {
            deposit_idx,
            deposit_txid,
            stake_chain_inputs,
        } => {
            handle_publish_deposit_setup(
                &cfg,
                output_handles.clone(),
                deposit_idx,
                deposit_txid,
                stake_chain_inputs,
            )
            .await
        }
        OperatorDuty::FulfillerDuty(fulfiller_duty) => match fulfiller_duty {
            FulfillerDuty::AdvanceStakeChain {
                stake_index,
                stake_tx,
            } => {
                handle_advance_stake_chain(&cfg, output_handles.clone(), stake_index, stake_tx)
                    .await
            }
            FulfillerDuty::PublishFulfillment {
                withdrawal_metadata,
                user_descriptor,
            } => {
                handle_withdrawal_fulfillment(
                    cfg,
                    output_handles,
                    withdrawal_metadata,
                    user_descriptor,
                )
                .await
            }
            ignored_fulfiller_duty => {
                warn!(?ignored_fulfiller_duty, "ignoring fulfiller duty");
                Ok(())
            }
        },
        ignored_duty => {
            warn!(?ignored_duty, "ignoring duty");
            Ok(())
        }
    }
}
