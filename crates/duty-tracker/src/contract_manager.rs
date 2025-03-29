//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams};
use bitcoin::{hashes::sha256d, Block, Network, OutPoint, Transaction, Txid};
use btc_notify::client::BtcZmqClient;
use futures::StreamExt;
use strata_bridge_primitives::{build_context::TxKind, operator_table::OperatorTable};
use strata_bridge_tx_graph::errors::TxGraphError;
use strata_btcio::rpc::{error::ClientError, traits::ReaderRpc, BitcoinClient};
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
use thiserror::Error;
use tokio::{task::JoinHandle, time};
use tracing::{error, warn};

use crate::{
    contract_persister::{ContractPersistErr, ContractPersister},
    contract_state_machine::{
        ContractEvent, ContractSM, DepositSetup, OperatorDuty, TransitionErr,
    },
    predicates::{deposit_request_info, parse_strata_checkpoint},
    stake_chain_persister::{StakeChainPersister, StakePersistErr},
    stake_chain_state_machine::{StakeChainErr, StakeChainSM},
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
    pub fn new(
        // Static Config Parameters
        network: Network,
        nag_interval: Duration,
        connector_params: ConnectorParams,
        pegout_graph_params: PegOutGraphParams,
        sidesystem_params: RollupParams,
        operator_table: OperatorTable,
        // Subsystem Handles
        zmq_client: BtcZmqClient,
        rpc_client: BitcoinClient,
        mut p2p_handle: P2PHandle,
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
    ) -> Self {
        let thread_handle = tokio::task::spawn(async move {
            let crash = |_e: ContractManagerErr| todo!();

            let active_contracts = match contract_persister.load_all().await {
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

            let stake_chains = match stake_chain_persister.load().await {
                Ok((loaded_operator_table, stake_chains)) => {
                    if loaded_operator_table == operator_table {
                        StakeChainSM::restore(network, loaded_operator_table, stake_chains)
                    } else {
                        crash(ContractManagerErr::ContractPersistErr(ContractPersistErr));
                        return;
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

            let mut ctx = ContractManagerCtx {
                // TODO(proofofkeags): prune the active contract set and still preserve the ability
                // to recover this value.
                network,
                operator_table,
                connector_params,
                pegout_graph_params,
                sidesystem_params,
                contract_persister,
                active_contracts,
                stake_chain_persister,
                stake_chains,
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
                if let Err(e) = ctx.process_block(block).await {
                    error!("failed to process block {}: {}", blockhash, e);
                    break;
                }

                cursor = next;
            }

            let mut block_sub = zmq_client.subscribe_blocks().await;
            let mut interval = time::interval(nag_interval);
            loop {
                tokio::select! {
                    Some(block) = block_sub.next() => {
                        let blockhash = block.block_hash();
                        if let Err(e) = ctx.process_block(block).await {
                            error!("failed to process block {}: {}", blockhash, e);
                            break;
                        }
                    },
                    Some(event) = p2p_handle.next() => match event {
                        Ok(Event::ReceivedMessage(msg)) => {
                            if let Err(e) = ctx.process_p2p_message(msg.clone()).await {
                                error!("failed to process p2p msg {:?}: {}", msg, e);
                                break;
                            }
                        },
                        Ok(Event::ReceivedRequest(req)) => match req {
                            GetMessageRequest::StakeChainExchange { stake_chain_id, .. } => {
                                // TODO(proofofkeags): actually choose the correct stake chain
                                // inputs based off the stake chain id we receive.
                                if let Some(inputs) = ctx.stake_chains
                                    .state()
                                    .get(ctx.operator_table.pov_op_key()) {
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
                            }
                            GetMessageRequest::DepositSetup { scope: _, .. } => {
                                ctx.execute_duty(OperatorDuty::PublishWOTSKeys);
                            }
                            GetMessageRequest::Musig2NoncesExchange { session_id, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(
                                    *sha256d::Hash::from_bytes_ref(session_id.as_ref())
                                );

                                if ctx.active_contracts.contains_key(&session_id_as_txid) {
                                    ctx.execute_duty(OperatorDuty::PublishGraphNonces);
                                } else if ctx.active_contracts
                                    .values()
                                    .map(|sm| sm.deposit_request_txid())
                                    .any(|txid| txid == session_id_as_txid) {

                                    ctx.execute_duty(OperatorDuty::PublishRootNonce);
                                }

                                // otherwise ignore this message.
                            }
                            GetMessageRequest::Musig2SignaturesExchange { session_id, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));

                                if ctx.active_contracts.contains_key(&session_id_as_txid) {
                                    ctx.execute_duty(OperatorDuty::PublishGraphSignatures);
                                } else if ctx.active_contracts
                                    .values()
                                    .map(|sm| sm.deposit_request_txid())
                                    .any(|txid| txid == session_id_as_txid) {

                                    ctx.execute_duty(OperatorDuty::PublishRootSignature);
                                }

                                // otherwise ignore this message.
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
            }
        });
        ContractManager { thread_handle }
    }
}
impl Drop for ContractManager {
    fn drop(&mut self) {
        self.thread_handle.abort();
    }
}

/// Unified error type for everything that can happen in the ContractManager.
#[derive(Debug, Error)]
pub enum ContractManagerErr {
    /// Errors related to writing contract state to disk.
    #[error("failed to commit contract state to disk: {0}")]
    ContractPersistErr(#[from] ContractPersistErr),

    /// Errors related to committing stake chain state to disk.
    #[error("failed to commit stake chain state to disk: {0}")]
    StakePersistErr(#[from] StakePersistErr),

    /// Errors related to state machines being unable to process ContractEvents
    #[error("contract state machine received an invalid event: {0}")]
    TransitionErr(#[from] TransitionErr),

    /// Errors related to events updating operators' stake chains.
    #[error("stake chain state machine received an invalid event: {0}")]
    StakeChainErr(#[from] StakeChainErr),

    /// Errors related to PegOutGraph generation.
    #[error("peg out graph generation failed: {0}")]
    TxGraphError(#[from] TxGraphError),

    /// Errors related to receiving P2P messages at protocol-invalid times.
    #[error("invalid p2p message: {0:?}")]
    InvalidP2PMessage(Box<UnsignedGossipsubMsg>),

    /// Errors related to calling Bitcoin Core's RPC interface.
    #[error("bitcoin core rpc call failed with: {0}")]
    BitcoinCoreRPCErr(#[from] ClientError),
}

struct ContractManagerCtx {
    network: Network,
    connector_params: ConnectorParams,
    pegout_graph_params: PegOutGraphParams,
    sidesystem_params: RollupParams,
    operator_table: OperatorTable,
    contract_persister: ContractPersister,
    stake_chain_persister: StakeChainPersister,
    active_contracts: BTreeMap<Txid, ContractSM>,
    stake_chains: StakeChainSM,
}

impl ContractManagerCtx {
    async fn process_block(&mut self, block: Block) -> Result<(), ContractManagerErr> {
        let height = block.bip34_block_height().unwrap_or(0);
        // TODO(proofofkeags): persist entire block worth of states at once. Ensure all the state
        // transitions succeed before committing them to disk.
        let mut duties = Vec::new();
        for tx in block.txdata {
            self.process_assignments(&tx)?;

            let txid = tx.compute_txid();
            let stake_index = self.active_contracts.len() as u32;
            if let Some(deposit_info) = deposit_request_info(
                &tx,
                &self.sidesystem_params,
                &self.pegout_graph_params,
                stake_index,
            ) {
                let deposit_request_txid = txid;
                let deposit_tx = match deposit_info.construct_signing_data(
                    &self.operator_table.tx_build_context(self.network),
                    self.pegout_graph_params.deposit_amount,
                    Some(self.pegout_graph_params.tag.as_bytes()),
                ) {
                    Ok(data) => data.psbt.unsigned_tx,
                    Err(_) => {
                        // TODO(proofofkeags): what does this mean? @Rajil1213
                        continue;
                    }
                };

                if self
                    .active_contracts
                    .contains_key(&deposit_tx.compute_txid())
                {
                    // We already processed this. Do not create another contract attached to this
                    // deposit txid.
                    continue;
                }

                // TODO(proofofkeags): prune the active contract set and still preserve the ability
                // to recover this value.
                let deposit_idx = self.active_contracts.len() as u32;
                let (sm, duty) = ContractSM::new(
                    self.network,
                    self.operator_table.clone(),
                    self.connector_params,
                    self.pegout_graph_params.clone(),
                    height,
                    height + self.pegout_graph_params.refund_delay as u64,
                    deposit_idx,
                    deposit_request_txid,
                    deposit_tx,
                );
                self.contract_persister.init(sm.cfg(), sm.state()).await?;

                self.active_contracts.insert(txid, sm);

                self.execute_duty(duty);

                // It's impossible for this transaction to be routable to another CSM so we move on
                continue;
            }

            if let Some(contract) = self.active_contracts.get_mut(&txid) {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                if let Ok(duty) =
                    contract.process_contract_event(ContractEvent::DepositConfirmation(tx))
                {
                    self.contract_persister
                        .commit(&txid, contract.state())
                        .await?;
                    if let Some(duty) = duty {
                        self.execute_duty(duty);
                    }
                }

                continue;
            }

            for (deposit_txid, contract) in self.active_contracts.iter_mut() {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                if contract.transaction_filter(&tx) {
                    let duty = contract.process_contract_event(
                        ContractEvent::PegOutGraphConfirmation(tx.clone(), height),
                    )?;
                    self.contract_persister
                        .commit(deposit_txid, contract.state())
                        .await?;
                    if let Some(duty) = duty {
                        duties.push(duty);
                    }
                }
            }
        }

        // Now that we've handled all the transaction level events, we should inform all the
        // CSMs that a new block has arrived
        for (_, contract) in self.active_contracts.iter_mut() {
            if let Some(duty) = contract.process_contract_event(ContractEvent::Block(height))? {
                duties.push(duty);
            }
        }

        for duty in duties {
            self.execute_duty(duty);
        }

        Ok(())
    }

    /// This function validates whether a transaction is a valid Strata checkpoint transaction,
    /// extracts any valid assigned deposit entries and produces the `Assignment` [`ContractEvent`]
    /// so that it can be processed further.
    fn process_assignments(&mut self, tx: &Transaction) -> Result<(), ContractManagerErr> {
        if let Some(checkpoint) = parse_strata_checkpoint(tx, &self.sidesystem_params) {
            let chain_state = checkpoint.sidecar().chainstate();

            if let Ok(chain_state) = borsh::from_slice::<Chainstate>(chain_state) {
                let deposits_table = chain_state.deposits_table().deposits();

                let assigned_deposit_entries = deposits_table
                    .filter(|entry| matches!(entry.deposit_state(), DepositState::Dispatched(_)));

                for entry in assigned_deposit_entries {
                    let deposit_txid = entry.output().outpoint().txid;

                    let sm = self
                        .active_contracts
                        .get_mut(&deposit_txid)
                        .expect("withdrawal info must be for an active contract");

                    sm.process_contract_event(ContractEvent::Assignment(entry.clone()))?;
                }
            }
        };

        Ok(())
    }

    async fn process_p2p_message(&mut self, msg: GossipsubMsg) -> Result<(), ContractManagerErr> {
        match msg.unsigned.clone() {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id,
                pre_stake_txid,
                pre_stake_vout,
            } => {
                self.stake_chains.process_exchange(
                    msg.key,
                    stake_chain_id,
                    OutPoint::new(pre_stake_txid, pre_stake_vout),
                )?;

                self.stake_chain_persister
                    .commit(self.stake_chains.state())
                    .await?;

                Ok(())
            }
            UnsignedGossipsubMsg::DepositSetup {
                scope,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => {
                let deposit_txid =
                    Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(scope.as_ref()));
                if let Some(contract) = self.active_contracts.get_mut(&deposit_txid) {
                    let setup = DepositSetup {
                        hash,
                        funding_outpoint: OutPoint::new(funding_txid, funding_vout),
                        operator_pk,
                        wots_pks: wots_pks.clone(),
                    };
                    self.stake_chains.process_setup(msg.key.clone(), &setup)?;
                    self.stake_chain_persister
                        .commit(self.stake_chains.state())
                        .await?;

                    let deposit_idx = contract.cfg().deposit_idx;
                    let stake_tx = if let Some(stake_tx) =
                        self.stake_chains.stake_tx(&msg.key, deposit_idx as usize)
                    {
                        stake_tx
                    } else {
                        return Err(ContractManagerErr::StakeChainErr(StakeChainErr));
                    };

                    if let Some(duty) =
                        contract.process_contract_event(ContractEvent::DepositSetup(
                            msg.key.clone(),
                            self.operator_table
                                .op_key_to_btc_key(&msg.key)
                                .unwrap()
                                .x_only_public_key()
                                .0,
                            hash,
                            stake_tx,
                            Box::new(wots_pks),
                        ))?
                    {
                        self.execute_duty(duty);
                    }
                } else {
                    // One of the other operators has may have seen a DRT that we have not yet
                    // seen
                    warn!(
                        "Received a P2P message about an unknown contract: {}",
                        deposit_txid
                    );
                }
                Ok(())
            }
            UnsignedGossipsubMsg::Musig2NoncesExchange {
                session_id,
                mut nonces,
            } => {
                let txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));
                if let Some(contract) = self.active_contracts.get_mut(&txid) {
                    if let Some(duty) = contract
                        .process_contract_event(ContractEvent::GraphNonces(msg.key, nonces))?
                    {
                        self.execute_duty(duty);
                    }
                } else if let Some((_, contract)) = self
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
                        self.execute_duty(duty);
                    }
                }

                Ok(())
            }
            UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id,
                mut signatures,
            } => {
                let txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));
                if let Some(contract) = self.active_contracts.get_mut(&txid) {
                    if let Some(duty) = contract
                        .process_contract_event(ContractEvent::GraphSigs(msg.key, signatures))?
                    {
                        self.execute_duty(duty);
                    }
                } else if let Some((_, contract)) = self
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
                        self.execute_duty(duty)
                    }
                }

                Ok(())
            }
        }
    }

    /// Generates a list of all of the commands needed to acquire P2P messages needed to move a
    /// deposit from the requested to deposited states.
    fn nag(&self) -> Vec<Command> {
        // Get the operator set as a whole.
        let want = self.operator_table.p2p_keys();

        let mut all_commands = Vec::new();
        all_commands.extend(
            want.difference(
                &self
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

        for (txid, contract) in self.active_contracts.iter() {
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

    fn execute_duty(&mut self, _duty: OperatorDuty) {
        todo!() // execute duty
    }
}
