//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::collections::BTreeMap;

use alpen_bridge_params::{
    prelude::{ConnectorParams, PegOutGraphParams},
    sidesystem::SideSystemParams,
};
use bitcoin::{hashes::sha256d::Hash, Block, Network, OutPoint, Txid};
use btc_notify::client::BtcZmqClient;
use futures::StreamExt;
use strata_bridge_primitives::{build_context::TxKind, operator_table::OperatorTable};
use strata_bridge_tx_graph::errors::TxGraphError;
use strata_p2p::{self, events::Event, swarm::handle::P2PHandle};
use strata_p2p_wire::p2p::v1::{GossipsubMsg, UnsignedGossipsubMsg};
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::{
    contract_persister::{ContractPersistErr, ContractPersister},
    contract_state_machine::{
        ContractEvent, ContractSM, DepositSetup, OperatorDuty, TransitionErr,
    },
    predicates::{deposit_request_info, is_rollup_commitment},
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
        network: Network,
        operator_table: OperatorTable,
        zmq_client: BtcZmqClient,
        tx_tag: Vec<u8>,
        connector_params: ConnectorParams,
        pegout_graph_params: PegOutGraphParams,
        sidesystem_params: SideSystemParams,
        mut p2p_handle: P2PHandle,
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
    ) -> Self {
        let thread_handle = tokio::task::spawn(async move {
            let crash = |e: ContractManagerErr| todo!();

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

            // TODO(proofofkeags): synchronize state with chain state

            let mut ctx = ContractManagerCtx {
                network,
                operator_table,
                tx_tag,
                connector_params,
                pegout_graph_params,
                sidesystem_params,
                contract_persister,
                active_contracts,
                stake_chain_persister,
                stake_chains,
            };

            let mut block_sub = zmq_client.subscribe_blocks().await;
            loop {
                tokio::select! {
                    Some(block) = block_sub.next() => {
                        let blockhash = block.block_hash();
                        if let Err(e) = ctx.process_block(block).await {
                            tracing::error!("failed to process block {}: {}", blockhash, e);
                            break;
                        }
                    },
                    Some(event) = p2p_handle.next() => match event {
                        Ok(Event::ReceivedMessage(msg)) => if let Err(e) = ctx.process_p2p_message(msg.clone()).await {
                            tracing::error!("failed to process p2p msg {:?}: {}", msg, e);
                            break;
                        },
                        Err(e) => {
                            tracing::error!("{}", e);
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
}

struct ContractManagerCtx {
    network: Network,
    tx_tag: Vec<u8>,
    connector_params: ConnectorParams,
    pegout_graph_params: PegOutGraphParams,
    sidesystem_params: SideSystemParams,
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
            if is_rollup_commitment(&tx) {
                todo!() // TODO(proofofkeags): handle the processing of the rollup commitment/state.
            }

            let txid = tx.compute_txid();
            let stake_index = self.active_contracts.len() as u32;
            if let Some(deposit_info) = deposit_request_info(
                &tx,
                &self.sidesystem_params,
                &self.pegout_graph_params,
                stake_index,
            ) {
                let deposit_tx = match deposit_info.construct_signing_data(
                    &self.operator_table.tx_build_context(self.network),
                    self.pegout_graph_params.deposit_amount,
                    Some(&self.tx_tag),
                ) {
                    Ok(data) => data.psbt.unsigned_tx,
                    Err(_) => {
                        // TODO(proofofkeags): what does this mean? @Rajil1213
                        continue;
                    }
                };

                // TODO(proofofkeags): prune the active contract set and still preserve the ability
                // to recover this value.
                let deposit_idx = self.active_contracts.len() as u32;
                let (sm, duty) = ContractSM::new(
                    self.network,
                    self.operator_table.clone(),
                    height,
                    height + self.pegout_graph_params.refund_delay as u64,
                    deposit_idx,
                    deposit_tx,
                );
                self.contract_persister.init(sm.cfg(), sm.state()).await?;

                self.active_contracts.insert(txid, sm);

                self.execute_duty(duty);

                // It's impossible for this transaction to be routable to another CSM so we move on
                continue;
            }

            if let Some(contract) = self.active_contracts.get_mut(&txid) {
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
                if contract.transaction_filter()(&tx) {
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
            if let Some(duty) = contract
                .process_contract_event(ContractEvent::Block(height, self.connector_params))?
            {
                duties.push(duty);
            }
        }

        for duty in duties {
            self.execute_duty(duty);
        }

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
                let deposit_txid = Txid::from_raw_hash(*Hash::from_bytes_ref(scope.as_ref()));
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
                }
                Ok(())
            }
            UnsignedGossipsubMsg::Musig2NoncesExchange {
                session_id,
                mut nonces,
            } => {
                let txid = Txid::from_raw_hash(*Hash::from_bytes_ref(session_id.as_ref()));
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
                let txid = Txid::from_raw_hash(*Hash::from_bytes_ref(session_id.as_ref()));
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

    fn execute_duty(&mut self, _duty: OperatorDuty) {
        todo!() // execute duty
    }
}
