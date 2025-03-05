//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::collections::BTreeMap;

use bitcoin::{hashes::sha256d::Hash, Block, Txid};
use btc_notify::client::BtcZmqClient;
use futures::StreamExt;
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext, TxKind},
    params::prelude::StakeChainParams,
    types::OperatorIdx,
};
use strata_bridge_tx_graph::{
    errors::TxGraphError,
    peg_out_graph::{PegOutGraph, PegOutGraphInput, PegOutGraphSummary},
};
use strata_p2p::{self, events::Event, swarm::handle::P2PHandle};
use strata_p2p_wire::p2p::v1::{GossipsubMsg, UnsignedGossipsubMsg};
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::{
    contract_persister::{ContractPersister, PersistErr},
    contract_state_machine::{ContractEvent, ContractSM, OperatorDuty, TransitionErr},
    predicates::{deposit_request_info, is_rollup_commitment},
};

/// System that handles all of the chain and p2p events and forwards them to their respective
/// [`ContractSM`]s.
#[derive(Debug)]
pub struct ContractManager {
    thread_handle: JoinHandle<()>,
}
impl ContractManager {
    /// Initializes the ContractManager with the appropriate external event feeds and data stores.
    pub fn new(
        build_context: TxBuildContext,
        zmq_client: BtcZmqClient,
        mut p2p_handle: P2PHandle,
        contract_persister: ContractPersister,
    ) -> Self {
        let thread_handle = tokio::task::spawn(async move {
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
                Err(_) => {
                    todo!() // TODO(proofofkeags): probably wanna crash here?
                }
            };
            // TODO(proofofkeags): synchronize state with chain state

            let mut ctx = ContractManagerCtx {
                // TODO(proofofkeags): prune the active contract set and still preserve the ability
                // to recover this value.
                next_deposit_idx: active_contracts.len() as u32,
                build_context,
                contract_persister,
                active_contracts,
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

const REFUND_DELAY: u64 = 144;

/// Unified error type for everything that can happen in the ContractManager.
#[derive(Debug, Error)]
pub enum ContractManagerErr {
    /// Errors related to writing stuff to disk.
    #[error("failed to commit state to disk: {0}")]
    PersistErr(#[from] PersistErr),

    /// Errors related to state machines being unable to process ContractEvents
    #[error("state machine received an invalid event: {0}")]
    TransitionErr(#[from] TransitionErr),

    /// Errors related to PegOutGraph generation.
    #[error("peg out graph generation failed: {0}")]
    TxGraphError(#[from] TxGraphError),

    /// Errors related to receiving P2P messages at protocol-invalid times.
    #[error("invalid p2p message: {0:?}")]
    InvalidP2PMessage(Box<UnsignedGossipsubMsg>),
}

struct ContractManagerCtx {
    next_deposit_idx: u32,
    build_context: TxBuildContext,
    contract_persister: ContractPersister,
    active_contracts: BTreeMap<Txid, ContractSM>,
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
            if let Some(deposit_info) = deposit_request_info(&tx) {
                let deposit_tx = match deposit_info.construct_signing_data(&self.build_context) {
                    Ok(data) => data.psbt.unsigned_tx,
                    Err(_) => {
                        // TODO(proofofkeags): what does this mean? @Rajil1213
                        continue;
                    }
                };

                let peg_out_graphs = self
                    .build_context
                    .pubkey_table()
                    .0
                    .iter()
                    .map(|(idx, key)| {
                        let input = PegOutGraphInput {
                            stake_outpoint: todo!(),                  // @Rajil1213
                            withdrawal_fulfillment_outpoint: todo!(), // @Rajil1213
                            stake_hash: todo!(),                      // @Rajil1213
                            operator_pubkey: key.x_only_public_key().0,
                            wots_public_keys: todo!(),
                        };
                        PegOutGraph::generate(
                            input,
                            &self.build_context,
                            deposit_tx.compute_txid(),
                            todo!(),
                            StakeChainParams::default(),
                            todo!(), // Where am I supposed to get these from @Rajil1213?
                        )
                        .map(|(graph, _)| (*idx, graph.summarize()))
                    })
                    .collect::<Result<BTreeMap<OperatorIdx, PegOutGraphSummary>, TxGraphError>>()?;
                let (sm, duty) = ContractSM::new(
                    self.build_context.own_index(),
                    self.build_context.pubkey_table().clone(),
                    height,
                    height + REFUND_DELAY,
                    deposit_tx,
                    peg_out_graphs,
                );

                self.contract_persister.init(sm.cfg(), sm.state()).await?;

                self.execute_duty(duty);

                // It's impossible for this transaction to be routable to another CSM so we move on
                continue;
            }

            if let Some(contract) = self.active_contracts.get_mut(&txid) {
                if let Ok(duty) = contract.process_contract_event(
                    ContractEvent::DepositConfirmation(tx, self.next_deposit_idx),
                ) {
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
            if let Some(duty) = contract.process_contract_event(ContractEvent::Block(height))? {
                duties.push(duty);
            }
        }

        for duty in duties {
            self.execute_duty(duty);
        }

        Ok(())
    }

    async fn process_p2p_message(&mut self, msg: GossipsubMsg) -> Result<(), ContractManagerErr> {
        match msg.unsigned {
            UnsignedGossipsubMsg::StakeChainExchange { .. } => todo!(),
            UnsignedGossipsubMsg::DepositSetup {
                scope, wots_pks, ..
            } => {
                let deposit_txid = Txid::from_raw_hash(*Hash::from_bytes_ref(scope.as_ref()));
                if let Some(contract) = self.active_contracts.get_mut(&deposit_txid) {
                    if let Some(duty) = contract.process_contract_event(ContractEvent::WotsKeys(
                        msg.key,
                        Box::new(wots_pks),
                    ))? {
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
                        // TODO(proofofkeags): is this an error?
                        todo!()
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
