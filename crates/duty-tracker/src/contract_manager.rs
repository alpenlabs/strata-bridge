use std::collections::BTreeMap;

use bitcoin::{hashes::sha256d::Hash, Block, Txid};
use btc_notify::client::BtcZmqClient;
use futures::StreamExt;
use strata_bridge_primitives::build_context::{BuildContext, TxBuildContext, TxKind};
use strata_p2p::{self, events::Event, swarm::handle::P2PHandle};
use strata_p2p_wire::p2p::v1::{GossipsubMsg, UnsignedGossipsubMsg};
use tokio::task::JoinHandle;

use crate::{
    contract_persister::{ContractPersister, PersistErr},
    contract_state_machine::{ContractEvent, ContractSM, TransitionErr},
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
                    debug_assert!(false, "Failed to load contracts");
                    BTreeMap::new()
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
                    Some(block) = block_sub.next() => if let Err(e) = ctx.process_block(block).await {
                        todo!() // TODO(proofofkeags): error handling
                    },
                    Some(event) = p2p_handle.next() => match event {
                        Ok(Event::ReceivedMessage(msg)) => if let Err(e) = ctx.process_p2p_message(msg).await {
                            todo!() // TODO(proofofkeags): error handling
                        },
                        Err(e) => todo!(),
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
struct ContractManagerErr;
impl From<PersistErr> for ContractManagerErr {
    fn from(value: PersistErr) -> Self {
        ContractManagerErr
    }
}
impl From<TransitionErr> for ContractManagerErr {
    fn from(value: TransitionErr) -> Self {
        ContractManagerErr
    }
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
                let (sm, duty) = ContractSM::new(
                    self.build_context.own_index(),
                    self.build_context.pubkey_table().clone(),
                    height,
                    height + REFUND_DELAY,
                    deposit_tx,
                    todo!(), // TODO(proofofkeags): generate all pegout graphs. Help @Rajil1213
                );

                self.contract_persister.init(sm.cfg(), sm.state()).await?;

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
                        todo!() // TODO(proofofkeags): execute duty
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
                        todo!() // TODO(proofofkeags): execute duty
                    }
                }
            }
        }

        // Now that we've handled all the transaction level events, we should inform all the
        // CSMs that a new block has arrived
        for (deposit_txid, contract) in self.active_contracts.iter_mut() {
            if let Some(duty) = contract.process_contract_event(ContractEvent::Block(height))? {
                todo!() // TODO(proofofkeags): execute duty
            }
        }

        Ok(())
    }

    async fn process_p2p_message(&mut self, msg: GossipsubMsg) -> Result<(), ContractManagerErr> {
        match msg.unsigned {
            UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id,
                info,
            } => todo!(),
            UnsignedGossipsubMsg::DepositSetup { scope, wots_pks } => {
                let deposit_txid = Txid::from_raw_hash(*Hash::from_bytes_ref(scope.as_ref()));
                if let Some(contract) = self.active_contracts.get_mut(&deposit_txid) {
                    if let Some(duty) = contract
                        .process_contract_event(ContractEvent::WotsKeys(msg.key, wots_pks))?
                    {
                        todo!() // TODO(proofofkeags): execute duty
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
                        todo!() // TODO(proofofkeags): execute duty
                    }
                } else if let Some((deposit_txid, contract)) = self
                    .active_contracts
                    .iter_mut()
                    .find(|(_, contract)| contract.deposit_request_txid() == txid)
                {
                    if nonces.len() != 1 {
                        // TODO(proofofkeags): is this an error?
                        todo!()
                    }
                    let nonce = nonces.pop().unwrap();
                    if let Some(duty) =
                        contract.process_contract_event(ContractEvent::RootNonce(msg.key, nonce))?
                    {
                        todo!() // TODO(proofofkeags): execute duty
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
                        todo!() // TODO(proofofkeags): execute duty
                    }
                } else if let Some((deposit_txid, contract)) = self
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
                        todo!() // TODO(proofofkeags): execute duty
                    }
                }

                Ok(())
            }
        }
    }
}
