//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Duration,
};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bitcoin::{
    hashes::{sha256, sha256d, Hash as _},
    sighash::{Prevouts, SighashCache},
    Block, FeeRate, Network, OutPoint, TapSighashType, Transaction, Txid,
};
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use btc_notify::client::BtcZmqClient;
use futures::{
    future::{join3, join_all},
    StreamExt,
};
use operator_wallet::{FundingUtxo, OperatorWallet};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::*;
use strata_bridge_db::{persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::{build_context::TxKind, operator_table::OperatorTable};
use strata_bridge_stake_chain::transactions::stake::StakeTxData;
use strata_btcio::rpc::{traits::ReaderRpc, BitcoinClient};
use strata_p2p::{
    self,
    commands::{Command, UnsignedPublishMessage},
    events::Event,
    swarm::handle::P2PHandle,
};
use strata_p2p_types::{
    P2POperatorPubKey, Scope, SessionId, StakeChainId, Wots128PublicKey, Wots256PublicKey,
    WotsPublicKeys,
};
use strata_p2p_wire::p2p::v1::{GetMessageRequest, GossipsubMsg, UnsignedGossipsubMsg};
use strata_primitives::params::RollupParams;
use strata_state::{bridge_state::DepositState, chain_state::Chainstate};
use tokio::{task::JoinHandle, time};
use tracing::{error, info, warn};

use crate::{
    contract_persister::ContractPersister,
    contract_state_machine::{ContractEvent, ContractSM, DepositSetup, OperatorDuty},
    errors::{ContractManagerErr, StakeChainErr},
    predicates::{deposit_request_info, parse_strata_checkpoint},
    stake_chain_persister::StakeChainPersister,
    stake_chain_state_machine::StakeChainSM,
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
        stake_chain_params: StakeChainParams,
        sidesystem_params: RollupParams,
        operator_table: OperatorTable,
        // Subsystem Handles
        zmq_client: BtcZmqClient,
        rpc_client: BitcoinClient,
        mut p2p_handle: P2PHandle,
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
        s2_client: SecretServiceClient,
        wallet: OperatorWallet,
        stakechain_prestake_utxo: OutPoint,
        db: SqliteDb,
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

            let mut ctx = ContractManagerCtx {
                // TODO(proofofkeags): prune the active contract set and still preserve the ability
                // to recover this value.
                network,
                operator_table,
                connector_params,
                pegout_graph_params,
                stake_chain_params,
                sidesystem_params,
                contract_persister,
                active_contracts,
                stake_chain_persister,
                stake_chains,
                wallet,
                s2_client,
                p2p_msg_handle: MessageHandler::new(p2p_handle.clone()),
                stakechain_prestake_utxo,
                db,
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
                            GetMessageRequest::DepositSetup { scope, .. } => {
                                let deposit_txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(scope.as_ref()));
                                if let Some(deposit_idx) = ctx.active_contracts.get(&deposit_txid).map(|sm| sm.cfg().deposit_idx) {
                                    match ctx.execute_duty(OperatorDuty::PublishDepositSetup {
                                        deposit_txid,
                                        deposit_idx,
                                    }).await {
                                        Ok(()) => { info!(%deposit_idx, %deposit_txid, "published deposit setup message"); },
                                        Err(e) => {
                                            // NOTE: might want to panic here.
                                            error!(%e, %deposit_idx, %deposit_txid, "could not publish deposit setup message");
                                        }
                                    }
                                } else {
                                    warn!(%deposit_txid, "received deposit setup message for unknown contract");
                                }
                            }
                            GetMessageRequest::Musig2NoncesExchange { session_id, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(
                                    *sha256d::Hash::from_bytes_ref(session_id.as_ref())
                                );

                                if ctx.active_contracts.contains_key(&session_id_as_txid) {
                                    let _ = ctx.execute_duty(OperatorDuty::PublishGraphNonces).await;
                                } else if ctx.active_contracts
                                    .values()
                                    .map(|sm| sm.deposit_request_txid())
                                    .any(|txid| txid == session_id_as_txid) {

                                    let _ = ctx.execute_duty(OperatorDuty::PublishRootNonce).await;
                                } else {
                                    // otherwise ignore this message.
                                    warn!(txid=%session_id_as_txid, "received a musig2 nonces exchange for an unknown session");
                                }
                            }
                            GetMessageRequest::Musig2SignaturesExchange { session_id, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));

                                if ctx.active_contracts.contains_key(&session_id_as_txid) {
                                    let _ = ctx.execute_duty(OperatorDuty::PublishGraphSignatures).await;
                                } else if ctx.active_contracts
                                    .values()
                                    .map(|sm| sm.deposit_request_txid())
                                    .any(|txid| txid == session_id_as_txid) {

                                    let _ = ctx.execute_duty(OperatorDuty::PublishRootSignature).await;
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

struct ContractManagerCtx {
    network: Network,
    connector_params: ConnectorParams,
    pegout_graph_params: PegOutGraphParams,
    stake_chain_params: StakeChainParams,
    sidesystem_params: RollupParams,
    operator_table: OperatorTable,
    contract_persister: ContractPersister,
    stake_chain_persister: StakeChainPersister,
    active_contracts: BTreeMap<Txid, ContractSM>,
    stake_chains: StakeChainSM,
    wallet: OperatorWallet,
    s2_client: SecretServiceClient,
    /// NOTE: DO NOT CALL .next() because it will mess with the contract manager and break shit
    p2p_msg_handle: MessageHandler,
    stakechain_prestake_utxo: OutPoint,
    db: SqliteDb,
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
                    self.stake_chain_params,
                    height,
                    height + self.pegout_graph_params.refund_delay as u64,
                    deposit_idx,
                    deposit_request_txid,
                    deposit_tx,
                );
                self.contract_persister.init(sm.cfg(), sm.state()).await?;

                self.active_contracts.insert(txid, sm);

                self.execute_duty(duty).await?;

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
                        self.execute_duty(duty).await?;
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
            self.execute_duty(duty).await?;
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

                Ok(())
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
                if let Some(contract) = self.active_contracts.get_mut(&deposit_txid) {
                    let setup = DepositSetup {
                        index,
                        hash,
                        funding_outpoint: OutPoint::new(funding_txid, funding_vout),
                        operator_pk,
                        wots_pks: wots_pks.clone(),
                    };
                    self.stake_chains.process_setup(msg.key.clone(), &setup)?;

                    self.stake_chain_persister
                        .commit_stake_data(&self.operator_table, self.stake_chains.state().clone())
                        .await?;

                    let deposit_idx = contract.cfg().deposit_idx;
                    let stake_tx = self
                        .stake_chains
                        .stake_tx(&msg.key, deposit_idx as usize)?
                        .ok_or(StakeChainErr::StakeTxNotFound(msg.key.clone(), deposit_idx))?;

                    if let Some(duty) =
                        contract.process_contract_event(ContractEvent::DepositSetup {
                            operator_p2p_key: msg.key.clone(),
                            operator_btc_key: self
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
                        self.execute_duty(duty).await?;
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
                        self.execute_duty(duty).await?;
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
                        self.execute_duty(duty).await?;
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
                        self.execute_duty(duty).await?;
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
                        self.execute_duty(duty).await?
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

    async fn execute_duty(&mut self, duty: OperatorDuty) -> Result<(), ContractManagerErr> {
        match duty {
            OperatorDuty::PublishDepositSetup {
                deposit_idx,
                deposit_txid,
            } => {
                let operator_pk = self.s2_client.general_wallet_signer().pubkey().await?;
                let wots_client = self.s2_client.wots_signer();
                /// VOUT is static because irrelevant so we're just gonna use 0
                const VOUT: u32 = 0;
                // withdrawal_fulfillment uses index 0
                let withdrawal_fulfillment = Wots256PublicKey::from_flattened_bytes(
                    &wots_client
                        .get_256_public_key(deposit_txid, VOUT, 0)
                        .await?,
                );
                const NUM_FQS: usize = NUM_U256;
                const NUM_PUB_INPUTS: usize = NUM_PUBS;
                const NUM_HASHES: usize = NUM_HASH;
                let public_inputs_ftrs: [_; NUM_PUB_INPUTS] = std::array::from_fn(|i| {
                    wots_client.get_256_public_key(deposit_txid, VOUT, i as u32)
                });
                let fqs_ftrs: [_; NUM_FQS] = std::array::from_fn(|i| {
                    wots_client.get_256_public_key(deposit_txid, VOUT, (i + NUM_PUB_INPUTS) as u32)
                });
                let hashes_ftrs: [_; NUM_HASHES] = std::array::from_fn(|i| {
                    wots_client.get_128_public_key(deposit_txid, VOUT, i as u32)
                });

                let (public_inputs, fqs, hashes) = join3(
                    join_all(public_inputs_ftrs),
                    join_all(fqs_ftrs),
                    join_all(hashes_ftrs),
                )
                .await;
                let public_inputs = public_inputs
                    .into_iter()
                    .map(|result| {
                        result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes))
                    })
                    .collect::<Result<_, _>>()?;
                let fqs = fqs
                    .into_iter()
                    .map(|result| {
                        result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes))
                    })
                    .collect::<Result<_, _>>()?;
                let hashes = hashes
                    .into_iter()
                    .map(|result| {
                        result.map(|bytes| Wots128PublicKey::from_flattened_bytes(&bytes))
                    })
                    .collect::<Result<_, _>>()?;

                let wots_pks =
                    WotsPublicKeys::new(withdrawal_fulfillment, public_inputs, fqs, hashes);

                let scope = Scope::from_bytes(deposit_txid.as_raw_hash().to_byte_array());

                let stakechain_preimg = self
                    .s2_client
                    .stake_chain_preimages()
                    .get_preimg(
                        self.stakechain_prestake_utxo.txid,
                        self.stakechain_prestake_utxo.vout,
                        deposit_idx,
                    )
                    .await?;

                let stakechain_preimg_hash = sha256::Hash::hash(&stakechain_preimg);

                // check if there's a funding outpoint already for this stake index
                // otherwise, find a new unspent one from operator wallet and filter out all the
                // outpoints already in the db

                let maybe_stake_data = self
                    .db
                    .get_stake_data(
                        self.operator_table.pov_idx(),
                        self.active_contracts.len() as u32,
                    )
                    .await?;

                let funding_utxo = if let Some(sd) = maybe_stake_data {
                    sd.operator_funds
                } else {
                    let ignore = self
                        .db
                        .get_all_stake_data(self.operator_table.pov_idx())
                        .await?
                        .into_iter()
                        .map(|data| data.operator_funds)
                        .collect::<HashSet<_>>();
                    let funding_op = self.wallet.claim_funding_utxo(|op| ignore.contains(&op));
                    match funding_op {
                        FundingUtxo::Available(outpoint) => outpoint,
                        FundingUtxo::ShouldRefill { op, left } => {
                            info!("refilling stakechain funding utxos, have {left} left");
                            let psbt = self
                                .wallet
                                .refill_claim_funding_utxos(FeeRate::BROADCAST_MIN)?;
                            let mut tx = psbt.unsigned_tx;
                            let txins_as_outs = tx
                                .input
                                .iter()
                                .map(|txin| {
                                    self.wallet
                                        .general_wallet()
                                        .get_utxo(txin.previous_output)
                                        .expect("always have this output because the wallet selected it in the first place")
                                        .txout
                                })
                                .collect::<Vec<_>>();
                            let mut sighasher = SighashCache::new(&mut tx);

                            let sighash_type = TapSighashType::All;
                            let prevouts = Prevouts::All(&txins_as_outs);
                            for input_index in 0..txins_as_outs.len() {
                                let sighash = sighasher
                                    .taproot_key_spend_signature_hash(
                                        input_index,
                                        &prevouts,
                                        sighash_type,
                                    )
                                    .expect("failed to construct sighash");
                                let signature = self
                                    .s2_client
                                    .general_wallet_signer()
                                    .sign(&sighash.to_byte_array())
                                    .await?;

                                let signature = bitcoin::taproot::Signature {
                                    signature,
                                    sighash_type,
                                };
                                sighasher
                                    .witness_mut(input_index)
                                    .expect("an input here")
                                    .push(signature.to_vec());
                            }

                            // todo! @zk2u broadcast refill tx

                            op
                        }
                        FundingUtxo::Empty => {
                            panic!("aaaaaa there's no funding utxos for a new stake")
                        }
                    }
                };

                let withdrawal_fulfillment_pk =
                    std::array::from_fn(|i| wots_pks.withdrawal_fulfillment[i]);
                let stake_data = StakeTxData {
                    operator_funds: funding_utxo,
                    hash: stakechain_preimg_hash,
                    withdrawal_fulfillment_pk: strata_bridge_primitives::wots::Wots256PublicKey(
                        withdrawal_fulfillment_pk,
                    ),
                };
                self.db
                    .add_stake_data(self.operator_table.pov_idx(), deposit_idx, stake_data)
                    .await?;

                self.p2p_msg_handle
                    .send_deposit_setup(
                        deposit_idx,
                        scope,
                        stakechain_preimg_hash,
                        funding_utxo,
                        operator_pk,
                        wots_pks,
                    )
                    .await;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
