//! This module implements the top level ContractManager. This system is responsible for monitoring
//! and responding to chain events and operator p2p network messages according to the Strata Bridge
//! protocol rules.
use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::Duration,
};

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bdk_wallet::{error::CreateTxError, miniscript::ToPublicKey};
use bitcoin::{
    hashes::{sha256, sha256d, Hash as _},
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Block, FeeRate, Network, OutPoint, TapNodeHash, TapSighashType, Transaction, Txid,
};
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use btc_notify::client::BtcZmqClient;
use futures::{
    future::{join3, join_all, try_join_all},
    StreamExt,
};
use operator_wallet::{FundingUtxo, OperatorWallet};
use secret_service_client::{
    musig2::{Musig2FirstRound, Musig2SecondRound},
    SecretServiceClient,
};
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::ConnectorStake;
use strata_bridge_db::{
    errors::DbError, operator::OperatorDb, persistent::sqlite::SqliteDb, public::PublicDb,
};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::{
    build_context::{BuildContext, TxKind},
    deposit::DepositInfo,
    operator_table::OperatorTable,
    scripts::{
        prelude::drt_take_back,
        taproot::{create_message_hash, TaprootWitness},
    },
    wots::PublicKeys,
};
use strata_bridge_stake_chain::{
    prelude::{StakeTx, STAKE_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::StakeTxData,
};
use strata_bridge_tx_graph::{
    errors::TxGraphError,
    peg_out_graph::{PegOutGraph, PegOutGraphInput},
    transactions::prelude::CovenantTx,
};
use strata_btcio::rpc::{error::ClientError, traits::ReaderRpc, BitcoinClient};
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
use tokio::{sync::RwLock, task::JoinHandle, time};
use tracing::{error, info, warn};

use crate::{
    contract_persister::{ContractPersistErr, ContractPersister},
    contract_state_machine::{
        convert_g16_keys, ContractEvent, ContractSM, ContractState, DepositSetup, FulfillerDuty,
        OperatorDuty, TransitionErr,
    },
    errors::{ContractManagerErr, StakeChainErr},
    predicates::{deposit_request_info, parse_strata_checkpoint},
    stake_chain_persister::StakeChainPersister,
    stake_chain_state_machine::StakeChainSM,
    tx_driver::TxDriver,
};

/// Helper macro for loading a Musig2 round 1 nonce from the database or create by creating a new
/// session with the secret service.
macro_rules! get_or_create_nonce {
    ($self:expr, $outpoint:expr, $ordered_pubkeys:expr, $witness:expr) => {{
        if let Some(pubnonce) = $self
            .db
            .collected_pubnonces($outpoint.txid, $outpoint.vout)
            .await?
            .get(&$self.operator_table.pov_idx())
        {
            pubnonce.clone()
        } else {
            let r = get_or_set_ms2_session(&mut $self.s2_musig2_sessions, $outpoint, || async {
                $self
                    .s2_client
                    .musig2_signer()
                    .new_session(
                        $ordered_pubkeys.clone(),
                        $witness,
                        $outpoint.txid,
                        $outpoint.vout,
                    )
                    .await
                    .map(|inner| Musig2Round::Musig2FirstRound(inner.expect("valid first round")))
            })
            .await?;

            let Musig2Round::Musig2FirstRound(r1) = r else {
                todo!()
            };

            let our_nonce = r1.our_nonce().await?;

            $self
                .db
                .add_pubnonce(
                    $outpoint.txid,
                    $outpoint.vout,
                    $self.operator_table.pov_idx(),
                    our_nonce.clone(),
                )
                .await?;

            our_nonce
        }
    }};
}

macro_rules! generate_partial_sig {
    ($self:expr, $outpoint:expr, $pubnonces:expr, $nonce_idx:expr, $sighash:expr, $partial_sigs:expr) => {{
        let mut r1 = $self
            .s2_musig2_sessions
            .remove(&$outpoint)
            .unwrap()
            .r1_owned()
            .unwrap();

        for (operator, nonces) in &$pubnonces {
            r1.receive_pub_nonce(
                $self
                    .operator_table
                    .op_key_to_btc_key(operator)
                    .unwrap()
                    .to_x_only_pubkey(),
                nonces[$nonce_idx].clone(),
            )
            .await?
            .unwrap();
        }

        assert!(r1.is_complete().await?);
        let r2 = r1.finalize($sighash).await?.unwrap();
        let our_sig = r2.our_signature().await?;
        $self.s2_musig2_sessions.insert($outpoint, r2.into());
        $partial_sigs.push(our_sig);
        $nonce_idx += 1;
    }};
}

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
        tx_driver: TxDriver,
        mut p2p_handle: P2PHandle,
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
        s2_client: SecretServiceClient,
        wallet: OperatorWallet,
        db: SqliteDb,
    ) -> Self {
        let thread_handle = tokio::task::spawn(async move {
            let crash = |_e: ContractManagerErr| todo!();

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
                            let cfg = cfg.clone();
                            let output_handles = output_handles.clone();
                            tokio::task::spawn(async move {
                                let _ = execute_duty(cfg, output_handles, duty).await;
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
                        match ctx.process_block(block).await {
                            Ok(block_duties) => {
                                duties.extend(block_duties.into_iter());
                            },
                            Err(e) => {
                                error!("failed to process block {}: {}", blockhash, e);
                                break;
                            }
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
                            }
                            GetMessageRequest::Musig2NoncesExchange { session_id, operator_pk, .. } => {
                                let session_id_as_txid = Txid::from_raw_hash(
                                    *sha256d::Hash::from_bytes_ref(session_id.as_ref())
                                );

                                if ctx.state.active_contracts.contains_key(&session_id_as_txid) {
                                    let pog = ctx.gen_pog(session_id_as_txid, operator_pk.clone()).expect("pog generation must succeed");
                                    duties.push(OperatorDuty::PublishGraphNonces {
                                        deposit_txid:session_id_as_txid,
                                        operator_p2p_key: operator_pk,
                                        pog,
                                    });
                                } else if let Some(csm) = ctx.state.active_contracts
                                    .values()
                                    .find(|sm| sm.deposit_request_txid() == session_id_as_txid) {

                                    duties.push(OperatorDuty::PublishRootNonce {
                                        deposit_request_txid: session_id_as_txid,
                                        takeback_key: *csm.cfg().deposit_info.x_only_public_key()
                                    });
                                } else {
                                    // otherwise ignore this message.
                                    warn!(txid=%session_id_as_txid, "received a musig2 nonces exchange for an unknown session");
                                }
                            }
                            GetMessageRequest::Musig2SignaturesExchange { session_id, operator_pk } => {
                                let session_id_as_txid = Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(session_id.as_ref()));

                                if ctx.state.active_contracts.contains_key(&session_id_as_txid) {
                                    let pog = ctx.gen_pog(session_id_as_txid, operator_pk).expect("pog generation must succeed");
                                    duties.push(OperatorDuty::PublishGraphSignatures {
                                        deposit_txid: session_id_as_txid,
                                        operator_p2p_key: operator_pk,
                                        pubnonces: todo!(),
                                        pog,
                                    });
                                } else if let Some(csm) = ctx.state.active_contracts
                                    .values()
                                    .find(|sm| sm.deposit_request_txid() == session_id_as_txid) {
                                    let nonces = match &csm.state().state {
                                        ContractState::Requested { root_nonces, .. } => root_nonces.clone(),
                                        invalid_state => {
                                            warn!(?invalid_state, "cannot send nonces if the contract is not in the requested state");
                                            BTreeMap::new()
                                        }
                                    };

                                    duties.push(OperatorDuty::PublishRootSignature { nonces, deposit_info: todo!() });
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

/// The handles required by the duty tracker to execute duties.
struct OutputHandles {
    wallet: RwLock<OperatorWallet>,
    msg_handler: MessageHandler,
    s2_client: SecretServiceClient,
    tx_driver: TxDriver,
    db: SqliteDb,
}

/// The actual state that is being tracked by the [`ContractManager`].
#[derive(Debug)]
struct ExecutionState {
    active_contracts: BTreeMap<Txid, ContractSM>,
    stake_chains: StakeChainSM,
}

/// The proxy for the state being tracked by the [`ContractManager`].
#[derive(Debug)]
struct StateHandles {
    contract_persister: ContractPersister,
    stake_chain_persister: StakeChainPersister,
}

/// The parameters that all duty executions depend upon.
#[derive(Debug, Clone)]
struct ExecutionConfig {
    network: Network,
    connector_params: ConnectorParams,
    pegout_graph_params: PegOutGraphParams,
    stake_chain_params: StakeChainParams,
    sidesystem_params: RollupParams,
    operator_table: OperatorTable,
}

struct ContractManagerCtx {
    cfg: ExecutionConfig,
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
        for tx in block.txdata {
            let assignment_duties = self.process_assignments(&tx).await?;
            duties.extend(assignment_duties.into_iter());

            let txid = tx.compute_txid();
            let stake_index = self.state.active_contracts.len() as u32;
            if let Some(deposit_info) = deposit_request_info(
                &tx,
                &self.cfg.sidesystem_params,
                &self.cfg.pegout_graph_params,
                stake_index,
            ) {
                let deposit_request_txid = txid;
                let deposit_tx = match deposit_info.construct_signing_data(
                    &self.cfg.operator_table.tx_build_context(self.cfg.network),
                    self.cfg.pegout_graph_params.deposit_amount,
                    Some(self.cfg.pegout_graph_params.tag.as_bytes()),
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

                // TODO(proofofkeags): prune the active contract set and still preserve the ability
                // to recover this value.
                let deposit_idx = self.state.active_contracts.len() as u32;
                let (sm, duty) = ContractSM::new(
                    self.cfg.network,
                    self.cfg.operator_table.clone(),
                    self.cfg.connector_params,
                    self.cfg.pegout_graph_params.clone(),
                    self.cfg.stake_chain_params,
                    height,
                    height + self.cfg.pegout_graph_params.refund_delay as u64,
                    deposit_idx,
                    deposit_request_txid,
                    deposit_tx,
                    deposit_info,
                );
                self.state_handles
                    .contract_persister
                    .init(sm.cfg(), sm.state())
                    .await?;

                self.state.active_contracts.insert(txid, sm);

                duties.push(duty);

                // It's impossible for this transaction to be routable to another CSM so we move on
                continue;
            }

            if let Some(contract) = self.state.active_contracts.get_mut(&txid) {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                if let Ok(duty) =
                    contract.process_contract_event(ContractEvent::DepositConfirmation(tx))
                {
                    self.state_handles
                        .contract_persister
                        .commit(&txid, contract.state())
                        .await?;
                    if let Some(duty) = duty {
                        duties.push(duty);
                    }
                }

                continue;
            }

            for (deposit_txid, contract) in self.state.active_contracts.iter_mut() {
                if contract.state().block_height >= height {
                    // Don't process events if we've already processed them.
                    continue;
                }

                if contract.transaction_filter(&tx) {
                    let duty = contract.process_contract_event(
                        ContractEvent::PegOutGraphConfirmation(tx.clone(), height),
                    )?;
                    self.state_handles
                        .contract_persister
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
        for (_, contract) in self.state.active_contracts.iter_mut() {
            if let Some(duty) = contract.process_contract_event(ContractEvent::Block(height))? {
                duties.push(duty);
            }
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
                if let Some(contract) = self.state.active_contracts.get_mut(&deposit_txid) {
                    let setup = DepositSetup {
                        index,
                        hash,
                        funding_outpoint: OutPoint::new(funding_txid, funding_vout),
                        operator_pk,
                        wots_pks: wots_pks.clone(),
                    };
                    self.state
                        .stake_chains
                        .process_setup(msg.key.clone(), &setup)?;

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

    fn gen_pog(
        &self,
        deposit_txid: Txid,
        operator_p2p_key: P2POperatorPubKey,
    ) -> Result<PegOutGraph, Result<(), ContractManagerErr>> {
        let Some(active_contract) = self.state.active_contracts.get(&deposit_txid) else {
            // this can only happen if some other operator is requesting nonces
            // and we have not yet observed the corresponding chain event.
            // so, it should be fine to ignore this error and allow the node to re-query our
            // node once we presumably observe the chain event.
            error!(
                ?deposit_txid,
                ?operator_p2p_key,
                "missing active contract for deposit txid"
            );
            return Err(Ok(())); // FIXME: @Zk2u dude what?
        };

        let stake_index = active_contract.cfg().deposit_idx;
        let pov_idx = self.cfg.operator_table.pov_idx();
        let operator_idx = self
            .cfg
            .operator_table
            .op_key_to_idx(&operator_p2p_key)
            .expect("operator key must be part of the operator table");

        let Some(stake_data) = self.state.stake_chains.state().get(&operator_p2p_key) else {
            error!(?operator_p2p_key, %pov_idx, %operator_idx, %deposit_txid, %stake_index, "missing stake data for operator");

            // ignore this error to let the client re-request this data in the future
            if pov_idx != operator_idx {
                return Err(Ok(()));
            }

            // otherwise, we have somehow lost our own stake data!
            return Err(Err(
                StakeChainErr::StakeSetupDataNotFound(operator_p2p_key).into()
            ));
        };

        let stake_input = stake_data
            .stake_inputs
            .iter()
            .nth(stake_index as usize)
            .expect("we should have a stake input for this operator");
        let Ok(Some(stake_tx)) = self
            .state
            .stake_chains
            .stake_tx(&operator_p2p_key, stake_index as usize)
        else {
            warn!(?operator_p2p_key, %pov_idx, %operator_idx, %deposit_txid, %stake_index, "missing stake tx for operator");

            // ignore this error to let the client re-request this data in the future
            return Err(Ok(()));
        };

        let stake_txid = stake_tx.compute_txid();
        let stake_outpoint = OutPoint::new(stake_txid, STAKE_VOUT);
        let withdrawal_fulfillment_outpoint =
            OutPoint::new(stake_txid, WITHDRAWAL_FULFILLMENT_VOUT);
        let wots_public_keys = match &active_contract.state().state {
            ContractState::Requested { wots_keys, .. } => {
                let Some(wots_keys) = wots_keys.get(&operator_p2p_key) else {
                    error!(%stake_index, %operator_idx, "wots data missing");
                    // we should always have our own data but it could be that we don't have
                    // the operator's wots key before their request for nonces reaches us.
                    // so, let them re-query our data.
                    return Err(Ok(()));
                };

                wots_keys.clone()
            }
            _ => unreachable!("this should only be called in the requested state"),
        };

        let input = PegOutGraphInput {
            stake_outpoint,
            withdrawal_fulfillment_outpoint,
            stake_hash: stake_input.hash,
            wots_public_keys: strata_bridge_primitives::wots::PublicKeys {
                withdrawal_fulfillment: strata_bridge_primitives::wots::Wots256PublicKey(
                    std::array::from_fn(|i| wots_public_keys.withdrawal_fulfillment[i]),
                ),
                groth16: convert_g16_keys(wots_public_keys.groth16.clone())
                    .expect("must have valid sizes"),
            },
            operator_pubkey: stake_data.operator_pubkey,
        };

        let (pog, _pog_conns) = PegOutGraph::generate(
            input,
            &self.cfg.operator_table.tx_build_context(self.cfg.network),
            deposit_txid,
            self.cfg.pegout_graph_params.clone(),
            self.cfg.connector_params,
            self.cfg.stake_chain_params,
            Vec::new(),
        )
        .expect("must be able to generate peg out graph");
        Ok(pog)
    }
}

async fn execute_duty(
    cfg: ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    duty: OperatorDuty,
) -> Result<(), ContractManagerErr> {
    let OutputHandles {
        wallet,
        msg_handler: p2p_handle,
        s2_client,
        tx_driver,
        db,
    } = &*output_handles;

    match duty {
        OperatorDuty::PublishDepositSetup {
            deposit_idx,
            deposit_txid,
            stake_chain_inputs,
        } => {
            let operator_pk = s2_client.general_wallet_signer().pubkey().await?;
            let wots_client = s2_client.wots_signer();
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
                .map(|result| result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes)))
                .collect::<Result<_, _>>()?;
            let fqs = fqs
                .into_iter()
                .map(|result| result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes)))
                .collect::<Result<_, _>>()?;
            let hashes = hashes
                .into_iter()
                .map(|result| result.map(|bytes| Wots128PublicKey::from_flattened_bytes(&bytes)))
                .collect::<Result<_, _>>()?;

            let wots_pks = WotsPublicKeys::new(withdrawal_fulfillment, public_inputs, fqs, hashes);

            let scope = Scope::from_bytes(deposit_txid.as_raw_hash().to_byte_array());

            let StakeChainInputs {
                stake_inputs,
                pre_stake_outpoint,
                ..
            } = stake_chain_inputs;

            let stakechain_preimg = s2_client
                .stake_chain_preimages()
                .get_preimg(
                    pre_stake_outpoint.txid,
                    pre_stake_outpoint.vout,
                    deposit_idx,
                )
                .await?;

            let stakechain_preimg_hash = sha256::Hash::hash(&stakechain_preimg);

            // check if there's a funding outpoint already for this stake index
            // otherwise, find a new unspent one from operator wallet and filter out all the
            // outpoints already in the db

            let ignore = stake_inputs
                .iter()
                .map(|input| input.operator_funds.to_owned())
                .collect::<HashSet<OutPoint>>();

            let mut wallet = wallet.write().await;
            let funding_op = wallet.claim_funding_utxo(|op| ignore.contains(&op));
            let funding_utxo = match funding_op {
                FundingUtxo::Available(outpoint) => outpoint,
                FundingUtxo::ShouldRefill { op, left } => {
                    info!("refilling stakechain funding utxos, have {left} left");
                    let psbt = wallet.refill_claim_funding_utxos(FeeRate::BROADCAST_MIN)?;
                    let mut tx = psbt.unsigned_tx;
                    let txins_as_outs = tx
                        .input
                        .iter()
                        .map(|txin| {
                            wallet
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
                            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
                            .expect("failed to construct sighash");
                        let signature = s2_client
                            .general_wallet_signer()
                            .sign(&sighash.to_byte_array(), None)
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

                    // FIXME: Use something other than 0.
                    tx_driver
                        .drive(tx, 0)
                        .await
                        .map_err(|e| ContractManagerErr::FatalErr(Box::new(e)))?;

                    op
                }
                FundingUtxo::Empty => {
                    panic!("aaaaaa there's no funding utxos for a new stake")
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
            db.add_stake_data(cfg.operator_table.pov_idx(), deposit_idx, stake_data)
                .await?;

            p2p_handle
                .send_deposit_setup(
                    deposit_idx,
                    scope,
                    stakechain_preimg_hash,
                    funding_utxo,
                    operator_pk,
                    wots_pks,
                )
                .await;

            let wots_pks = WotsPublicKeys::new(withdrawal_fulfillment, public_inputs, fqs, hashes);

            let scope = Scope::from_bytes(deposit_txid.as_raw_hash().to_byte_array());

            let stakechain_preimg = output_handles
                .s2_client
                .stake_chain_preimages()
                .get_preimg(
                    stake_chain_inputs.pre_stake_outpoint.txid,
                    stake_chain_inputs.pre_stake_outpoint.vout,
                    deposit_idx,
                )
                .await?;

            let stakechain_preimg_hash = sha256::Hash::hash(&stakechain_preimg);

            // check if there's a funding outpoint already for this stake index
            // otherwise, find a new unspent one from operator wallet and filter out all the
            // outpoints already in the db

            let maybe_stake_data = output_handles
                .db
                .get_stake_data(cfg.operator_table.pov_idx(), deposit_idx)
                .await?;

            let funding_utxo = if let Some(sd) = maybe_stake_data {
                sd.operator_funds
            } else {
                let mut wallet = output_handles.wallet.write().await;
                let ignore = output_handles
                    .db
                    .get_all_stake_data(cfg.operator_table.pov_idx())
                    .await?
                    .into_iter()
                    .map(|data| data.operator_funds)
                    .collect::<HashSet<_>>();
                let funding_op = wallet.claim_funding_utxo(|op| ignore.contains(&op));
                match funding_op {
                    FundingUtxo::Available(outpoint) => outpoint,
                    FundingUtxo::ShouldRefill { op, left } => {
                        info!("refilling stakechain funding utxos, have {left} left");
                        let psbt = wallet.refill_claim_funding_utxos(FeeRate::BROADCAST_MIN)?;
                        let mut tx = psbt.unsigned_tx;
                        let txins_as_outs = tx
                            .input
                            .iter()
                            .map(|txin| {
                                wallet
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
                            let signature = output_handles
                                .s2_client
                                .general_wallet_signer()
                                .sign(&sighash.to_byte_array(), None)
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

                        // FIXME: Use something other than 0.
                        output_handles
                            .tx_driver
                            .drive(tx, 0)
                            .await
                            .map_err(|e| ContractManagerErr::FatalErr(Box::new(e)))?;

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
            output_handles
                .db
                .add_stake_data(cfg.operator_table.pov_idx(), deposit_idx, stake_data)
                .await?;

            output_handles
                .msg_handler
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
        OperatorDuty::PublishRootNonce {
            deposit_request_txid,
            takeback_key,
        } => {
            const VOUT: u32 = 0;

            if let Some(our_nonce) = output_handles
                .db
                .collected_pubnonces(deposit_request_txid, VOUT)
                .await?
                .get(&cfg.operator_table.pov_idx())
            {
                output_handles
                    .msg_handler
                    .send_musig2_nonces(
                        SessionId::from_bytes(deposit_request_txid.as_raw_hash().to_byte_array()),
                        vec![our_nonce.clone()],
                    )
                    .await;
                return Ok(());
            }

            let ordered_pubkeys = cfg
                .operator_table
                .tx_build_context(cfg.network)
                .pubkey_table()
                .0
                .values()
                .map(|pk| pk.to_x_only_pubkey())
                .collect();
            let drt_takeback_script =
                drt_take_back(takeback_key, cfg.pegout_graph_params.refund_delay);
            let session_id = OutPoint::new(deposit_request_txid, VOUT);

            let r = get_or_set_ms2_session(&mut self.s2_musig2_sessions, session_id, || async {
                output_handles
                    .s2_client
                    .musig2_signer()
                    .new_session(
                        ordered_pubkeys,
                        TaprootWitness::Tweaked {
                            tweak: TapNodeHash::from_script(
                                &drt_takeback_script,
                                LeafVersion::TapScript,
                            ),
                        },
                        deposit_request_txid,
                        0,
                    )
                    .await
                    .map(|inner| Musig2Round::Musig2FirstRound(inner.expect("valid first round")))
            })
            .await?;

            let Musig2Round::Musig2FirstRound(r1) = r else {
                // only possible when the database is modified externally
                // stop touching your database
                // it doesn't want to be touched
                unreachable!("the database doesn't want the tea") // https://youtu.be/oQbei5JGiT8
            };
            let our_nonce = r1.our_nonce().await?;

            output_handles
                .db
                .add_pubnonce(
                    deposit_request_txid,
                    VOUT,
                    cfg.operator_table.pov_idx(),
                    our_nonce,
                )
                .await?;

            output_handles
                .msg_handler
                .send_musig2_nonces(
                    SessionId::from_bytes(deposit_request_txid.as_raw_hash().to_byte_array()),
                    vec![our_nonce],
                )
                .await;

            Ok(())
        }

        OperatorDuty::PublishGraphNonces {
            deposit_txid,
            operator_p2p_key,
            pog,
        } => {
            let sighashes = pog.sighashes();
            let ordered_pubkeys = cfg
                .operator_table
                .tx_build_context(cfg.network)
                .pubkey_table()
                .0
                .values()
                .map(|pk| pk.to_x_only_pubkey())
                .collect::<Vec<_>>();

            // note that this will change as slash stake txs changes length
            let mut nonces = Vec::with_capacity(10);

            let outpoint = OutPoint::new(pog.challenge_tx.compute_txid(), 0);
            let our_nonce = get_or_create_nonce!(
                self,
                outpoint,
                ordered_pubkeys,
                pog.challenge_tx.witnesses()[outpoint.vout as usize].clone()
            );
            nonces.push(our_nonce);

            let outpoint = OutPoint::new(pog.assert_chain.pre_assert.compute_txid(), 0);
            let our_nonce = get_or_create_nonce!(
                self,
                outpoint,
                ordered_pubkeys,
                pog.assert_chain.pre_assert.witnesses()[outpoint.vout as usize].clone()
            );
            nonces.push(our_nonce);

            let post_assert_txid = pog.assert_chain.pre_assert.compute_txid();
            for input_idx in 0..sighashes.post_assert.len() {
                let outpoint = OutPoint::new(post_assert_txid, input_idx as u32);
                let our_nonce = get_or_create_nonce!(
                    self,
                    outpoint,
                    ordered_pubkeys,
                    pog.assert_chain.pre_assert.witnesses()[outpoint.vout as usize].clone()
                );
                nonces.push(our_nonce);
            }

            let payout_optimistic_txid = pog.payout_optimistic.compute_txid();
            for input_idx in 0..sighashes.payout_optimistic.len() {
                let outpoint = OutPoint::new(payout_optimistic_txid, input_idx as u32);
                let our_nonce = get_or_create_nonce!(
                    self,
                    outpoint,
                    ordered_pubkeys,
                    pog.payout_optimistic.witnesses()[outpoint.vout as usize].clone()
                );
                nonces.push(our_nonce);
            }

            let payout_txid = pog.payout_tx.compute_txid();
            for input_idx in 0..sighashes.payout.len() {
                let outpoint = OutPoint::new(payout_txid, input_idx as u32);
                let our_nonce = get_or_create_nonce!(
                    self,
                    outpoint,
                    ordered_pubkeys,
                    pog.payout_tx.witnesses()[outpoint.vout as usize].clone()
                );
                nonces.push(our_nonce);
            }

            let disprove_txid = pog.disprove_tx.compute_txid();
            let outpoint = OutPoint::new(disprove_txid, 0);
            let our_nonce = get_or_create_nonce!(
                self,
                outpoint,
                ordered_pubkeys,
                pog.payout_tx.witnesses()[outpoint.vout as usize].clone()
            );
            nonces.push(our_nonce);

            for slash_stake_idx in 0..sighashes.slash_stake.len() {
                let slash_stake_txid = pog.slash_stake_txs[slash_stake_idx].compute_txid();
                for input_idx in 0..sighashes.payout.len() {
                    let outpoint = OutPoint::new(slash_stake_txid, input_idx as u32);
                    let our_nonce = get_or_create_nonce!(
                        self,
                        outpoint,
                        ordered_pubkeys,
                        pog.payout_tx.witnesses()[input_idx].clone()
                    );
                    nonces.push(our_nonce);
                }
            }

            let session_id = SessionId::from_bytes(deposit_txid.to_byte_array());
            output_handles
                .msg_handler
                .send_musig2_nonces(session_id, nonces)
                .await;

            Ok(())
        }

        OperatorDuty::PublishGraphSignatures {
            deposit_txid,
            pubnonces,
            operator_p2p_key,
            pog,
        } => {
            let sighashes = pog.sighashes();

            let mut nonce_idx = 0;

            let mut partial_sigs = Vec::new();

            let outpoint = OutPoint::new(pog.challenge_tx.compute_txid(), 0);
            generate_partial_sig!(
                self,
                outpoint,
                pubnonces,
                nonce_idx,
                *sighashes.challenge.as_ref(),
                partial_sigs
            );

            let outpoint = OutPoint::new(pog.assert_chain.pre_assert.compute_txid(), 0);
            generate_partial_sig!(
                self,
                outpoint,
                pubnonces,
                nonce_idx,
                *sighashes.challenge.as_ref(),
                partial_sigs
            );

            for input_idx in 0..sighashes.post_assert.len() {
                let outpoint =
                    OutPoint::new(pog.assert_chain.pre_assert.compute_txid(), input_idx as u32);
                generate_partial_sig!(
                    self,
                    outpoint,
                    pubnonces,
                    nonce_idx,
                    *sighashes.challenge.as_ref(),
                    partial_sigs
                );
            }

            let payout_optimistic_txid = pog.payout_optimistic.compute_txid();
            for input_idx in 0..sighashes.payout_optimistic.len() {
                let outpoint = OutPoint::new(payout_optimistic_txid, input_idx as u32);
                generate_partial_sig!(
                    self,
                    outpoint,
                    pubnonces,
                    nonce_idx,
                    *sighashes.challenge.as_ref(),
                    partial_sigs
                );
            }

            let payout_txid = pog.payout_tx.compute_txid();
            for input_idx in 0..sighashes.payout.len() {
                let outpoint = OutPoint::new(payout_txid, input_idx as u32);
                generate_partial_sig!(
                    self,
                    outpoint,
                    pubnonces,
                    nonce_idx,
                    *sighashes.challenge.as_ref(),
                    partial_sigs
                );
            }

            let outpoint = OutPoint::new(pog.disprove_tx.compute_txid(), 0);
            generate_partial_sig!(
                self,
                outpoint,
                pubnonces,
                nonce_idx,
                *sighashes.challenge.as_ref(),
                partial_sigs
            );

            for slash_stake_idx in 0..sighashes.slash_stake.len() {
                let slash_stake_txid = pog.slash_stake_txs[slash_stake_idx].compute_txid();
                for input_idx in 0..sighashes.payout.len() {
                    let outpoint = OutPoint::new(slash_stake_txid, input_idx as u32);
                    generate_partial_sig!(
                        self,
                        outpoint,
                        pubnonces,
                        nonce_idx,
                        *sighashes.challenge.as_ref(),
                        partial_sigs
                    );
                }
            }

            output_handles.msg_handler.send_musig2_signatures(
                SessionId::from_bytes(deposit_txid.to_byte_array()),
                partial_sigs,
            );

            Ok(())
        }
        OperatorDuty::PublishRootSignature {
            nonces,
            deposit_info,
        } => {
            const VOUT: u32 = 0;
            let our_pubkey = cfg.operator_table.pov_op_key();
            let Entry::Occupied(mut entry) = self
                .s2_musig2_sessions
                .entry(*deposit_info.deposit_request_outpoint())
            else {
                todo!()
            };
            let Musig2Round::Musig2FirstRound(r1) = entry.get_mut() else {
                todo!()
            };
            for (p2p_key, nonce) in nonces
                .into_iter()
                .filter(|(p2p_pk, _)| p2p_pk != our_pubkey)
            {
                let musig2_pubkey = cfg
                    .operator_table
                    .op_key_to_btc_key(&p2p_key)
                    .expect("we should have a musig2 pubkey for this operator")
                    .to_x_only_pubkey();
                r1.receive_pub_nonce(musig2_pubkey, nonce).await?;
            }

            assert!(r1.is_complete().await?);
            let Musig2Round::Musig2FirstRound(r1) = entry.remove() else {
                todo!()
            };

            let maybe_tx_signing_data = deposit_info
                .construct_signing_data(
                    &cfg.operator_table.tx_build_context(cfg.network),
                    cfg.pegout_graph_params.deposit_amount,
                    Some(cfg.pegout_graph_params.tag.as_bytes()),
                )
                .expect("this should've already been checked when contract is instantiated");

            let deposit_psbt = &maybe_tx_signing_data.psbt;
            let mut sighash_cache = SighashCache::new(&maybe_tx_signing_data.psbt.unsigned_tx);
            let prevouts = deposit_psbt
                .inputs
                .iter()
                .map(|input| {
                    input
                        .witness_utxo
                        .as_ref()
                        .expect("must have been set")
                        .clone()
                })
                .collect::<Vec<_>>();
            let witness_type = &maybe_tx_signing_data.spend_path;
            let sighash_type = TapSighashType::All;
            let input_index = 0;

            let msg = create_message_hash(
                &mut sighash_cache,
                Prevouts::All(&prevouts),
                witness_type,
                sighash_type,
                input_index,
            )
            .expect("must be able to consturct the message hash for DT");

            let r2 = r1.finalize(*msg.as_ref()).await?.expect("round 2");
            let our_partial_sig = r2.our_signature().await?;
            self.s2_musig2_sessions.insert(
                *deposit_info.deposit_request_outpoint(),
                Musig2Round::Musig2SecondRound(r2),
            );

            output_handles
                .msg_handler
                .send_musig2_signatures(
                    SessionId::from_bytes(
                        deposit_info
                            .deposit_request_outpoint()
                            .txid
                            .as_raw_hash()
                            .to_byte_array(),
                    ),
                    vec![our_partial_sig],
                )
                .await;
            Ok(())
        }
        OperatorDuty::FulfillerDuty(FulfillerDuty::AdvanceStakeChain {
            stake_index,
            stake_tx,
        }) => handle_advance_stake_chain(&cfg, output_handles.clone(), stake_index, stake_tx).await,
        _ => Ok(()),
    }
}

async fn handle_advance_stake_chain(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_index: u32,
    stake_tx: StakeTx,
) -> Result<(), ContractManagerErr> {
    let operator_id = cfg.operator_table.pov_idx();
    let op_p2p_key = cfg.operator_table.pov_op_key();

    let pre_stake_outpoint = output_handles
        .db
        .get_pre_stake(operator_id)
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(op_p2p_key.clone()))?;

    let messages = stake_tx.sighashes();
    let funds_signature = output_handles
        .s2_client
        .general_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;

    let signed_stake_tx = if stake_index == 0 {
        // the first stake transaction spends the pre-stake which is locked by the key in the
        // stake-chain wallet
        let stake_signature = output_handles
            .s2_client
            .general_wallet_signer()
            .sign(messages[1].as_ref(), None)
            .await?;

        stake_tx.finalize_initial(funds_signature, stake_signature)
    } else {
        let pre_image_client = output_handles.s2_client.stake_chain_preimages();
        let OutPoint {
            txid: pre_stake_txid,
            vout: pre_stake_vout,
        } = pre_stake_outpoint;
        let prev_preimage = pre_image_client
            .get_preimg(pre_stake_txid, pre_stake_vout, stake_index - 1)
            .await?;
        let n_of_n_agg_pubkey = cfg
            .operator_table
            .tx_build_context(cfg.network)
            .aggregated_pubkey();
        let operator_pubkey = output_handles
            .s2_client
            .general_wallet_signer()
            .pubkey()
            .await?
            .to_x_only_pubkey();
        let stake_hash = pre_image_client
            .get_preimg(pre_stake_txid, pre_stake_vout, stake_index)
            .await?;
        let stake_hash = sha256::Hash::hash(&stake_hash);
        let StakeChainParams { delta, .. } = cfg.stake_chain_params;
        let prev_connector_s = ConnectorStake::new(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hash,
            delta,
            cfg.network,
        );

        // all the stake transactions except the first one are locked with the general wallet
        // signer.
        // this is a caveat of the fact that we only share one x-only pubkey during deposit
        // setup which is used for reimbursements/cpfp.
        // so instead of sharing ones, we can just reuse this key (which is part of a taproot
        // address).
        let stake_signature = output_handles
            .s2_client
            .stakechain_wallet_signer()
            .sign_no_tweak(messages[1].as_ref())
            .await?;

        stake_tx.finalize(
            &prev_preimage,
            funds_signature,
            stake_signature,
            prev_connector_s,
        )
    };

    let confirm_by = 1;
    // FIXME: (@Rajil1213) change this to the current block height
    // once the tx driver's deadline handling is implemented
    output_handles
        .tx_driver
        .drive(signed_stake_tx, confirm_by)
        .await?;

    Ok(())
}
enum Musig2Round {
    Musig2FirstRound(Musig2FirstRound),
    Musig2SecondRound(Musig2SecondRound),
}

impl From<Musig2FirstRound> for Musig2Round {
    fn from(r1: Musig2FirstRound) -> Self {
        Musig2Round::Musig2FirstRound(r1)
    }
}

impl From<Musig2SecondRound> for Musig2Round {
    fn from(r2: Musig2SecondRound) -> Self {
        Musig2Round::Musig2SecondRound(r2)
    }
}

impl Musig2Round {
    fn r1_mut(&mut self) -> Result<&mut Musig2FirstRound, &mut Musig2SecondRound> {
        match self {
            Musig2Round::Musig2FirstRound(r1) => Ok(r1),
            Musig2Round::Musig2SecondRound(r2) => Err(r2),
        }
    }
    fn r2_mut(&mut self) -> Result<&mut Musig2SecondRound, &mut Musig2FirstRound> {
        match self {
            Musig2Round::Musig2SecondRound(r2) => Ok(r2),
            Musig2Round::Musig2FirstRound(r1) => Err(r1),
        }
    }
    fn r1_owned(self) -> Result<Musig2FirstRound, Musig2SecondRound> {
        match self {
            Musig2Round::Musig2FirstRound(r1) => Ok(r1),
            Musig2Round::Musig2SecondRound(r2) => Err(r2),
        }
    }
    fn r2_owned(self) -> Result<Musig2SecondRound, Musig2FirstRound> {
        match self {
            Musig2Round::Musig2SecondRound(r2) => Ok(r2),
            Musig2Round::Musig2FirstRound(r1) => Err(r1),
        }
    }
}

async fn get_or_set_ms2_session<Func, Ftr>(
    hm: &mut HashMap<OutPoint, Musig2Round>,
    k: OutPoint,
    create: Func,
) -> Result<&Musig2Round, secret_service_proto::v1::traits::ClientError>
where
    Ftr: Future<Output = Result<Musig2Round, secret_service_proto::v1::traits::ClientError>>,
    Func: FnOnce() -> Ftr,
{
    // Check if the key exists first
    if hm.contains_key(&k) {
        // Get a reference after confirming existence
        return Ok(hm.get(&k).expect("Key exists"));
    }

    // If key doesn't exist, create and insert new value
    let v = create().await?;
    hm.insert(k, v);

    // Return reference to the newly inserted value
    Ok(hm.get(&k).expect("Key was just inserted"))
}
