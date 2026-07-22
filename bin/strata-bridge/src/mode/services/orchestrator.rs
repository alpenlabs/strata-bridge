//! Provides orchestrator initialization.

use std::{cmp, collections::VecDeque, num::NonZero, sync::Arc, time::Duration};

use anyhow::anyhow;
use bitcoin::{FeeRate, relative};
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::{client::BtcNotifyHealthEvent, tx_driver::TxDriver};
use jsonrpsee::http_client::HttpClient;
use libp2p_identity::ed25519::Keypair;
use secret_service_client::SecretServiceClient;
use strata_bridge_asm_events::client::{AsmEventFeed, AsmFeedHealthEvent};
use strata_bridge_common::params::Params;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_exec::{
    config::ExecutionConfig,
    output_handles::{NativeWallet, OutputHandles},
};
use strata_bridge_orchestrator::{
    duty_dispatcher::DutyDispatcher, events_mux::EventsMux, persister::Persister,
    pipeline::Pipeline, sm_registry::SMConfig,
};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_sm::{
    self, deposit::config::DepositSMCfg, graph::config::GraphSMCfg, stake::config::StakeSMCfg,
};
use strata_bridge_tx_graph::{
    game_graph::{AdminMultisig, ProtocolParams as TxGraphProtocolParams},
    stake_graph::ProtocolParams as StakeGraphProtocolParams,
};
use strata_mosaic_client_api::MosaicClientApi;
use strata_p2p::swarm::handle::{GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tokio::{
    select,
    sync::{RwLock, mpsc, oneshot},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    constants::DEFAULT_HEALTH_PROBE_INTERVAL,
    health::{
        COMPONENT_ASM_ASSIGNMENT_FEED, COMPONENT_ASM_SAFE_HARBOUR_FEED, COMPONENT_BITCOIN_ZMQ,
        COMPONENT_ORCHESTRATOR, COMPONENT_TX_DRIVER, HealthRegistry,
    },
    mode::services::{
        btc_client::init_zmq_client,
        health_probes::{spawn_orchestrator_stale_monitor, spawn_tx_driver_probe},
        startup_checks,
    },
};

#[expect(clippy::too_many_arguments)]
pub(crate) async fn init_orchestrator<M>(
    params: &Params,
    config: &Config,
    operator_table: OperatorTable,
    s2_client: &SecretServiceClient,
    mosaic_client: Arc<M>,
    gossip_handle: GossipHandle,
    req_resp_handle: ReqRespHandle,
    p2p_keypair: Keypair,
    wallet: Arc<RwLock<NativeWallet>>,
    claim_funding_utxo_value: bitcoin::Amount,
    btc_rpc_client: BitcoinClient,
    asm_rpc_client: HttpClient,
    fdb_client: Arc<FdbClient>,
    executor: &TaskExecutor,
    health_registry: HealthRegistry,
) -> anyhow::Result<()>
where
    M: MosaicClientApi + 'static,
{
    let persister = Persister::new(fdb_client.clone());
    let sm_config = build_sm_config(config, params);
    let registry = persister
        .recover_registry(sm_config.clone())
        .await
        .map_err(|e| anyhow!("failed to recover state machine registry from database: {e:?}"))?;

    let start_height = registry
        .get_deposit_ids()
        .iter()
        .filter_map(|dep_idx| {
            registry
                .get_deposit(dep_idx)?
                .state()
                .last_processed_block_height()
                .map(|height| height + 1)
        })
        .min()
        .unwrap_or(params.genesis_height);
    let zmq_health_registry = health_registry.clone();
    let zmq_client = init_zmq_client(
        config,
        params.protocol.bury_depth,
        start_height,
        move |event| match event {
            BtcNotifyHealthEvent::MessageReceived => {
                zmq_health_registry.mark_ok(COMPONENT_BITCOIN_ZMQ, "message_received")
            }
            BtcNotifyHealthEvent::MessageError => {
                zmq_health_registry.mark_unhealthy(COMPONENT_BITCOIN_ZMQ, "message_error")
            }
            BtcNotifyHealthEvent::StreamEnded => {
                zmq_health_registry.mark_unhealthy(COMPONENT_BITCOIN_ZMQ, "stream_ended")
            }
        },
    )
    .await?;
    health_registry.mark_ok(COMPONENT_BITCOIN_ZMQ, "client_connected");

    let (ouroboros_msg_sender, ouroboros_msg_receiver) = mpsc::unbounded_channel();
    let message_handler =
        MessageHandler::new(ouroboros_msg_sender, gossip_handle.clone(), p2p_keypair);

    debug!("initializing asm state feed");
    let asm_block_feed = zmq_client.subscribe_blocks().await;
    let feed_health_registry = health_registry.clone();
    let asm_feed = AsmEventFeed::new(asm_rpc_client.clone(), config.asm_rpc.clone())
        .with_health_observer(move |event| match event {
            AsmFeedHealthEvent::AssignmentsFetched => {
                feed_health_registry.mark_ok(COMPONENT_ASM_ASSIGNMENT_FEED, "assignments_fetched")
            }
            AsmFeedHealthEvent::AssignmentsFetchFailed => feed_health_registry
                .mark_unhealthy(COMPONENT_ASM_ASSIGNMENT_FEED, "assignments_fetch_failed"),
            AsmFeedHealthEvent::SafeHarbourFetched => feed_health_registry
                .mark_ok(COMPONENT_ASM_SAFE_HARBOUR_FEED, "safe_harbour_fetched"),
            AsmFeedHealthEvent::SafeHarbourFetchFailed => feed_health_registry
                .mark_unhealthy(COMPONENT_ASM_SAFE_HARBOUR_FEED, "safe_harbour_fetch_failed"),
        });
    let asm_feed = asm_feed.attach_block_stream(asm_block_feed);
    let asm_state_sub = asm_feed.subscribe_asm_state().await;
    info!("asm state feed initialized and subscribed to assignment and safe-harbour events");
    health_registry.mark_ok(COMPONENT_ASM_ASSIGNMENT_FEED, "assignments_subscribed");
    health_registry.mark_ok(COMPONENT_ASM_SAFE_HARBOUR_FEED, "safe_harbour_subscribed");

    let orchestrator_block_sub = zmq_client.subscribe_blocks().await;

    let mosaic_event_sub = mosaic_client.as_ref().subscribe_events().await;

    let nag_tick = tokio::time::interval_at(tokio::time::Instant::now(), config.nag_interval);
    let retry_tick = tokio::time::interval_at(tokio::time::Instant::now(), config.retry_interval);

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let events_mux = EventsMux {
        ouroboros_msg_rx: ouroboros_msg_receiver,
        shutdown_rx: Some(shutdown_receiver),
        block_sub: orchestrator_block_sub,
        asm_state_sub,
        mosaic_event_sub,
        gossip_handle,
        req_resp_handle,
        nag_tick,
        retry_tick,
        pending: VecDeque::new(),
    };

    let exec_cfg = build_exec_config(params, config, &sm_config, claim_funding_utxo_value);
    let tx_driver = TxDriver::new(zmq_client, btc_rpc_client.clone()).await;
    let tx_driver_health = tx_driver.health_handle();
    health_registry.mark_ok(COMPONENT_TX_DRIVER, "driver_initialized");
    spawn_tx_driver_probe(
        tx_driver_health,
        DEFAULT_HEALTH_PROBE_INTERVAL,
        health_registry.clone(),
    );
    let bridge_proof_host = strata_bridge_proof::build_host(&config.bridge_proof).await?;
    let counterproof_host = strata_bridge_counterproof::build_host(&config.counterproof).await?;
    if config.dev {
        warn!("dev mode: skipping bridge startup consistency checks");
    } else {
        startup_checks::verify(params, &bridge_proof_host, &counterproof_host)?;
    }
    let output_handles = OutputHandles {
        wallet,
        msg_handler: RwLock::new(message_handler),
        db: fdb_client.clone(),
        bitcoind_rpc_client: btc_rpc_client,
        asm_rpc_client,
        s2_client: s2_client.clone(),
        tx_driver,
        mosaic_client,
        bridge_proof_host,
        counterproof_host,
    };
    let duty_dispatcher = DutyDispatcher::new(exec_cfg.into(), output_handles.into());

    let orchestrator_pipeline = Pipeline::new(events_mux, registry, persister, duty_dispatcher);

    debug!("starting orchestrator pipeline");
    health_registry.mark_ok(COMPONENT_ORCHESTRATOR, "pipeline_spawned");
    spawn_orchestrator_stale_monitor(orchestrator_stale_after(config), health_registry.clone());
    let pipeline_health_registry = health_registry.clone();
    executor.spawn_critical_async_with_shutdown("orchestrator", |shutdown_guard| async move {
        let pipeline = orchestrator_pipeline;

        // Prevent asm_feed from being dropped so its background runner isn't aborted.
        let _asm_feed = asm_feed;

        select! {
            _shutdown_received = shutdown_guard.wait_for_shutdown() => {
                info!("shutdown signal received, initiating graceful shutdown");
                shutdown_sender.send(()).map_err(|e| anyhow!("failed to send shutdown signal to orchestrator pipeline: {e:?}"))?;

                Ok(())
            }

            // Handle pipeline completion (this should indicate an error as this is supposed to run indefinitely)
            pipeline_complete = tokio::task::spawn(async move {
                pipeline
                    .run_with_observer(operator_table, start_height, move || {
                        pipeline_health_registry.mark_ok(COMPONENT_ORCHESTRATOR, "event_processed");
                    })
                    .await
            }) => {
                match pipeline_complete {
                    Ok(Ok(())) => {
                        info!("orchestrator pipeline terminated");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        health_registry.mark_unhealthy(COMPONENT_ORCHESTRATOR, "pipeline_failed");
                        error!(error=?e, "orchestrator pipeline failed");
                        Err(e.into())
                    }
                    Err(e) => {
                        health_registry.mark_unhealthy(COMPONENT_ORCHESTRATOR, "pipeline_panicked");
                        error!(error=?e, "orchestrator pipeline task panicked");
                        Err(e.into())
                    }
                }
            }
        }
    });
    info!("orchestrator pipeline started");

    Ok(())
}

fn orchestrator_stale_after(config: &Config) -> Duration {
    let base_interval = cmp::max(config.nag_interval, config.retry_interval);
    base_interval.checked_mul(2).unwrap_or(base_interval)
}

pub(in crate::mode) fn build_sm_config(config: &Config, params: &Params) -> SMConfig {
    // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2665>
    // Import this from the counterproof module once it exists.
    const COUNTERPROOF_N_DATA: usize = 128 + 4; // proof bytes (groth16) + deposit_idx (4 bytes)
    let network = params.network;
    let magic_bytes = params.protocol.magic_bytes;
    let deposit_amount = params.protocol.deposit_amount;
    let operator_fee = params.protocol.operator_fee;

    let deposit_config = DepositSMCfg {
        network,
        cooperative_payout_timeout_blocks: config.cooperative_payout_timeout as u64,
        deposit_amount,
        operator_fee,
        magic_bytes,
        recovery_delay: params.protocol.recovery_delay,
    };

    let game_graph_params = TxGraphProtocolParams {
        network,
        magic_bytes,
        contest_timelock: relative::Height::from_height(params.protocol.contest_timelock),
        proof_timelock: relative::Height::from_height(params.protocol.proof_timelock),
        ack_timelock: relative::Height::from_height(params.protocol.ack_timelock),
        nack_timelock: relative::Height::from_height(params.protocol.nack_timelock),
        contested_payout_timelock: relative::Height::from_height(
            params.protocol.contested_payout_timelock,
        ),
        counterproof_n_data: NonZero::new(COUNTERPROOF_N_DATA)
            .expect("counterproof_n_data must be non-zero"),
        deposit_amount,
        stake_amount: params.protocol.stake_amount,
    };

    let graph_config = GraphSMCfg {
        game_graph_params,
        operator_fee,
        admin: AdminMultisig {
            pubkeys: params.keys.admin.pubkeys.clone(),
            threshold: params.keys.admin.threshold,
        },
        payout_descs: params
            .keys
            .covenant
            .iter()
            .map(|cov| cov.payout_descriptor.clone())
            .collect(),
        bridge_proof_predicate: params.protocol.bridge_proof_predicate.clone(),
        counterproof_predicate: params.protocol.counterproof_predicate.clone(),
    };

    let stake_config = StakeSMCfg {
        protocol_params: StakeGraphProtocolParams {
            network,
            magic_bytes,
            unstaking_timelock: relative::Height::from_height(params.protocol.unstaking_timelock),
            stake_amount: params.protocol.stake_amount,
        },
    };

    SMConfig {
        deposit: Arc::new(deposit_config),
        graph: Arc::new(graph_config),
        stake: Arc::new(stake_config),
    }
}

fn build_exec_config(
    params: &Params,
    config: &Config,
    sm_config: &SMConfig,
    claim_funding_utxo_value: bitcoin::Amount,
) -> ExecutionConfig {
    ExecutionConfig {
        network: params.network,
        min_withdrawal_fulfillment_window: config.min_withdrawal_fulfillment_window,
        magic_bytes: params.protocol.magic_bytes,
        maximum_fee_rate: FeeRate::from_sat_per_vb(config.max_fee_rate).unwrap(),
        operator_fee: params.protocol.operator_fee,
        stake_amount: params.protocol.stake_amount,
        claim_funding_utxo_value,
        funding_uxto_pool_size: config.operator_wallet.claim_funding_pool_size,
        graph_sm_cfg: sm_config.graph.clone(),
    }
}
