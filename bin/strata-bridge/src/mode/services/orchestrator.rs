//! Provides orchestrator initialization.

use std::{cmp, collections::VecDeque, num::NonZero, sync::Arc, time::Duration};

use anyhow::anyhow;
use bitcoin::relative;
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::{client::BtcNotifyHealthEvent, tx_driver::TxDriver};
use jsonrpsee::http_client::HttpClient;
use libp2p_identity::ed25519::Keypair;
use operator_wallet::{OperatorWallet, SqliteStore};
use secret_service_client::SecretServiceClient;
use strata_bridge_asm_events::client::{AsmEventFeed, AsmFeedHealthEvent};
use strata_bridge_common::params::Params;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_exec::{
    config::ExecutionConfig,
    cpfp::{
        adapters::{
            BitcoindCpfpMempool, OperatorWalletCpfpAdapter, build_anchor_input_signer,
            build_multi_anchor_signer, build_wallet_input_signer,
        },
        ladder::CpfpContext,
        observability,
    },
    fees::{FeeQuoteMemo, FeeTargetPolicy},
    output_handles::OutputHandles,
};
use strata_bridge_orchestrator::{
    duty_dispatcher::DutyDispatcher, events_mux::EventsMux, persister::Persister,
    pipeline::Pipeline, sm_registry::SMConfig,
};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_proof::BridgeProofHost;
use strata_bridge_sm::{
    self, deposit::config::DepositSMCfg, graph::config::GraphSMCfg, stake::config::StakeSMCfg,
};
use strata_bridge_tx_graph::{
    game_graph::{AdminMultisig, ProtocolParams as TxGraphProtocolParams},
    stake_graph::ProtocolParams as StakeGraphProtocolParams,
};
use strata_mosaic_client_api::{MosaicClientApi, types::COUNTERPROOF_N_DATA};
use strata_p2p::swarm::handle::{GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tokio::{
    select,
    sync::{Mutex, RwLock, mpsc, oneshot},
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
        operator_wallet::sync_wallet_on_new_blocks,
        startup_checks::FeeLimits,
    },
};

#[expect(clippy::too_many_arguments)]
pub(crate) async fn init_orchestrator<M>(
    params: &Params,
    config: &Config,
    fee_limits: FeeLimits,
    operator_table: OperatorTable,
    s2_client: &SecretServiceClient,
    mosaic_client: Arc<M>,
    gossip_handle: GossipHandle,
    req_resp_handle: ReqRespHandle,
    p2p_keypair: Keypair,
    wallet: Arc<RwLock<OperatorWallet<SqliteStore>>>,
    btc_rpc_client: BitcoinClient,
    asm_rpc_client: HttpClient,
    bridge_proof_host: BridgeProofHost,
    counterproof_host: BridgeCounterproofHost,
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

    // Replay the minimum persisted height itself: existing cursors may have committed that
    // block before a newly created deposit/graph group, which cannot contribute to the minimum
    // while absent. DRT outpoint deduplication preserves deposits that already committed.
    // First-pass cursors prevent older replay from admitting DRTs with later stake state.
    let start_height = registry
        .earliest_processed_block_height()
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

    let wallet_block_sub = zmq_client.subscribe_blocks().await;
    let sync_wallet = wallet.clone();
    executor.spawn_critical_async_with_shutdown(
        "operator-wallet-sync",
        |shutdown_guard| async move {
            select! {
                _ = shutdown_guard.wait_for_shutdown() => {}
                _ = sync_wallet_on_new_blocks(sync_wallet, wallet_block_sub) => {}
            }
            Ok(())
        },
    );

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
        pending_asm_events: VecDeque::new(),
    };

    let btc_rpc_arc = Arc::new(btc_rpc_client.clone());

    // One fee quote memo serves the executors and the CPFP bump loop below. Its first read happens
    // on the first use, so a source that does not answer stops nothing at boot.
    let fee_source = config
        .fee_source
        .build(btc_rpc_arc.clone())
        .map_err(|e| anyhow!("failed to construct fee source from config: {e}"))?;
    let fee_quotes = Arc::new(FeeQuoteMemo::new(fee_source));

    let fee_target = FeeTargetPolicy {
        premium_percent: config.cpfp_fee_premium_percent,
        min_package_fee_rate: fee_limits.min_package_fee_rate,
        max_fee_rate: fee_limits.max_fee_rate,
    };
    let exec_cfg = build_exec_config(params, config, fee_target, &sm_config, fee_quotes.clone());

    // CPFP wiring: bundle the wallet / shared fee-source / mempool / anchor-signer
    // adapters into a `CpfpContext` the tx-driver consumes for its bumps.
    //
    // `OutputHandles` carries the musig2 key to validate named anchors.
    let operator_musig2_pubkey = operator_table.pov_btc_key().x_only_public_key().0;

    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(wallet.clone()));
    let cpfp_mempool = Arc::new(BitcoindCpfpMempool::new(btc_rpc_arc.clone()));
    // Two distinct signers, bound to two distinct keys:
    //   - anchor inputs use the musig2-signer pubkey (the bridge tx-graph keys every KeyedAnchor to
    //     this pubkey — see `bridge-sm::graph::context::generate_key_data`).
    //   - wallet funding inputs use the general-wallet-signer pubkey (the key of
    //     `GeneralCustody::SecretService`). On a Fireblocks node the vault signs its own inputs
    //     first (`CpfpWallet::sign_owned_inputs`), and this signer takes only the inputs the wallet
    //     leaves unsigned, which is none unless an output pays the secret-service key.
    let anchor_input_signer = build_anchor_input_signer(s2_client.clone());
    // Script-path variant for `MultiAnchor` anchors (contest, bridge-proof-timeout): same
    // musig2 key, signed untweaked because the leaf is satisfied directly.
    let multi_anchor_signer = build_multi_anchor_signer(s2_client.clone());
    let wallet_input_signer = build_wallet_input_signer(s2_client.clone());
    observability::describe_metrics();
    let cpfp_ctx = CpfpContext {
        wallet: cpfp_wallet,
        fee_source: fee_quotes,
        anchor_input_signer,
        multi_anchor_signer,
        wallet_input_signer,
        // The executors read the same policy, so a parent funded at the target needs no child
        // until the target rises.
        policy: fee_target,
        mempool: cpfp_mempool,
    };
    let tx_driver = TxDriver::with_cpfp(
        zmq_client,
        btc_rpc_client.clone(),
        Arc::new(cpfp_ctx),
        config.cpfp_bump_check_interval,
    )
    .await;
    let tx_driver_health = tx_driver.health_handle();
    health_registry.mark_ok(COMPONENT_TX_DRIVER, "driver_initialized");
    spawn_tx_driver_probe(
        tx_driver_health,
        DEFAULT_HEALTH_PROBE_INTERVAL,
        health_registry.clone(),
    );
    let general_script_pubkey = wallet.read().await.general().script_pubkey();
    let output_handles = OutputHandles {
        wallet,
        claim_funding_refill: Mutex::new(()),
        msg_handler: RwLock::new(message_handler),
        db: fdb_client.clone(),
        bitcoind_rpc_client: btc_rpc_client.clone(),
        asm_rpc_client,
        s2_client: s2_client.clone(),
        tx_driver,
        mosaic_client,
        bridge_proof_host,
        counterproof_host,
        operator_musig2_pubkey,
        network: params.network,
        general_script_pubkey,
    };
    let duty_dispatcher = DutyDispatcher::new(exec_cfg.into(), output_handles.into());

    let nag_dedup_window = config.nag_dedup_window.unwrap_or(config.nag_interval / 2);
    if !nag_dedup_window.is_zero() && nag_dedup_window >= config.nag_interval {
        warn!(
            ?nag_dedup_window,
            nag_interval = ?config.nag_interval,
            "nag dedup window is not shorter than the nag interval; a peer's retry after a lost reply is dropped"
        );
    }
    let nag_dedup_in_flight_timeout = config
        .nag_dedup_in_flight_timeout
        .unwrap_or(config.nag_interval);
    let orchestrator_pipeline = Pipeline::new(
        events_mux,
        registry,
        persister,
        duty_dispatcher,
        btc_rpc_client,
        nag_dedup_window,
        nag_dedup_in_flight_timeout,
    );

    debug!("starting orchestrator pipeline");
    health_registry.mark_ok(COMPONENT_ORCHESTRATOR, "pipeline_spawned");
    spawn_orchestrator_stale_monitor(orchestrator_stale_after(config), health_registry.clone());
    let pipeline_health_registry = health_registry.clone();
    let registrations = params.keys.operators.clone();
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
                    .run_with_observer(operator_table, registrations, start_height, move || {
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
    let network = params.network;
    let magic_bytes = params.protocol.magic_bytes;
    let deposit_amount = params.protocol.deposit_amount;
    let operator_fee = params.protocol.operator_fee;

    // Fail fast on a mis-set sweep_fee_rate instead of panicking at sweep time.
    strata_bridge_tx_graph::fee::sweep_payout_value(params.protocol.sweep_fee_rate, deposit_amount)
        .expect("sweep_fee_rate must leave a sweep payout above dust");

    let deposit_config = DepositSMCfg {
        network,
        cooperative_payout_timeout_blocks: config.cooperative_payout_timeout as u64,
        deposit_amount,
        operator_fee,
        magic_bytes,
        recovery_delay: params.protocol.recovery_delay,
        sweep_fee_rate: params.protocol.sweep_fee_rate,
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
            .operators
            .iter()
            .map(|operator| (operator.index(), operator.payout_descriptor().clone()))
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
        max_active_deposits: config.max_active_deposits,
        deposit_index_offset: params.protocol.deposit_index_offset,
    }
}

fn build_exec_config(
    params: &Params,
    config: &Config,
    fee_target: FeeTargetPolicy,
    sm_config: &SMConfig,
    fee_source: Arc<FeeQuoteMemo>,
) -> ExecutionConfig {
    ExecutionConfig {
        network: params.network,
        min_withdrawal_fulfillment_window: config.min_withdrawal_fulfillment_window,
        magic_bytes: params.protocol.magic_bytes,
        fee_target,
        operator_fee: params.protocol.operator_fee,
        stake_amount: params.protocol.stake_amount,
        funding_uxto_pool_size: config.operator_wallet.claim_funding_pool_size,
        bury_depth: u32::try_from(params.protocol.bury_depth).expect("bury depth fits in u32"),
        graph_sm_cfg: sm_config.graph.clone(),
        fee_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::test_config, mode::services::test_fixtures::test_params};

    #[test]
    fn sm_config_carries_the_protocol_deposit_index_offset() {
        let mut params = test_params();
        params.protocol.deposit_index_offset = 1200;
        assert_eq!(
            build_sm_config(&test_config(), &params).deposit_index_offset,
            1200,
            "The registry must allocate from the offset supplied in the protocol params"
        );
    }
}
