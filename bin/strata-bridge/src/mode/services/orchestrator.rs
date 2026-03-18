//! Provides orchestrator initialization.

use std::{num::NonZero, sync::Arc};

use anyhow::anyhow;
use bitcoin::{FeeRate, relative};
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::tx_driver::TxDriver;
use libp2p_identity::ed25519::Keypair;
use operator_wallet::OperatorWallet;
use secret_service_client::SecretServiceClient;
use strata_bridge_asm_events::client::AsmEventFeed;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_exec::{config::ExecutionConfig, output_handles::OutputHandles};
use strata_bridge_orchestrator::{
    duty_dispatcher::DutyDispatcher, events_mux::EventsMux, persister::Persister,
    pipeline::Pipeline, sm_registry::SMConfig,
};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_sm::{self, deposit::config::DepositSMCfg, graph::config::GraphSMCfg};
use strata_bridge_tx_graph::game_graph::ProtocolParams as TxGraphProtocolParams;
use strata_p2p::swarm::handle::{GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tokio::{
    select,
    sync::{RwLock, mpsc, oneshot},
};
use tracing::{debug, error, info};

use crate::{config::Config, mode::services::btc_client::init_zmq_client, params::Params};

#[expect(clippy::too_many_arguments)]
pub(crate) async fn init_orchestrator(
    params: &Params,
    config: &Config,
    operator_table: OperatorTable,
    s2_client: &SecretServiceClient,
    gossip_handle: GossipHandle,
    req_resp_handle: ReqRespHandle,
    p2p_keypair: Keypair,
    wallet: OperatorWallet,
    btc_rpc_client: BitcoinClient,
    fdb_client: Arc<FdbClient>,
    executor: &TaskExecutor,
) -> anyhow::Result<()> {
    let persister = Persister::new(fdb_client.clone());
    let sm_config = build_sm_config(config, params);
    let registry = persister
        .recover_registry(sm_config)
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
    let zmq_client = init_zmq_client(config, start_height).await?;

    let (ouroboros_msg_sender, ouroboros_msg_receiver) = mpsc::unbounded_channel();
    let message_handler =
        MessageHandler::new(ouroboros_msg_sender, gossip_handle.clone(), p2p_keypair);

    debug!("initializing asm assignments feed");
    let asm_block_feed = zmq_client.subscribe_blocks().await;
    let asm_feed = AsmEventFeed::new(config.asm_rpc.clone());
    let asm_feed = asm_feed.attach_block_stream(asm_block_feed);
    let assignments_sub = asm_feed.subscribe_assignments_state().await;
    info!("asm assignments feed initialized and subscribed to assignment events");

    let orchestrator_block_sub = zmq_client.subscribe_blocks().await;

    let nag_tick = tokio::time::interval_at(tokio::time::Instant::now(), config.nag_interval);
    let retry_tick = tokio::time::interval_at(tokio::time::Instant::now(), config.retry_interval);

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let events_mux = EventsMux {
        ouroboros_msg_rx: ouroboros_msg_receiver,
        shutdown_rx: Some(shutdown_receiver),
        block_sub: orchestrator_block_sub,
        assignments_sub,
        gossip_handle,
        req_resp_handle,
        nag_tick,
        retry_tick,
    };

    let exec_cfg = build_exec_config(params, config);
    let tx_driver = TxDriver::new(zmq_client, btc_rpc_client.clone()).await;
    let output_handles = OutputHandles {
        wallet: RwLock::new(wallet),
        msg_handler: RwLock::new(message_handler),
        db: fdb_client.clone(),
        bitcoind_rpc_client: btc_rpc_client,
        s2_client: s2_client.clone(),
        tx_driver,
    };
    let duty_dispatcher = DutyDispatcher::new(exec_cfg.into(), output_handles.into());

    let orchestrator_pipeline = Pipeline::new(events_mux, registry, persister, duty_dispatcher);

    debug!("starting orchestrator pipeline");
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
                pipeline.run(operator_table).await
            }) => {
                match pipeline_complete {
                    Ok(Ok(())) => {
                        info!("orchestrator pipeline terminated");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        error!(error=?e, "orchestrator pipeline failed");
                        Err(e.into())
                    }
                    Err(e) => {
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

pub(super) fn build_sm_config(config: &Config, params: &Params) -> SMConfig {
    // FIXME: <https://atlassian.alpenlabs.net/browse/STR-2665>
    // Import this from the counterproof module once it exists.
    const COUNTERPROOF_N_BYTES: usize = 128 + 32 + 4; // proof bytes (groth16) + deposit_idx (4 bytes) + operator pubkey (32 bytes)
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
        counterproof_n_bytes: NonZero::new(COUNTERPROOF_N_BYTES)
            .expect("counterproof_n_bytes must be non-zero"),
        deposit_amount,
        stake_amount: params.protocol.stake_amount,
    };

    // FIXME: <https://atlassian.alpenlabs.net/browse/STR-2666>
    // Construct adaptor keys and descriptors once they move out of `Config` and into `Context`.
    let graph_config = GraphSMCfg {
        game_graph_params,
        operator_fee,
        operator_adaptor_keys: params.keys.covenant.iter().map(|cov| cov.adaptor).collect(),
        admin_pubkey: params.keys.admin,
        watchtower_fault_pubkeys: params
            .keys
            .covenant
            .iter()
            .map(|cov| cov.watchtower_fault)
            .collect(),
        payout_descs: params
            .keys
            .covenant
            .iter()
            .map(|cov| cov.payout_descriptor.clone())
            .collect(),
    };

    SMConfig {
        deposit: Arc::new(deposit_config),
        graph: Arc::new(graph_config),
    }
}

fn build_exec_config(params: &Params, config: &Config) -> ExecutionConfig {
    ExecutionConfig {
        network: params.network,
        min_withdrawal_fulfillment_window: config.min_withdrawal_fulfillment_window,
        magic_bytes: params.protocol.magic_bytes,
        maximum_fee_rate: FeeRate::from_sat_per_vb(config.max_fee_rate).unwrap(),
        operator_fee: params.protocol.operator_fee,
        funding_uxto_pool_size: config.operator_wallet.claim_funding_pool_size,
    }
}
