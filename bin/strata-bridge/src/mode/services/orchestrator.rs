//! Provides orchestrator initialization.

use std::{num::NonZero, sync::Arc};

use anyhow::anyhow;
use bitcoin::{FeeRate, relative};
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::{
    cpfp::{CachedFeeSource, CpfpContext},
    tx_driver::TxDriver,
};
use jsonrpsee::http_client::HttpClient;
use libp2p_identity::ed25519::Keypair;
use operator_wallet::AnyOperatorWallet;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_asm_events::client::AsmEventFeed;
use strata_bridge_common::params::Params;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_exec::{
    config::ExecutionConfig,
    cpfp_adapters::{
        BitcoindCpfpPackageSubmitter, OperatorWalletCpfpAdapter, build_anchor_input_signer,
        build_wallet_input_signer,
    },
    output_handles::OutputHandles,
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
    fee, game_graph::ProtocolParams as TxGraphProtocolParams,
    stake_graph::ProtocolParams as StakeGraphProtocolParams,
};
use strata_mosaic_client_api::MosaicClientApi;
use strata_p2p::swarm::handle::{GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tokio::{
    select,
    sync::{RwLock, mpsc, oneshot},
};
use tracing::{debug, error, info};

use crate::{config::Config, mode::services::btc_client::init_zmq_client};

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
    wallet: Arc<RwLock<AnyOperatorWallet>>,
    claim_funding_utxo_value: bitcoin::Amount,
    btc_rpc_client: BitcoinClient,
    asm_rpc_client: HttpClient,
    fdb_client: Arc<FdbClient>,
    executor: &TaskExecutor,
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
    let zmq_client = init_zmq_client(config, params.protocol.bury_depth, start_height).await?;

    let (ouroboros_msg_sender, ouroboros_msg_receiver) = mpsc::unbounded_channel();
    let message_handler =
        MessageHandler::new(ouroboros_msg_sender, gossip_handle.clone(), p2p_keypair);

    debug!("initializing asm assignments feed");
    let asm_block_feed = zmq_client.subscribe_blocks().await;
    let asm_feed = AsmEventFeed::new(asm_rpc_client.clone(), config.asm_rpc.clone());
    let asm_feed = asm_feed.attach_block_stream(asm_block_feed);
    let assignments_sub = asm_feed.subscribe_assignments_state().await;
    info!("asm assignments feed initialized and subscribed to assignment events");

    let orchestrator_block_sub = zmq_client.subscribe_blocks().await;

    let mosaic_event_sub = mosaic_client.as_ref().subscribe_events().await;

    let nag_tick = tokio::time::interval_at(tokio::time::Instant::now(), config.nag_interval);
    let retry_tick = tokio::time::interval_at(tokio::time::Instant::now(), config.retry_interval);

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let events_mux = EventsMux {
        ouroboros_msg_rx: ouroboros_msg_receiver,
        shutdown_rx: Some(shutdown_receiver),
        block_sub: orchestrator_block_sub,
        assignments_sub,
        mosaic_event_sub,
        gossip_handle,
        req_resp_handle,
        nag_tick,
        retry_tick,
    };

    // Validate both Duration knobs up-front — `tokio::time::interval` panics if `period` is
    // zero, and the panic would surface deep inside `CachedFeeSource::spawn` /
    // `TxDriver::with_cpfp` as a cryptic task crash. Fail at orchestrator startup with a
    // clear message instead.
    if config.fee_refresh_interval.is_zero() {
        return Err(anyhow!(
            "config.fee_refresh_interval must be > 0; got {:?}",
            config.fee_refresh_interval
        ));
    }
    if config.cpfp_bump_check_interval.is_zero() {
        return Err(anyhow!(
            "config.cpfp_bump_check_interval must be > 0; got {:?}",
            config.cpfp_bump_check_interval
        ));
    }

    let btc_rpc_arc = Arc::new(btc_rpc_client.clone());

    // Build the configured fee source and wrap it once in a background-refreshed cache. That one
    // cache is shared by the executors (per-tx-build estimates via `CachedFeeSource::current`) and
    // the CPFP bump loop below, so neither hits the network on its hot path. Built up-front so a
    // misconfigured fee source fails fast at boot rather than on the first duty firing.
    let live_fee_source = config
        .fee_source
        .clone()
        .build(btc_rpc_arc.clone())
        .map_err(|e| anyhow!("failed to construct fee source from config: {e}"))?;
    let cached_fee_source = Arc::new(
        CachedFeeSource::spawn(Arc::new(live_fee_source), config.fee_refresh_interval)
            .await
            .map_err(|e| anyhow!("failed to initialize cached fee source: {e}"))?,
    );

    let exec_cfg = build_exec_config(
        params,
        config,
        &sm_config,
        claim_funding_utxo_value,
        cached_fee_source.clone(),
    );

    // CPFP wiring: bundle the wallet / shared fee-source / package-submitter / anchor-signer
    // adapters into a `CpfpContext` the tx-driver consumes in its bump loop.
    //
    // Fetch the operator's pubkeys up-front: needed both for the CPFP adapter
    // (`operator_general_pubkey` is used as the foreign-UTXO `tap_internal_key` for
    // `ParentTxCombined` strategies) and for `OutputHandles` (anchor inference key + caveat
    // pubkeys for the publishing helper).
    let operator_musig2_pubkey = s2_client
        .musig2_signer()
        .pubkey()
        .await
        .map_err(|e| anyhow!("failed to fetch operator musig2 pubkey from s2: {e:?}"))?;
    let operator_general_pubkey = s2_client
        .general_wallet_signer()
        .pubkey()
        .await
        .map_err(|e| anyhow!("failed to fetch operator general wallet pubkey from s2: {e:?}"))?;

    // Sanity check that our own musig2 pubkey is present in the covenant set. This is
    // tautological by construction today (the operator table is built from `covenant.iter`
    // and `OperatorTable::select_btc_x_only(our_pubkey)`), but the explicit lookup catches
    // configuration drift between secret-service and the static params file.
    //
    // The OTHER invariant the CPFP path depends on — `watchtower_pubkey == musig2_pubkey`
    // for counterproof / counterproof_ack anchors — is anchored at the `CovenantKeys`
    // definition itself via `_covenant_keys_field_audit` (see `crates/common/src/params.rs`).
    // That destructuring forces a compile error if anyone adds a separate `watchtower` field,
    // which is the cue to thread per-anchor keys through `CpfpKind::InferAnchor`.
    params
        .keys
        .covenant
        .iter()
        .find(|c| c.musig2 == operator_musig2_pubkey)
        .ok_or_else(|| {
            anyhow!(
                "operator musig2 pubkey {} is not in the configured covenant set; \
                 cannot establish watchtower-key = musig2-key invariant required by CPFP",
                operator_musig2_pubkey,
            )
        })?;

    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(
        wallet.clone(),
        operator_general_pubkey,
    ));
    let cpfp_submitter = Arc::new(BitcoindCpfpPackageSubmitter::new(btc_rpc_arc.clone()));
    // Two distinct signers, bound to two distinct keys:
    //   - anchor inputs use the musig2-signer pubkey (the bridge tx-graph keys every KeyedAnchor to
    //     this pubkey — see `bridge-sm::graph::context::generate_key_data`).
    //   - wallet funding inputs use the general-wallet-signer pubkey (the descriptor key of
    //     `NativeGeneralWallet`).
    let anchor_input_signer = build_anchor_input_signer(s2_client.clone());
    let wallet_input_signer = build_wallet_input_signer(s2_client.clone());
    let cpfp_ctx = CpfpContext {
        wallet: cpfp_wallet,
        fee_source: cached_fee_source,
        anchor_input_signer,
        wallet_input_signer,
        max_fee_rate: exec_cfg.maximum_fee_rate,
        package_submitter: cpfp_submitter,
    };
    let tx_driver = TxDriver::with_cpfp(
        zmq_client,
        btc_rpc_client.clone(),
        Some(cpfp_ctx),
        fee::FEE_RATE,
        config.cpfp_bump_check_interval,
    )
    .await;

    let bridge_proof_host = strata_bridge_proof::build_host(&config.bridge_proof).await?;
    let counterproof_host = strata_bridge_counterproof::build_host(&config.counterproof).await?;
    let output_handles = OutputHandles {
        wallet,
        msg_handler: RwLock::new(message_handler),
        db: fdb_client.clone(),
        bitcoind_rpc_client: btc_rpc_client,
        asm_rpc_client,
        s2_client: s2_client.clone(),
        tx_driver,
        mosaic_client,
        operator_table: operator_table.clone(),
        bridge_proof_host,
        counterproof_host,
        operator_general_pubkey,
        operator_musig2_pubkey,
        network: params.network,
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
                pipeline.run(operator_table, start_height).await
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
        admin_pubkey: params.keys.admin,
        payout_descs: params
            .keys
            .covenant
            .iter()
            .map(|cov| cov.payout_descriptor.clone())
            .collect(),
        bridge_proof_predicate: params.protocol.bridge_proof_predicate.clone(),
        counterproof_predicate: params.protocol.counterproof_predicate.clone(),
    };

    // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2924>
    // Promote `unstaking_timelock` to a protocol parameter on `ProtocolParams` once the
    // params schema is updated. For now, use a sensible default (approximately 21 days).
    const DEFAULT_UNSTAKING_TIMELOCK_BLOCKS: u16 = 3024;
    let stake_config = StakeSMCfg {
        protocol_params: StakeGraphProtocolParams {
            network,
            magic_bytes,
            unstaking_timelock: relative::Height::from_height(DEFAULT_UNSTAKING_TIMELOCK_BLOCKS),
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
    fee_source: Arc<CachedFeeSource>,
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
        fee_source,
    }
}
