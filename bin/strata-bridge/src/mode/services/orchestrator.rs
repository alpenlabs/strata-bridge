//! Provides orchestrator initialization.

use std::{cmp, collections::VecDeque, num::NonZero, sync::Arc, time::Duration};

use anyhow::anyhow;
use bitcoin::{FeeRate, relative};
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::{
    client::BtcNotifyHealthEvent,
    cpfp::{CachedFeeSource, CpfpContext},
    tx_driver::TxDriver,
};
use jsonrpsee::http_client::HttpClient;
use libp2p_identity::ed25519::Keypair;
use operator_wallet::AnyOperatorWallet;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_asm_events::client::{AsmEventFeed, AsmFeedHealthEvent};
use strata_bridge_common::params::Params;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_exec::{
    config::ExecutionConfig,
    cpfp_adapters::{
        BitcoindCpfpMempool, OperatorWalletCpfpAdapter, build_anchor_input_signer,
        build_multi_anchor_signer, build_wallet_input_signer,
    },
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
    fee,
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
    wallet: Arc<RwLock<AnyOperatorWallet>>,
    claim_funding_utxo_value: bitcoin::Amount,
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
        pending_asm_events: VecDeque::new(),
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
    // cache is shared by the executors (per-tx-build estimates via `CachedFeeSource::try_current`,
    // which aborts duty pricing when the cache is stale) and
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
    // The related invariant is `watchtower_pubkey == musig2_pubkey`. The operator table makes
    // it, from `covenant[i].musig2`. A field change on `CovenantKeys` breaks the compilation
    // of `_covenant_keys_field_audit` (see `crates/common/src/params.rs`).
    let own_covenant = params
        .keys
        .covenant
        .iter()
        .find(|c| c.musig2 == operator_musig2_pubkey)
        .ok_or_else(|| {
            anyhow!(
                "operator musig2 pubkey {} is not in the configured covenant set",
                operator_musig2_pubkey,
            )
        })?;

    // The presigned graph pays this operator's covenant `payout_descriptor` (a params-file
    // value the peers signed against), while gossip-built payouts and every spend go through
    // the wallet's own `payout_descriptor()`. These must resolve to the same script: on a
    // mismatch, graph payouts (uncontested/contested payout, counterproof nack) land on an
    // output this wallet neither tracks nor can sign — unspendable by this operator, and
    // their CPFP bumps fail forever. Warn rather than abort: graphs presigned under older
    // params can differ legitimately, and an operator mid-rotation must still start.
    //
    // The comparison is type-aware. Params validation pins every covenant payout descriptor
    // to P2TR, and the Fireblocks backend derives its descriptor from a P2WPKH vault
    // address, so on that backend the scripts can never match — a same-script check fires
    // on every startup and reads as rotation drift, which it is not. The two cases carry
    // different messages: a cross-type mismatch is structural (the backend class cannot
    // receive presigned-graph payouts; the general key held by secret-service still can,
    // out of band), while a same-type mismatch is the rotation-drift signal the check was
    // built for.
    {
        let wallet_payout_descriptor = wallet.read().await.payout_descriptor();
        let wallet_payout_script = wallet_payout_descriptor.to_script();
        let covenant_payout_script = own_covenant.payout_descriptor.to_script();
        if covenant_payout_script != wallet_payout_script {
            if own_covenant.payout_descriptor.type_tag() == wallet_payout_descriptor.type_tag() {
                warn!(
                    covenant_descriptor = %own_covenant.payout_descriptor,
                    %wallet_payout_script,
                    "params covenant payout_descriptor does not match the wallet's payout \
                     script; presigned-graph payouts will be unspendable and unbumpable by \
                     this operator"
                );
            } else {
                // Only claim "recoverable via the secret-service general key" after
                // checking it: the claim holds exactly when the covenant descriptor is the
                // tap-tweaked P2TR of the s2 general key. On a mainnet-first deployment
                // this line informs an operator's judgment about whether presigned-graph
                // payouts are safe to leave unclaimed — it must not overstate.
                let s2_general_script = bitcoin::Address::p2tr(
                    bitcoin::secp256k1::SECP256K1,
                    operator_general_pubkey,
                    None,
                    params.network,
                )
                .script_pubkey();
                let recovery = if covenant_payout_script == s2_general_script {
                    "those outputs stay recoverable through the secret-service general key"
                } else {
                    "those outputs are recoverable only by whoever controls the key behind \
                     the params descriptor"
                };
                warn!(
                    covenant_descriptor = %own_covenant.payout_descriptor,
                    wallet_descriptor = %wallet_payout_descriptor,
                    "the general-wallet backend cannot receive presigned-graph payouts \
                     (descriptor types differ); {recovery}, and this wallet will not track \
                     or bump them"
                );
            }
        }
    }

    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(
        wallet.clone(),
        operator_general_pubkey,
    ));
    let cpfp_submitter = Arc::new(BitcoindCpfpMempool::new(btc_rpc_arc.clone()));
    // Two distinct signers, bound to two distinct keys:
    //   - anchor inputs use the musig2-signer pubkey (the bridge tx-graph keys every KeyedAnchor to
    //     this pubkey — see `bridge-sm::graph::context::generate_key_data`).
    //   - wallet funding inputs use the general-wallet-signer pubkey (the descriptor key of
    //     `NativeGeneralWallet`).
    let anchor_input_signer = build_anchor_input_signer(s2_client.clone());
    // Script-path variant for `MultiAnchor` anchors (contest, bridge-proof-timeout): same
    // musig2 key, signed untweaked because the leaf is satisfied directly.
    let multi_anchor_signer = build_multi_anchor_signer(s2_client.clone());
    let wallet_input_signer = build_wallet_input_signer(s2_client.clone());
    let cpfp_ctx = CpfpContext {
        wallet: cpfp_wallet,
        fee_source: cached_fee_source,
        anchor_input_signer,
        multi_anchor_signer,
        wallet_input_signer,
        max_fee_rate: exec_cfg.maximum_fee_rate,
        mempool: cpfp_submitter,
    };
    let tx_driver = TxDriver::with_cpfp(
        zmq_client,
        btc_rpc_client.clone(),
        Some(cpfp_ctx),
        fee::FEE_RATE,
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
        operator_general_pubkey,
        operator_musig2_pubkey,
        network: params.network,
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
