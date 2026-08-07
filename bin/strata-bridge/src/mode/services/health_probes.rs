//! Periodic bridge component health probes.

use std::{fmt::Display, future::Future, sync::Arc, time::Duration};

use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::tx_driver::TxDriverHealthHandle;
use jsonrpsee::http_client::HttpClient;
use operator_wallet::AnyOperatorWallet;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_asm_rpc::traits::AsmControlApiClient;
use strata_bridge_db::fdb::client::FdbClient;
use strata_mosaic_client::MosaicClient;
use strata_p2p::swarm::handle::CommandHandle;
use tokio::{
    sync::RwLock,
    time::{interval, timeout},
};
use tracing::{error, warn};

use crate::{
    constants::DEFAULT_HEALTH_PROBE_TIMEOUT,
    health::{
        COMPONENT_ASM_RPC, COMPONENT_BITCOIN_RPC, COMPONENT_FDB, COMPONENT_MOSAIC,
        COMPONENT_ORCHESTRATOR, COMPONENT_P2P, COMPONENT_S2, COMPONENT_TX_DRIVER, COMPONENT_WALLET,
        HealthRegistry,
    },
    mode::services::mosaic_client::BridgeMosaicIdResolver,
};

type BridgeMosaicClient = MosaicClient<HttpClient, BridgeMosaicIdResolver>;

/// Starts a periodic FoundationDB liveness probe.
pub(in crate::mode) fn spawn_fdb_probe(
    db: Arc<FdbClient>,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            run_external_probe(
                &health_registry,
                COMPONENT_FDB,
                "fdb",
                db.health_check(),
                "fdb_reachable",
                "fdb_unreachable",
            )
            .await;
        }
    });
}

/// Starts a periodic Bitcoin RPC probe.
pub(in crate::mode) fn spawn_bitcoin_rpc_probe(
    client: BitcoinClient,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            run_external_probe(
                &health_registry,
                COMPONENT_BITCOIN_RPC,
                "bitcoin_rpc",
                client.get_block_count(),
                "block_count_read",
                "block_count_failed",
            )
            .await;
        }
    });
}

/// Starts a periodic ASM RPC liveness probe.
pub(in crate::mode) fn spawn_asm_rpc_probe(
    client: HttpClient,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            run_external_probe(
                &health_registry,
                COMPONENT_ASM_RPC,
                "asm_rpc",
                client.get_uptime(),
                "asm_rpc_reachable",
                "asm_rpc_unreachable",
            )
            .await;
        }
    });
}

/// Starts a periodic P2P command/peer connectivity probe.
pub(in crate::mode) fn spawn_p2p_probe(
    command_handle: CommandHandle,
    expected_peer_count: usize,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            // `get_connected_peers` is internally bounded: it returns an empty set rather than
            // hanging if the swarm task is unresponsive, so it cannot leave the probe stuck.
            let connected_peer_count = command_handle.get_connected_peers(None).await.len();

            if expected_peer_count == 0 {
                health_registry.mark_ok(COMPONENT_P2P, "no_peers_configured");
            } else if connected_peer_count == 0 {
                health_registry.mark_unhealthy(COMPONENT_P2P, "no_connected_peers");
                error!(
                    expected_peer_count,
                    "P2P health probe found no connected peers"
                );
            } else if connected_peer_count < expected_peer_count {
                health_registry.mark_degraded(COMPONENT_P2P, "partial_peer_connectivity");
                warn!(
                    connected_peer_count,
                    expected_peer_count, "P2P health probe found partial peer connectivity"
                );
            } else {
                health_registry.mark_ok(COMPONENT_P2P, "peers_connected");
            }
        }
    });
}

/// Starts a periodic Mosaic RPC probe.
pub(in crate::mode) fn spawn_mosaic_probe(
    client: Arc<BridgeMosaicClient>,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            run_external_probe(
                &health_registry,
                COMPONENT_MOSAIC,
                "mosaic",
                client.health_check(),
                "rpc_reachable",
                "rpc_unreachable",
            )
            .await;
        }
    });
}

/// Starts a periodic secret-service probe.
pub(in crate::mode) fn spawn_s2_probe(
    client: SecretServiceClient,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            run_external_probe(
                &health_registry,
                COMPONENT_S2,
                "secret_service",
                client.musig2_signer().pubkey(),
                "s2_read_succeeded",
                "s2_read_failed",
            )
            .await;
        }
    });
}

/// Age past which a successful general-backend sync stops counting as `ok` and reports
/// `degraded` instead. Thirty minutes covers the normal duty cadence with margin: under
/// regular operation duties sync far more often than this, so a verdict this old means the
/// bridge is idle or the duty pipeline is stuck — either way, "the backend is healthy now"
/// is no longer a claim the probe can make.
const GENERAL_SYNC_STALENESS_BOUND: Duration = Duration::from_secs(30 * 60);

/// Starts a periodic operator-wallet liveness probe.
///
/// Reads the wallet's local chain tip through a shared read lock — a non-mutating, in-memory
/// check. It deliberately does not call `sync()`: syncing takes the exclusive write lock and
/// drives backend I/O, which would let a slow or stuck backend serialize wallet-dependent
/// duties. The read-lock acquisition is bounded so a stuck writer cannot leave the component
/// reporting a stale `ok` state.
pub(in crate::mode) fn spawn_wallet_probe(
    wallet: Arc<RwLock<AnyOperatorWallet>>,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            match timeout(DEFAULT_HEALTH_PROBE_TIMEOUT, wallet.read()).await {
                Ok(guard) => {
                    let height = guard.local_chain_tip_height();
                    let general_sync = guard.last_general_sync();
                    drop(guard);
                    // The tip comes from the reserved wallet and keeps advancing while the
                    // general backend fails its syncs (the two sync independently), so the
                    // general backend gets its own verdict:
                    //
                    // - A failed last attempt is unhealthy until a sync succeeds.
                    // - A success older than the staleness bound is degraded, not ok. Syncs are
                    //   duty-driven, so an idle bridge holds an old verdict — the degraded state
                    //   says "the backend was healthy when last used", which is the true claim.
                    // - `None` means no sync has run yet: expected briefly at startup while the
                    //   initial sync task retries, not a fault by itself.
                    match general_sync {
                        Some((false, _)) => {
                            health_registry.mark_unhealthy(
                                COMPONENT_WALLET,
                                format!("general_backend_sync_failed_at_height_{height}"),
                            );
                            error!("operator wallet general backend failed its last sync");
                        }
                        Some((true, at)) if at.elapsed() > GENERAL_SYNC_STALENESS_BOUND => {
                            health_registry.mark_degraded(
                                COMPONENT_WALLET,
                                format!(
                                    "last_general_sync_ok_{}s_ago_at_height_{height}",
                                    at.elapsed().as_secs()
                                ),
                            );
                        }
                        Some((true, _)) => {
                            health_registry
                                .mark_ok(COMPONENT_WALLET, format!("synced_to_height_{height}"));
                        }
                        None => {
                            health_registry.mark_ok(
                                COMPONENT_WALLET,
                                format!("awaiting_first_sync_at_height_{height}"),
                            );
                        }
                    }
                }
                Err(_) => {
                    health_registry.mark_unhealthy(COMPONENT_WALLET, "probe_timed_out");
                    error!("operator wallet health probe timed out acquiring read lock");
                }
            }
        }
    });
}

/// Starts a periodic transaction-driver liveness probe.
pub(in crate::mode) fn spawn_tx_driver_probe(
    tx_driver_health: TxDriverHealthHandle,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            if tx_driver_health.is_accepting_jobs() {
                health_registry.mark_ok(COMPONENT_TX_DRIVER, "driver_accepting_jobs");
            } else {
                health_registry.mark_unhealthy(COMPONENT_TX_DRIVER, "driver_not_accepting_jobs");
                error!("transaction driver health probe found driver not accepting jobs");
            }
        }
    });
}

/// Starts a monitor that marks the orchestrator unhealthy when its heartbeat becomes stale.
pub(in crate::mode) fn spawn_orchestrator_stale_monitor(
    stale_after: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let stale_after = nonzero_interval(stale_after);
        let probe_interval = stale_after
            .checked_div(2)
            .filter(|interval| !interval.is_zero())
            .unwrap_or(stale_after);
        let mut ticker = interval(probe_interval);

        loop {
            ticker.tick().await;
            health_registry.mark_unhealthy_if_stale(
                COMPONENT_ORCHESTRATOR,
                stale_after,
                "pipeline_stale",
            );
        }
    });
}

const fn nonzero_interval(interval: Duration) -> Duration {
    if interval.is_zero() {
        Duration::from_secs(1)
    } else {
        interval
    }
}

async fn run_external_probe<T, E, F>(
    health_registry: &HealthRegistry,
    component: &'static str,
    probe_name: &'static str,
    probe: F,
    ok_reason: &'static str,
    error_reason: &'static str,
) where
    E: Display,
    F: Future<Output = Result<T, E>>,
{
    match timeout(DEFAULT_HEALTH_PROBE_TIMEOUT, probe).await {
        Ok(Ok(_)) => health_registry.mark_ok(component, ok_reason),
        Ok(Err(err)) => {
            health_registry.mark_unhealthy(component, error_reason);
            error!(component, probe_name, %err, "health probe failed");
        }
        Err(_) => {
            health_registry.mark_unhealthy(component, "probe_timed_out");
            error!(component, probe_name, "health probe timed out");
        }
    }
}
