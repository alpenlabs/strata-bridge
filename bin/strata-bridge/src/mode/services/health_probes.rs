//! Periodic bridge component health probes.

use std::{sync::Arc, time::Duration};

use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::tx_driver::TxDriverHealthHandle;
use jsonrpsee::http_client::HttpClient;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_asm_rpc::traits::AsmControlApiClient;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_exec::output_handles::NativeWallet;
use strata_bridge_orchestrator::{persister::Persister, sm_registry::SMConfig};
use strata_mosaic_client::MosaicClient;
use strata_p2p::swarm::handle::CommandHandle;
use tokio::{sync::RwLock, time::interval};
use tracing::warn;

use crate::{
    health::{
        COMPONENT_ASM_RPC, COMPONENT_BITCOIN_RPC, COMPONENT_FDB, COMPONENT_MOSAIC,
        COMPONENT_ORCHESTRATOR, COMPONENT_P2P, COMPONENT_S2, COMPONENT_TX_DRIVER, COMPONENT_WALLET,
        HealthRegistry,
    },
    mode::services::mosaic_client::BridgeMosaicIdResolver,
};

type BridgeMosaicClient = MosaicClient<HttpClient, BridgeMosaicIdResolver>;

/// Starts a periodic FoundationDB probe by recovering bridge state from disk.
pub(in crate::mode) fn spawn_fdb_probe(
    db: Arc<FdbClient>,
    sm_config: SMConfig,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let persister = Persister::new(db);
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            match persister.recover_registry(sm_config.clone()).await {
                Ok(_) => health_registry.mark_ok(COMPONENT_FDB, "recover_registry_succeeded"),
                Err(err) => {
                    health_registry.mark_unhealthy(COMPONENT_FDB, "recover_registry_failed");
                    warn!(%err, "FDB health probe failed");
                }
            }
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
            match client.get_block_count().await {
                Ok(_) => health_registry.mark_ok(COMPONENT_BITCOIN_RPC, "block_count_read"),
                Err(err) => {
                    health_registry.mark_unhealthy(COMPONENT_BITCOIN_RPC, "block_count_failed");
                    warn!(%err, "Bitcoin RPC health probe failed");
                }
            }
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
            match client.get_uptime().await {
                Ok(_) => health_registry.mark_ok(COMPONENT_ASM_RPC, "asm_rpc_reachable"),
                Err(err) => {
                    health_registry.mark_unhealthy(COMPONENT_ASM_RPC, "asm_rpc_unreachable");
                    warn!(%err, "ASM RPC health probe failed");
                }
            }
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
            let connected_peer_count = command_handle.get_connected_peers(None).await.len();

            if expected_peer_count == 0 {
                health_registry.mark_ok(COMPONENT_P2P, "no_peers_configured");
            } else if connected_peer_count == 0 {
                health_registry.mark_unhealthy(COMPONENT_P2P, "no_connected_peers");
                warn!(
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
            match client.health_check().await {
                Ok(()) => health_registry.mark_ok(COMPONENT_MOSAIC, "rpc_reachable"),
                Err(err) => {
                    health_registry.mark_unhealthy(COMPONENT_MOSAIC, "rpc_unreachable");
                    warn!(%err, "Mosaic health probe failed");
                }
            }
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
            match client.musig2_signer().pubkey().await {
                Ok(_) => health_registry.mark_ok(COMPONENT_S2, "s2_read_succeeded"),
                Err(err) => {
                    health_registry.mark_unhealthy(COMPONENT_S2, "s2_read_failed");
                    warn!(%err, "secret-service health probe failed");
                }
            }
        }
    });
}

/// Starts a periodic operator-wallet sync probe.
pub(in crate::mode) fn spawn_wallet_probe(
    wallet: Arc<RwLock<NativeWallet>>,
    probe_interval: Duration,
    health_registry: HealthRegistry,
) {
    tokio::spawn(async move {
        let mut ticker = interval(nonzero_interval(probe_interval));

        loop {
            ticker.tick().await;
            match wallet.write().await.sync().await {
                Ok(()) => health_registry.mark_ok(COMPONENT_WALLET, "sync_succeeded"),
                Err(err) => {
                    health_registry.mark_unhealthy(COMPONENT_WALLET, "sync_failed");
                    warn!(%err, "operator wallet health probe failed");
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
                warn!("transaction driver health probe found driver not accepting jobs");
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

fn nonzero_interval(interval: Duration) -> Duration {
    if interval.is_zero() {
        Duration::from_secs(1)
    } else {
        interval
    }
}
