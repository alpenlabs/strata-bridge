//! Mosaic client initialization and setup for the bridge operator.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use anyhow::anyhow;
use async_trait::async_trait;
use futures::future;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};
use strata_mosaic_client::{MosaicClient, MosaicIdResolver, PeerId, PubkeyBytes};
use strata_mosaic_client_api::{MosaicClientApi, MosaicError, types::Role};
use strata_tasks::TaskExecutor;
use tokio::select;
use tracing::{error, info};

use crate::config::MosaicConfig;

/// Resolves bridge operator indices to mosaic-native identifiers.
///
/// Peer IDs come from the bridge config; operator pubkeys come from the full operator table.
pub(crate) struct BridgeMosaicIdResolver {
    /// `(mosaic_peer_id, xonly_pubkey_bytes)` indexed by `OperatorIdx`.
    operators: HashMap<OperatorIdx, (PeerId, [u8; 32])>,
}

impl BridgeMosaicIdResolver {
    /// Build a resolver from the mosaic config (peer IDs) and full operator table (pubkeys).
    ///
    /// # Panics
    ///
    /// Panics if the configured peer ID operator indices do not exactly match the full operator
    /// table, or if any peer ID is not valid 32-byte hex.
    fn new(config: &MosaicConfig, full_operator_table: &OperatorTable) -> Self {
        let operator_idxs = full_operator_table.operator_idxs();
        let mut configured_peer_ids = BTreeMap::new();
        for peer_id in &config.peer_ids {
            assert!(
                configured_peer_ids
                    .insert(peer_id.operator_idx, peer_id.peer_id.as_str())
                    .is_none(),
                "mosaic config peer_ids must not contain duplicate operator index {}",
                peer_id.operator_idx
            );
        }
        let configured_operator_idxs: BTreeSet<OperatorIdx> =
            configured_peer_ids.keys().copied().collect();
        assert_eq!(
            configured_operator_idxs, operator_idxs,
            "mosaic config peer_ids operator indices must match the full operator table"
        );

        let operators = operator_idxs
            .into_iter()
            .map(|idx| {
                let peer_id_hex = configured_peer_ids
                    .get(&idx)
                    .unwrap_or_else(|| panic!("missing mosaic peer_id for operator index {idx}"));
                let peer_id_bytes: [u8; 32] = hex::decode(peer_id_hex)
                    .unwrap_or_else(|e| {
                        panic!("invalid hex for mosaic peer_id at index {idx}: {e}")
                    })
                    .try_into()
                    .unwrap_or_else(|v: Vec<u8>| {
                        panic!(
                            "mosaic peer_id at index {idx} must be 32 bytes, got {}",
                            v.len()
                        )
                    });

                let btc_key = full_operator_table
                    .idx_to_btc_key(&idx)
                    .unwrap_or_else(|| panic!("operator index {idx} not found in operator table"));
                let xonly_bytes = btc_key.x_only_public_key().0.serialize();

                (idx, (peer_id_bytes, xonly_bytes))
            })
            .collect();

        Self { operators }
    }
}

#[async_trait]
impl MosaicIdResolver for BridgeMosaicIdResolver {
    async fn resolve_peer_id(&self, operator_idx: OperatorIdx) -> Result<PeerId, MosaicError> {
        self.operators
            .get(&operator_idx)
            .map(|(peer_id, _)| *peer_id)
            .ok_or(MosaicError::UnknownOperator(operator_idx))
    }

    async fn resolve_operator_pubkey(
        &self,
        operator_idx: OperatorIdx,
    ) -> Result<PubkeyBytes, MosaicError> {
        self.operators
            .get(&operator_idx)
            .map(|(_, pubkey)| *pubkey)
            .ok_or(MosaicError::UnknownOperator(operator_idx))
    }
}

/// Build a [`MosaicClient`] from the mosaic config and full operator table.
pub(crate) fn init_mosaic_client(
    config: &MosaicConfig,
    full_operator_table: &OperatorTable,
    pov_idx: OperatorIdx,
) -> MosaicClient<HttpClient, BridgeMosaicIdResolver> {
    let http_client = HttpClientBuilder::default()
        .build(&config.rpc_url)
        .unwrap_or_else(|e| {
            panic!(
                "failed to build mosaic HTTP client for {}: {e}",
                config.rpc_url
            )
        });

    let resolver = BridgeMosaicIdResolver::new(config, full_operator_table);

    MosaicClient::builder(Arc::new(http_client), resolver, pov_idx)
        .retry_delay(config.retry_delay)
        .max_retries(config.max_retries)
        .poll_interval(config.poll_interval)
        .build()
}

/// Run `ensure_mosaic_setup` for every `(other_operator, role)` pair concurrently.
///
/// Skips the point-of-view operator (self). Fails fast on the first error — remaining in-flight
/// futures are dropped.
pub(crate) async fn run_mosaic_setup(
    client: &MosaicClient<HttpClient, BridgeMosaicIdResolver>,
    full_operator_table: &OperatorTable,
) -> anyhow::Result<()> {
    let pov_idx = full_operator_table.pov_idx();
    let pairs = mosaic_setup_pairs(full_operator_table);

    let total = pairs.len();
    info!(
        %pov_idx,
        total,
        "starting mosaic setup for all operator pairs"
    );

    future::try_join_all(pairs.into_iter().map(|(idx, role)| async move {
        info!(%idx, ?role, "starting mosaic setup");
        client.ensure_mosaic_setup(idx, role).await.map_err(|e| {
            error!(%idx, ?role, %e, "mosaic setup failed");
            anyhow!("mosaic setup failed for operator {idx} role {role:?}: {e}")
        })?;
        info!(%idx, ?role, "mosaic setup complete");
        Ok::<(), anyhow::Error>(())
    }))
    .await?;

    info!("mosaic setup completed successfully for all {total} pairs");
    Ok(())
}

fn mosaic_setup_pairs(full_operator_table: &OperatorTable) -> Vec<(OperatorIdx, Role)> {
    remote_operator_idxs(full_operator_table)
        .into_iter()
        .flat_map(|idx| [(idx, Role::Garbler), (idx, Role::Evaluator)])
        .collect()
}

fn remote_operator_idxs(full_operator_table: &OperatorTable) -> Vec<OperatorIdx> {
    let pov_idx = full_operator_table.pov_idx();

    full_operator_table
        .operator_idxs()
        .into_iter()
        .filter(|idx| *idx != pov_idx)
        .collect()
}

/// Spawn the mosaic watched-deposits poller as a critical task.
///
/// The poller is what drives the `Incomplete` branch of `init_garbler_deposit`/
/// `init_evaluator_deposit` to eventual completion: deposits that aren't ready at init time are
/// inserted into an internal watch list, and this loop polls their status until `Ready` (emitted
/// as `AdaptorsVerified`) or a terminal state. Without this task running, the GSM waits in
/// `GraphGenerated` forever.
///
/// Must be spawned *after* the event subscription is set up (i.e. after
/// `subscribe_events` has been called by the orchestrator) so that emitted events are not
/// dropped.
pub(crate) fn spawn_mosaic_poller(
    executor: &TaskExecutor,
    client: Arc<MosaicClient<HttpClient, BridgeMosaicIdResolver>>,
) {
    executor.spawn_critical_async_with_shutdown("mosaic_poller", |shutdown_guard| async move {
        select! {
            _ = shutdown_guard.wait_for_shutdown() => {
                info!("shutdown signal received; stopping mosaic watched-deposits poller");
                Ok(())
            }
            // `poll_watched_deposits` is an infinite loop, so its future completing means the
            // worker exited unexpectedly.
            _ = client.poll_watched_deposits() => {
                Err(anyhow!("mosaic watched-deposits poller exited unexpectedly"))
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use strata_bridge_test_utils::bridge_fixtures::test_operator_table;
    use strata_mosaic_client::MosaicIdResolver;

    use super::*;
    use crate::config::MosaicPeerIdConfig;

    fn peer_id_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn peer_id(byte: u8) -> PeerId {
        [byte; 32]
    }

    fn peer_ids_by_operator(
        entries: impl IntoIterator<Item = (OperatorIdx, u8)>,
    ) -> Vec<MosaicPeerIdConfig> {
        entries
            .into_iter()
            .map(|(operator_idx, byte)| MosaicPeerIdConfig {
                operator_idx,
                peer_id: peer_id_hex(byte),
            })
            .collect()
    }

    fn test_mosaic_config(peer_ids: Vec<MosaicPeerIdConfig>) -> MosaicConfig {
        MosaicConfig {
            rpc_url: "http://127.0.0.1:0".to_string(),
            retry_delay: Duration::from_millis(1),
            max_retries: 0,
            poll_interval: Duration::from_millis(1),
            peer_ids,
        }
    }

    #[tokio::test]
    async fn resolver_resolves_peer_ids_and_pubkeys_by_operator_index() {
        let full_operator_table = test_operator_table(3, 1);
        let config = test_mosaic_config(peer_ids_by_operator([(2, 19), (0, 7), (1, 11)]));

        let resolver = BridgeMosaicIdResolver::new(&config, &full_operator_table);

        let actual_peer_id = resolver
            .resolve_peer_id(0)
            .await
            .expect("operator 0 should resolve to its configured mosaic peer id");
        assert_eq!(
            actual_peer_id,
            peer_id(7),
            "resolver should select the mosaic peer id configured for operator index 0"
        );

        let actual_peer_id = resolver
            .resolve_peer_id(2)
            .await
            .expect("operator 2 should resolve to a configured mosaic peer id");
        assert_eq!(
            actual_peer_id,
            peer_id(19),
            "resolver should select the mosaic peer id configured for operator index 2"
        );

        let pubkey = resolver
            .resolve_operator_pubkey(2)
            .await
            .expect("operator 2 should resolve to its covenant public key");
        let expected_pubkey = full_operator_table
            .idx_to_btc_key(&2)
            .expect("operator 2 should have a covenant public key")
            .x_only_public_key()
            .0
            .serialize();
        assert_eq!(
            pubkey, expected_pubkey,
            "resolver should select the covenant public key for the requested operator index"
        );

        let actual_peer_id = resolver
            .resolve_peer_id(1)
            .await
            .expect("POV operator should still resolve to its configured mosaic peer id");
        assert_eq!(
            actual_peer_id,
            peer_id(11),
            "resolver should preserve full-table peer ID semantics for the POV operator"
        );

        let err = resolver
            .resolve_peer_id(3)
            .await
            .expect_err("unknown operator index should fail peer-id resolution");
        assert!(
            matches!(err, MosaicError::UnknownOperator(3)),
            "resolver should report unknown operators as MosaicError::UnknownOperator"
        );
    }

    #[test]
    fn resolver_rejects_peer_ids_with_mismatched_operator_indices() {
        let full_operator_table = test_operator_table(3, 1);
        let config = test_mosaic_config(peer_ids_by_operator([(0, 7), (1, 11), (3, 23)]));

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let panic =
            std::panic::catch_unwind(|| BridgeMosaicIdResolver::new(&config, &full_operator_table));
        std::panic::set_hook(previous_hook);

        assert!(
            panic.is_err(),
            "resolver should reject peer ID maps whose operator indices do not match the full operator table"
        );
    }

    #[test]
    fn setup_pairs_cover_every_non_pov_operator_in_full_table() {
        let full_operator_table = test_operator_table(4, 1);

        let pairs = mosaic_setup_pairs(&full_operator_table);

        assert_eq!(
            pairs,
            vec![
                (0, Role::Garbler),
                (0, Role::Evaluator),
                (2, Role::Garbler),
                (2, Role::Evaluator),
                (3, Role::Garbler),
                (3, Role::Evaluator),
            ],
            "mosaic setup should include both roles for every non-POV operator in the full table"
        );
    }
}
