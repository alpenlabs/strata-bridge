//! Mosaic client initialization and setup for the bridge operator.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use futures::future;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};
use strata_mosaic_client::{MosaicClient, MosaicIdResolver, PeerId, PubkeyBytes};
use strata_mosaic_client_api::{MosaicClientApi, MosaicError, types::Role};
use strata_tasks::TaskExecutor;
use tokio::select;
use tracing::{error, info};

use crate::config::{MosaicConfig, MosaicPeerConfig};

/// Resolves bridge operator indices to mosaic-native identifiers.
///
/// Peer IDs come from the bridge config; operator pubkeys come from the operator table.
pub(crate) struct BridgeMosaicIdResolver {
    /// `(mosaic_peer_id, xonly_pubkey_bytes)` indexed by `OperatorIdx`.
    operators: HashMap<OperatorIdx, (PeerId, [u8; 32])>,
}

impl BridgeMosaicIdResolver {
    /// Builds a resolver from the configured peer IDs and the operator table's signing keys.
    ///
    /// Fails unless every operator in the table has exactly one well-formed peer ID, no entry
    /// names an unregistered operator, and no two operators share a peer ID.
    fn new(config: &MosaicConfig, operator_table: &OperatorTable) -> anyhow::Result<Self> {
        let mut operators = HashMap::new();
        let mut peer_id_owners: HashMap<PeerId, OperatorIdx> = HashMap::new();

        for MosaicPeerConfig {
            operator_idx,
            peer_id,
        } in &config.peers
        {
            let operator_idx = *operator_idx;
            let btc_key = operator_table.idx_to_btc_key(&operator_idx).ok_or_else(|| {
                anyhow!("mosaic peer entry names operator {operator_idx}, which is not registered in params")
            })?;

            let peer_id: PeerId = hex::decode(peer_id)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    anyhow!(
                        "mosaic peer ID for operator {operator_idx} must be 32 hex-encoded bytes"
                    )
                })?;

            if let Some(owner) = peer_id_owners.insert(peer_id, operator_idx)
                && owner != operator_idx
            {
                let (first, second) = (owner.min(operator_idx), owner.max(operator_idx));
                bail!(
                    "mosaic peer ID {} is configured for operators {first} and {second}",
                    hex::encode(peer_id)
                );
            }

            let xonly_bytes = btc_key.x_only_public_key().0.serialize();
            if operators
                .insert(operator_idx, (peer_id, xonly_bytes))
                .is_some()
            {
                bail!("mosaic peers list operator {operator_idx} more than once");
            }
        }

        if let Some(missing) = operator_table
            .operator_idxs()
            .into_iter()
            .find(|idx| !operators.contains_key(idx))
        {
            bail!("no mosaic peer ID is configured for operator {missing}");
        }

        Ok(Self { operators })
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

/// Build a [`MosaicClient`] from the mosaic config and operator table.
///
/// Fails if the configured peer IDs do not cover the operator table exactly.
pub(crate) fn init_mosaic_client(
    http_client: HttpClient,
    config: &MosaicConfig,
    operator_table: &OperatorTable,
    pov_idx: OperatorIdx,
) -> anyhow::Result<MosaicClient<HttpClient, BridgeMosaicIdResolver>> {
    let resolver = BridgeMosaicIdResolver::new(config, operator_table)?;

    Ok(
        MosaicClient::builder(Arc::new(http_client), resolver, pov_idx)
            .retry_delay(config.retry_delay)
            .max_retries(config.max_retries)
            .poll_interval(config.poll_interval)
            .build(),
    )
}

/// Build a [`jsonrpsee`] HTTP client targeting the local Mosaic RPC service.
pub(crate) fn init_mosaic_rpc_client(config: &MosaicConfig) -> HttpClient {
    HttpClientBuilder::default()
        .build(&config.rpc_url)
        .unwrap_or_else(|e| {
            panic!(
                "failed to build mosaic HTTP client for {}: {e}",
                config.rpc_url
            )
        })
}

/// Run `ensure_mosaic_setup` for every `(other_operator, role)` pair concurrently.
///
/// Skips the point-of-view operator (self). Fails fast on the first error — remaining in-flight
/// futures are dropped.
pub(crate) async fn run_mosaic_setup(
    client: &MosaicClient<HttpClient, BridgeMosaicIdResolver>,
    operator_table: &OperatorTable,
) -> anyhow::Result<()> {
    let pov_idx = operator_table.pov_idx();
    let pairs = mosaic_setup_pairs(operator_table);

    let total = pairs.len();
    info!(
        %pov_idx,
        total,
        "starting mosaic setup for all operator pairs"
    );

    future::try_join_all(pairs.into_iter().map(|(idx, role)| async move {
        info!(%idx, ?role, "starting mosaic setup");
        client
            .ensure_mosaic_setup(idx, role)
            .await
            .inspect_err(|source| {
                error!(%idx, ?role, err = %source, "mosaic setup failed");
            })
            .context(format!(
                "mosaic setup failed for operator {idx} role {role}"
            ))?;
        info!(%idx, ?role, "mosaic setup complete");
        Ok::<(), anyhow::Error>(())
    }))
    .await?;

    info!("mosaic setup completed successfully for all {total} pairs");
    Ok(())
}

/// Returns the `(operator, role)` pairs this node sets up: both roles with every other operator.
fn mosaic_setup_pairs(operator_table: &OperatorTable) -> Vec<(OperatorIdx, Role)> {
    let pov_idx = operator_table.pov_idx();
    operator_table
        .operator_idxs()
        .into_iter()
        .filter(|idx| *idx != pov_idx)
        .flat_map(|idx| [(idx, Role::Garbler), (idx, Role::Evaluator)])
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

    use super::*;

    /// Operator table registering indices 0, 2 and 5, with this node at `pov_idx`.
    fn gapped_table(pov_idx: OperatorIdx) -> OperatorTable {
        let dense = test_operator_table(3, 0);
        let entries = [(0, 0), (1, 2), (2, 5)]
            .into_iter()
            .map(|(dense_idx, idx)| {
                (
                    idx,
                    dense.idx_to_p2p_key(&dense_idx).unwrap().clone(),
                    dense.idx_to_btc_key(&dense_idx).unwrap(),
                )
            })
            .collect();
        OperatorTable::new(entries, move |entry| entry.0 == pov_idx).expect("valid table")
    }

    fn peer_id_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn config(peers: &[(OperatorIdx, String)]) -> MosaicConfig {
        MosaicConfig {
            rpc_url: "http://localhost:7500".to_string(),
            retry_delay: Duration::from_secs(1),
            max_retries: 1,
            poll_interval: Duration::from_secs(1),
            peers: peers
                .iter()
                .map(|(operator_idx, peer_id)| MosaicPeerConfig {
                    operator_idx: *operator_idx,
                    peer_id: peer_id.clone(),
                })
                .collect(),
        }
    }

    fn all_peers() -> Vec<(OperatorIdx, String)> {
        vec![
            (0, peer_id_hex(1)),
            (2, peer_id_hex(3)),
            (5, peer_id_hex(6)),
        ]
    }

    fn resolver_err(peers: &[(OperatorIdx, String)]) -> String {
        BridgeMosaicIdResolver::new(&config(peers), &gapped_table(0))
            .err()
            .expect("the mosaic peer configuration is invalid")
            .to_string()
    }

    #[tokio::test]
    async fn resolver_follows_operator_indices_not_entry_order() {
        let table = gapped_table(0);
        let mut reversed = all_peers();
        reversed.reverse();

        for peers in [all_peers(), reversed] {
            let resolver = BridgeMosaicIdResolver::new(&config(&peers), &table)
                .expect("valid mosaic peer configuration");

            assert_eq!(
                resolver
                    .resolve_peer_id(5)
                    .await
                    .expect("operator 5 is known"),
                [6; 32],
                "operator 5 must resolve to its own peer ID regardless of entry order"
            );
            assert_eq!(
                resolver
                    .resolve_operator_pubkey(5)
                    .await
                    .expect("operator 5 is known"),
                table
                    .idx_to_btc_key(&5)
                    .unwrap()
                    .x_only_public_key()
                    .0
                    .serialize(),
                "operator 5 must resolve to its own signing key"
            );
        }
    }

    #[test]
    fn resolver_rejects_unknown_operators() {
        let mut peers = all_peers();
        peers.push((7, peer_id_hex(8)));

        let err = resolver_err(&peers);

        assert!(
            err.contains("operator 7") && err.contains("not registered"),
            "an index without a registration must be named: {err}"
        );
    }

    #[test]
    fn resolver_rejects_duplicate_operators() {
        for repeated_peer_id in [peer_id_hex(9), peer_id_hex(3)] {
            let mut peers = all_peers();
            peers.push((2, repeated_peer_id));

            let err = resolver_err(&peers);

            assert!(
                err.contains("operator 2") && err.contains("more than once"),
                "a repeated index must be rejected whether or not its peer ID changes: {err}"
            );
        }
    }

    #[test]
    fn resolver_rejects_missing_operators() {
        let err = resolver_err(&all_peers()[..2]);

        assert!(
            err.contains("operator 5"),
            "every registered operator needs a peer ID: {err}"
        );
    }

    #[test]
    fn resolver_rejects_peer_ids_shared_by_operators() {
        let peers = vec![
            (0, peer_id_hex(1)),
            (2, peer_id_hex(1)),
            (5, peer_id_hex(6)),
        ];

        let err = resolver_err(&peers);

        assert!(
            err.contains("operators 0 and 2"),
            "a peer ID claimed by two operators is ambiguous: {err}"
        );
    }

    #[test]
    fn resolver_rejects_malformed_peer_ids() {
        let peers = vec![
            (0, peer_id_hex(1)),
            (2, "abcd".to_string()),
            (5, peer_id_hex(6)),
        ];

        let err = resolver_err(&peers);

        assert!(
            err.contains("operator 2") && err.contains("32"),
            "a peer ID that is not 32 bytes must be rejected: {err}"
        );
    }

    #[test]
    fn setup_pairs_cover_every_other_registered_operator() {
        let pairs = mosaic_setup_pairs(&gapped_table(2));

        assert_eq!(
            pairs,
            vec![
                (0, Role::Garbler),
                (0, Role::Evaluator),
                (5, Role::Garbler),
                (5, Role::Evaluator),
            ],
            "setup must pair this node with every other registration in both roles"
        );
    }
}
