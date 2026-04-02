//! Mosaic client initialization and setup for the bridge operator.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::stream::{self, StreamExt, TryStreamExt};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};
use strata_mosaic_client::{MosaicClient, MosaicIdResolver, PeerId};
use strata_mosaic_client_api::{MosaicClientApi, MosaicError, types::Role};
use tracing::{error, info};

use crate::config::MosaicConfig;

/// Resolves bridge operator indices to mosaic-native identifiers.
///
/// Peer IDs come from the bridge config; operator pubkeys come from the operator table.
pub(crate) struct BridgeMosaicIdResolver {
    /// `(mosaic_peer_id, xonly_pubkey_bytes)` indexed by `OperatorIdx`.
    operators: HashMap<OperatorIdx, (PeerId, [u8; 32])>,
}

impl BridgeMosaicIdResolver {
    /// Build a resolver from the mosaic config (peer IDs) and operator table (pubkeys).
    ///
    /// # Panics
    ///
    /// Panics if `config.peer_ids.len() != operator_table.cardinality()` or if any peer ID is not
    /// valid 32-byte hex.
    fn new(config: &MosaicConfig, operator_table: &OperatorTable) -> Self {
        assert_eq!(
            config.peer_ids.len(),
            operator_table.cardinality(),
            "mosaic config peer_ids length ({}) must match operator count ({})",
            config.peer_ids.len(),
            operator_table.cardinality(),
        );

        let operators = operator_table
            .operator_idxs()
            .into_iter()
            .map(|idx| {
                let peer_id_hex = &config.peer_ids[idx as usize];
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

                let btc_key = operator_table
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
    ) -> Result<[u8; 32], MosaicError> {
        self.operators
            .get(&operator_idx)
            .map(|(_, pubkey)| *pubkey)
            .ok_or(MosaicError::UnknownOperator(operator_idx))
    }
}

/// Build a [`MosaicClient`] from the mosaic config and operator table.
pub(crate) fn init_mosaic_client(
    config: &MosaicConfig,
    operator_table: &OperatorTable,
) -> MosaicClient<HttpClient, BridgeMosaicIdResolver> {
    let http_client = HttpClientBuilder::default()
        .build(&config.rpc_url)
        .unwrap_or_else(|e| {
            panic!(
                "failed to build mosaic HTTP client for {}: {e}",
                config.rpc_url
            )
        });

    let resolver = BridgeMosaicIdResolver::new(config, operator_table);

    MosaicClient::builder(Arc::new(http_client), resolver)
        .retry_delay(config.retry_delay)
        .max_retries(config.max_retries)
        .poll_interval(config.poll_interval)
        .build()
}

/// Run [`ensure_mosaic_setup`] for every `(other_operator, role)` pair with bounded concurrency.
///
/// Skips the point-of-view operator (self). Fails fast on the first error — remaining in-flight
/// futures are dropped.
pub(crate) async fn run_mosaic_setup(
    client: &MosaicClient<HttpClient, BridgeMosaicIdResolver>,
    operator_table: &OperatorTable,
    concurrency: usize,
) -> anyhow::Result<()> {
    let pov_idx = operator_table.pov_idx();

    let pairs: Vec<(OperatorIdx, Role)> = operator_table
        .operator_idxs()
        .into_iter()
        .filter(|idx| *idx != pov_idx)
        .flat_map(|idx| [(idx, Role::Garbler), (idx, Role::Evaluator)])
        .collect();

    let total = pairs.len();
    info!(
        %pov_idx,
        total,
        concurrency,
        "starting mosaic setup for all operator pairs"
    );

    stream::iter(pairs)
        .map(Ok)
        .try_for_each_concurrent(concurrency, |(idx, role)| async move {
            info!(%idx, ?role, "starting mosaic setup");
            client.ensure_mosaic_setup(idx, role).await.map_err(|e| {
                error!(%idx, ?role, %e, "mosaic setup failed");
                anyhow::anyhow!("mosaic setup failed for operator {idx} role {role:?}: {e}")
            })?;
            info!(%idx, ?role, "mosaic setup complete");
            Ok::<(), anyhow::Error>(())
        })
        .await?;

    info!("mosaic setup completed successfully for all {total} pairs");
    Ok(())
}
