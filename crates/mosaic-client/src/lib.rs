//! Mosaic Client
//!
//! JSON-RPC client for interacting with a mosaic instance. Handles tableset
//! lifecycle (setup, deposit, withdrawal), background polling of watched
//! deposits, and event broadcasting.
//!
//! The client is generic over a [`MosaicIdResolver`] which resolves
//! bridge-native identifiers (`OperatorIdx`, `DepositIdx`) to mosaic-native
//! ones (`PeerId`, `DepositId`). All mosaic-specific input derivation
//! (setup inputs, deposit inputs, withdrawal inputs) is handled internally.
//!
//! # Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let client = MosaicClient::builder(rpc_client, provider)
//!     .retry_delay(Duration::from_secs(3))
//!     .max_retries(10)
//!     .poll_interval(Duration::from_secs(10))
//!     .build();
//!
//! // Setup a tableset for an operator.
//! client.ensure_mosaic_setup(operator_idx, Role::Garbler).await?;
//!
//! // Initialize a deposit.
//! client.init_garbler_deposit(operator_idx, deposit_idx, sighashes, adaptor_pk).await?;
//!
//! // Subscribe to events and spawn the background poller.
//! let mut events = client.subscribe_events();
//! tokio::spawn(client.clone().poll_watched_deposits());
//! ```

use std::{collections::HashMap, sync::Arc, time::Duration};

use algebra::retry::{Strategy, retry_with};
use mosaic_rpc_types::RpcTablesetId;
use strata_bridge_primitives::types::OperatorIdx;
use strata_mosaic_client_api::{MosaicError, MosaicEvent, types::*};
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::util::{DEFAULT_INSTANCE, to_cac_role};

mod client;
mod resolver;
mod rpc;
mod task;
pub(crate) mod util;

pub use resolver::*;
pub use rpc::MosaicApi;

type WatchDepositKey = (RpcTablesetId, OperatorIdx, DepositIdx);

const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(2);
const DEFAULT_MAX_RETRIES: usize = 5;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Client for interacting with a mosaic instance over JSON-RPC.
///
/// Manages tableset lifecycle, deposit watching, and event broadcasting
/// to subscribed listeners.
#[derive(Debug, Clone)]
pub struct MosaicClient<R: MosaicApi, P: MosaicIdResolver> {
    // rpc client connection to mosaic
    rpc: Arc<R>,
    // resolve operator related data
    provider: P,
    // cache of known tableset ids
    tablesets: Arc<RwLock<HashMap<(Role, OperatorIdx), RpcTablesetId>>>,
    // deposits pending adaptor verification watched in background
    watched_deposits: Arc<Mutex<HashMap<WatchDepositKey, usize>>>,
    // channels to send [`MosaicEvent`] from watched deposits
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<MosaicEvent>>>>,
    // delay between retries for network errors and some protocol errors.
    retry_delay: Duration,
    // max number of retries
    max_retries: usize,
    // deposit watch task poll interval
    poll_interval: Duration,
}

/// Builder for [`MosaicClient`].
#[derive(Debug)]
pub struct MosaicClientBuilder<R: MosaicApi, Provider: MosaicIdResolver> {
    rpc: Arc<R>,
    provider: Provider,
    retry_delay: Duration,
    max_retries: usize,
    poll_interval: Duration,
}

impl<R: MosaicApi, P: MosaicIdResolver> MosaicClientBuilder<R, P> {
    /// Create a new builder with the required RPC client and ID provider.
    pub const fn new(client: Arc<R>, provider: P) -> Self {
        Self {
            rpc: client,
            provider,
            retry_delay: DEFAULT_RETRY_DELAY,
            max_retries: DEFAULT_MAX_RETRIES,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Set the delay between retries for network and protocol errors.
    pub const fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Set the maximum number of retries.
    pub const fn max_retries(mut self, max: usize) -> Self {
        self.max_retries = max;
        self
    }

    /// Set the poll interval for watched deposits.
    pub const fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Build the [`MosaicClient`].
    pub fn build(self) -> MosaicClient<R, P> {
        MosaicClient {
            rpc: self.rpc,
            provider: self.provider,
            subscribers: Arc::new(Mutex::new(Vec::new())),
            tablesets: Arc::new(RwLock::new(HashMap::new())),
            watched_deposits: Arc::new(Mutex::new(HashMap::new())),
            retry_delay: self.retry_delay,
            max_retries: self.max_retries,
            poll_interval: self.poll_interval,
        }
    }
}

impl<R: MosaicApi, P: MosaicIdResolver> MosaicClient<R, P> {
    /// Create a [`MosaicClientBuilder`].
    pub const fn builder(client: Arc<R>, provider: P) -> MosaicClientBuilder<R, P> {
        MosaicClientBuilder::new(client, provider)
    }

    async fn emit(&self, evt: MosaicEvent) {
        self.subscribers
            .lock()
            .await
            .retain(|subscriber| subscriber.send(evt).is_ok());
    }

    async fn get_tableset_id(
        &self,
        role: Role,
        operator_idx: OperatorIdx,
    ) -> Result<RpcTablesetId, MosaicError> {
        // First check from cache
        if let Some(tableset_id) = self
            .tablesets
            .read()
            .await
            .get(&(role, operator_idx))
            .cloned()
        {
            return Ok(tableset_id);
        };

        let peer_id = self.provider.resolve_peer_id(operator_idx).await?;
        let rpc = self.rpc.clone();
        let tableset_id = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            let rpc_peer_id = peer_id.into();
            async move {
                rpc.get_tableset_id(to_cac_role(role), rpc_peer_id, DEFAULT_INSTANCE.into())
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        // Cache tableset ids for future calls
        self.tablesets
            .write()
            .await
            .insert((role, operator_idx), tableset_id);

        Ok(tableset_id)
    }

    fn default_retry_strategy<T: Send + Sync + 'static>(&self) -> Strategy<T> {
        Strategy::fixed_delay(self.retry_delay).with_max_retries(self.max_retries)
    }
}
