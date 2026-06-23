use std::time::Duration;

/// Default thread count for the bridge node.
pub(crate) const DEFAULT_THREAD_COUNT: u8 = 4;

/// Default thread stack size for the bridge node.
pub(crate) const DEFAULT_THREAD_STACK_SIZE: usize = 100 * 1024 * 1024;

/// Default RPC state cache refresh interval for the bridge node.
///
/// The rationale is to use 10 minutes since on every new block that the orchestrator scans,
/// it refreshes the state.
pub(crate) const DEFAULT_RPC_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Default interval for bridge component health probes.
pub(crate) const DEFAULT_HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum time a single health probe waits on an external system before it is marked unhealthy.
pub(crate) const DEFAULT_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

const _: () = assert!(
    DEFAULT_HEALTH_PROBE_TIMEOUT.as_secs() < DEFAULT_HEALTH_PROBE_INTERVAL.as_secs(),
    "health probe timeout must be shorter than the probe interval"
);
