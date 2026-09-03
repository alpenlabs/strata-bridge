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

/// Maximum time the wallet health probe waits for the wallet's shared read guard.
///
/// This is a liveness cutoff, not a worst-case hold bound. A healthy wallet can hold the
/// exclusive guard for minutes: `OperatorWallet::sync` is a retry loop (six attempts, each up
/// to a 15 s Fireblocks round trip, plus a reserved-wallet sync with no timeout of its own),
/// and the Fireblocks signing path holds the same guard for up to `SIGN_MAX_DURATION` (180 s)
/// while it waits on workspace approval. A `probe_timed_out` report during those windows is
/// expected and self-clears on the next probe tick; sizing the cutoff to the true ceiling
/// would delay detection of a genuinely wedged lock by several ticks, which is the one thing
/// the probe exists to catch quickly.
pub(crate) const WALLET_PROBE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

const _: () = assert!(
    DEFAULT_HEALTH_PROBE_TIMEOUT.as_secs() < DEFAULT_HEALTH_PROBE_INTERVAL.as_secs(),
    "health probe timeout must be shorter than the probe interval"
);
