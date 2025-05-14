use std::time::Duration;

/// Default startup delay for the bridge node.
pub(crate) const STARTUP_DELAY: Duration = Duration::from_secs(2);

/// Default thread count for the bridge node.
pub(crate) const DEFAULT_THREAD_COUNT: u8 = 4;

/// Default thread stack size for the bridge node.
pub(crate) const DEFAULT_THREAD_STACK_SIZE: usize = 100 * 1024 * 1024;

/// Default RPC state cache refresh interval for the bridge node.
///
/// The rationale is to use 10 minutes since on every new block that the Duty Tracker scans,
/// it refreshes the state.
pub(crate) const DEFAULT_RPC_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);
