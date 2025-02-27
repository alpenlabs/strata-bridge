//! Constants used throughout the p2p-client.

/// Default RPC host.
pub(crate) const DEFAULT_RPC_HOST: &str = "127.0.0.1";

/// Default RPC port.
pub(crate) const DEFAULT_RPC_PORT: u32 = 4780;

pub(crate) const DEFAULT_NUM_THREADS: usize = 2;

/// Default stack size in MB.
pub(crate) const DEFAULT_STACK_SIZE_MB: usize = 512;

/// Default idle connection timeout in seconds.
pub(crate) const DEFAULT_IDLE_CONNECTION_TIMEOUT: u16 = 30;
