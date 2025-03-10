//! Constants used throughout the p2p-client.

use std::net::Ipv4Addr;

/// Default RPC host.
pub const DEFAULT_HOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Default RPC port.
pub const DEFAULT_PORT: u16 = 4780;

/// Default number of threads.
pub const DEFAULT_NUM_THREADS: usize = 2;

/// Default idle connection timeout in seconds.
pub const DEFAULT_IDLE_CONNECTION_TIMEOUT: u64 = 30;
