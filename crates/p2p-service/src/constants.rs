//! Constants used throughout the p2p-client.

use std::{net::Ipv4Addr, time::Duration};

/// Default RPC host.
pub const DEFAULT_HOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Default RPC port.
pub const DEFAULT_PORT: u16 = 4780;

/// Default number of threads.
pub const DEFAULT_NUM_THREADS: usize = 2;

/// Default idle connection timeout in seconds.
pub const DEFAULT_IDLE_CONNECTION_TIMEOUT: u64 = 30;

/// Default interval between peer-reconnection attempts.
pub const DEFAULT_PEER_RECONNECT_INTERVAL: Duration = Duration::from_secs(60);

/// Default size of the inbound gossip event buffer.
pub const DEFAULT_GOSSIP_EVENT_BUFFER_SIZE: usize = 4096;

/// Default size of the outbound gossip command queue.
pub const DEFAULT_GOSSIP_COMMAND_BUFFER_SIZE: usize = 4096;
