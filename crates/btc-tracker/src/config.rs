//! Configuration for the Bitcoin ZMQ client.
use serde::{Deserialize, Serialize};

use crate::constants::DEFAULT_BURY_DEPTH;

/// Main configuration type used to establish the connection with the ZMQ interface of Bitcoin.
///
/// It accepts independent connection strings for each of the stream types. Any connection strings
/// that are left as None when initializing the [`crate::client::BtcNotifyClient`] will result in
/// those streams going unmonitored. In the limit, this means that the default [`BtcNotifyConfig`]
/// will result in a [`crate::client::BtcNotifyClient`] that does absolutely nothing (NOOP).
///
/// You should construct a [`BtcNotifyConfig`] with [`Default::default`] and modify it with the
/// member methods on this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcNotifyConfig {
    /// Depth at which a transaction is considered buried, defaults to [`DEFAULT_BURY_DEPTH`].
    pub(crate) bury_depth: usize,

    /// Connection string used in `bitcoin.conf => zmqpubhashblock`.
    pub(crate) hashblock_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubhashtx`.
    pub(crate) hashtx_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubrawblock`.
    pub(crate) rawblock_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubrawtx`.
    pub(crate) rawtx_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubsequence`.
    pub(crate) sequence_connection_string: Option<String>,
}

impl BtcNotifyConfig {
    /// Updates the [`BtcNotifyConfig`] with a `zmqpubhashblock` connection string and returns the
    /// updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_hashblock_connection_string(mut self, s: &str) -> Self {
        self.hashblock_connection_string = Some(s.to_string());
        self
    }

    /// Updates the [`BtcNotifyConfig`] with a `zmqpubhashtx` connection string and returns the
    /// updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_hashtx_connection_string(mut self, s: &str) -> Self {
        self.hashtx_connection_string = Some(s.to_string());
        self
    }

    /// Updates the [`BtcNotifyConfig`] with a `zmqpubrawblock` connection string and returns the
    /// updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_rawblock_connection_string(mut self, s: &str) -> Self {
        self.rawblock_connection_string = Some(s.to_string());
        self
    }

    /// Updates the [`BtcNotifyConfig`] with a `zmqpubrawtx` connection string and returns the
    /// updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_rawtx_connection_string(mut self, s: &str) -> Self {
        self.rawtx_connection_string = Some(s.to_string());
        self
    }

    /// Updates the [`BtcNotifyConfig`] with a `zmqpubsequence` connection string and returns the
    /// updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_sequence_connection_string(mut self, s: &str) -> Self {
        self.sequence_connection_string = Some(s.to_string());
        self
    }

    /// Updates the [`BtcNotifyConfig`] with a new bury depth and returns the updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    ///
    /// Note, this is the number of blocks that must be built on top of a given block before that
    /// block is considered buried. A bury depth of 6 will mean that the most recent "buried"
    /// block will be the 7th newest block. A bury depth of 0 would mean that the block is
    /// considered buried the moment it is mined.
    pub const fn with_bury_depth(mut self, n: usize) -> Self {
        self.bury_depth = n;
        self
    }

    /// Returns the value configured with the [`BtcNotifyConfig::with_bury_depth`] function.
    pub const fn bury_depth(&self) -> usize {
        self.bury_depth
    }
}

impl Default for BtcNotifyConfig {
    fn default() -> Self {
        BtcNotifyConfig {
            bury_depth: DEFAULT_BURY_DEPTH,
            hashblock_connection_string: None,
            hashtx_connection_string: None,
            rawblock_connection_string: None,
            rawtx_connection_string: None,
            sequence_connection_string: None,
        }
    }
}
