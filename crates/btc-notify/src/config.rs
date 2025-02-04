use crate::constants::DEFAULT_BURY_DEPTH;

/// BtcZmqConfig is the main configuration type used to establish the connection with the ZMQ
/// interface of Bitcoin.
///
/// It accepts independent connection strings for each of the stream types. Any connection strings
/// that are left as None when initializing the BtcZmqClient will result in those streams going
/// unmonitored. In the limit, this means that the default BtcZmqConfig will result in a
/// BtcZmqClient that does absolutely nothing (NOOP).
///
/// You should construct a BtcZmqConfig with [`Default::default`] and modify it with the member
/// methods on this struct.
#[derive(Debug, Clone)]
pub struct BtcZmqConfig {
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

impl BtcZmqConfig {
    /// Updates the [`BtcZmqConfig`] with a `zmqpubhashblock` connection string and returns the updated
    /// config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_hashblock_connection_string(mut self, s: &str) -> Self {
        self.hashblock_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubhashtx connection string and returns the updated
    /// config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_hashtx_connection_string(mut self, s: &str) -> Self {
        self.hashtx_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubrawblock connection string and returns the updated
    /// config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_rawblock_connection_string(mut self, s: &str) -> Self {
        self.rawblock_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubrawtx connection string and returns the updated
    /// config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_rawtx_connection_string(mut self, s: &str) -> Self {
        self.rawtx_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubsequence connection string and returns the updated
    /// config.
    ///
    /// Useful for a builder pattern with dotchaining.
    pub fn with_sequence_connection_string(mut self, s: &str) -> Self {
        self.sequence_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a new bury depth and returns the updated config.
    ///
    /// Useful for a builder pattern with dotchaining.
    ///
    /// Note, this is the number of blocks that must be built on top of a given block before that
    /// block is considered buried. A bury depth of 6 will mean that the most recent "buried"
    /// block will be the 7th newest block. A bury depth of 0 would mean that the block is
    /// considered buried the moment it is mined.
    pub fn with_bury_depth(mut self, n: usize) -> Self {
        self.bury_depth = n;
        self
    }
}

impl Default for BtcZmqConfig {
    fn default() -> Self {
        BtcZmqConfig {
            bury_depth: DEFAULT_BURY_DEPTH,
            hashblock_connection_string: None,
            hashtx_connection_string: None,
            rawblock_connection_string: None,
            rawtx_connection_string: None,
            sequence_connection_string: None,
        }
    }
}
