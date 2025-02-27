//! Parses command-line arguments for the p2p-client CLI.

use clap::{crate_version, Parser};

use crate::constants::{
    DEFAULT_NUM_THREADS, DEFAULT_RPC_HOST, DEFAULT_RPC_PORT, DEFAULT_STACK_SIZE_MB,
};

/// CLI arguments for the p2p-client.
#[derive(Debug, Parser)]
#[clap(
    name = "strata-bridge",
    about = "The bridge node for Strata",
    version = crate_version!()
)]
pub(crate) struct Cli {
    /// RPC server host for the p2p node.
    #[clap(long, help = "RPC server host for the p2p node", default_value_t = DEFAULT_RPC_HOST.to_string())]
    pub rpc_host: String,

    /// RPC server port for the p2p node.
    #[clap(long, help = "RPC server port for the p2p node", default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u32,

    /// The number of tokio threads to use.
    #[clap(long, help = "The number of tokio threads to use", default_value_t = DEFAULT_NUM_THREADS)]
    pub num_threads: usize,

    /// The stack size per thread (in MB).
    #[clap(long, help = "The stack size per thread (in MB)", default_value_t = DEFAULT_STACK_SIZE_MB)]
    pub stack_size: usize,
}
