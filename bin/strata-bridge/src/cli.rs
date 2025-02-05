//! Parses command-line arguments for the bridge-client CLI.

use std::{path::PathBuf, time::Duration};

use clap::{crate_version, Parser};

use crate::constants::{
    DEFAULT_NUM_THREADS, DEFAULT_RPC_HOST, DEFAULT_RPC_PORT, DEFAULT_STACK_SIZE_MB,
};

#[derive(Debug, Parser)]
#[clap(
    name = "strata-bridge",
    about = "The bridge node for Strata",
    version = crate_version!()
)]
pub(crate) struct Cli {
    #[clap(
        long,
        help = "ws URL of the rollup RPC server",
        default_value = "ws://localhost:8432"
    )]
    pub strata_url: String,

    #[clap(long, help = "Request timeout for websocket connection to strata (in milliseconds)", default_value = "300000", value_parser = parse_duration)]
    pub strata_ws_timeout: Duration,

    #[clap(
        long,
        help = "URL of the bitcoind node",
        default_value = "http://localhost:18433"
    )]
    pub btc_url: String,

    #[clap(long, help = "Bitcoind username", env = "BTC_USER")]
    pub btc_user: String,

    #[clap(long, help = "Bitcoind password", env = "BTC_PASSWORD")]
    pub btc_pass: String,

    #[clap(long, help = "Bitcoind password", env = "BTC_PASSWORD")]
    pub btc_pass: String,

    #[clap(long, help = "Bitcoind RPC Retry count", env = "BTC_RPC_RETRY_COUNT")]
    pub btc_retry_count: Option<u8>,

    #[clap(
        long,
        help = "Bitcoind RPC retry interval",
        env = "BTC_RPC_RETRY_INTERVAL"
    )]
    pub btc_retry_interval: Option<u64>,

    #[clap(
        long,
        default_value = "1",
        help = "Bridge duty polling interval (in milliseconds)",
        value_parser = parse_duration,
    )]
    pub btc_scan_interval: Duration,

    #[clap(long, default_value_t = 0, help = "Block height to start scans from")]
    pub btc_genesis_height: u32,

    #[clap(long, help = "RPC server host for the bridge node", default_value_t = DEFAULT_RPC_HOST.to_string())]
    pub rpc_host: String,

    #[clap(long, help = "RPC server host for the bridge node", default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u32,

    #[clap(
        long,
        help = "percentage of operators that are faulty (max: 100)",
        default_value_t = 33,
        value_parser = parse_fault_tolerance,
    )]
    pub fault_tolerance: u8,

    #[clap(
        long,
        default_value = "30",
        help = "Bridge duty polling interval (in milliseconds)",
        value_parser = parse_duration,
    )]
    pub duty_interval: Duration,

    #[clap(
        long,
        help = "The file containing the list of client privkeys to use (one per line)",
        default_value = "xpriv.bin"
    )]
    pub xpriv_file: PathBuf,

    #[clap(
        long,
        help = "The file containing RollupParams",
        default_value = "rollup_params.json"
    )]
    pub rollup_params_file: PathBuf,

    #[clap(
        long,
        help = "The file containing the list of client WOTS master key to use (one per line)",
        default_value = "msks.bin"
    )]
    pub msks_file: PathBuf,

    #[clap(long, help = "The number of tokio threads to use", default_value_t = DEFAULT_NUM_THREADS)]
    pub num_threads: usize,

    #[clap(long, help = "The stack size per thread (in MB)", default_value_t = DEFAULT_STACK_SIZE_MB)]
    pub stack_size: usize,

    #[clap(long, help = "The directory for databases", default_value = ".data")]
    pub data_dir: PathBuf,

    #[clap(
        long,
        help = "The wallet name prefix for operators",
        env = "WALLET_PREFIX"
    )]
    pub wallet_prefix: String,
}

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;

    Ok(std::time::Duration::from_millis(seconds))
}

fn parse_fault_tolerance(arg: &str) -> anyhow::Result<u8> {
    let value: u8 = arg.parse()?;

    let value = value.min(100);

    Ok(value)
}
