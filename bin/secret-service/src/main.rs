//! Runs the Secret Service.

// use secret_service_server::rustls::ServerConfig;
pub mod config;
mod observability;
pub mod seeded_impl;
#[cfg(test)]
mod tests;
mod tls;

use std::{env::args, path::PathBuf, str::FromStr, sync::LazyLock};

use bitcoin::Network;
use colored::Colorize;
use config::Config;
use secret_service_server::{run_server, Config as ServerConfig};
use seeded_impl::Service;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tls::load_tls;
use tokio::runtime::Handle;
use tracing::{info, warn};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Configures Jemalloc to support memory profiling when the feature is enabled.
/// This allows us to build flamegraphs for memory usage.
/// - `prof:true`: enables profiling for memory allocations
/// - `prof_active:true`: activates the profiling that was enabled by prev option
/// - `lg_prof_sample:19`: sampling interval of every 1 in 2^19 (~512kib) allocations
#[cfg(feature = "memory_profiling")]
#[expect(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

/// Runs the Secret Service in development mode if the `SECRET_SERVICE_DEV` environment variable is
/// set to `1`.
pub static DEV_MODE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("SECRET_SERVICE_DEV").is_ok_and(|v| &v == "1"));

#[tokio::main]
async fn main() {
    #[cfg(feature = "memory_profiling")]
    memory_pprof::setup_memory_profiling(3_000);
    let config_path =
        PathBuf::from_str(&args().nth(1).unwrap_or_else(|| "config.toml".to_string()))
            .expect("valid config path");

    let text = std::fs::read_to_string(&config_path).expect("read config file");
    let conf: Config = toml::from_str(&text).expect("valid toml");
    let network = conf.network.unwrap_or(Network::Signet);
    let seed_path = conf
        .seed
        .unwrap_or(PathBuf::from_str("seed").expect("valid path"));

    tls::install_rustls_crypto_provider();
    observability::init(
        &conf.metrics,
        &conf.tls,
        network,
        *DEV_MODE,
        &Handle::current(),
    );
    if *DEV_MODE {
        warn!("DEV_MODE active");
    }

    let tls = load_tls(conf.tls).await;

    let config = ServerConfig {
        addr: conf.transport.addr,
        tls_config: tls,
        connection_limit: conf.transport.conn_limit,
    };

    let service = Service::load_from_seed(&seed_path, network)
        .await
        .expect("good service");

    info!("Running on {}", config.addr.to_string().bold());
    match config.connection_limit {
        Some(conn_limit) => info!("Connection limit: {}", conn_limit.to_string().bold()),
        None => info!("No connection limit"),
    }
    let result = run_server(config, service.into()).await;
    observability::finalize();
    result.unwrap();
}
