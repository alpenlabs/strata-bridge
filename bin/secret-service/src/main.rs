#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
//! Runs the Secret Service.

// use secret_service_server::rustls::ServerConfig;
pub mod config;
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
use tracing::{info, warn, Level};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(feature = "memory_profiling")]
#[allow(non_upper_case_globals)]
#[expect(missing_docs)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

/// Runs the Secret Service in development mode if the `SECRET_SERVICE_DEV` environment variable is
/// set to `1`.
pub static DEV_MODE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("SECRET_SERVICE_DEV").is_ok_and(|v| &v == "1"));

#[tokio::main]
async fn main() {
    #[cfg(feature = "memory_profiling")]
    memory_pprof::setup_memory_profiling(3000);
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    if *DEV_MODE {
        warn!("⚠️ DEV_MODE active");
    }
    let config_path =
        PathBuf::from_str(&args().nth(1).unwrap_or_else(|| "config.toml".to_string()))
            .expect("valid config path");

    let text = std::fs::read_to_string(&config_path).expect("read config file");
    let conf: Config = toml::from_str(&text).expect("valid toml");
    let tls = load_tls(conf.tls).await;

    let config = ServerConfig {
        addr: conf.transport.addr,
        tls_config: tls,
        connection_limit: conf.transport.conn_limit,
    };

    let service = Service::load_from_seed(
        &conf
            .seed
            .unwrap_or(PathBuf::from_str("seed").expect("valid path")),
        conf.network.unwrap_or(Network::Signet),
    )
    .await
    .expect("good service");

    info!("Running on {}", config.addr.to_string().bold());
    match config.connection_limit {
        Some(conn_limit) => info!("Connection limit: {}", conn_limit.to_string().bold()),
        None => info!("No connection limit"),
    }
    run_server(config, service.into()).await.unwrap();
}
