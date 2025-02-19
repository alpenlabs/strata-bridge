// use secret_service_server::rustls::ServerConfig;

pub mod config;
pub mod disk;
mod tls;

use std::{env::args, path::PathBuf, str::FromStr, sync::LazyLock};

use config::TomlConfig;
use disk::Service;
use secret_service_server::{run_server, Config};
use tls::load_tls;
use tracing::info;

pub static DEV_MODE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("S2_DEV").is_ok_and(|v| &v == "1"));

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    if *DEV_MODE {
        info!("DEV_MODE active");
    }
    let config_path =
        PathBuf::from_str(&args().nth(1).unwrap_or_else(|| "config.toml".to_string()))
            .expect("valid config path");

    let text = std::fs::read_to_string(&config_path).expect("read config file");
    let conf: TomlConfig = toml::from_str(&text).expect("valid toml");
    let tls = load_tls(conf.tls).await;

    let config = Config {
        addr: conf.transport.addr,
        tls_config: tls,
        connection_limit: conf.transport.conn_limit,
    };

    let service = Service::load_from_seed(
        &conf
            .seed
            .unwrap_or(PathBuf::from_str("seed").expect("valid path")),
    )
    .await
    .expect("good service");

    info!("Running on {}", config.addr);
    match config.connection_limit {
        Some(conn_limit) => info!("Connection limit: {}", conn_limit),
        None => info!("No connection limit"),
    }
    run_server(config, service.into()).await.unwrap();
}
