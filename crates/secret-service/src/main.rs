// use secret_service_server::rustls::ServerConfig;

pub mod config;
pub mod disk;

use std::{env::args, path::PathBuf, str::FromStr};

use config::{TlsConfig, TomlConfig};
use disk::Service;
use secret_service_server::{
    run_server,
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    Config,
};
use tokio::fs;
use tracing::info;

#[tokio::main]
async fn main() {
    let config_path =
        PathBuf::from_str(&args().nth(1).unwrap_or_else(|| "config.toml".to_string()))
            .expect("valid config path");

    let text = std::fs::read_to_string(&config_path).expect("read config file");
    let conf: TomlConfig = toml::from_str(&text).expect("valid toml");

    let (certs, key) = if let Some(TlsConfig {
        cert: Some(ref crt_path),
        key: Some(ref key_path),
    }) = conf.tls
    {
        let key = fs::read(key_path).await.expect("readable key");
        let key = if key_path.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .expect("valid PEM-encoded private key")
                .expect("non-empty private key")
        };
        let cert_chain = fs::read(crt_path).await.expect("readable certificate");
        let cert_chain = if crt_path.extension().is_some_and(|x| x == "der") {
            vec![CertificateDer::from(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .collect::<Result<_, _>>()
                .expect("valid PEM-encoded certificate")
        };

        (cert_chain, key)
    } else {
        info!("using self-signed certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert = cert.cert.into();
        (vec![cert], key.into())
    };

    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("valid rustls config");

    let config = Config {
        addr: conf.transport.addr,
        tls_config: tls,
        connection_limit: conf.transport.conn_limit,
    };

    let service = Service::load_from_seed_and_db(
        &conf
            .seed
            .unwrap_or(PathBuf::from_str("seed").expect("valid path")),
        conf.db
            .unwrap_or(PathBuf::from_str("db").expect("valid path")),
    )
    .await
    .expect("good service");

    let persister = service.round_persister().expect("good persister");

    run_server(config, service.into(), persister.into())
        .unwrap()
        .await;
}
