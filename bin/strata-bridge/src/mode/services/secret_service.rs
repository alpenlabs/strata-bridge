//! Provides secret service client initialization.
use std::{fs, io, path::Path, time::Duration};

use secret_service_client::{
    SecretServiceClient,
    rustls::{
        self, ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};
use tokio::net::lookup_host;
use tracing::debug;

use crate::config::SecretServiceConfig;

pub(in crate::mode) async fn init_secret_service_client(
    config: &SecretServiceConfig,
) -> SecretServiceClient {
    install_rustls_crypto_provider();

    let key = fs::read(&config.key).expect("readable key");
    let key = if config.key.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .expect("valid PEM-encoded private key")
            .expect("non-empty private key")
    };
    let certs = read_cert(&config.cert).expect("valid cert");

    let ca_certs = read_cert(&config.service_ca).expect("valid CA cert");
    let mut root_store = RootCertStore::empty();
    let (added, ignored) = root_store.add_parsable_certificates(ca_certs);
    debug!("loaded {added} certs for the secret service CA, ignored {ignored}");

    let tls_client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("good client config");

    let mut addrs = lookup_host(&config.server_addr)
        .await
        .expect("DNS resolution failed");

    let server_addr = addrs.next().expect("DNS resolved, but no addresses");

    let s2_config = secret_service_client::Config {
        server_addr,
        server_hostname: config.server_hostname.clone(),
        local_addr: None,
        tls_config: tls_client_config,
        timeout: Duration::from_secs(config.timeout),
    };
    SecretServiceClient::new(s2_config)
        .await
        .expect("good client")
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Reads a certificate from a file.
fn read_cert(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(path)?;
    if path.extension().is_some_and(|x| x == "der") {
        Ok(vec![CertificateDer::from(cert_chain)])
    } else {
        rustls_pemfile::certs(&mut &*cert_chain).collect()
    }
}
