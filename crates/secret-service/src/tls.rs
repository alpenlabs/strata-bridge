use std::path::PathBuf;

use secret_service_server::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use tokio::{fs, io};
use tracing::{error, info, warn};

use crate::{config::TlsConfig, DEV_MODE};

pub async fn load_tls(conf: TlsConfig) -> ServerConfig {
    let (certs, key) = if let (Some(crt_path), Some(key_path)) = (conf.cert, conf.key) {
        let key = fs::read(&key_path).await.expect("readable key");
        let key = if key_path.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .expect("valid PEM-encoded private key")
                .expect("non-empty private key")
        };
        let cert_chain = read_cert(crt_path).await.expect("valid cert");

        (cert_chain, key)
    } else if *DEV_MODE {
        warn!("⚠️ using self-signed certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert = cert.cert.into();
        (vec![cert], key.into())
    } else {
        error!("TLS configuration is missing certificate and key paths");
        std::process::exit(10);
    };

    let tls_builder = if let Some(ca_path) = conf.ca {
        let ca_certs = read_cert(ca_path).await.expect("valid CA cert");
        let mut root_store = RootCertStore::empty();
        let (added, ignored) = root_store.add_parsable_certificates(ca_certs);
        info!(
            "Added {} certificates to client CA store, ignored {}",
            added, ignored
        );
        let client_cert_verifier = WebPkiClientVerifier::builder(root_store.into())
            .build()
            .expect("valid client verifier");
        ServerConfig::builder().with_client_cert_verifier(client_cert_verifier)
    } else if *DEV_MODE {
        warn!("⚠️ no CA certificate provided, disabling client authentication");
        ServerConfig::builder().with_no_client_auth()
    } else {
        error!("TLS configuration is missing CA certificate path");
        std::process::exit(11);
    };

    tls_builder
        .with_single_cert(certs, key)
        .expect("valid rustls config")
}

async fn read_cert(path: PathBuf) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(&path).await?;
    if path.extension().is_some_and(|x| x == "der") {
        Ok(vec![CertificateDer::from(cert_chain)])
    } else {
        rustls_pemfile::certs(&mut &*cert_chain).collect::<Result<_, _>>()
    }
}
