use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use bitcoin::key::Secp256k1;
use musig2::secp256k1::Message;
use rand::{thread_rng, Rng};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::{OperatorSigner, P2PSigner, SecretService};
use secret_service_server::{
    run_server,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        ClientConfig, ServerConfig,
    },
};

use crate::disk::Service;

#[tokio::test]
async fn e2e() {
    let server_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 20000).into();
    let server_host = "localhost".to_string();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = cert.cert.into();
    let server_tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("valid config");
    let config = secret_service_server::Config {
        addr: server_addr.clone(),
        tls_config: server_tls_config,
        connection_limit: None,
    };
    let service = Service::new_with_seed([0u8; 32]);

    tokio::spawn(async move {
        run_server(config, service.into()).await.unwrap();
    });

    let client_tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let client_config = secret_service_client::Config {
        server_addr,
        server_hostname: server_host,
        local_addr: None,
        tls_config: client_tls,
        timeout: Duration::from_secs(1),
    };

    let client = SecretServiceClient::new(client_config)
        .await
        .expect("good conn");

    let mut rng = thread_rng();
    let secp_ctx = Secp256k1::verification_only();

    // operator signer
    let op_signer = client.operator_signer();
    let pubkey = op_signer.pubkey().await.expect("good response");
    let to_sign = rng.gen();
    let sig = op_signer.sign(&to_sign).await.expect("good response");
    assert!(secp_ctx
        .verify_schnorr(&sig, &Message::from_digest(to_sign), &pubkey)
        .is_ok());

    // p2p signer
    let p2p_signer = client.p2p_signer();
    let pubkey = p2p_signer.pubkey().await.expect("good response");
    let to_sign = rng.gen();
    let sig = p2p_signer.sign(&to_sign).await.expect("good response");
    assert!(secp_ctx
        .verify_schnorr(&sig, &Message::from_digest(to_sign), &pubkey)
        .is_ok());
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
