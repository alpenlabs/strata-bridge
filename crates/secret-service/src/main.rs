// use secret_service_server::rustls::ServerConfig;

use std::{
    env::args,
    fs,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use secret_service_proto::v1::traits::{
    Musig2SignerFirstRound, Musig2SignerSecondRound, OperatorSigner, Origin, SecretService, Server,
};
use secret_service_server::{
    run_server,
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    Config,
};
use tracing::info;

#[tokio::main]
async fn main() {
    // let config = ServerConfig::builder()
    //     .with_client_cert_verifier(client_cert_verifier)
    // let config = Config {
    //     addr: SocketAddr::V4(())
    // }
    // run_server(c, service)
    let config_path =
        PathBuf::from_str(&args().nth(1).unwrap_or_else(|| "config.toml".to_string()))
            .expect("valid config path");

    let text = std::fs::read_to_string(&config_path).expect("read config file");
    let conf: TomlConfig = toml::from_str(&text).expect("valid toml");

    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&conf.key, &conf.cert) {
        let key = fs::read(key_path).expect("readable key");
        let key = if key_path.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .expect("valid PEM-encoded private key")
                .expect("non-empty private key")
        };
        let cert_chain = fs::read(cert_path).expect("readable certificate");
        let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
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
        addr: conf.addr,
        tls_config: tls,
        connection_limit: conf.conn_limit,
    };

    run_server(config, Service.into()).unwrap().await;
}

#[derive(serde::Deserialize)]
struct TomlConfig {
    addr: SocketAddr,
    conn_limit: Option<usize>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

struct Service;

struct FirstRound;

impl Musig2SignerFirstRound<Server, SecondRound> for FirstRound {
    fn our_nonce(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::PubNonce>> + Send {
        async move { todo!() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<Vec<musig2::secp256k1::PublicKey>>> + Send
    {
        async move { todo!() }
    }

    fn is_complete(&self) -> impl Future<Output = <Server as Origin>::Container<bool>> + Send {
        async move { todo!() }
    }

    fn receive_pub_nonce(
        &self,
        pubkey: musig2::secp256k1::PublicKey,
        pubnonce: musig2::PubNonce,
    ) -> impl Future<
        Output = <Server as Origin>::Container<Result<(), musig2::errors::RoundContributionError>>,
    > + Send {
        async move { todo!() }
    }

    fn finalize(
        self,
        hash: [u8; 32],
    ) -> impl Future<
        Output = <Server as Origin>::Container<
            Result<SecondRound, musig2::errors::RoundFinalizeError>,
        >,
    > + Send {
        async move { todo!() }
    }
}

struct SecondRound;

impl Musig2SignerSecondRound<Server> for SecondRound {
    fn agg_nonce(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::AggNonce>> + Send {
        async move { todo!() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<Vec<musig2::secp256k1::PublicKey>>> + Send
    {
        async move { todo!() }
    }

    fn our_signature(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::PartialSignature>> + Send {
        async move { todo!() }
    }

    fn is_complete(&self) -> impl Future<Output = <Server as Origin>::Container<bool>> + Send {
        async move { todo!() }
    }

    fn receive_signature(
        &self,
        pubkey: musig2::secp256k1::PublicKey,
        signature: musig2::PartialSignature,
    ) -> impl Future<
        Output = <Server as Origin>::Container<Result<(), musig2::errors::RoundContributionError>>,
    > + Send {
        async move { todo!() }
    }

    fn finalize(
        self,
    ) -> impl Future<
        Output = <Server as Origin>::Container<
            Result<musig2::LiftedSignature, musig2::errors::RoundFinalizeError>,
        >,
    > + Send {
        async move { todo!() }
    }
}

struct Operator;

impl OperatorSigner<Server> for Operator {
    fn sign_psbt(
        &self,
        psbt: bitcoin::Psbt,
    ) -> impl Future<Output = O::Container<bitcoin::Psbt>> + Send {
        async move { todo!() }
    }
}

struct P2PSigner;

impl SecretService<Server, FirstRound, SecondRound> for Service {
    type OperatorSigner = Operator;

    type P2PSigner;

    type Musig2Signer;

    type WotsSigner;

    fn operator_signer(&self) -> Self::OperatorSigner {
        todo!()
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        todo!()
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        todo!()
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        todo!()
    }
}
